import base64
import logging
import six

from cryptojwt import as_bytes
from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.jws import alg2keytype

from oidcservice import JWT_BEARER
from oidcservice import rndstr
from oidcservice import sanitize
from oidcservice.client_auth import AuthnFailure
from oidcmsg.exception import FailedAuthentication
from oidcmsg.exception import NotForMe
from oidcmsg.exception import UnknownAssertionType
from oidcmsg.key_jar import check_key_availability
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oidc import AuthnTokencd
from oidcmsg.time_util import utc_time_sans_frac

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


# ========================================================================
def assertion_jwt(cli, keys, audience, algorithm, lifetime=600):
    _now = utc_time_sans_frac()

    at = AuthnToken(iss=cli.client_id, sub=cli.client_id,
                    aud=audience, jti=rndstr(32),
                    exp=_now + lifetime, iat=_now)
    logger.debug('AuthnToken: {}'.format(at.to_dict()))
    return at.to_jwt(key=keys, algorithm=algorithm)


class ClientAuthnMethod(object):
    def __init__(self, srv=None):
        """
        :param srv: Server instance
        """
        self.srv = srv

    def verify(self, **kwargs):
        """
        Verify authentication information in a request
        :param kwargs:
        :return: True/False
        """
        raise NotImplementedError()


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """

    def verify(self, areq, client_id, **kwargs):
        if self.srv.cdb[client_id]["client_secret"] == areq["client_secret"]:
            return client_id
        else:
            raise AuthnFailure()


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """
    pass


class BearerHeader(ClientAuthnMethod):
    def verify(self, environ, **kwargs):
        try:
            cred = environ["HTTP_AUTHORIZATION"]
        except KeyError:
            raise AuthnFailure("missing authorization info")

        try:
            assert cred.startswith("Bearer ")
        except AssertionError:
            raise AuthnFailure("Wrong type of authorization token")

        label, token = cred.split(" ")
        return token


class BearerBody(ClientAuthnMethod):
    pass


class JWSAuthnMethod(ClientAuthnMethod):
    def verify(self, areq, **kwargs):
        try:
            try:
                argv = {'sender': areq['client_id']}
            except KeyError:
                argv = {}
            bjwt = AuthnToken().from_jwt(areq["client_assertion"],
                                         keyjar=self.srv.keyjar,
                                         **argv)
        except (Invalid, MissingKey) as err:
            logger.info("%s" % sanitize(err))
            raise AuthnFailure("Could not verify client_assertion.")

        logger.debug("authntoken: %s" % sanitize(bjwt.to_dict()))
        areq['parsed_client_assertion'] = bjwt

        # logger.debug("known clients: %s" % sanitize(self.cli.cdb.keys()))
        try:
            cid = kwargs["client_id"]
        except KeyError:
            cid = bjwt["iss"]

        try:
            # There might not be a client_id in the request
            assert str(cid) in self.srv.cdb  # It's a client I know
        except KeyError:
            pass

        # aud can be a string or a list
        _aud = bjwt["aud"]
        logger.debug("audience: %s, baseurl: %s" % (_aud, self.srv.baseurl))

        # figure out authn method
        if alg2keytype(bjwt.jws_header['alg']) == 'oct':  # Symmetric key
            authn_method = 'client_secret_jwt'
        else:
            authn_method = 'private_key_jwt'

        try:
            if isinstance(_aud, six.string_types):
                assert str(_aud).startswith(self.srv.baseurl)
            else:
                for target in _aud:
                    if target.startswith(self.srv.baseurl):
                        return cid, authn_method
                raise NotForMe("Not for me!")
        except AssertionError:
            raise NotForMe("Not for me!")

        return cid, authn_method


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """
    pass


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """
    pass


CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
}

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def valid_client_info(cinfo, when=0):
    eta = cinfo.get('client_secret_expires_at', 0)
    now = when or utc_time_sans_frac()
    if eta != 0 and eta < now:
        return False
    return True


def get_client_id(cdb, req, authn):
    """
    Verify the client and return the client id

    :param req: The request
    :param authn: Authentication information from the HTTP header
    :return:
    """

    logger.debug("REQ: %s" % sanitize(req.to_dict()))
    if authn:
        if authn.startswith("Basic "):
            logger.debug("Basic auth")
            (_id, _secret) = base64.b64decode(
                authn[6:].encode("utf-8")).decode("utf-8").split(":")

            _bid = as_bytes(_id)
            _cinfo = None
            try:
                _cinfo = cdb[_id]
            except KeyError:
                try:
                    _cinfo[_bid]
                except AttributeError:
                    pass

            if not _cinfo:
                logger.debug("Unknown client_id")
                raise FailedAuthentication("Unknown client_id")
            else:
                if not valid_client_info(_cinfo):
                    logger.debug("Invalid Client info")
                    raise FailedAuthentication("Invalid Client")

                if _secret != _cinfo["client_secret"]:
                    logger.debug("Incorrect secret")
                    raise FailedAuthentication("Incorrect secret")
        else:
            if authn[:6].lower() == "bearer":
                logger.debug("Bearer auth")
                _token = authn[7:]
            else:
                raise FailedAuthentication("AuthZ type I don't know")

            try:
                _id = cdb[_token]
            except KeyError:
                logger.debug("Unknown access token")
                raise FailedAuthentication("Unknown access token")
    else:
        try:
            _id = str(req["client_id"])
            if _id not in cdb:
                logger.debug("Unknown client_id")
                raise FailedAuthentication("Unknown client_id")
            if not valid_client_info(cdb[_id]):
                raise FailedAuthentication("Invalid client_id")
        except KeyError:
            raise FailedAuthentication("Missing client_id")

    return _id


def verify_client(inst, areq, authn, type_method=TYPE_METHOD):
    """
    Initiated Guessing !

    :param inst: Entity instance
    :param areq: The request
    :param authn: client authentication information
    :return: tuple containing client id and client authentication method
    """

    if authn:  # HTTP Basic auth (client_secret_basic)
        cid = get_client_id(inst.cdb, areq, authn)
        auth_method = 'client_secret_basic'
    elif "client_secret" in areq:  # client_secret_post
        client_id = get_client_id(inst.cdb, areq, authn)
        logger.debug("Verified Client ID: %s" % client_id)
        cid = ClientSecretBasic(inst).verify(areq, client_id)
        auth_method = 'client_secret_post'
    elif "client_assertion" in areq:  # client_secret_jwt or private_key_jwt
        check_key_availability(inst, areq['client_assertion'])

        for typ, method in type_method:
            if areq["client_assertion_type"] == typ:
                cid, auth_method = method(inst).verify(areq)
                break
        else:
            logger.error('UnknownAssertionType: {}'.format(
                areq["client_assertion_type"]))
            raise UnknownAssertionType(areq["client_assertion_type"], areq)
    else:
        logger.error("Missing client authentication.")
        raise FailedAuthentication("Missing client authentication.")

    if isinstance(areq, AccessTokenRequest):
        try:
            _method = inst.cdb[cid]['token_endpoint_auth_method']
        except KeyError:
            _method = 'client_secret_basic'

        if _method != auth_method:
            logger.error("Wrong authentication method used: {} != {}".format(
                auth_method, _method))
            raise FailedAuthentication("Wrong authentication method used")

    # store which authn method was used where
    try:
        inst.cdb[cid]['auth_method'][areq.__class__.__name__] = auth_method
    except KeyError:
        try:
            inst.cdb[cid]['auth_method'] = {
                areq.__class__.__name__: auth_method}
        except KeyError:
            pass

    return cid
