import base64
import logging

from jwkest import as_bytes
from jwkest.jws import alg2keytype

from oiccli import rndstr
from oiccli import sanitize
from oiccli import DEF_SIGN_ALG
from oiccli import JWT_BEARER
from oicmsg.exception import FailedAuthentication
from oicmsg.message import VREQUIRED
from oicmsg.oauth2 import AccessTokenRequest
from oicmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oicmsg.oic import AuthnToken
from oicmsg.time_util import utc_time_sans_frac

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class AuthnFailure(Exception):
    pass


class NoMatchingKey(Exception):
    pass


class UnknownAuthnMethod(Exception):
    pass


# ========================================================================
def assertion_jwt(client_id, keys, audience, algorithm, lifetime=600):
    _now = utc_time_sans_frac()

    at = AuthnToken(iss=client_id, sub=client_id,
                    aud=audience, jti=rndstr(32),
                    exp=_now + lifetime, iat=_now)
    logger.debug('AuthnToken: {}'.format(at.to_dict()))
    return at.to_jwt(key=keys, algorithm=algorithm)


class ClientAuthnMethod(object):
    def construct(self, **kwargs):
        """ Add authentication information to a request
        :return:
        """
        raise NotImplementedError()


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """

    def construct(self, cis, cli_info=None, request_args=None, http_args=None,
                  **kwargs):
        """
        :param cis: Request class instance
        :param request_args: Request arguments
        :param http_args: HTTP arguments
        :return: dictionary of HTTP arguments
        """

        if http_args is None:
            http_args = {}

        try:
            passwd = kwargs["password"]
        except KeyError:
            try:
                passwd = http_args["password"]
            except KeyError:
                try:
                    passwd = cis["client_secret"]
                except KeyError:
                    passwd = cli_info.client_secret

        try:
            user = kwargs["user"]
        except KeyError:
            user = cli_info.client_id

        if "headers" not in http_args:
            http_args["headers"] = {}

        credentials = "{}:{}".format(user, passwd)
        authz = base64.urlsafe_b64encode(credentials.encode("utf-8")).decode(
            "utf-8")
        http_args["headers"]["Authorization"] = "Basic {}".format(authz)

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        if isinstance(cis, AccessTokenRequest) and cis[
            'grant_type'] == 'authorization_code':
            if 'client_id' not in cis:
                try:
                    cis['client_id'] = cli_info.client_id
                except AttributeError:
                    pass
        else:
            try:
                _req = cis.c_param["client_id"][VREQUIRED]
            except KeyError:
                _req = False

            if not _req:
                try:
                    del cis["client_id"]
                except KeyError:
                    pass

        return http_args


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """

    def construct(self, cis, cli_info=None, request_args=None, http_args=None,
                  **kwargs):

        if "client_secret" not in cis:
            try:
                cis["client_secret"] = http_args["client_secret"]
                del http_args["client_secret"]
            except (KeyError, TypeError):
                if cli_info.client_secret:
                    cis["client_secret"] = cli_info.client_secret
                else:
                    raise AuthnFailure("Missing client secret")

        cis["client_id"] = cli_info.client_id

        return http_args


class BearerHeader(ClientAuthnMethod):
    def construct(self, cis=None, cli_info=None, request_args=None,
                  http_args=None, **kwargs):
        """
        More complicated logic then I would have liked it to be

        :param cis: Request class instance
        :param ci: Client information
        :param request_args: request arguments
        :param http_args: HTTP header arguments
        :param kwargs:
        :return:
        """

        if cis is not None:
            if "access_token" in cis:
                _acc_token = cis["access_token"]
                del cis["access_token"]
                # Required under certain circumstances :-) not under other
                cis.c_param["access_token"] = SINGLE_OPTIONAL_STRING
            else:
                try:
                    _acc_token = request_args["access_token"]
                    del request_args["access_token"]
                except (KeyError, TypeError):
                    try:
                        _acc_token = kwargs["access_token"]
                    except KeyError:
                        _acc_token = cli_info.state_db.get_token_info(
                            **kwargs)['access_token']
        else:
            try:
                _acc_token = kwargs["access_token"]
            except KeyError:
                _acc_token = request_args["access_token"]

        # Do I need to base64 encode the access token ? Probably !
        # _bearer = "Bearer %s" % base64.b64encode(_acc_token)
        _bearer = "Bearer %s" % _acc_token
        if http_args is None:
            http_args = {"headers": {}}
            http_args["headers"]["Authorization"] = _bearer
        else:
            try:
                http_args["headers"]["Authorization"] = _bearer
            except KeyError:
                http_args["headers"] = {"Authorization": _bearer}

        return http_args


class BearerBody(ClientAuthnMethod):
    def construct(self, cis, cli_info=None, request_args=None, http_args=None,
                  **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in cis:
            pass
        else:
            try:
                cis["access_token"] = request_args["access_token"]
            except KeyError:
                try:
                    kwargs["state"]
                except KeyError:
                    if not cli_info.state:
                        raise AuthnFailure("Missing state specification")
                    kwargs["state"] = cli_info.state

                cis["access_token"] = cli_info.state_db.get_token_info(
                    **kwargs)['access_token']

        return http_args


def bearer_auth(req, authn):
    """
    Pick out the access token, either in HTTP_Authorization header or
    in request body.

    :param req:
    :param authn:
    :return:
    """

    try:
        return req["access_token"]
    except KeyError:
        assert authn.startswith("Bearer ")
        return authn[7:]


class JWSAuthnMethod(ClientAuthnMethod):
    def choose_algorithm(self, entity, **kwargs):
        try:
            algorithm = kwargs["algorithm"]
        except KeyError:
            algorithm = DEF_SIGN_ALG[entity]
        if not algorithm:
            raise AuthnFailure("Missing algorithm specification")
        return algorithm

    def get_signing_key(self, algorithm, cli_info):
        return cli_info.keyjar.get_signing_key(
            alg2keytype(algorithm), alg=algorithm)

    def get_key_by_kid(self, kid, algorithm, cli_info):
        _key = cli_info.keyjar.get_key_by_kid(kid)
        if _key:
            ktype = alg2keytype(algorithm)
            try:
                assert _key.kty == ktype
            except AssertionError:
                raise NoMatchingKey("Wrong key type")
            else:
                return _key
        else:
            raise NoMatchingKey("No key with kid:%s" % kid)

    def construct(self, cis, cli_info=None, request_args=None, http_args=None,
                  **kwargs):
        """
        Constructs a client assertion and signs it with a key.
        The request is modified as a side effect.

        :param cis: The request
        :param request_args: request arguments
        :param http_args: HTTP arguments
        :param kwargs: Extra arguments
        :return: Constructed HTTP arguments, in this case none
        """

        # audience is the OP endpoint
        # audience = self.cli._endpoint(REQUEST2ENDPOINT[cis.type()])
        # OR OP identifier

        if 'client_assertion' in kwargs:
            cis["client_assertion"] = kwargs['client_assertion']
            if 'client_assertion_type' in kwargs:
                cis['client_assertion_type'] = kwargs['client_assertion_type']
            else:
                cis["client_assertion_type"] = JWT_BEARER
        elif 'client_assertion' in cis:
            if 'client_assertion_type' not in cis:
                cis["client_assertion_type"] = JWT_BEARER
        else:
            algorithm = None
            if kwargs['authn_endpoint'] in ['token', 'refresh']:
                try:
                    algorithm = cli_info.registration_info[
                        'token_endpoint_auth_signing_alg']
                except (KeyError, AttributeError):
                    pass
                audience = cli_info.provider_info['token_endpoint']
            else:
                audience = cli_info.provider_info['issuer']

            if not algorithm:
                algorithm = self.choose_algorithm(**kwargs)

            ktype = alg2keytype(algorithm)
            try:
                if 'kid' in kwargs:
                    signing_key = [self.get_key_by_kid(kwargs["kid"], algorithm,
                                                       cli_info)]
                elif ktype in cli_info.kid["sig"]:
                    try:
                        signing_key = [self.get_key_by_kid(
                            cli_info.kid["sig"][ktype], algorithm, cli_info)]
                    except KeyError:
                        signing_key = self.get_signing_key(algorithm, cli_info)
                else:
                    signing_key = self.get_signing_key(algorithm, cli_info)
            except NoMatchingKey as err:
                logger.error("%s" % sanitize(err))
                raise

            try:
                _args = {'lifetime': kwargs['lifetime']}
            except KeyError:
                _args = {}

            cis["client_assertion"] = assertion_jwt(
                cli_info.client_id, signing_key, audience,
                algorithm, **_args)

            cis["client_assertion_type"] = JWT_BEARER

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        if not cis.c_param["client_id"][VREQUIRED]:
            try:
                del cis["client_id"]
            except KeyError:
                pass

        return {}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    def choose_algorithm(self, entity="client_secret_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm, cli_info):
        return cli_info.keyjar.get_signing_key(
            alg2keytype(algorithm), alg=algorithm)


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """

    def choose_algorithm(self, entity="private_key_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm, cli_info=None):
        return cli_info.keyjar.get_signing_key(
            alg2keytype(algorithm), "", alg=algorithm)


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


# This is server side
# def get_client_id(cdb, req, authn):
#     """
#     Verify the client and return the client id
#
#     :param cdb: Client database
#     :param req: The request
#     :param authn: Authentication information from the HTTP header
#     :return:
#     """
#
#     logger.debug("REQ: %s" % sanitize(req.to_dict()))
#     if authn:
#         if authn.startswith("Basic "):
#             logger.debug("Basic auth")
#             (_id, _secret) = base64.b64decode(
#                 authn[6:].encode("utf-8")).decode("utf-8").split(":")
#
#             _bid = as_bytes(_id)
#             _cinfo = None
#             try:
#                 _cinfo = cdb[_id]
#             except KeyError:
#                 try:
#                     _cinfo[_bid]
#                 except AttributeError:
#                     pass
#
#             if not _cinfo:
#                 logger.debug("Unknown client_id")
#                 raise FailedAuthentication("Unknown client_id")
#             else:
#                 if not valid_client_info(_cinfo):
#                     logger.debug("Invalid Client info")
#                     raise FailedAuthentication("Invalid Client")
#
#                 if _secret != _cinfo["client_secret"]:
#                     logger.debug("Incorrect secret")
#                     raise FailedAuthentication("Incorrect secret")
#         else:
#             if authn[:6].lower() == "bearer":
#                 logger.debug("Bearer auth")
#                 _token = authn[7:]
#             else:
#                 raise FailedAuthentication("AuthZ type I don't know")
#
#             try:
#                 _id = cdb[_token]
#             except KeyError:
#                 logger.debug("Unknown access token")
#                 raise FailedAuthentication("Unknown access token")
#     else:
#         try:
#             _id = str(req["client_id"])
#             if _id not in cdb:
#                 logger.debug("Unknown client_id")
#                 raise FailedAuthentication("Unknown client_id")
#             if not valid_client_info(cdb[_id]):
#                 raise FailedAuthentication("Invalid client_id")
#         except KeyError:
#             raise FailedAuthentication("Missing client_id")
#
#     return _id
