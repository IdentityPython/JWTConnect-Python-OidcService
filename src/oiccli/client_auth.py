import base64
import logging

from cryptojwt.jws import alg2keytype
from oiccli.exception import MissingRequiredAttribute

from oiccli import rndstr
from oiccli import sanitize
from oiccli import DEF_SIGN_ALG
from oiccli import JWT_BEARER
from oicmsg.message import VREQUIRED
from oicmsg.oauth2 import AccessTokenRequest
from oicmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oicmsg.oic import AuthnToken
from oicmsg.time_util import utc_time_sans_frac

logger = logging.getLogger(__name__)

__author__ = 'roland hedberg'


class AuthnFailure(Exception):
    pass


class NoMatchingKey(Exception):
    pass


class UnknownAuthnMethod(Exception):
    pass


# ========================================================================
def assertion_jwt(client_id, keys, audience, algorithm, lifetime=600):
    """
    Create a signed Json Web Token containing some information.

    :param client_id: The Client ID
    :param keys: Signing keys
    :param audience: Who is the receivers for this assertion
    :param algorithm: Signing algorithm
    :param lifetime: The lifetime of the signed Json Web Token
    :return: A Signed Json Web Token
    """
    _now = utc_time_sans_frac()

    at = AuthnToken(iss=client_id, sub=client_id,
                    aud=audience, jti=rndstr(32),
                    exp=_now + lifetime, iat=_now)
    logger.debug('AuthnToken: {}'.format(at.to_dict()))
    return at.to_jwt(key=keys, algorithm=algorithm)


class ClientAuthnMethod(object):
    """
    Basic Client Authentication Method class.
    Only has one method: 'construct'
    """

    def construct(self, **kwargs):
        """ Add authentication information to a request
        :return:
        """
        raise NotImplementedError()


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, may authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.

    The upshot of this is to construct an Authorization header that has the
    value 'Basic <token>' where <token> is username and password concatenated
    together with a ':' in between and then URL safe base64 encoded.
    """

    def construct(self, request, cli_info=None, http_args=None, **kwargs):
        """
        Construct a dictionary to be added to the HTTP request headers

        :param request: The request
        :param cli_info: A :py:class:`oiccli.client_info.ClientInfo` instance
        :param http_args: HTTP arguments
        :return: dictionary of HTTP arguments
        """

        if http_args is None:
            http_args = {}

        if "headers" not in http_args:
            http_args["headers"] = {}

        # get the username (client_id) and the password (client_secret)
        try:
            passwd = kwargs["password"]
        except KeyError:
            try:
                passwd = http_args["password"]
            except KeyError:
                try:
                    passwd = request["client_secret"]
                except KeyError:
                    passwd = cli_info.client_secret

        try:
            user = kwargs["user"]
        except KeyError:
            user = cli_info.client_id

        # The credential is username and password concatenated with a ':'
        # in between and then base 64 encoded becomes the authentication
        # token.
        credentials = "{}:{}".format(user, passwd)
        authz = base64.urlsafe_b64encode(credentials.encode("utf-8")).decode(
            "utf-8")
        http_args["headers"]["Authorization"] = "Basic {}".format(authz)

        # If client_secret was part of the request message instance remove it
        try:
            del request["client_secret"]
        except KeyError:
            pass

        # If we're doing an access token request with an authorization code
        # then we should add client_id to the request if it's not already
        # there
        if isinstance(request, AccessTokenRequest) and request[
                'grant_type'] == 'authorization_code':
            if 'client_id' not in request:
                try:
                    request['client_id'] = cli_info.client_id
                except AttributeError:
                    pass
        else:
            # remove client_id if not required by the request definition
            try:
                _req = request.c_param["client_id"][VREQUIRED]
            except KeyError:
                _req = False

            # if it's not required remove it
            if not _req:
                try:
                    del request["client_id"]
                except KeyError:
                    pass

        return http_args


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.

    These means putting both client_secret and client_id in the request body.
    """

    def construct(self, request, cli_info=None, http_args=None, **kwargs):
        # I MUST have a client_secret, there are 3 possible places
        # where I can find it. In the request, as an argument in http_args
        # or among the client information.
        if "client_secret" not in request:
            try:
                request["client_secret"] = http_args["client_secret"]
                del http_args["client_secret"]
            except (KeyError, TypeError):
                if cli_info.client_secret:
                    request["client_secret"] = cli_info.client_secret
                else:
                    raise AuthnFailure("Missing client secret")

        # Add the client_id to the request
        request["client_id"] = cli_info.client_id

        # return a possbly modified http_args dictionary
        return http_args


class BearerHeader(ClientAuthnMethod):
    def construct(self, request=None, cli_info=None, http_args=None, **kwargs):
        """
        Constructing the Authorization header. The value of
        the Authorization header is "Bearer <access_token>".

        :param request: Request class instance
        :param ci: Client information
        :param http_args: HTTP header arguments
        :param kwargs: extra keyword arguments
        :return:
        """

        # try to find the access_token in the request
        if request is not None:
            if "access_token" in request:
                _acc_token = request["access_token"]
                del request["access_token"]
                # Required under certain circumstances :-) not under other
                request.c_param["access_token"] = SINGLE_OPTIONAL_STRING
            else:
                try:
                    _acc_token = kwargs["access_token"]
                except KeyError:
                    _acc_token = cli_info.state_db.get_token_info(
                        **kwargs)['access_token']
        else:
            try:
                _acc_token = kwargs["access_token"]
            except KeyError:
                raise MissingRequiredAttribute('access_token')

        # The authorization value starts with 'Bearer' when bearer tokens
        # are used
        _bearer = "Bearer {}".format(_acc_token)

        # Add 'Authorization' to the headers
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
    def construct(self, request, cli_info=None, http_args=None, **kwargs):
        """
        Will add access_token to the request if not present

        :param request: The request
        :param cli_info: A :py:class:`oiccli.client_info.ClientInfo` instance
        :param http_args: HTTP arguments
        :param kwargs: extra keyword arguments
        :return: A possibly modified dictionary with HTTP arguments.
        """

        if "access_token" in request:
            pass
        else:
            try:
                request["access_token"] = kwargs["access_token"]
            except KeyError:
                try:
                    kwargs["state"]
                except KeyError:
                    if not cli_info.state:
                        raise AuthnFailure("Missing state specification")
                    kwargs["state"] = cli_info.state

                request["access_token"] = cli_info.state_db.get_token_info(
                    **kwargs)['access_token']

        return http_args


def bearer_auth(request, authn):
    """
    Pick out the access token, either in HTTP_Authorization header or
    in request body.

    :param request: The request
    :param authn: The value of the Authorization header
    :return: An access token
    """

    try:
        return request["access_token"]
    except KeyError:
        if not authn.startswith("Bearer "):
            raise ValueError('Not a bearer token')
        return authn[7:]


class JWSAuthnMethod(ClientAuthnMethod):
    """
    Base class for client authentication methods that uses signed Json
    Web Tokens.
    """

    def choose_algorithm(self, context, **kwargs):
        """
        Pick signing algorithm

        :param context: Signing context
        :param kwargs: extra keyword arguments
        :return: Name of a signing algorithm
        """
        try:
            algorithm = kwargs["algorithm"]
        except KeyError:
            # different contexts uses different signing algorithms
            algorithm = DEF_SIGN_ALG[context]
        if not algorithm:
            raise AuthnFailure("Missing algorithm specification")
        return algorithm

    def get_signing_key(self, algorithm, cli_info):
        """
        Pick signing key based on signing algorithm to be used

        :param algorithm: Signing algorithm
        :param cli_info: A :py:class:`oiccli.client_info.ClientInfo` instance
        :return: A key
        """
        return cli_info.keyjar.get_signing_key(
            alg2keytype(algorithm), alg=algorithm)

    def get_key_by_kid(self, kid, algorithm, cli_info):
        """
        Pick a key that matches a given key ID and signing algorithm.

        :param kid: Key ID
        :param algorithm: Signing algorithm
        :param cli_info: A :py:class:`oiccli.client_info.ClientInfo` instance
        :return: A matching key
        """
        _key = cli_info.keyjar.get_key_by_kid(kid)
        if _key:
            ktype = alg2keytype(algorithm)
            if _key.kty != ktype:
                raise NoMatchingKey("Wrong key type")
            else:
                return _key
        else:
            raise NoMatchingKey("No key with kid:%s" % kid)

    def construct(self, request, cli_info=None, http_args=None, **kwargs):
        """
        Constructs a client assertion and signs it with a key.
        The request is modified as a side effect.

        :param request: The request
        :param cli_info: A :py:class:`oiccli.client_info.ClientInfo` instance
        :param http_args: HTTP arguments
        :param kwargs: Extra arguments
        :return: Constructed HTTP arguments, in this case none
        """

        if 'client_assertion' in kwargs:
            request["client_assertion"] = kwargs['client_assertion']
            if 'client_assertion_type' in kwargs:
                request[
                    'client_assertion_type'] = kwargs['client_assertion_type']
            else:
                request["client_assertion_type"] = JWT_BEARER
        elif 'client_assertion' in request:
            if 'client_assertion_type' not in request:
                request["client_assertion_type"] = JWT_BEARER
        else:
            algorithm = None
            # audience for the signed JWT depends on which endpoint
            # we're talking to.
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

            # construct the signed JWT with the assertions and add
            # it as value to the 'client_assertion' claim of the request
            request["client_assertion"] = assertion_jwt(
                cli_info.client_id, signing_key, audience,
                algorithm, **_args)

            request["client_assertion_type"] = JWT_BEARER

        try:
            del request["client_secret"]
        except KeyError:
            pass

        # If client_id is not required to be present, remove it.
        if not request.c_param["client_id"][VREQUIRED]:
            try:
                del request["client_id"]
            except KeyError:
                pass

        return {}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server can create a signed JWT using an HMAC SHA algorithm, such as
    HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    def choose_algorithm(self, context="client_secret_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, context, **kwargs)

    def get_signing_key(self, algorithm, cli_info):
        return cli_info.keyjar.get_signing_key(
            alg2keytype(algorithm), alg=algorithm)


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key can sign a JWT using that key.
    """

    def choose_algorithm(self, context="private_key_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, context, **kwargs)

    def get_signing_key(self, algorithm, cli_info=None):
        return cli_info.keyjar.get_signing_key(
            alg2keytype(algorithm), "", alg=algorithm)


# Map from client authentication identifiers to corresponding class
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
    """
    Check if the client_secret has expired

    :param cinfo: A :py:class:`oiccli.client_info.ClientInfo` instance
    :param when: A time stamp against which the expiration time is to be checked
    :return: True if the client_secret is still valid
    """
    eta = getattr(cinfo, 'registration_expires', 0)
    now = when or utc_time_sans_frac()
    if eta != 0 and eta < now:
        return False
    return True
