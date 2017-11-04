import logging

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oiccli import grant
from oiccli import oauth2

from oiccli.oic import requests
from oiccli.grant import Token
from oiccli.webfinger import OIC_ISSUER
from oiccli.webfinger import WebFinger

from oicmsg.oic import AuthorizationResponse
from oicmsg.oic import AccessTokenResponse

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

DEFAULT_SERVICES = ['AuthorizationRequest', 'AccessTokenRequest',
                    'RefreshAccessTokenRequest', 'ProviderInfoDiscovery',
                    'UserInfoRequest', 'RegistrationRequest']

# -----------------------------------------------------------------------------

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400

# -----------------------------------------------------------------------------
# ACR_LISTS = [
#     ["0", "1", "2", "3", "4"],
# ]
#
#
# def verify_acr_level(req, level):
#     if req is None:
#         return level
#     elif "values" in req:
#         for _r in req["values"]:
#             for alist in ACR_LISTS:
#                 try:
#                     if alist.index(_r) <= alist.index(level):
#                         return level
#                 except ValueError:
#                     pass
#     else:  # Required or Optional
#         return level
#
#     raise AccessDenied("", req)


class Grant(grant.Grant):
    _authz_resp = AuthorizationResponse
    _acc_resp = AccessTokenResponse
    _token_class = Token

    def add_token(self, resp):
        tok = self._token_class(resp)
        if tok.access_token:
            self.tokens.append(tok)
        else:
            _tmp = getattr(tok, "id_token", None)
            if _tmp:
                self.tokens.append(tok)


PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg":
        "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc":
        "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg":
        "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc":
        "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg":
        "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc":
        "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg":
        "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    'grant_types': 'grant_types_supported'
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


class Client(oauth2.Client):
    def __init__(self, ca_certs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, config=None, client_cert=None, httplib=None, 
                 services=None, service_factory=None):

        _srvs = services or DEFAULT_SERVICES
        service_factory = service_factory or requests.factory
        oauth2.Client.__init__(self, ca_certs,
                               client_authn_method=client_authn_method,
                               keyjar=keyjar, verify_ssl=verify_ssl,
                               config=config, client_cert=client_cert,
                               httplib=httplib, services=_srvs,
                               service_factory=service_factory)

        self.wf = WebFinger(OIC_ISSUER)
        self.wf.httpd = self.http

    # ------------------------------------------------------------------------

    # def user_info_request(self, method="GET", state="", scope="", **kwargs):
    #     uir = UserInfoRequest()
    #     logger.debug("[user_info_request]: kwargs:%s" % (sanitize(kwargs),))
    #     token = None
    #     if "token" in kwargs:
    #         if kwargs["token"]:
    #             uir["access_token"] = kwargs["token"]
    #             token = Token()
    #             token.token_type = "Bearer"
    #             token.access_token = kwargs["token"]
    #             kwargs["behavior"] = "use_authorization_header"
    #         else:
    #             # What to do ? Need a callback
    #             pass
    #     elif "access_token" in kwargs and kwargs["access_token"]:
    #         uir["access_token"] = kwargs["access_token"]
    #         del kwargs["access_token"]
    #     elif state:
    #         token = self.grant[state].get_token(scope)
    #
    #         if token.is_valid():
    #             uir["access_token"] = token.access_token
    #             if token.token_type and token.token_type.lower() == "bearer" \
    #                     and method == "GET":
    #                 kwargs["behavior"] = "use_authorization_header"
    #         else:
    #             # raise oauth2.OldAccessToken
    #             if self.log:
    #                 self.log.info("do access token refresh")
    #             try:
    #                 self.do_access_token_refresh(token=token)
    #                 token = self.grant[state].get_token(scope)
    #                 uir["access_token"] = token.access_token
    #             except Exception:
    #                 raise
    #
    #     uri = self._endpoint("userinfo_endpoint", **kwargs)
    #     # If access token is a bearer token it might be sent in the
    #     # authorization header
    #     # 4 ways of sending the access_token:
    #     # - POST with token in authorization header
    #     # - POST with token in message body
    #     # - GET with token in authorization header
    #     # - GET with token as query parameter
    #     if "behavior" in kwargs:
    #         _behav = kwargs["behavior"]
    #         _token = uir["access_token"]
    #         _ttype = ''
    #         try:
    #             _ttype = kwargs["token_type"]
    #         except KeyError:
    #             if token:
    #                 try:
    #                     _ttype = token.token_type
    #                 except AttributeError:
    #                     raise MissingParameter("Unspecified token type")
    #
    #         if 'as_query_parameter' == _behav:
    #             method = 'GET'
    #         elif token:
    #             # use_authorization_header, token_in_message_body
    #             if "use_authorization_header" in _behav:
    #                 token_header = "{type} {token}".format(
    #                     type=_ttype.capitalize(),
    #                     token=_token)
    #                 if "headers" in kwargs:
    #                     kwargs["headers"].update(
    #                         {"Authorization": token_header})
    #                 else:
    #                     kwargs["headers"] = {"Authorization": token_header}
    #
    #             if "token_in_message_body" not in _behav:
    #                 # remove the token from the request
    #                 del uir["access_token"]
    #
    #     path, body, kwargs = get_or_post(uri, method, uir, **kwargs)
    #
    #     h_args = dict([(k, v) for k, v in kwargs.items() if k in HTTP_ARGS])
    #
    #     return path, body, method, h_args



