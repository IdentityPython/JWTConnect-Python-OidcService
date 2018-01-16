import logging

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oiccli import oauth2

from oiccli.oic import service
from oiccli.webfinger import OIC_ISSUER
from oiccli.webfinger import WebFinger

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

DEFAULT_SERVICES = ['Authorization', 'AccessToken', 'RefreshAccessToken',
                    'ProviderInfoDiscovery', 'UserInfo', 'Registration']

# -----------------------------------------------------------------------------

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400


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
        service_factory = service_factory or service.factory
        oauth2.Client.__init__(self, ca_certs,
                               client_authn_method=client_authn_method,
                               keyjar=keyjar, verify_ssl=verify_ssl,
                               config=config, client_cert=client_cert,
                               httplib=httplib, services=_srvs,
                               service_factory=service_factory)

        # self.wf = WebFinger(OIC_ISSUER)
        # self.wf.httpd = self.http
