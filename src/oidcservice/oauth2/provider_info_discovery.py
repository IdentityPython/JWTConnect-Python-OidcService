"""The service that talks to the OAuth2 provider info discovery endpoint."""
import logging

from cryptojwt.key_jar import KeyJar

from oidcmsg import oauth2
from oidcmsg.oauth2 import ResponseMessage

from oidcservice import OIDCONF_PATTERN
from oidcservice.exception import OidcServiceError
from oidcservice.service import Service

LOGGER = logging.getLogger(__name__)


class ProviderInfoDiscovery(Service):
    """The service that talks to the OAuth2 provider info discovery endpoint."""
    msg_type = oauth2.Message
    response_cls = oauth2.ASConfigurationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = 'provider_info'
    http_method = 'GET'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory, conf=conf)

    def get_endpoint(self):
        """
        Find the issuer ID and from it construct the service endpoint

        :return: Service endpoint
        """
        try:
            _iss = self.service_context.issuer
        except AttributeError:
            _iss = self.endpoint

        if _iss.endswith('/'):
            return OIDCONF_PATTERN.format(_iss[:-1])

        return OIDCONF_PATTERN.format(_iss)

    def get_request_parameters(self, method="GET", **kwargs):
        """
        The Provider info discovery version of get_request_parameters()

        :param method:
        :param kwargs:
        :return:
        """
        return {'url': self.get_endpoint(), 'method': method}

    def _verify_issuer(self, resp, issuer):
        _pcr_issuer = resp["issuer"]
        if resp["issuer"].endswith("/"):
            if issuer.endswith("/"):
                _issuer = issuer
            else:
                _issuer = issuer + "/"
        else:
            if issuer.endswith("/"):
                _issuer = issuer[:-1]
            else:
                _issuer = issuer

        # In some cases we can live with the two URLs not being
        # the same. But this is an excepted that has to be explicit
        try:
            self.service_context.allow['issuer_mismatch']
        except KeyError:
            if _issuer != _pcr_issuer:
                raise OidcServiceError(
                    "provider info issuer mismatch '%s' != '%s'" % (
                        _issuer, _pcr_issuer))
        return _issuer

    @staticmethod
    def _store_endpoint(srvs, key, val):
        for _srv in srvs.values():
            # Every service has an endpoint_name assigned
            # when initiated. This name *MUST* match the
            # endpoint names used in the provider info
            if _srv.endpoint_name == key:
                _srv.endpoint = val
                break

    def _set_endpoints(self, resp):
        """
        If there are services defined set the service endpoint to be
        the URLs specified in the provider information."""
        try:
            _srvs = self.service_context.service
        except AttributeError:
            pass
        else:
            if _srvs:
                for key, val in resp.items():
                    # All service endpoint parameters in the provider info has
                    # a name ending in '_endpoint' so I can look specifically
                    # for those
                    if key.endswith("_endpoint"):
                        self._store_endpoint(_srvs, key, val)

    def _update_service_context(self, resp):
        """
        Deal with Provider Config Response. Based on the provider info
        response a set of parameters in different places needs to be set.

        :param resp: The provider info response
        :param service_context: Information collected/used by services
        """

        # Verify that the issuer value received is the same as the
        # url that was used as service endpoint (without the .well-known part)
        if "issuer" in resp:
            _pcr_issuer = self._verify_issuer(resp, self.service_context.issuer)
        else:  # No prior knowledge
            _pcr_issuer = self.service_context.issuer

        self.service_context.issuer = _pcr_issuer
        self.service_context.provider_info = resp

        self._set_endpoints(resp)

        # If I already have a Key Jar then I'll add then provider keys to
        # that. Otherwise a new Key Jar is minted
        try:
            _keyjar = self.service_context.keyjar
        except KeyError:
            _keyjar = KeyJar()

        # Load the keys. Note that this only means that the key specification
        # is loaded not necessarily that any keys are fetched.
        if 'jwks_uri' in resp:
            _keyjar.load_keys(_pcr_issuer, jwks_uri=resp['jwks_uri'])
        elif 'jwks' in resp:
            _keyjar.load_keys(_pcr_issuer, jwks=resp['jwks'])

        self.service_context.keyjar = _keyjar

    def update_service_context(self, resp, **kwargs):
        return self._update_service_context(resp)
