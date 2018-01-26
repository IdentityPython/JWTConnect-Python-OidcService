import logging

from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.client_info import ClientInfo
from oiccli.exception import OicCliError
from oiccli.http import HTTPLib
from oiccli.oauth2 import service
from oiccli.service import Service, build_services

from oicmsg.key_jar import KeyJar

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

Version = "2.0"

DEFAULT_SERVICES = [
    ('Authorization', {}),
    ['AccessToken', {}],
    ('RefreshAccessToken', {}),
    ('ProviderInfoDiscovery', {})
]


class ExpiredToken(OicCliError):
    pass


# =============================================================================


class Client(object):
    def __init__(self, ca_certs=None, client_authn_method=None,
                 keyjar=None, verify_ssl=True, config=None, client_cert=None,
                 httplib=None, services=None, service_factory=None):
        """

        :param ca_certs: Certificates used to verify HTTPS certificates
        :param client_authn_method: Methods that this client can use to
            authenticate itself. It's a dictionary with method names as
            keys and method classes as values.
        :param verify_ssl: Whether the SSL certificate should be verified.
        :return: Client instance
        """

        self.http = httplib or HTTPLib(ca_certs=ca_certs,
                                       verify_ssl=verify_ssl,
                                       client_cert=client_cert,
                                       keyjar=keyjar)

        if not keyjar:
            keyjar = KeyJar()

        self.events = None
        self.client_info = ClientInfo(keyjar, config=config)
        if self.client_info.client_id:
            self.client_id = self.client_info.client_id
        _cam = client_authn_method or CLIENT_AUTHN_METHOD
        self.service_factory = service_factory or service.factory
        _srvs = services or DEFAULT_SERVICES

        self.service = build_services(_srvs, self.service_factory, self.http,
                                      keyjar, _cam)

        self.client_info.service = self.service

        self.verify_ssl = verify_ssl

    def construct(self, request_type, request_args=None, extra_args=None,
                  **kwargs):
        try:
            self.service[request_type]
        except KeyError:
            raise NotImplemented(request_type)

        met = getattr(self, 'construct_{}_request'.format(request_type))
        return met(self.client_info, request_args, extra_args, **kwargs)

    def do_request(self, request_type, scope="", response_body_type="",
                   method="", request_args=None, extra_args=None,
                   http_args=None, authn_method="", **kwargs):

        _srv = self.service[request_type]
        if not method:
            method = _srv.http_method

        _info = _srv.do_request_init(
            self.client_info, method=method, scope=scope,
            request_args=request_args, extra_args=extra_args,
            authn_method=authn_method, http_args=http_args, **kwargs)

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug('do_request info: {}'.format(_info))

        try:
            _body = _info['body']
        except KeyError:
            _body = None

        return _srv.service_request(
            _info['uri'], method, _body, response_body_type,
            http_args=_info['http_args'], client_info=self.client_info,
            **kwargs)

    def set_client_id(self, client_id):
        self.client_id = client_id
        self.client_info.client_id = client_id
