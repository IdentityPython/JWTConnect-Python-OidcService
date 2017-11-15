import logging

from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.client_info import ClientInfo
from oiccli.exception import OicCliError
from oiccli.http import HTTPLib
from oiccli.http_util import BadRequest
from oiccli.http_util import Response
from oiccli.http_util import R2C
from oiccli.http_util import SeeOther
from oiccli.oauth2 import requests
from oiccli.request import Request

from oicmsg.oauth2 import AuthorizationErrorResponse
from oicmsg.oauth2 import ErrorResponse
from oicmsg.key_jar import KeyJar

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

Version = "2.0"

DEFAULT_SERVICES = ['AuthorizationRequest', 'AccessTokenRequest',
                    'RefreshAccessTokenRequest', 'ProviderInfoDiscovery']


class ExpiredToken(OicCliError):
    pass


# =============================================================================

def error_response(error, descr='', status="400 Bad Request"):
    response = ErrorResponse(error=error, error_description=descr)
    return Response(response.to_json(), content="application/json",
                    status=status)


def error(error, descr=None, status_code=400):
    stat_txt = R2C[status_code]._status
    return error_response(error=error, descr=descr, status=stat_txt)


def authz_error(error, descr=None, status_code=400):
    response = AuthorizationErrorResponse(error=error)
    if descr:
        response["error_description"] = descr
    stat_txt = R2C[status_code]._status
    return Response(response.to_json(), content="application/json",
                    status=stat_txt)


def redirect_authz_error(error, redirect_uri, descr=None, state="",
                         return_type=None):
    err = AuthorizationErrorResponse(error=error)
    if descr:
        err["error_description"] = descr
    if state:
        err["state"] = state
    if return_type is None or return_type == ["code"]:
        location = err.request(redirect_uri)
    else:
        location = err.request(redirect_uri, True)
    return SeeOther(location)


def exception_to_error_mesg(excep):
    if isinstance(excep.args, tuple):
        _msg = excep.args[0]
    else:
        _msg = ', '.join(excep.args)

    err = ErrorResponse(error='service_error',
                        error_description='{}: {}'.format(
                            excep.__class__.__name__, _msg))
    resp = BadRequest(err.to_json(), content='application/json')
    return resp


# =============================================================================


def build_services(srvs, service_factory, http, keyjar, client_authn_method):
    service = {}
    for serv in srvs:
        _srv = service_factory(serv, httplib=http, keyjar=keyjar,
                               client_authn_method=client_authn_method)
        service[_srv.request] = _srv

    # For any unspecified service
    service['any'] = Request(httplib=http, keyjar=keyjar,
                             client_authn_method=client_authn_method)
    return service


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
        self.service_factory = service_factory or requests.factory
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

    def do_request(self, request_type, scope="", body_type="json",
                   method="POST", request_args=None, extra_args=None,
                   http_args=None, authn_method="", **kwargs):

        _srv = self.service[request_type]

        _info = _srv.do_request_init(
            self.client_info, method=method, scope=scope,
            request_args=request_args, extra_args=extra_args,
            authn_method=authn_method, http_args=http_args, **kwargs)

        return _srv.request_and_return(
            _info['url'], method, _info['body'], body_type,
            http_args=_info['http_args'], client_info=self.client_info,
            **kwargs)

    def set_client_id(self, client_id):
        self.client_id = client_id
        self.client_info.client_id = client_id
