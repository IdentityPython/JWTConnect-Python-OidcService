import logging

from jwkest import b64e

from oiccli import CC_METHOD
from oiccli import unreserved
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.exception import OicCliError
from oiccli.exception import Unsupported
from oiccli.grant import GrantDB
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

def error_response(error, descr=None, status="400 Bad Request"):
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

    return Response(response.to_json(), content="application/json",
                    status="400 Bad Request")


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
    if isinstance(excep, OicCliError):
        if excep.content_type:
            if isinstance(excep.args, tuple):
                resp = BadRequest(excep.args[0], content=excep.content_type)
            else:
                resp = BadRequest(excep.args, content=excep.content_type)
        else:
            resp = BadRequest()
    else:
        err = ErrorResponse(error='service_error',
                            error_description='{}:{}'.format(
                                excep.__class__.__name__, excep.args))
        resp = BadRequest(err.to_json(), content='application/json')
    return resp


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


# =============================================================================

class ClientInfo(object):
    def __init__(self, keyjar=None, config=None, events=None, **kwargs):
        self.keyjar = keyjar or KeyJar()
        self.grant_db = GrantDB()
        self.state2nonce = {}
        self.provider_info = {}
        self.kid = {"sig": {}, "enc": {}}

        # the OAuth issuer is the URL of the authorization server's
        # configuration information location
        self.config = config or {}

        for attr in ['client_id', 'issuer', 'client_secret']:
            try:
                setattr(self, attr, config[attr])
            except:
                setattr(self, attr, '')

        try:
            self.redirect_uris = config['redirect_uris']
        except:
            self.redirect_uris = [None]

        self.allow = {}
        self.provider_info = {}
        self.events = events
        self.behaviour = {}
        self.client_prefs = {}

        for key, val in kwargs.items():
            setattr(self, key, val)

    def get_client_secret(self):
        return self._c_secret

    def set_client_secret(self, val):
        if not val:
            self._c_secret = ""
        else:
            self._c_secret = val
            # client uses it for signing
            # Server might also use it for signing which means the
            # client uses it for verifying server signatures
            if self.keyjar is None:
                self.keyjar = KeyJar()
            self.keyjar.add_symmetric("", str(val))

    client_secret = property(get_client_secret, set_client_secret)

    def __setitem__(self, key, value):
        setattr(self, key, value)


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

        :param client_id: The client identifier
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

    def add_code_challenge(self):
        """
        PKCE RFC 7636 support

        :return:
        """
        try:
            cv_len = self.client_info.config['code_challenge']['length']
        except KeyError:
            cv_len = 64  # Use default

        code_verifier = unreserved(cv_len)
        _cv = code_verifier.encode()

        try:
            _method = self.client_info.config['code_challenge']['method']
        except KeyError:
            _method = 'S256'

        try:
            _h = CC_METHOD[_method](_cv).hexdigest()
            code_challenge = b64e(_h.encode()).decode()
        except KeyError:
            raise Unsupported(
                'PKCE Transformation method:{}'.format(_method))

        # TODO store code_verifier

        return {"code_challenge": code_challenge,
                "code_challenge_method": _method}, code_verifier
