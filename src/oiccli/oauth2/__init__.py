import logging

from jwkest import b64e

from oiccli import CC_METHOD
from oiccli import OIDCONF_PATTERN
from oiccli import unreserved
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

from oicmsg.exception import GrantExpired
from oicmsg.oauth2 import ASConfigurationResponse
from oicmsg.oauth2 import AuthorizationErrorResponse
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oicmsg.key_jar import KeyJar
from oicmsg.time_util import utc_time_sans_frac

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

DEF_SIGN_ALG = {"id_token": "RS256",
                "openid_request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}

Version = "2.0"

HTTP_ARGS = ["headers", "redirections", "connection_type"]

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
    def __init__(self, keyjar, client_id='', config=None, events=None):
        self.keyjar = keyjar
        self.client_id = client_id
        self.grant_db = GrantDB()
        self.state2nonce = {}
        # own endpoints
        self.redirect_uris = [None]

        self.provider_info = {}
        self.kid = {"sig": {}, "enc": {}}
        self.authz_req = None

        # the OAuth issuer is the URL of the authorization server's
        # configuration information location
        self.config = config or {}
        try:
            self.issuer = self.config['issuer']
        except KeyError:
            self.issuer = ''
        self.allow = {}
        self.provider_info = {}
        self.events = events

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


class Client(object):
    def __init__(self, client_id='', ca_certs=None, client_authn_method=None,
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

        self.events = None
        self.client_info = ClientInfo(keyjar, client_id=client_id)

        self.service_factory = service_factory or requests.factory
        self.service = {}
        _srvs = services or DEFAULT_SERVICES
        for serv in _srvs:
            _srv = self.service_factory(
                serv, httplib=self.http, keyjar=self.keyjar,
                client_authn_method=client_authn_method)
            self.service[_srv.request] = _srv

        # For any unspecified service
        self.service['any'] = Request(httplib=self.http, keyjar=self.keyjar,
                                      client_authn_method=client_authn_method)

        self.verify_ssl = verify_ssl

    def construct(self, request_type, request_args=None, extra_args=None,
                  **kwargs):
        try:
            self.service[request_type]
        except KeyError:
            raise NotImplemented(request_type)

        met = getattr(self, 'construct_{}_request'.format(request_type))
        return met(self.client_info, request_args, extra_args, **kwargs)

    def do_request(self, url, method, body, http_args):
        """
        Send the request to the other entity, receive the response 
        and return it.

        :param url: 
        :param method: 
        :param body: 
        :param http_args: 
        :return: 
        """

        if http_args is None:
            http_args = {}

        try:
            resp = self.http(url, method, data=body, **http_args)
        except Exception:
            raise

        return resp

    def do_authorization_request(self, state="", body_type="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 **kwargs):

        _srv = self.service['authorization']
        _info = _srv.do_request_init(self.client_info, state=state,
                                     method=method, request_args=request_args,
                                     extra_args=extra_args,
                                     http_args=http_args, **kwargs)

        # redirect to the authorization server

        #
        # req_resp = self.do_request(_info['url'], method, _info['body'],
        #                            http_args=http_args)
        #
        # resp = _srv.parse_request_response(req_resp, body_type, state, **kwargs)
        #
        # if isinstance(resp, Message):
        #     if resp.type() == _srv.error_msg:
        #         resp.state = _info['cis'].state
        #
        # return resp

    def do_access_token_request(self, scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                authn_method="", **kwargs):

        _srv = self.service['accesstoken']
        _info = _srv.do_request_init(
            self.client_info, state=state, method=method, scope=scope,
            request_args=request_args, extra_args=extra_args,
            authn_method=authn_method, http_args=http_args, **kwargs)

        return _srv.request_and_return(
            _info['url'], method, _info['body'], body_type, state=state,
            http_args=_info['http_args'], client_info=self.client_info,
            **kwargs)

    def do_access_token_refresh(self, state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None,
                                authn_method="", **kwargs):

        kwargs['token'] = self.grant_db.get_token(also_expired=True,
                                                  state=state, **kwargs)
        kwargs['authn_endpoint'] = 'refresh'

        _srv = self.service['refresh_token']
        _info = _srv.do_request_init(
            self.client_info(), state=state, method=method,
            request_args=request_args, extra_args=extra_args,
            authn_method=authn_method, http_args=http_args, **kwargs)

        return _srv.request_and_return(
            _info['url'], method, _info['body'], body_type, state=state,
            http_args=_info['http_args'], session_info=self.session_info(),
            **kwargs)

    def fetch_protected_resource(self, uri, method="GET", headers=None,
                                 state="", body_type='json', **kwargs):

        if "token" in kwargs and kwargs["token"]:
            token = kwargs["token"]
            request_args = {"access_token": token}
        else:
            try:
                token = self.grant_db.get_token(state=state, **kwargs)
            except ExpiredToken:
                # The token is to old, refresh
                self.do_access_token_refresh()
                token = self.grant_db.get_token(state=state, **kwargs)
            request_args = {"access_token": token.access_token}

        if headers is None:
            headers = {}

        _srv = self.service['any']
        if "authn_method" not in kwargs:
            kwargs['authn_method'] = 'bearer_header'
        kwargs['endpoint'] = uri

        _info = _srv.do_request_init(
            self.client_info(), state=state, method=method,
            request_args=request_args, **kwargs)

        return _srv.request_and_return(
            _info['url'], method, _info['body'], body_type, state=state,
            http_args=_info['http_args'], session_info=self.session_info(),
            **kwargs)

    def add_code_challenge(self):
        """
        PKCE RFC 7636 support

        :return:
        """
        try:
            cv_len = self.config['code_challenge']['length']
        except KeyError:
            cv_len = 64  # Use default

        code_verifier = unreserved(cv_len)
        _cv = code_verifier.encode()

        try:
            _method = self.config['code_challenge']['method']
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

    def do_provider_info_discovery(self, state="", body_type="json",
                                   method="GET", request_args=None,
                                   extra_args=None, http_args=None,
                                   authn_method="", **kwargs):

        _srv = self.service['discovery']
        _info = _srv.do_request_init(
            self.client_info(), state=state, method=method,
            request_args=request_args, extra_args=extra_args,
            authn_method=authn_method, http_args=http_args, **kwargs)

        _sinfo = self.session_info()

        res = _srv.request_and_return(
            _info['url'], method, _info['body'], body_type, state=state,
            http_args=_info['http_args'], session_info=_sinfo,
            **kwargs)

        try:
            self.keyjar = _sinfo['keyjar']
        except KeyError:
            pass

        return res
