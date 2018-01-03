import inspect
import logging
import sys

from oiccli import OIDCONF_PATTERN
from oiccli.exception import OicCliError
from oiccli.service import Service

from oicmsg import oauth2
from oicmsg.exception import MissingParameter
from oicmsg.key_jar import KeyJar
from oicmsg.oauth2 import AccessTokenResponse
from oicmsg.oauth2 import AuthorizationResponse

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


def _post_x_parse_response(resp, cli_info, state=''):
    if isinstance(resp, (AuthorizationResponse, AccessTokenResponse)):
        cli_info.state_db.add_message_info(resp, state)


def get_state(request_args, kwargs):
    try:
        _state = kwargs['state']
    except KeyError:
        try:
            _state = request_args['state']
        except KeyError:
            raise MissingParameter('state')

    return _state


class Authorization(Service):
    msg_type = oauth2.AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_msg = oauth2.AuthorizationErrorResponse
    endpoint_name = 'authorization_endpoint'
    synchronous = False
    request = 'authorization'

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
        Service.__init__(self, httplib=httplib, keyjar=keyjar,
                         client_authn_method=client_authn_method)
        self.pre_construct.append(self.oauth_pre_construct)
        self.post_parse_response.append(_post_x_parse_response)

    def parse_args(self, cli_info, **kwargs):
        ar_args = Service.parse_args(self, cli_info, **kwargs)

        if 'redirect_uri' not in ar_args:
            try:
                ar_args['redirect_uri'] = cli_info.redirect_uris[0]
            except (KeyError, AttributeError):
                raise MissingParameter('redirect_uri')

        return ar_args

    def do_request_init(self, cli_info, body_type="", method="GET",
                        authn_method='', request_args=None, http_args=None,
                        **kwargs):

        try:
            _algs = kwargs['algs']
        except KeyError:
            _algs = {}
        else:
            del kwargs['algs']

        _info = Service.do_request_init(self, cli_info, body_type=body_type,
                                        method=method,
                                        authn_method=authn_method,
                                        request_args=request_args,
                                        http_args=http_args,
                                        **kwargs)

        _info['algs'] = _algs
        return _info

    def oauth_pre_construct(self, cli_info, request_args=None, **kwargs):

        if request_args is not None:
            try:  # change default
                new = request_args["redirect_uri"]
                if new:
                    self.redirect_uris = [new]
            except KeyError:
                pass
        else:
            request_args = {}

        request_args['state'] = get_state(request_args, kwargs)
        return request_args, {}


class AccessToken(Service):
    msg_type = oauth2.AccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse
    endpoint_name = 'token_endpoint'
    synchronous = True
    request = 'accesstoken'
    default_authn_method = 'client_secret_basic'
    http_method = 'POST'

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
        Service.__init__(self, httplib=httplib, keyjar=keyjar,
                         client_authn_method=client_authn_method)
        self.pre_construct.append(self.oauth_pre_construct)
        self.post_parse_response.append(_post_x_parse_response)

    def oauth_pre_construct(self, cli_info, request_args=None, **kwargs):
        _state = get_state(request_args, kwargs)
        req_args = cli_info.state_db.get_request_args(_state, self.msg_type)

        if request_args is None:
            request_args = req_args
        else:
            request_args.update(req_args)

        if "grant_type" not in request_args:
            request_args["grant_type"] = "authorization_code"

        return request_args, {}


class RefreshAccessToken(Service):
    msg_type = oauth2.RefreshAccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse
    endpoint_name = 'token_endpoint'
    synchronous = True
    request = 'refresh_token'
    default_authn_method = 'bearer_header'
    http_method = 'POST'

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
        Service.__init__(self, httplib=httplib, keyjar=keyjar,
                         client_authn_method=client_authn_method)
        self.pre_construct.append(self.oauth_pre_construct)

    def oauth_pre_construct(self, cli_info, request_args=None, **kwargs):
        _state = get_state(request_args, kwargs)
        req_args = cli_info.state_db.get_request_args(_state, self.msg_type)

        if request_args is None:
            request_args = req_args
        else:
            request_args.update(req_args)

        return request_args, {}


class ProviderInfoDiscovery(Service):
    msg_type = oauth2.Message
    response_cls = oauth2.ASConfigurationResponse
    error_msg = oauth2.ErrorResponse
    synchronous = True
    request = 'provider_info'
    http_method = 'GET'

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
        Service.__init__(self, httplib=httplib, keyjar=keyjar,
                         client_authn_method=client_authn_method)
        self.post_parse_response.append(self.oauth_post_parse_response)

    def request_info(self, cli_info, method="GET", request_args=None,
                     lax=False, **kwargs):

        issuer = cli_info.issuer

        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        return {'uri': OIDCONF_PATTERN % _issuer}

    def oauth_post_parse_response(self, resp, cli_info, **kwargs):
        """
        Deal with Provider Config Response
        :param resp: The provider info response
        :param cli_info: Information about the client/server session
        """
        issuer = cli_info.issuer

        if "issuer" in resp:
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

            try:
                cli_info.allow['issuer_mismatch']
            except KeyError:
                try:
                    assert _issuer == _pcr_issuer
                except AssertionError:
                    raise OicCliError(
                        "provider info issuer mismatch '%s' != '%s'" % (
                            _issuer, _pcr_issuer))

        else:  # No prior knowledge
            _pcr_issuer = issuer

        cli_info.issuer = _pcr_issuer
        cli_info.provider_info = resp

        for key, val in resp.items():
            if key.endswith("_endpoint"):
                for _srv in cli_info.service.values():
                    if _srv.endpoint_name == key:
                        _srv.endpoint = val

        try:
            kj = cli_info.keyjar
        except KeyError:
            kj = KeyJar()

        kj.load_keys(resp, _pcr_issuer)
        cli_info.keyjar = kj


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Service):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass
