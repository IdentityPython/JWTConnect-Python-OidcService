import inspect
import logging
import sys

from oidcmsg import oauth2
from oidcmsg.exception import MissingParameter
from oidcmsg.key_jar import KeyJar
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcservice import OIDCONF_PATTERN
from oidcservice.exception import OidcServiceError
from oidcservice.service import Service

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


def get_state_parameter(request_args, kwargs):
    try:
        _state = kwargs['state']
    except KeyError:
        try:
            _state = request_args['state']
        except KeyError:
            raise MissingParameter('state')

    return _state


def pick_redirect_uris(request_args=None, service=None, **kwargs):
    _context = service.service_context
    if 'redirect_uri' in request_args:
        pass
    elif _context.callback:
        try:
            _response_type = request_args['response_type']
        except KeyError:
            _response_type = _context.behaviour['response_types'][0]
            request_args['response_type'] = _response_type

        try:
            _response_mode = request_args['response_mode']
        except KeyError:
            _response_mode = ''

        if _response_mode == 'form_post':
            request_args['redirect_uri'] = _context.callback[
                'form_post']
        elif _response_type == 'code':
            request_args['redirect_uri'] = _context.callback['code']
        else:
            request_args['redirect_uri'] = _context.callback[
                'implicit']
    else:
        request_args['redirect_uri'] = _context.redirect_uris[0]
    return request_args, {}


def set_state_parameter(request_args=None, **kwargs):
    request_args['state'] = get_state_parameter(request_args, kwargs)
    return request_args, {'state': request_args['state']}


class Authorization(Service):
    msg_type = oauth2.AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_msg = ResponseMessage
    endpoint_name = 'authorization_endpoint'
    synchronous = False
    service_name = 'authorization'
    response_body_type = 'urlencoded'

    def __init__(self, service_context, state_db,
                 client_authn_factory=None, conf=None):
        Service.__init__(self, service_context, state_db=state_db,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.extend([pick_redirect_uris, set_state_parameter])
        self.post_construct.append(self.store_auth_request)

    def update_service_context(self, resp, state='', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.store_item(resp, 'auth_response', state)

    def store_auth_request(self, request_args=None, **kwargs):
        _key = get_state_parameter(request_args, kwargs)
        self.store_item(request_args, 'auth_request', _key)
        return request_args

    def gather_request_args(self, **kwargs):
        ar_args = Service.gather_request_args(self, **kwargs)

        if 'redirect_uri' not in ar_args:
            try:
                ar_args['redirect_uri'] = self.service_context.redirect_uris[0]
            except (KeyError, AttributeError):
                raise MissingParameter('redirect_uri')

        return ar_args

    def post_parse_response(self, response, **kwargs):
        """
        Add scope claim to responsefrom the request if not present in the
        response

        :param response: The response
        :param kwargs: Extra Keyword arguments
        :return: A possibly augmented response
        """

        if "scope" not in response:
            try:
                _key = kwargs['state']
            except KeyError:
                pass
            else:
                if _key:
                    item = self.get_item(oauth2.AuthorizationRequest,
                                         'auth_request', _key)
                    try:
                        response["scope"] = item["scope"]
                    except KeyError:
                        pass
        return response


class AccessToken(Service):
    msg_type = oauth2.AccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = ResponseMessage
    endpoint_name = 'token_endpoint'
    synchronous = True
    service_name = 'accesstoken'
    default_authn_method = 'client_secret_basic'
    http_method = 'POST'
    request_body_type = 'urlencoded'
    response_body_type = 'json'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.append(self.oauth_pre_construct)

    def update_service_context(self, resp, key='', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.store_item(resp, 'token_response', key)

    def oauth_pre_construct(self, request_args=None, **kwargs):
        """

        :param request_args: Initial set of request arguments
        :param kwargs: Extra keyword arguments
        :return: Request arguments
        """
        _state = get_state_parameter(request_args, kwargs)
        parameters = list(self.msg_type.c_param.keys())

        _args = self.extend_request_args({}, oauth2.AuthorizationRequest,
                                         'auth_request', _state, parameters)

        _args = self.extend_request_args(_args, oauth2.AuthorizationResponse,
                                         'auth_response', _state, parameters)

        if "grant_type" not in _args:
            _args["grant_type"] = "authorization_code"

        if request_args is None:
            request_args = _args
        else:
            _args.update(request_args)
            request_args = _args

        return request_args, {}


class RefreshAccessToken(Service):
    msg_type = oauth2.RefreshAccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = ResponseMessage
    endpoint_name = 'token_endpoint'
    synchronous = True
    service_name = 'refresh_token'
    default_authn_method = 'bearer_header'
    http_method = 'POST'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.append(self.oauth_pre_construct)

    def update_service_context(self, resp, key='', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.store_item(resp, 'token_response', key)

    def oauth_pre_construct(self, request_args=None, **kwargs):
        _state = get_state_parameter(request_args, kwargs)
        parameters = list(self.msg_type.c_param.keys())

        _args = self.extend_request_args({}, oauth2.AccessTokenResponse,
                                         'token_response', _state, parameters)

        _args = self.extend_request_args(_args, oauth2.AccessTokenResponse,
                                         'refresh_token_response', _state,
                                         parameters)

        if request_args is None:
            request_args = _args
        else:
            _args.update(request_args)
            request_args = _args

        return request_args, {}


class ProviderInfoDiscovery(Service):
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
        else:
            return OIDCONF_PATTERN.format(_iss)

    def get_request_parameters(self, method="GET", **kwargs):
        """
        The Provider info discovery version of get_request_parameters()

        :param method:
        :param kwargs:
        :return:
        """
        return {'url': self.get_endpoint(), 'method': method}

    def _update_service_context(self, resp, **kwargs):
        """
        Deal with Provider Config Response. Based on the provider info
        response a set of parameters in different places needs to be set.

        :param resp: The provider info response
        :param service_context: Information collected/used by services
        """
        issuer = self.service_context.issuer

        # Verify that the issuer value received is the same as the
        # url that was used as service endpoint (without the .well-known part)
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

            # In some cases we can live with the two URLs not being
            # the same. But this is an excepted that has to be explicit
            try:
                self.service_context.allow['issuer_mismatch']
            except KeyError:
                if _issuer != _pcr_issuer:
                    raise OidcServiceError(
                        "provider info issuer mismatch '%s' != '%s'" % (
                            _issuer, _pcr_issuer))

        else:  # No prior knowledge
            _pcr_issuer = issuer

        self.service_context.issuer = _pcr_issuer
        self.service_context.provider_info = resp

        # If there are services defined set the service endpoint to be
        # the URLs specified in the provider information.
        try:
            _srvs = self.service_context.service
        except AttributeError:
            pass
        else:
            if self.service_context.service:
                for key, val in resp.items():
                    # All service endpoint parameters in the provider info has
                    # a name ending in '_endpoint' so I can look specifically
                    # for those
                    if key.endswith("_endpoint"):
                        for _srv in self.service_context.service.values():
                            # Every service has an endpoint_name assigned
                            # when initiated. This name *MUST* match the
                            # endpoint names used in the provider info
                            if _srv.endpoint_name == key:
                                _srv.endpoint = val

        # If I already have a Key Jar then I'll add then provider keys to
        # that. Otherwise a new Key Jar is minted
        try:
            kj = self.service_context.keyjar
        except KeyError:
            kj = KeyJar()

        # Load the keys. Note that this only means that the key specification
        # is loaded not necessarily that any keys are fetched.
        kj.load_keys(resp, _pcr_issuer)
        self.service_context.keyjar = kj

    def update_service_context(self, resp, **kwargs):
        return self._update_service_context(resp, **kwargs)


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Service):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass
