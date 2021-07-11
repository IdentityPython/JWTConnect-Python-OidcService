from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import Message
import pytest

from oidcservice.service import Service
from oidcservice.service_context import ServiceContext
from oidcservice.service_factory import service_factory


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


def test_service():
    req = Service(service_context=ServiceContext(None),
                  client_authn_method=None)
    assert isinstance(req, Service)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'behaviour': {'response_types': ['code']}
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('Authorization', ['oauth2'],
                                       service_context=service_context)

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.service.construct(request_args=req_args, state='state')
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'client_id', 'redirect_uri', 'foo', 'state'}
        assert self.service.service_context.state.get_state('state')
        _item = self.service.service_context.state.get_item(AuthorizationRequest, 'auth_request',
                                                            'state')
        assert _item.to_dict() == {
            'foo': 'bar', 'redirect_uri': 'https://example.com/cli/authz_cb',
            'state': 'state', 'client_id': 'client_id'
        }

    def test_get_request_parameters(self):
        req_args = {'response_type': 'code'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args,
                                                    state='state')
        assert set(_info.keys()) == {'url', 'method', 'request'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert msg.to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state'
        }

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': "state"}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {'url', 'method', 'request'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert msg.to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state'
        }

    def test_response(self):
        _state = "today"
        req_args = {'response_type': 'code', 'state': _state}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {'url', 'method', 'request'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        self.service.service_context.state.store_item(msg, "auth_request", _state)

        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = self.service.parse_response(
            resp1.to_urlencoded(), "urlencoded", state=_state)
        self.service.update_service_context(response, key=_state)
        assert self.service.service_context.state.get_state(_state)


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb']
        }
        service_context = ServiceContext(config=client_config)
        service_context.redirect_uris= ['https://example.com/cli/authz_cb']
        self.service = service_factory('AccessToken', ['oauth2'], service_context=service_context)
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )
        auth_response = AuthorizationResponse(code='access_code')
        _state = self.service.service_context.state
        _state.store_item(auth_request, 'auth_request', 'state')
        _state.store_item(auth_response, 'auth_response', 'state')

    def test_construct(self):
        req_args = {'foo': 'bar', 'state': 'state'}

        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {'client_id', 'foo', 'grant_type',
                                    'client_secret', 'code', 'state',
                                    'redirect_uri'}

    def test_construct_2(self):
        # Note that state as a argument means it will not end up in the
        # request
        req_args = {'foo': 'bar'}

        _req = self.service.construct(request_args=req_args,
                                      state='state')
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {'client_id', 'foo', 'grant_type',
                                    'client_secret', 'code', 'state',
                                    'redirect_uri'}

    def test_get_request_parameters(self):
        req_args = {
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'code': 'access_code'
        }
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(
            request_args=req_args, state='state',
            authn_method='client_secret_basic')
        assert set(_info.keys()) == {'headers', 'body', 'url', 'method', 'request'}
        assert _info['url'] == 'https://example.com/authorize'
        assert 'Authorization' in _info['headers']
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code', 'state': 'state',
            'redirect_uri': 'https://example.com/cli/authz_cb'
        }
        assert 'client_secret' not in msg

    def test_request_init(self):
        req_args = {
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'code': 'access_code'
        }
        self.service.endpoint = 'https://example.com/authorize'

        _info = self.service.get_request_parameters(request_args=req_args,
                                                    state='state')
        assert set(_info.keys()) == {'body', 'url', 'headers', 'method', 'request'}
        assert _info['url'] == 'https://example.com/authorize'
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id', 'state': 'state',
            'code': 'access_code', 'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'
        }


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self._iss = 'https://example.com/as'

        client_config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            "client_preferences":
                {
                    "application_type": "web",
                    "application_name": "rphandler",
                    "contacts": ["ops@example.org"],
                    "response_types": ["code"],
                    "scope": ["openid", "profile", "email", "address", "phone"],
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('ProviderInfoDiscovery', ['oauth2'],
                                       service_context=service_context)
        self.service.endpoint = '{}/.well-known/openid-configuration'.format(
            self._iss)

    def test_construct(self):
        _req = self.service.construct()
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters()
        assert set(_info.keys()) == {'url', 'method'}
        assert _info['url'] == '{}/.well-known/openid-configuration'.format(
            self._iss)


class TestRefreshAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb']
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('RefreshAccessToken', ['oauth2'],
                                       service_context=service_context)
        auth_response = AuthorizationResponse(code='access_code')
        token_response = AccessTokenResponse(access_token='bearer_token',
                                             refresh_token='refresh')
        _state = self.service.service_context.state
        _state.store_item(auth_response, 'auth_response', 'abcdef')
        _state.store_item(token_response, 'token_response', 'abcdef')
        self.service.endpoint = 'https://example.com/token'

    def test_construct(self):
        _req = self.service.construct(state='abcdef')
        assert isinstance(_req, Message)
        assert len(_req) == 4
        assert set(_req.keys()) == {'client_id', 'client_secret', 'grant_type',
                                    'refresh_token'}

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters(state='abcdef')
        assert set(_info.keys()) == {'url', 'body', 'headers', 'method', 'request'}


def test_access_token_srv_conf():
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'a longesh password',
        'redirect_uris': ['https://example.com/cli/authz_cb']
    }
    service_context = ServiceContext(config=client_config)
    service = service_factory('AccessToken', ['oauth2'],
                              service_context=service_context,
                              conf={'default_authn_method': 'client_secret_post'})

    _state_val = service_context.state.create_state(service_context.issuer)
    auth_request = AuthorizationRequest(
        redirect_uri='https://example.com/cli/authz_cb', state=_state_val)
    _state_interface = service.service_context.state
    _state_interface.store_item(auth_request, "auth_request", _state_val)

    auth_response = AuthorizationResponse(code='access_code')
    _state_interface.store_item(auth_response, "auth_response", _state_val)

    req_args = {
        'redirect_uri': 'https://example.com/cli/authz_cb',
        'code': 'access_code'
    }
    service.endpoint = 'https://example.com/authorize'
    _info = service.get_request_parameters(request_args=req_args,
                                           state=_state_val)

    assert _info
    msg = AccessTokenRequest().from_urlencoded(service.get_urlinfo(
        _info['body']))
    assert 'client_secret' in msg
