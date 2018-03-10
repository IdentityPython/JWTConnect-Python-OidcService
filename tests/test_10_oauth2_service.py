import pytest

from oidcservice.client_auth import CLIENT_AUTHN_METHOD
from oidcservice.service_context import ServiceContext
from oidcservice.oauth2.service import factory
from oidcservice.service import Service

from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import Message


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


def test_service_factory():
    req = factory('Service', httplib=None, keyjar=None,
                  client_authn_method=None)
    assert isinstance(req, Service)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('Authorization')
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.state_db['state'] = {}

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.service.construct(self.cli_info, request_args=req_args,
                                      state='state')
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'client_id', 'redirect_uri', 'foo',
                                    'redirect_uri', 'state'}

    def test_get_request_parameters(self):
        req_args = {'response_type': 'code'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args,
                                                     state='state')
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert msg.to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state'}

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert msg.to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state'}


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('AccessToken',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.state_db['state'] = {'code': 'access_code'}

    def test_construct(self):
        req_args = {'foo': 'bar', 'state': 'state'}

        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {'client_id', 'foo', 'grant_type',
                                    'client_secret', 'code', 'state'}

    def test_construct_2(self):
        # Note that state as a argument means it will not end up in the
        # request
        req_args = {'foo': 'bar'}

        _req = self.service.construct(self.cli_info, request_args=req_args,
                                      state='state')
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {'client_id', 'foo', 'grant_type',
                                    'client_secret', 'code'}

    def test_get_request_parameters(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args,
                                                     state='state',
                                                     authn_method='client_secret_basic')
        assert set(_info.keys()) == {'headers', 'body', 'url', 'method'}
        assert _info['url'] == 'https://example.com/authorize'
        assert 'Authorization' in _info['headers']
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
        assert 'client_secret' not in msg

    def test_request_init(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.service.endpoint = 'https://example.com/authorize'

        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args,
                                                     state='state')
        assert set(_info.keys()) == {'body', 'url', 'headers', 'method'}
        assert _info['url'] == 'https://example.com/authorize'
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id',
            'code': 'access_code', 'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('ProviderInfoDiscovery')
        self._iss = 'https://example.com/as'
        self.service.endpoint = '{}/.well-known/openid-configuration'.format(
            self._iss)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss}
        self.cli_info = ServiceContext(config=client_config)

    def test_construct(self):
        _req = self.service.construct(self.cli_info)
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters(self.cli_info)
        assert set(_info.keys()) == {'url', 'method'}
        assert _info['url'] == '{}/.well-known/openid-configuration'.format(
            self._iss)


class TestRefreshAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('RefreshAccessToken',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self.service.endpoint = 'https://example.com/token'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.state_db['abcdef'] = {'code': 'access_code'}
        self.cli_info.state_db.add_response(
            {'access_token': 'bearer_token', 'refresh_token': 'refresh'},
            'abcdef'
        )

    def test_construct(self):
        _req = self.service.construct(self.cli_info, state='abcdef')
        assert isinstance(_req, Message)
        assert len(_req) == 4
        assert set(_req.keys()) == {'client_id', 'client_secret', 'grant_type',
                                    'refresh_token'}

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters(self.cli_info,
                                                     state='abcdef')
        assert set(_info.keys()) == {'url', 'body', 'headers', 'method'}


def test_access_token_srv_conf():
    service = factory('AccessToken',
                      client_authn_method=CLIENT_AUTHN_METHOD,
                      conf={'default_authn_method': 'client_secret_post'})
    client_config = {'client_id': 'client_id', 'client_secret': 'password',
                     'redirect_uris': ['https://example.com/cli/authz_cb']}
    cli_info = ServiceContext(config=client_config)
    cli_info.state_db['state'] = {'code': 'access_code'}

    req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                'code': 'access_code'}
    service.endpoint = 'https://example.com/authorize'
    _info = service.get_request_parameters(cli_info, request_args=req_args,
                                            state='state')

    assert _info
    msg = AccessTokenRequest().from_urlencoded(
        service.get_urlinfo(_info['body']))
    assert 'client_secret' in msg
    assert 'Authorization' not in _info['headers']
