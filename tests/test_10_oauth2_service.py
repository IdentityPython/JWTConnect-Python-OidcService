import pytest
from oiccli.client_auth import CLIENT_AUTHN_METHOD

from oiccli.exception import WrongContentType
from oiccli.oauth2 import ClientInfo
from oicmsg.oauth2 import AccessTokenRequest
from oicmsg.oauth2 import AccessTokenResponse
from oicmsg.oauth2 import ASConfigurationResponse
from oicmsg.oauth2 import AuthorizationRequest
from oicmsg.oauth2 import AuthorizationResponse
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oiccli.oauth2.service import factory
from oiccli.service import Service


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
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.state_db['state'] = {}

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.service.construct(self.cli_info, request_args=req_args,
                                      state='state')
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'client_id', 'redirect_uri', 'foo',
                                    'redirect_uri', 'state'}

    def test_request_info(self):
        req_args = {'response_type': 'code'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.request_info(self.cli_info, request_args=req_args,
                                          state='state')
        assert set(_info.keys()) == {'uri', 'cis'}
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.do_request_init(self.cli_info,
                                             request_args=req_args)
        assert set(_info.keys()) == {'cis', 'http_args', 'uri', 'algs'}
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state'}
        assert _info['http_args'] == {}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        req_resp = Response(
            200,
            AuthorizationResponse(code='access_code',
                                  state='state').to_urlencoded())
        resp = self.service.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, AuthorizationResponse)
        assert set(resp.keys()) == {'code', 'state'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(
            200, ErrorResponse(error='invalid_request').to_urlencoded())
        resp = self.service.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(
            400, ErrorResponse(error='invalid_request').to_urlencoded())
        resp = self.service.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_json(self):
        req_resp = Response(200, AuthorizationResponse(code='access_code',
                                                       state='state').to_json(),
                            headers={'content-type': 'application/json'})
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')
        assert isinstance(resp, AuthorizationResponse)
        assert set(resp.keys()) == {'code', 'state'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(200, AuthorizationResponse(code='access_code',
                                                       state='state').to_json(),
                            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                       response_body_type='json')


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('AccessToken',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ClientInfo(config=client_config)
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

    def test_request_info(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.request_info(self.cli_info, request_args=req_args,
                                          state='state',
                                          authn_method='client_secret_basic')
        assert set(_info.keys()) == {'kwargs', 'body', 'uri', 'cis'}
        assert _info['uri'] == 'https://example.com/authorize'
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.service.endpoint = 'https://example.com/authorize'

        _info = self.service.do_request_init(self.cli_info,
                                             request_args=req_args,
                                             state='state')
        assert set(_info.keys()) == {'body', 'cis', 'uri', 'http_args',
                                     'kwargs'}
        assert _info['uri'] == 'https://example.com/authorize'
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'code': 'access_code', 'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        req_resp = Response(
            200,
            AccessTokenResponse(access_token='access_token',
                                state='state',
                                token_type='Bearer').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')
        assert isinstance(resp, AccessTokenResponse)
        assert set(resp.keys()) == {'access_token', 'token_type', 'state'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(
            200, ErrorResponse(error='invalid_request').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(
            400, ErrorResponse(error='invalid_request').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(200, AccessTokenResponse(code='access_code',
                                                     state='state').to_json(),
                            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                       response_body_type='json')


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('ProviderInfoDiscovery')
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss}
        self.cli_info = ClientInfo(config=client_config)

    def test_construct(self):
        _req = self.service.construct(self.cli_info)
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_request_info(self):
        _info = self.service.request_info(self.cli_info)
        assert set(_info.keys()) == {'uri'}
        assert _info['uri'] == '{}/.well-known/openid-configuration'.format(
            self._iss)

    def test_parse_request_response(self):
        req_resp = Response(
            200,
            ASConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                grant_types_supported=['Bearer']
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')
        assert isinstance(resp, ASConfigurationResponse)
        assert set(resp.keys()) == {'issuer', 'response_types_supported',
                                    'version', 'grant_types_supported'}


class TestRefreshAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = factory('RefreshAccessToken',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self.service.endpoint = 'https://example.com/token'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ClientInfo(config=client_config)
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

    def test_request_info(self):
        _info = self.service.request_info(self.cli_info, state='abcdef')
        assert set(_info.keys()) == {'uri', 'body', 'cis', 'kwargs'}
