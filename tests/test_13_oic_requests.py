import pytest
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oicmsg.oic import ProviderConfigurationResponse

from oiccli.oauth2 import ClientInfo, build_services, DEFAULT_SERVICES

from oiccli.exception import WrongContentType

from oicmsg.oauth2 import AccessTokenRequest, Message, ASConfigurationResponse
from oicmsg.oauth2 import AccessTokenResponse
from oicmsg.oauth2 import AuthorizationRequest
from oicmsg.oauth2 import AuthorizationResponse
from oicmsg.oauth2 import ErrorResponse

from oiccli.oic.requests import factory
from oiccli.request import Request


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


def test_request_factory():
    req = factory('Request', httplib=None, keyjar=None,
                  client_authn_method=None)
    assert isinstance(req, Request)


class TestAuthorizationRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('AuthorizationRequest')
        self.cli_info = ClientInfo(
            None, redirect_uris=['https://example.com/cli/authz_cb'],
            client_id='client_id', client_secret='password')

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.req.construct(self.cli_info, request_args=req_args,
                                  state='state', scope=['openid'])
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'client_id', 'redirect_uri', 'foo',
                                    'redirect_uri', 'state', 'scope'}

    def test_request_info(self):
        req_args = {'response_type': 'code'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.request_info(self.cli_info, request_args=req_args,
                                      state='state', scope=['openid'])
        assert set(_info.keys()) == {'body', 'uri', 'cis', 'h_args'}
        assert _info['body'] is None
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state', 'scope': 'openid'}
        assert _info['h_args'] == {}
        msg = AuthorizationRequest().from_urlencoded(
            self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': 'state',
                    'scope': ['openid']}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.do_request_init(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'body', 'cis', 'http_args', 'uri', 'algs',
                                     'h_args'}
        assert _info['body'] is None
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state', 'scope': 'openid'}
        assert _info['h_args'] == {}
        assert _info['http_args'] == {}
        msg = AuthorizationRequest().from_urlencoded(
            self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        req_resp = Response(
            200,
            AuthorizationResponse(
                code='access_code', state='state',
                scope=['openid']).to_urlencoded())
        resp = self.req.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, AuthorizationResponse)
        assert set(resp.keys()) == {'code', 'state', 'scope'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(
            200, ErrorResponse(error='invalid_request').to_urlencoded())
        resp = self.req.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(
            400, ErrorResponse(error='invalid_request').to_urlencoded())
        resp = self.req.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_json(self):
        req_resp = Response(
            200,
            AuthorizationResponse(code='access_code', state='state',
                                  scope=['openid']).to_json(),
            headers={'content-type': 'application/json'})
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, AuthorizationResponse)
        assert set(resp.keys()) == {'code', 'state', 'scope'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(
            200,
            AuthorizationResponse(code='access_code', state='state',
                                  scope=['openid']).to_json(),
            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.req.parse_request_response(req_resp, self.cli_info,
                                                   body_type='json')


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('AccessTokenRequest')
        self.cli_info = ClientInfo(
            None, redirect_uris=['https://example.com/cli/authz_cb'],
            client_id='client_id', client_secret='password')
        self.cli_info.grant_db['state'] = self.cli_info.grant_db.grant_class(
            resp=AuthorizationResponse(code='access_code'))

    def test_construct(self):
        req_args = {'foo': 'bar', 'state': 'state'}

        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {'client_id', 'foo', 'grant_type',
                                    'client_secret', 'code'}

    def test_request_info(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.request_info(self.cli_info, request_args=req_args,
                                      state='state')
        assert set(_info.keys()) == {'body', 'uri', 'cis', 'h_args'}
        assert _info['body'] is None
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id', 'client_secret': 'password',
            'code': 'access_code', 'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
        assert _info['h_args'] == {}
        msg = AccessTokenRequest().from_urlencoded(
            self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.req.endpoint = 'https://example.com/authorize'

        _info = self.req.do_request_init(self.cli_info, request_args=req_args,
                                         state='state')
        assert set(_info.keys()) == {'body', 'cis', 'uri', 'http_args',
                                     'h_args'}
        assert _info['uri'] == 'https://example.com/authorize'
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id', 'client_secret': 'password',
            'code': 'access_code', 'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
        assert _info['h_args'] == {
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}}
        msg = AccessTokenRequest().from_urlencoded(
            self.req.get_urlinfo(_info['body']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        req_resp = Response(
            200,
            AccessTokenResponse(access_token='access_token',
                                state='state',
                                token_type='Bearer').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, AccessTokenResponse)
        assert set(resp.keys()) == {'access_token', 'token_type', 'state'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(
            200, ErrorResponse(error='invalid_request').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(
            400, ErrorResponse(error='invalid_request').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(200, AccessTokenResponse(code='access_code',
                                                     state='state').to_json(),
                            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.req.parse_request_response(req_resp, self.cli_info,
                                                   body_type='json')



class TestProviderInfoRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('ProviderInfoDiscovery')
        self._iss = 'https://example.com/as'
        self.cli_info = ClientInfo(
            None, config={'issuer': self._iss},
            redirect_uris=['https://example.com/cli/authz_cb'],
            client_id='client_id', client_secret='password')
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_construct(self):
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_request_info(self):
        _info = self.req.request_info(self.cli_info)
        assert set(_info.keys()) == {'uri'}
        assert _info['uri'] == '{}/.well-known/openid-configuration'.format(
            self._iss)

    def test_parse_request_response(self):
        req_resp = Response(
            200,
            ProviderConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                grant_types_supported=['Bearer'],
                subject_types_supported=['pair'],
                authorization_endpoint='https://example.com/op/authz',
                id_token_signing_alg_values_supported=['RS256'],
                jwks_uri='https://example.com/op/jwks.json',
                token_endpoint='https://example.com/op/token'
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration'}
