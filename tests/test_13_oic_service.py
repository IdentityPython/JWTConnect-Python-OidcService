import json
import os

import pytest
from oiccli.state import UnknownState
from oicmsg.jwt import JWT
from oicmsg.key_jar import build_keyjar
from oicmsg.key_jar import public_keys_keyjar

from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.exception import ConfigurationError
from oiccli.exception import ParameterError
from oiccli.exception import WrongContentType
from oiccli.oauth2 import build_services
from oiccli.oauth2 import ClientInfo
from oiccli.oauth2 import DEFAULT_SERVICES
from oiccli.oic.service import factory
from oiccli.service import Service

from oicmsg.oauth2 import AccessTokenRequest
from oicmsg.oauth2 import AccessTokenResponse
from oicmsg.oauth2 import AuthorizationRequest
from oicmsg.oauth2 import AuthorizationResponse
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oicmsg.oic import CheckIDRequest, OpenIDSchema
from oicmsg.oic import CheckSessionRequest
from oicmsg.oic import EndSessionRequest
from oicmsg.oic import ProviderConfigurationResponse
from oicmsg.oic import RegistrationRequest


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

keyjar = build_keyjar(KEYSPEC)[1]


def test_request_factory():
    req = factory('Service', httplib=None, keyjar=None,
                  client_authn_method=None)
    assert isinstance(req, Service)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('Authorization',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ClientInfo(keyjar, config=client_config)

    def test_construct(self):
        req_args = {'foo': 'bar', 'response_type': 'code',
                    'state': 'state'}
        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state'}

    def test_construct_token(self):
        req_args = {'foo': 'bar', 'response_type': 'token',
                    'state': 'state'}
        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce'}

    def test_construct_token_nonce(self):
        req_args = {'foo': 'bar', 'response_type': 'token', 'nonce': 'nonce',
                    'state': 'state'}
        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state', 'nonce'}
        assert _req['nonce'] == 'nonce'

    def test_request_info(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.request_info(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'uri', 'cis'}
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'scope': 'openid', 'state': 'state'}
        msg = AuthorizationRequest().from_urlencoded(
            self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.do_request_init(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'cis', 'http_args', 'uri', 'algs'}
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'response_type': 'code', 'state': 'state', 'scope': 'openid'}
        assert _info['http_args'] == {}
        msg = AuthorizationRequest().from_urlencoded(
            self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init_request_method(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.do_request_init(self.cli_info, request_args=req_args,
                                         request_method='value')
        assert set(_info.keys()) == {'cis', 'http_args', 'uri', 'algs'}
        assert set(_info['cis'].keys()) == {
            'client_id', 'redirect_uri', 'response_type', 'state', 'scope',
            'request'}
        assert _info['http_args'] == {}
        msg = AuthorizationRequest().from_urlencoded(
            self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        self.cli_info.state_db['state'] = {}
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
        self.cli_info.state_db['state'] = {}
        req_resp = Response(
            200,
            AuthorizationResponse(code='access_code', state='state',
                                  scope=['openid']).to_json(),
            headers={'content-type': 'application/json'})
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, AuthorizationResponse)
        assert set(resp.keys()) == {'code', 'state', 'scope'}

    def test_parse_request_response_wrong_content_type(self):
        self.cli_info.state_db['state'] = {}
        req_resp = Response(
            200,
            AuthorizationResponse(code='access_code', state='state',
                                  scope=['openid']).to_json(),
            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.req.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')

    def test_request_param(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.req.endpoint = 'https://example.com/authorize'
        self.cli_info.registration_response = {
            'redirect_uris': ['https://example.com/cb'],
            'request_uris': ['https://example.com/request123456.json']
        }
        self.cli_info.base_url = 'https://example.com/'
        _info = self.req.do_request_init(self.cli_info, request_args=req_args,
                                         request_method='reference')
        assert _info['cis'][
                   'request_uri'] == 'https://example.com/request123456.json'

        assert os.path.isfile('request123456.json')


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('AccessToken',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ClientInfo(keyjar, config=client_config)
        self.cli_info.state_db['state'] = {'code': 'access_code'}

    def test_construct(self):
        req_args = {'foo': 'bar'}

        _req = self.req.construct(self.cli_info, request_args=req_args,
                                  state='state')
        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == {'client_id', 'foo', 'grant_type',
                                    'client_secret', 'code'}

    def test_request_info(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.request_info(self.cli_info, request_args=req_args,
                                      state='state',
                                      authn_method='client_secret_basic')
        assert set(_info.keys()) == {'body', 'uri', 'cis', 'kwargs', 'h_args'}
        assert _info['uri'] == 'https://example.com/authorize'
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
        msg = AccessTokenRequest().from_urlencoded(
            self.req.get_urlinfo(_info['body']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'redirect_uri': 'https://example.com/cli/authz_cb',
                    'code': 'access_code'}
        self.req.endpoint = 'https://example.com/authorize'

        _info = self.req.do_request_init(self.cli_info, request_args=req_args,
                                         state='state')
        assert set(_info.keys()) == {'body', 'cis', 'uri', 'http_args',
                                     'kwargs', 'h_args'}
        assert _info['uri'] == 'https://example.com/authorize'
        assert _info['cis'].to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}
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
                                               response_body_type='json')
        assert isinstance(resp, AccessTokenResponse)
        assert set(resp.keys()) == {'access_token', 'token_type', 'state'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(
            200, ErrorResponse(error='invalid_request').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(
            400, ErrorResponse(error='invalid_request').to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(200, AccessTokenResponse(code='access_code',
                                                     state='state').to_json(),
                            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.req.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')

    def test_id_token_nonce_match(self):
        self.cli_info.state_db.bind_nonce_to_state('nonce', 'state')
        resp = AccessTokenResponse(verified_id_token={'nonce': 'nonce'})
        self.cli_info.state_db.bind_nonce_to_state('nonce2', 'state2')
        with pytest.raises(UnknownState):
            self.req.do_post_parse_response(resp, self.cli_info, state='state2')


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('ProviderInfoDiscovery',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss,
                         'client_prefs': {
                             'id_token_signed_response_alg': 'RS384',
                             'userinfo_signed_response_alg': 'RS384'
                         }}
        self.cli_info = ClientInfo(config=client_config)
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

    def test_parse_request_response_1(self):
        req_resp = Response(
            200,
            ProviderConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                grant_types_supported=['Bearer'],
                subject_types_supported=['pairwise'],
                authorization_endpoint='https://example.com/op/authz',
                jwks_uri='https://example.com/op/jwks.json',
                token_endpoint='https://example.com/op/token',
                id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512'],
                userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512']
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert self.cli_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'}

    def test_parse_request_response_2(self):
        req_resp = Response(
            200,
            ProviderConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                grant_types_supported=['Bearer'],
                subject_types_supported=['pairwise'],
                authorization_endpoint='https://example.com/op/authz',
                jwks_uri='https://example.com/op/jwks.json',
                token_endpoint='https://example.com/op/token',
                id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512'],
                userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512']
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'

        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert self.cli_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384',
            'token_endpoint_auth_method': 'client_secret_basic'}

    def test_parse_request_response_added_default(self):
        req_resp = Response(
            200,
            ProviderConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                subject_types_supported=['pairwise'],
                authorization_endpoint='https://example.com/op/authz',
                jwks_uri='https://example.com/op/jwks.json',
                token_endpoint='https://example.com/op/token',
                id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512'],
                userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512']
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli_info.client_prefs['grant_types'] = ['authorization_code']

        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert self.cli_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384',
            'token_endpoint_auth_method': 'client_secret_basic',
            'grant_types': ['authorization_code']}

    def test_parse_request_response_no_match(self):
        req_resp = Response(
            200,
            ProviderConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                subject_types_supported=['pairwise'],
                authorization_endpoint='https://example.com/op/authz',
                jwks_uri='https://example.com/op/jwks.json',
                token_endpoint='https://example.com/op/token',
                id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512'],
                userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512']
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli_info.client_prefs['grant_types'] = ['authorization_code']
        self.cli_info.client_prefs['request_object_signing_alg'] = ['ES256']

        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               response_body_type='json')
        assert isinstance(resp, ProviderConfigurationResponse)
        assert set(resp.keys()) == {
            'issuer', 'response_types_supported', 'version',
            'grant_types_supported', 'subject_types_supported',
            'authorization_endpoint', 'jwks_uri',
            'id_token_signing_alg_values_supported',
            'request_uri_parameter_supported', 'request_parameter_supported',
            'claims_parameter_supported', 'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'require_request_uri_registration',
            'userinfo_signing_alg_values_supported'}
        assert self.cli_info.behaviour == {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384',
            'token_endpoint_auth_method': 'client_secret_basic',
            'grant_types': ['authorization_code'],
            'request_object_signing_alg': 'ES256'}

    def test_parse_request_response_no_match_strict(self):
        req_resp = Response(
            200,
            ProviderConfigurationResponse(
                issuer=self._iss, response_types_supported=['code'],
                subject_types_supported=['pairwise'],
                authorization_endpoint='https://example.com/op/authz',
                jwks_uri='https://example.com/op/jwks.json',
                token_endpoint='https://example.com/op/token',
                id_token_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512'],
                userinfo_signing_alg_values_supported=['RS256', 'RS384',
                                                       'RS512']
            ).to_json(),
            headers={'content-type': "application/json"}
        )
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli_info.client_prefs[
            'token_endpoint_auth_method'] = 'client_secret_basic'
        self.cli_info.client_prefs['grant_types'] = ['authorization_code']
        self.cli_info.client_prefs['request_object_signing_alg'] = ['ES256']
        self.cli_info.strict_on_preferences = True

        with pytest.raises(ConfigurationError):
            resp = self.req.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json')


class TestRegistration(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('Registration',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_construct(self):
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 3

    def test_config_with_post_logout(self):
        self.cli_info.post_logout_redirect_uris = [
            'https://example.com/post_logout']
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 4
        assert 'post_logout_redirect_uris' in _req

    def test_config_with_required_request_uri(self):
        self.cli_info.provider_info['require_request_uri_registration'] = True
        _req = self.req.construct(self.cli_info)
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 4
        assert 'request_uris' in _req


class TestUserInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('UserInfo',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {
            'id_token': 'a.signed.jwt',
            'token': {'access_token': 'access_token'}}
        _req = self.req.construct(self.cli_info, state='abcde')
        assert isinstance(_req, Message)
        assert len(_req) == 1
        assert 'access_token' in _req

    def test_unpack_simple_response(self):
        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall')
        _resp = self.req.parse_response(resp.to_json(), self.cli_info)
        assert _resp

    def test_unpack_aggregated_response(self):
        claims = {
            "address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US"},
            "phone_number": "+1 (555) 123-4567"
        }

        _keyjar = build_keyjar(KEYSPEC)[1]

        srv = JWT(_keyjar, iss='https://example.org/op/', sign_alg='ES256')
        _jwt = srv.pack(payload=claims)

        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall',
                            _claim_names={'address': 'src1',
                                          'phone_number': 'src1'},
                            _claim_sources={'src1': {'JWT': _jwt}})

        public_keys_keyjar(_keyjar, '', self.cli_info.keyjar,
                           'https://example.org/op/')

        _resp = self.req.parse_response(resp.to_json(), self.cli_info)
        assert set(_resp.keys()) == {'sub', 'given_name', 'family_name',
                                     '_claim_names', '_claim_sources',
                                     'address', 'phone_number'}


class TestCheckSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('CheckSession',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {'id_token': 'a.signed.jwt'}
        _req = self.req.construct(self.cli_info, state='abcde')
        assert isinstance(_req, CheckSessionRequest)
        assert len(_req) == 1


class TestCheckID(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('CheckID',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {'id_token': 'a.signed.jwt'}
        _req = self.req.construct(self.cli_info, state='abcde')
        assert isinstance(_req, CheckIDRequest)
        assert len(_req) == 1


class TestEndSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('EndSession',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {'id_token': 'a.signed.jwt'}
        _req = self.req.construct(self.cli_info, state='abcde')
        assert isinstance(_req, EndSessionRequest)
        assert len(_req) == 1


class TestWebFinger(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = factory('WebFinger',
                           client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/',
                         'resource': 'joe@example.com'}
        self.cli_info = ClientInfo(config=client_config)
        self.cli_info.service = build_services(DEFAULT_SERVICES,
                                               factory, None, None,
                                               CLIENT_AUTHN_METHOD)

    def test_request_info(self):
        _req = self.req.request_info(self.cli_info)
        assert set(_req.keys()) == {'uri'}
        assert _req['uri'] == \
               'https://example.com/.well-known/webfinger?resource=acct%3Ajoe' \
               '%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect' \
               '%2F1.0%2Fissuer'

    def test_parse_response(self):
        _info = {
            "subject": "acct:joe@example.com",
            "links":
                [
                    {
                        "rel": "http://openid.net/specs/connect/1.0/issuer",
                        "href": "https://server.example.com"
                    }
                ]
        }
        resp = self.req.parse_response(json.dumps(_info), self.cli_info)
        assert resp.to_dict() == _info
        assert self.cli_info.issuer == _info['links'][0]['href']


def test_authz_service_conf():
    srv = factory(
        'Authorization',
        client_authn_method=CLIENT_AUTHN_METHOD,
        conf={
            'request_args': {
                'claims': {
                    "id_token":
                        {
                            "auth_time": {"essential": True},
                            "acr": {"values": ["urn:mace:incommon:iap:silver"]}
                        }}}})
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'behaviour': {'response_types': ['code']}
    }
    cli_info = ClientInfo(keyjar, config=client_config)
    req = srv.construct(cli_info)
    assert 'claims' in req
    assert set(req['claims'].keys()) == {'id_token'}
