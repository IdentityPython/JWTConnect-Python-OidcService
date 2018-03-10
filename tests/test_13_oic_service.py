import json
import os
import pytest

from oidcservice.client_auth import CLIENT_AUTHN_METHOD
from oidcservice.service_context import ServiceContext
from oidcservice.exception import ParameterError
from oidcservice.oidc import DEFAULT_SERVICES
from oidcservice.oidc.service import factory
from oidcservice.oidc.service import response_types_to_grant_types
from oidcservice.service import build_services
from oidcservice.service import Service

from oidcmsg.jwt import JWT
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import public_keys_keyjar
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import Message
from oidcmsg.oidc import CheckIDRequest
from oidcmsg.oidc import CheckSessionRequest
from oidcmsg.oidc import EndSessionRequest
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import RegistrationRequest


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

_dirname = os.path.dirname(os.path.abspath(__file__))


def test_request_factory():
    req = factory('Service', httplib=None, keyjar=None,
                  client_authn_method=None)
    assert isinstance(req, Service)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('Authorization',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ServiceContext(keyjar, config=client_config)

    def test_construct(self):
        req_args = {'foo': 'bar', 'response_type': 'code',
                    'state': 'state'}
        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce'}

    def test_construct_token(self):
        req_args = {'foo': 'bar', 'response_type': 'token',
                    'state': 'state'}
        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state'}

    def test_construct_token_nonce(self):
        req_args = {'foo': 'bar', 'response_type': 'token', 'nonce': 'nonce',
                    'state': 'state'}
        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state', 'nonce'}
        assert _req['nonce'] == 'nonce'

    def test_get_request_parameters(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert set(msg.keys()) == {'response_type', 'state', 'client_id',
                                   'nonce', 'redirect_uri', 'scope'}

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert set(msg.keys()) == {'client_id', 'scope', 'response_type',
                                   'state', 'redirect_uri', 'nonce'}

    def test_request_init_request_method(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args,
                                                     request_method='value')
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert set(msg.to_dict()) == {'client_id', 'redirect_uri',
                                      'response_type',
                                      'state', 'scope', 'nonce'}

    def test_request_param(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'

        assert os.path.isfile(os.path.join(_dirname, 'request123456.jwt'))

        self.cli_info.registration_response = {
            'redirect_uris': ['https://example.com/cb'],
            'request_uris': ['https://example.com/request123456.jwt']
        }
        self.cli_info.base_url = 'https://example.com/'
        _info = self.service.get_request_parameters(self.cli_info,
                                                     request_args=req_args,
                                                     request_method='reference')

        assert set(_info.keys()) == {'url', 'method'}


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('AccessToken',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb']}
        self.cli_info = ServiceContext(keyjar, config=client_config)
        self.cli_info.state_db['state'] = {'code': 'access_code'}

    def test_construct(self):
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
        assert set(_info.keys()) == {'body', 'url', 'headers', 'method'}
        assert _info['url'] == 'https://example.com/authorize'
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}

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
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb'}

    def test_id_token_nonce_match(self):
        self.cli_info.state_db.bind_nonce_to_state('nonce', 'state')
        resp = AccessTokenResponse(verified_id_token={'nonce': 'nonce'})
        self.cli_info.state_db.bind_nonce_to_state('nonce2', 'state2')
        with pytest.raises(ParameterError):
            self.service.update_client_info(self.cli_info, resp, state='state2')


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('ProviderInfoDiscovery',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss,
                         'client_prefs': {
                             'id_token_signed_response_alg': 'RS384',
                             'userinfo_signed_response_alg': 'RS384'
                         }}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_construct(self):
        _req = self.service.construct(self.cli_info)
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters(self.cli_info)
        assert set(_info.keys()) == {'url', 'method'}
        assert _info['url'] == '{}/.well-known/openid-configuration'.format(
            self._iss)


def test_response_types_to_grant_types():
    req_args = ['code']
    assert set(
        response_types_to_grant_types(req_args)) == {'authorization_code'}
    req_args = ['code', 'code id_token']
    assert set(
        response_types_to_grant_types(req_args)) == {'authorization_code',
                                                     'implicit'}
    req_args = ['code', 'id_token code', 'code token id_token']
    assert set(
        response_types_to_grant_types(req_args)) == {'authorization_code',
                                                     'implicit'}


class TestRegistration(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('Registration',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_construct(self):
        _req = self.service.construct(self.cli_info)
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 4

    def test_config_with_post_logout(self):
        self.cli_info.post_logout_redirect_uris = [
            'https://example.com/post_logout']
        _req = self.service.construct(self.cli_info)
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 5
        assert 'post_logout_redirect_uris' in _req

    def test_config_with_required_request_uri(self):
        self.cli_info.provider_info['require_request_uri_registration'] = True
        _req = self.service.construct(self.cli_info)
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 5
        assert 'request_uris' in _req


class TestUserInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('UserInfo',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {
            'id_token': 'a.signed.jwt',
            'token': {'access_token': 'access_token'}}
        _req = self.service.construct(self.cli_info, state='abcde')
        assert isinstance(_req, Message)
        assert len(_req) == 1
        assert 'access_token' in _req

    def test_unpack_simple_response(self):
        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall')
        _resp = self.service.parse_response(resp.to_json(), self.cli_info,
                                            state='abcde')
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

        _resp = self.service.parse_response(resp.to_json(), self.cli_info)
        _resp = self.service.post_parse_response(self.cli_info, _resp)
        assert set(_resp.keys()) == {'sub', 'given_name', 'family_name',
                                     '_claim_names', '_claim_sources',
                                     'address', 'phone_number'}


class TestCheckSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('CheckSession',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {'id_token': 'a.signed.jwt'}
        _req = self.service.construct(self.cli_info, state='abcde')
        assert isinstance(_req, CheckSessionRequest)
        assert len(_req) == 1


class TestCheckID(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('CheckID',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {'id_token': 'a.signed.jwt'}
        _req = self.service.construct(self.cli_info, state='abcde')
        assert isinstance(_req, CheckIDRequest)
        assert len(_req) == 1


class TestEndSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('EndSession',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        self._iss = 'https://example.com/as'
        client_config = {'client_id': 'client_id', 'client_secret': 'password',
                         'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'issuer': self._iss, 'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/'}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_construct(self):
        self.cli_info.state_db['abcde'] = {'id_token': 'a.signed.jwt'}
        _req = self.service.construct(self.cli_info, state='abcde')
        assert isinstance(_req, EndSessionRequest)
        assert len(_req) == 1


class TestWebFinger(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.service = factory('WebFinger',
                               client_authn_method=CLIENT_AUTHN_METHOD)
        client_config = {'redirect_uris': ['https://example.com/cli/authz_cb'],
                         'requests_dir': 'requests',
                         'base_url': 'https://example.com/cli/',
                         'resource': 'joe@example.com'}
        self.cli_info = ServiceContext(config=client_config)
        self.cli_info.service = build_services(
            DEFAULT_SERVICES, factory, keyjar=None,
            client_authn_method=CLIENT_AUTHN_METHOD)

    def test_get_request_parameters(self):
        request_args = {'resource': 'acct:joe@example.com'}
        _req = self.service.get_request_parameters(self.cli_info,
                                                    request_args=request_args)
        assert set(_req.keys()) == {'url'}
        assert _req['url'] == \
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
        resp = self.service.parse_response(json.dumps(_info), self.cli_info)
        assert resp.to_dict() == _info
        self.service.update_client_info(client_info=self.cli_info, resp=resp)
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
    cli_info = ServiceContext(keyjar, config=client_config)
    req = srv.construct(cli_info)
    assert 'claims' in req
    assert set(req['claims'].keys()) == {'id_token'}
