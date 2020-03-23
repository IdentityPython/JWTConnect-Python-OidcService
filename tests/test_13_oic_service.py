import json
import os

import pytest
from cryptojwt.jws import jws
from cryptojwt.jws.utils import left_hash
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import Message
from oidcmsg.oidc import IdToken
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc.session import CheckIDRequest
from oidcmsg.oidc.session import CheckSessionRequest
from oidcmsg.oidc.session import EndSessionRequest

from oidcservice.exception import ParameterError
from oidcservice.oidc.registration import add_jwks_uri_or_jwks
from oidcservice.oidc.registration import response_types_to_grant_types
from oidcservice.service_context import ServiceContext
from oidcservice.service_factory import service_factory
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = 'https://example.com'

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYSPEC, owner='client_id', read_only=False)

ISS_KEY = init_key_jar(public_path='{}/pub_iss.jwks'.format(_dirname),
                       private_path='{}/priv_iss.jwks'.format(_dirname),
                       key_defs=KEYSPEC, owner=ISS, read_only=False)

ISS_KEY.import_jwks_as_json(open('{}/pub_client.jwks'.format(_dirname)).read(),
                            'client_id')

CLI_KEY.import_jwks_as_json(open('{}/pub_iss.jwks'.format(_dirname)).read(),
                            ISS)


# def test_request_factory():
#     req = service_factory('Service', service_context=ServiceContext(None),
#                   state_db=InMemoryStateDataBase(), client_authn_method=None)
#     assert isinstance(req, Service)


class TestAuthorization(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb']
        }
        service_context = ServiceContext(CLI_KEY, config=client_config)
        service_context.issuer = 'https://example.com'
        self.service = service_factory('Authorization', ['oidc'],
                                       state_db=InMemoryStateDataBase(),
                                       service_context=service_context)

    def test_construct(self):
        req_args = {
            'foo': 'bar', 'response_type': 'code',
            'state': 'state'
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce'}

    def test_construct_missing_openid_scope(self):
        req_args = {
            'foo': 'bar', 'response_type': 'code',
            'state': 'state', 'scope': ['email']
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce'}
        assert _req['scope'] == ['email', 'openid']

    def test_construct_token(self):
        req_args = {
            'foo': 'bar', 'response_type': 'token',
            'state': 'state'
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state'}

    def test_construct_token_nonce(self):
        req_args = {
            'foo': 'bar', 'response_type': 'token', 'nonce': 'nonce',
            'state': 'state'
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state', 'nonce'}
        assert _req['nonce'] == 'nonce'

    def test_get_request_parameters(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert set(msg.keys()) == {'response_type', 'state', 'client_id',
                                   'nonce', 'redirect_uri', 'scope'}

    def test_request_init(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert set(msg.keys()) == {'client_id', 'scope', 'response_type',
                                   'state', 'redirect_uri', 'nonce'}

    def test_request_init_request_method(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args,
                                                    request_method='value')
        assert set(_info.keys()) == {'url', 'method'}
        msg = AuthorizationRequest().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert set(msg.to_dict()) == {'client_id', 'redirect_uri',
                                      'response_type', 'request',
                                      'state', 'scope', 'nonce'}
        _jws = jws.factory(msg['request'])
        assert _jws
        _resp = _jws.verify_compact(
            msg['request'],
            keys=ISS_KEY.get_signing_key(key_type='RSA',
                                         owner='client_id'))
        assert _resp
        assert set(_resp.keys()) == {'response_type', 'client_id', 'scope',
                                     'redirect_uri', 'state', 'nonce', 'iss', 'aud', 'iat'}

    def test_request_param(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'

        assert os.path.isfile(os.path.join(_dirname, 'request123456.jwt'))

        self.service.service_context.registration_response = {
            'redirect_uris': ['https://example.com/cb'],
            'request_uris': ['https://example.com/request123456.jwt']
        }
        self.service.service_context.base_url = 'https://example.com/'
        _info = self.service.get_request_parameters(request_args=req_args,
                                                    request_method='reference')

        assert set(_info.keys()) == {'url', 'method'}

    def test_update_service_context_no_idtoken(self):
        req_args = {'response_type': 'code', 'state': 'state'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        resp = AuthorizationResponse(state='state', code='code')
        self.service.update_service_context(resp, 'state')

    def test_update_service_context_with_idtoken(self):
        req_args = {'response_type': 'code', 'state': 'state', 'nonce': 'nonce'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(key_jar=ISS_KEY, iss=ISS, lifetime=3600)
        payload = {'sub': '123456789', 'aud': ['client_id'], 'nonce': 'nonce'}
        # have to calculate c_hash
        alg = 'RS256'
        halg = "HS%s" % alg[-3:]
        payload["c_hash"] = left_hash('code', halg)

        _idt = idt.pack(payload)
        resp = AuthorizationResponse(state='state', code='code', id_token=_idt)
        resp = self.service.parse_response(resp.to_urlencoded())
        self.service.update_service_context(resp, 'state')

    def test_update_service_context_with_idtoken_wrong_nonce(self):
        req_args = {'response_type': 'code', 'state': 'state', 'nonce': 'nonce'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(ISS_KEY, iss=ISS, lifetime=3600)
        payload = {
            'sub': '123456789', 'aud': ['client_id'],
            'nonce': 'nonce'
        }
        # have to calculate c_hash
        alg = 'RS256'
        halg = "HS%s" % alg[-3:]
        payload["c_hash"] = left_hash('code', halg)

        _idt = idt.pack(payload)
        resp = AuthorizationResponse(state='state', code='code', id_token=_idt)
        resp = self.service.parse_response(resp.to_urlencoded())
        with pytest.raises(ParameterError):
            self.service.update_service_context(resp, 'state2')

    def test_update_service_context_with_idtoken_missing_nonce(self):
        req_args = {'response_type': 'code', 'state': 'state', 'nonce': 'nonce'}
        self.service.endpoint = 'https://example.com/authorize'
        self.service.get_request_parameters(request_args=req_args)
        # Build an ID Token
        idt = JWT(ISS_KEY, iss=ISS, lifetime=3600)
        payload = {'sub': '123456789', 'aud': ['client_id']}
        # have to calculate c_hash
        alg = 'RS256'
        halg = "HS%s" % alg[-3:]
        payload["c_hash"] = left_hash('code', halg)

        _idt = idt.pack(payload)
        resp = AuthorizationResponse(state='state', code='code', id_token=_idt)
        resp = self.service.parse_response(resp.to_urlencoded())
        with pytest.raises(ValueError):
            self.service.update_service_context(resp, 'state')


class TestAuthorizationCallback(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'callback': {
                'code': 'https://example.com/cli/authz_cb',
                'implicit': 'https://example.com/cli/authz_im_cb',
                'form_post': 'https://example.com/cli/authz_fp_cb'
            }
        }
        service_context = ServiceContext(CLI_KEY, config=client_config)
        self.service = service_factory('Authorization', ['oidc'],
                                       state_db=InMemoryStateDataBase(),
                                       service_context=service_context)

    def test_construct_code(self):
        req_args = {
            'foo': 'bar', 'response_type': 'code',
            'state': 'state'
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce'}
        assert _req['redirect_uri'] == 'https://example.com/cli/authz_cb'

    def test_construct_implicit(self):
        req_args = {
            'foo': 'bar', 'response_type': 'id_token token',
            'state': 'state'
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce'}
        assert _req['redirect_uri'] == 'https://example.com/cli/authz_im_cb'

    def test_construct_form_post(self):
        req_args = {
            'foo': 'bar', 'response_type': 'code id_token token',
            'state': 'state', 'response_mode': 'form_post'
        }
        _req = self.service.construct(request_args=req_args)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {'redirect_uri', 'foo', 'client_id',
                                    'response_type', 'scope', 'state',
                                    'nonce', 'response_mode'}
        assert _req['redirect_uri'] == 'https://example.com/cli/authz_fp_cb'


class TestAccessTokenRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb']
        }
        service_context = ServiceContext(CLI_KEY, config=client_config)
        _db = InMemoryStateDataBase()
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state', response_type='code').to_json()
        auth_response = AuthorizationResponse(code='access_code').to_json()
        _db.set('state', State(auth_response=auth_response,
                               auth_request=auth_request).to_json())
        self.service = service_factory('AccessToken', ['oidc'], state_db=_db,
                                       service_context=service_context)

    def test_construct(self):
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
        _info = self.service.get_request_parameters(request_args=req_args,
                                                    state='state',
                                                    authn_method='client_secret_basic')
        assert set(_info.keys()) == {'body', 'url', 'headers', 'method'}
        assert _info['url'] == 'https://example.com/authorize'
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code', 'state': 'state',
            'redirect_uri': 'https://example.com/cli/authz_cb'
        }

    def test_request_init(self):
        req_args = {
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'code': 'access_code'
        }
        self.service.endpoint = 'https://example.com/authorize'

        _info = self.service.get_request_parameters(request_args=req_args,
                                                    state='state')
        assert set(_info.keys()) == {'body', 'url', 'headers', 'method'}
        assert _info['url'] == 'https://example.com/authorize'
        msg = AccessTokenRequest().from_urlencoded(
            self.service.get_urlinfo(_info['body']))
        assert msg.to_dict() == {
            'client_id': 'client_id', 'code': 'access_code',
            'grant_type': 'authorization_code', 'state': 'state',
            'redirect_uri': 'https://example.com/cli/authz_cb'
        }

    def test_id_token_nonce_match(self):
        self.service.store_nonce2state('nonce', 'state')
        resp = AccessTokenResponse()
        resp[verified_claim_name('id_token')] = {'nonce': 'nonce'}
        self.service.store_nonce2state('nonce2', 'state2')
        with pytest.raises(ParameterError):
            self.service.update_service_context(resp, key='state2')


class TestProviderInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss,
            'client_preferences':
                {
                    "application_type": "web",
                    "application_name": "rphandler",
                    "contacts": ["ops@example.org"],
                    "response_types": ["code"],
                    "scope": ["openid", "profile", "email",
                              "address", "phone"],
                    "token_endpoint_auth_method": "client_secret_basic",
                }
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('ProviderInfoDiscovery', ['oidc'],
                                       state_db=None,
                                       service_context=service_context)

    def test_construct(self):
        _req = self.service.construct()
        assert isinstance(_req, Message)
        assert len(_req) == 0

    def test_get_request_parameters(self):
        _info = self.service.get_request_parameters()
        assert set(_info.keys()) == {'url', 'method'}
        assert _info['url'] == '{}/.well-known/openid-configuration'.format(
            self._iss)

    def test_post_parse(self):
        OP_BASEURL = ISS

        provider_info_response = {
            "version": "3.0",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post", "client_secret_basic",
                "client_secret_jwt", "private_key_jwt"],
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "require_request_uri_registration": True,
            "grant_types_supported": ["authorization_code",
                                      "implicit",
                                      "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                      "refresh_token"],
            "response_types_supported": ["code", "id_token",
                                         "id_token token",
                                         "code id_token",
                                         "code token",
                                         "code id_token token"],
            "response_modes_supported": ["query", "fragment",
                                         "form_post"],
            "subject_types_supported": ["public", "pairwise"],
            "claim_types_supported": ["normal", "aggregated",
                                      "distributed"],
            "claims_supported": ["birthdate", "address",
                                 "nickname", "picture", "website",
                                 "email", "gender", "sub",
                                 "phone_number_verified",
                                 "given_name", "profile",
                                 "phone_number", "updated_at",
                                 "middle_name", "name", "locale",
                                 "email_verified",
                                 "preferred_username", "zoneinfo",
                                 "family_name"],
            "scopes_supported": ["openid", "profile", "email",
                                 "address", "phone",
                                 "offline_access", "openid"],
            "userinfo_signing_alg_values_supported": [
                "RS256", "RS384", "RS512",
                "ES256", "ES384", "ES512",
                "HS256", "HS384", "HS512",
                "PS256", "PS384", "PS512", "none"],
            "id_token_signing_alg_values_supported": [
                "RS256", "RS384", "RS512",
                "ES256", "ES384", "ES512",
                "HS256", "HS384", "HS512",
                "PS256", "PS384", "PS512", "none"],
            "request_object_signing_alg_values_supported": [
                "RS256", "RS384", "RS512", "ES256", "ES384",
                "ES512", "HS256", "HS384", "HS512", "PS256",
                "PS384", "PS512", "none"],
            "token_endpoint_auth_signing_alg_values_supported": [
                "RS256", "RS384", "RS512", "ES256", "ES384",
                "ES512", "HS256", "HS384", "HS512", "PS256",
                "PS384", "PS512"],
            "userinfo_encryption_alg_values_supported": [
                "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                "A128KW", "A192KW", "A256KW",
                "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
                "ECDH-ES+A256KW"],
            "id_token_encryption_alg_values_supported": [
                "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                "A128KW", "A192KW", "A256KW",
                "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
                "ECDH-ES+A256KW"],
            "request_object_encryption_alg_values_supported": [
                "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
                "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
                "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
            "userinfo_encryption_enc_values_supported": [
                "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                "A128GCM", "A192GCM", "A256GCM"],
            "id_token_encryption_enc_values_supported": [
                "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                "A128GCM", "A192GCM", "A256GCM"],
            "request_object_encryption_enc_values_supported": [
                "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                "A128GCM", "A192GCM", "A256GCM"],
            "acr_values_supported": ["PASSWORD"],
            "issuer": OP_BASEURL,
            "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(
                OP_BASEURL),
            "authorization_endpoint": "{}/authorization".format(OP_BASEURL),
            "token_endpoint": "{}/token".format(OP_BASEURL),
            "userinfo_endpoint": "{}/userinfo".format(OP_BASEURL),
            "registration_endpoint": "{}/registration".format(OP_BASEURL),
            "end_session_endpoint": "{}/end_session".format(OP_BASEURL)
        }
        assert self.service.service_context.behaviour == {}
        resp = self.service.post_parse_response(provider_info_response)
        self.service.update_service_context(resp)
        assert self.service.service_context.behaviour == {
            'token_endpoint_auth_method': 'client_secret_basic',
            'response_types': ['code'],
            'application_type': 'web',
            'application_name': 'rphandler',
            'contacts': ['ops@example.org'],
            'scope': ['openid', 'profile', 'email', 'address', 'phone']
        }

    def test_post_parse_2(self):
        OP_BASEURL = ISS

        provider_info_response = {
            "version": "3.0",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post", "client_secret_basic",
                "client_secret_jwt", "private_key_jwt"],
            "issuer": OP_BASEURL,
            "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(
                OP_BASEURL),
            "authorization_endpoint": "{}/authorization".format(OP_BASEURL),
            "token_endpoint": "{}/token".format(OP_BASEURL),
            "userinfo_endpoint": "{}/userinfo".format(OP_BASEURL),
            "registration_endpoint": "{}/registration".format(OP_BASEURL),
            "end_session_endpoint": "{}/end_session".format(OP_BASEURL)
        }
        assert self.service.service_context.behaviour == {}
        resp = self.service.post_parse_response(provider_info_response)
        self.service.update_service_context(resp)
        assert self.service.service_context.behaviour == {
            'token_endpoint_auth_method': 'client_secret_basic',
            'response_types': ['code'],
            'application_type': 'web',
            'application_name': 'rphandler',
            'contacts': ['ops@example.org'],
            'scope': ['openid', 'profile', 'email', 'address', 'phone']
        }


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


def create_jws(val):
    lifetime = 3600

    idts = IdToken(**val)

    return idts.to_jwt(key=ISS_KEY.get_signing_key('ec', owner=ISS),
                       algorithm="ES256", lifetime=lifetime)


class TestRegistration(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss, 'requests_dir': 'requests',
            'base_url': 'https://example.com/cli/'
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('Registration', ['oidc'], state_db=None,
                                       service_context=service_context)

    def test_construct(self):
        _req = self.service.construct()
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 4

    def test_config_with_post_logout(self):
        self.service.service_context.register_args[
            'post_logout_redirect_uris'] = ['https://example.com/post_logout']
        _req = self.service.construct()
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 5
        assert 'post_logout_redirect_uris' in _req

    def test_config_with_required_request_uri(self):
        self.service.service_context.provider_info[
            'require_request_uri_registration'] = True
        _req = self.service.construct()
        assert isinstance(_req, RegistrationRequest)
        assert len(_req) == 5
        assert 'request_uris' in _req


class TestUserInfo(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss, 'requests_dir': 'requests',
            'base_url': 'https://example.com/cli/'
        }
        service_context = ServiceContext(config=client_config)
        service_context.keyjar = CLI_KEY
        service_context.behaviour = {
            'userinfo_signed_response_alg': 'RS256',
            "userinfo_encrypted_response_alg": "RSA-OAEP",
            "userinfo_encrypted_response_enc": "A256GCM"
        }

        db = InMemoryStateDataBase()
        auth_response = AuthorizationResponse(code='access_code').to_json()

        idtval = {
            'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'diana',
            'iss': ISS, 'aud': 'client_id'
        }
        idt = create_jws(idtval)

        ver_idt = IdToken().from_jwt(idt, CLI_KEY)

        token_response = AccessTokenResponse(
            access_token='access_token', id_token=idt,
            __verified_id_token=ver_idt).to_json()
        db.set('abcde', State(token_response=token_response,
                              auth_response=auth_response).to_json())
        self.service = service_factory('UserInfo', ['oidc'], state_db=db,
                                       service_context=service_context)

    def test_construct(self):
        _req = self.service.construct(state='abcde')
        assert isinstance(_req, Message)
        assert len(_req) == 1
        assert 'access_token' in _req

    def test_unpack_simple_response(self):
        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall')
        _resp = self.service.parse_response(resp.to_json(),
                                            state='abcde')
        assert _resp

    def test_unpack_aggregated_response(self):
        claims = {
            "address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US"
            },
            "phone_number": "+1 (555) 123-4567"
        }

        srv = JWT(ISS_KEY, iss=ISS, sign_alg='ES256')
        _jwt = srv.pack(payload=claims)

        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall',
                            _claim_names={
                                'address': 'src1',
                                'phone_number': 'src1'
                            },
                            _claim_sources={'src1': {'JWT': _jwt}})

        _resp = self.service.parse_response(resp.to_json(), state='abcde')
        _resp = self.service.post_parse_response(_resp, state='abcde')
        assert set(_resp.keys()) == {'sub', 'given_name', 'family_name',
                                     '_claim_names', '_claim_sources',
                                     'address', 'phone_number'}

    def test_unpack_aggregated_response_missing_keys(self):
        claims = {
            "address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US"
            },
            "phone_number": "+1 (555) 123-4567"
        }

        _keyjar = build_keyjar(KEYSPEC)

        srv = JWT(_keyjar, iss=ISS, sign_alg='ES256')
        _jwt = srv.pack(payload=claims)

        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall',
                            _claim_names={
                                'address': 'src1',
                                'phone_number': 'src1'
                            },
                            _claim_sources={'src1': {'JWT': _jwt}})

        _resp = self.service.parse_response(resp.to_json(), state='abcde')
        assert _resp

    def test_unpack_signed_response(self):
        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall', iss=ISS)
        sk = ISS_KEY.get_signing_key('rsa', owner=ISS)
        alg = self.service.service_context.get_sign_alg('userinfo')
        _resp = self.service.parse_response(resp.to_jwt(sk, algorithm=alg),
                                            state='abcde', sformat='jwt')
        assert _resp

    def test_unpack_encrypted_response(self):
        # Add encryption key
        _kj = build_keyjar([{"type": "RSA", "use": ["enc"]}], owner='')
        # Own key jar gets the private key
        self.service.service_context.keyjar.import_jwks(
            _kj.export_jwks(private=True), issuer='client_id')
        # opponent gets the public key
        ISS_KEY.import_jwks(_kj.export_jwks(), issuer='client_id')

        resp = OpenIDSchema(sub='diana', given_name='Diana',
                            family_name='krall', iss=ISS, aud='client_id')
        enckey = ISS_KEY.get_encrypt_key('rsa', owner='client_id')
        algspec = self.service.service_context.get_enc_alg_enc(
            self.service.service_name)

        enc_resp = resp.to_jwe(enckey, **algspec)
        _resp = self.service.parse_response(enc_resp, state='abcde',
                                            sformat='jwt')
        assert _resp


class TestCheckSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss, 'requests_dir': 'requests',
            'base_url': 'https://example.com/cli/'
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('CheckSession', ['oidc'],
                                       state_db=InMemoryStateDataBase(),
                                       service_context=service_context)

    def test_construct(self):
        self.service.store_item(json.dumps({'id_token': 'a.signed.jwt'}),
                                'token_response',
                                'abcde')
        _req = self.service.construct(state='abcde')
        assert isinstance(_req, CheckSessionRequest)
        assert len(_req) == 1


class TestCheckID(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss, 'requests_dir': 'requests',
            'base_url': 'https://example.com/cli/'
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('CheckID', ['oidc'],
                                       state_db=InMemoryStateDataBase(),
                                       service_context=service_context)

    def test_construct(self):
        self.service.store_item(json.dumps({'id_token': 'a.signed.jwt'}),
                                'token_response', 'abcde')
        _req = self.service.construct(state='abcde')
        assert isinstance(_req, CheckIDRequest)
        assert len(_req) == 1


class TestEndSession(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'issuer': self._iss, 'requests_dir': 'requests',
            'base_url': 'https://example.com/cli/',
            'post_logout_redirect_uris': ['https://example.com/post_logout']
        }
        service_context = ServiceContext(config=client_config)
        self.service = service_factory('EndSession', ['oidc'],
                                       state_db=InMemoryStateDataBase(),
                                       service_context=service_context)

    def test_construct(self):
        self.service.store_item(json.dumps({'id_token': 'a.signed.jwt'}),
                                'token_response', 'abcde')
        _req = self.service.construct(state='abcde')
        assert isinstance(_req, EndSessionRequest)
        assert len(_req) == 3
        assert set(_req.keys()) == {'state', 'id_token_hint',
                                    'post_logout_redirect_uri'}


def test_authz_service_conf():
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'a longesh password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'behaviour': {'response_types': ['code']}
    }

    srv = service_factory(
        'Authorization', ['oidc'], state_db=InMemoryStateDataBase(),
        service_context=ServiceContext(CLI_KEY, config=client_config),
        conf={
            'request_args': {
                'claims': {
                    "id_token":
                        {
                            "auth_time": {"essential": True},
                            "acr": {"values": ["urn:mace:incommon:iap:silver"]}
                        }
                }
            }
        })

    req = srv.construct()
    assert 'claims' in req
    assert set(req['claims'].keys()) == {'id_token'}


def test_add_jwks_uri_or_jwks_0():
    client_config = {
        'client_id': 'client_id', 'client_secret': 'a longesh password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'jwks_uri': 'https://example.com/jwks/jwks.json',
        'issuer': ISS,
        'client_preferences': {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'
        }
    }
    service_context = ServiceContext(config=client_config)
    service = service_factory('Registration', ['oidc'], state_db=None,
                              service_context=service_context)
    req_args, post_args = add_jwks_uri_or_jwks({}, service)
    assert req_args['jwks_uri'] == 'https://example.com/jwks/jwks.json'


def test_add_jwks_uri_or_jwks_1():
    client_config = {
        'client_id': 'client_id', 'client_secret': 'a longesh password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'jwks_uri': 'https://example.com/jwks/jwks.json',
        'jwks': '{"keys":[]}',
        'issuer': ISS,
        'client_preferences': {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'
        }
    }
    service_context = ServiceContext(config=client_config)
    service = service_factory('Registration', ['oidc'], state_db=None,
                              service_context=service_context)
    req_args, post_args = add_jwks_uri_or_jwks({}, service)
    assert req_args['jwks_uri'] == 'https://example.com/jwks/jwks.json'
    assert set(req_args.keys()) == {'jwks_uri'}


def test_add_jwks_uri_or_jwks_2():
    client_config = {
        'client_id': 'client_id', 'client_secret': 'a longesh password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'issuer': ISS,
        'client_preferences': {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'
        }
    }
    service_context = ServiceContext(
        config=client_config, jwks_uri='https://example.com/jwks/jwks.json')
    service = service_factory('Registration', ['oidc'], state_db=None,
                              service_context=service_context)

    req_args, post_args = add_jwks_uri_or_jwks({}, service)
    assert req_args['jwks_uri'] == 'https://example.com/jwks/jwks.json'
    assert set(req_args.keys()) == {'jwks_uri'}


def test_add_jwks_uri_or_jwks_3():
    client_config = {
        'client_id': 'client_id', 'client_secret': 'a longesh password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'issuer': ISS,
        'client_preferences': {
            'id_token_signed_response_alg': 'RS384',
            'userinfo_signed_response_alg': 'RS384'
        }
    }
    service_context = ServiceContext(config=client_config, jwks='{"keys":[]}')
    service = service_factory('Registration', ['oidc'], state_db=None,
                              service_context=service_context)
    req_args, post_args = add_jwks_uri_or_jwks({}, service)
    assert req_args['jwks'] == '{"keys":[]}'
    assert set(req_args.keys()) == {'jwks'}
