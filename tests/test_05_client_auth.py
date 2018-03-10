import base64
import os
import pytest

from cryptojwt import as_bytes
from cryptojwt import b64e
from cryptojwt.jwk import SYMKey
from cryptojwt.jwk import rsa_load
from cryptojwt.jws import JWS
from cryptojwt.jwt import JWT

from oidcservice import JWT_BEARER
from oidcservice.client_auth import assertion_jwt
from oidcservice.client_auth import BearerBody
from oidcservice.client_auth import BearerHeader
from oidcservice.client_auth import CLIENT_AUTHN_METHOD
from oidcservice.client_auth import ClientSecretBasic
from oidcservice.client_auth import ClientSecretJWT
from oidcservice.client_auth import ClientSecretPost
from oidcservice.client_auth import PrivateKeyJWT
from oidcservice.client_auth import valid_service_context
from oidcservice.service_context import ServiceContext
from oidcservice.oidc import DEFAULT_SERVICES
from oidcservice.oidc import service
from oidcservice.service import build_services

from oidcmsg.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import CCAccessTokenRequest
from oidcmsg.oauth2 import ResourceRequest

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
CLIENT_ID = "A"

CLIENT_CONF = {'issuer': 'https://example.com/as',
               'redirect_uris': ['https://example.com/cli/authz_cb'],
               'client_secret': 'boarding pass',
               'client_id': CLIENT_ID}


def _eq(l1, l2):
    return set(l1) == set(l2)


@pytest.fixture
def services():
    return build_services(DEFAULT_SERVICES, service.factory, keyjar=None,
                          client_authn_method=CLIENT_AUTHN_METHOD)


@pytest.fixture
def service_context():
    service_context = ServiceContext(keyjar=None, config=CLIENT_CONF)
    _sdb = service_context.state_db
    _sdb['ABCDE'] = {'code': 'access_code'}
    service_context.client_secret = "boarding pass"
    return service_context


class TestClientSecretBasic(object):
    def test_construct(self, services, service_context):
        request = services['accesstoken'].construct(
            service_context, redirect_uri="http://example.com", state='ABCDE')

        csb = ClientSecretBasic()
        http_args = csb.construct(request, service_context=service_context)

        assert http_args == {"headers": {"Authorization": "Basic {}".format(
            base64.urlsafe_b64encode("A:boarding pass".encode("utf-8")).decode(
                "utf-8"))}}

    def test_does_not_remove_padding(self, service_context):
        request = AccessTokenRequest(code="foo",
                                     redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, service_context=service_context,
                                  user="ab", password="c")

        assert http_args["headers"]["Authorization"].endswith("==")

    def test_construct_cc(self, service_context):
        """CC == Client Credentials, the 4th OAuth2 flow"""
        request = CCAccessTokenRequest(grant_type="client_credentials")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, service_context=service_context,
                                  user="service1", password="secret")

        assert http_args["headers"]["Authorization"].startswith('Basic ')


class TestBearerHeader(object):
    def test_construct(self):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        http_args = bh.construct(request)

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        # Any HTTP args should just be passed on
        http_args = bh.construct(request, http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers_in_http_args(self):
        request = ResourceRequest(access_token="Sesame")

        bh = BearerHeader()
        http_args = bh.construct(request,
                                 http_args={"headers": {"x-foo": "bar"}})

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self, service_context):
        bh = BearerHeader()
        request = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(request, service_context=service_context)

        assert "access_token" not in request
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self, service_context, services):
        # Add a state and bind a code to it
        service_context.state_db['AAAA'] = {}
        resp1 = AuthorizationResponse(code="auth_grant", state="AAAA")
        response = services['authorization'].parse_response(
            resp1.to_urlencoded(), service_context, "urlencoded")
        services['authorization'].update_service_context(service_context,
                                                         response)

        # based on state find the code and then get an access token
        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state="AAAA")
        response = services['accesstoken'].parse_response(
            resp2.to_urlencoded(), service_context, "urlencoded")

        services['accesstoken'].update_service_context(service_context,
                                                       response)

        # and finally use the access token, bound to a state, to
        # construct the authorization header
        http_args = BearerHeader().construct(
            ResourceRequest(), service_context=service_context, state="AAAA")
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):
    def test_construct(self, service_context):
        request = ResourceRequest(access_token="Sesame")
        http_args = BearerBody().construct(request,
                                           service_context=service_context)

        assert request["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self, service_context):
        _sdb = service_context.state_db
        _sdb['FFFFF'] = {}
        resp = AuthorizationResponse(code="code", state="FFFFF")
        _sdb.add_response(resp)
        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example",
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value",
                                  scope=["inner", "outer"])
        _sdb.add_response(atr, state='FFFFF')

        request = ResourceRequest()
        http_args = BearerBody().construct(
            request, service_context=service_context, state="FFFFF")
        assert request["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self, service_context,
                                    services):
        service_context.state_db['EEEE'] = {}
        resp1 = AuthorizationResponse(code="auth_grant", state="EEEE")
        response = services['authorization'].parse_response(
            resp1.to_urlencoded(), service_context, "urlencoded")
        services['authorization'].update_service_context(service_context,
                                                         response)

        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state="EEEE")
        response = services['accesstoken'].parse_response(
            resp2.to_urlencoded(), service_context, "urlencoded")
        services['accesstoken'].update_service_context(service_context,
                                                       response)

        request = ResourceRequest()
        BearerBody().construct(request, service_context=service_context,
                               state="EEEE")

        assert "access_token" in request
        assert request["access_token"] == "token1"


class TestClientSecretPost(object):
    def test_construct(self, service_context,
                       services):
        request = services['accesstoken'].construct(
            service_context, redirect_uri="http://example.com", state='ABCDE')
        csp = ClientSecretPost()
        http_args = csp.construct(request, service_context=service_context)

        assert request["client_id"] == "A"
        assert request["client_secret"] == "boarding pass"
        assert http_args is None

        request = AccessTokenRequest(code="foo",
                                     redirect_uri="http://example.com")
        http_args = csp.construct(request, service_context=service_context,
                                  client_secret="another")
        assert request["client_id"] == "A"
        assert request["client_secret"] == "another"


class TestPrivateKeyJWT(object):
    def test_construct(self, service_context,
                       services):
        _key = rsa_load(
            os.path.join(BASE_PATH, "data/keys/rsa.key"))
        kc_rsa = KeyBundle([{"key": _key, "kty": "RSA", "use": "ver"},
                            {"key": _key, "kty": "RSA", "use": "sig"}])
        service_context.keyjar[""] = kc_rsa
        service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}
        services['accesstoken'].endpoint = "https://example.com/token"

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        http_args = pkj.construct(request, service_context=service_context,
                                  algorithm="RS256",
                                  authn_endpoint='token')
        assert http_args == {}
        cas = request["client_assertion"]

        pub_kb = KeyBundle(
            [{"key": _key.public_key(), "kty": "RSA", "use": "ver"},
             {"key": _key.public_key(), "kty": "RSA", "use": "sig"}])

        jso = JWT(
            rec_keys={service_context.client_id: pub_kb.get('RSA')}).unpack(
            cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        # assert _jwt.headers == {'alg': 'RS256'}
        assert jso['aud'] == [
            service_context.provider_info['token_endpoint']]

    def test_construct_client_assertion(self,
                                        service_context):
        _key = rsa_load(os.path.join(BASE_PATH, "data/keys/rsa.key"))
        kc_rsa = KeyBundle([{"key": _key, "kty": "RSA", "use": "ver"},
                            {"key": _key, "kty": "RSA", "use": "sig"}])

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        _ca = assertion_jwt(service_context.client_id, kc_rsa.get('RSA'),
                            "https://example.com/token", 'RS256')
        http_args = pkj.construct(request, client_assertion=_ca)
        assert http_args == {}
        assert request['client_assertion'] == _ca
        assert request['client_assertion_type'] == JWT_BEARER


class TestClientSecretJWT_TE(object):
    def test_client_secret_jwt(self, service_context):
        service_context.token_endpoint = "https://example.com/token"
        service_context.provider_info = {'issuer': 'https://example.com/',
                                         'token_endpoint':
                                             "https://example.com/token"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request, service_context=service_context,
                      algorithm="HS256",
                      authn_endpoint='token')
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _skey = [
            SYMKey(k=b64e(as_bytes(service_context.client_secret)), use='sig')]
        jso = JWT(rec_keys={service_context.client_id: _skey}).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "exp", "iat", 'jti'])

        _rj = JWS()
        info = _rj.verify_compact(cas, _skey)

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [service_context.provider_info['token_endpoint']]


class TestClientSecretJWT_UI(object):
    def test_client_secret_jwt(self, service_context):
        service_context.token_endpoint = "https://example.com/token"
        service_context.provider_info = {'issuer': 'https://example.com/',
                                         'token_endpoint':
                                             "https://example.com/token"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request, service_context=service_context,
                      algorithm="HS256",
                      authn_endpoint='userinfo')
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _skey = [
            SYMKey(k=b64e(as_bytes(service_context.client_secret)), use='sig')]
        jso = JWT(rec_keys={service_context.client_id: _skey}).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])

        _rj = JWS()
        info = _rj.verify_compact(cas,
                                  [SYMKey(k=b64e(as_bytes(
                                      service_context.client_secret)))])

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [service_context.provider_info['issuer']]


class TestValidClientInfo(object):
    def test_valid_service_context(self, service_context):
        _now = 123456  # At some time
        # Expiration time missing or 0, client_secret never expires
        # service_context.registration_expires
        assert valid_service_context(service_context, _now)
        service_context.registration_expires = 0
        assert valid_service_context(service_context, _now)
        # Expired secret
        service_context.registration_expires = 1
        assert valid_service_context(service_context, _now) is not True

        service_context.registration_expires = 123455
        assert valid_service_context(service_context, _now) is not True

        # Valid secret
        service_context.registration_expires = 123460
        assert valid_service_context({'registration_expires': 123460}, _now)
