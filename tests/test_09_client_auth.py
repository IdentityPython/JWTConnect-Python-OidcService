import base64
import os
from urllib.parse import quote_plus

import pytest

from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from oidcmsg.message import Message

from oidcservice import JWT_BEARER
from oidcservice.client_auth import assertion_jwt
from oidcservice.client_auth import BearerBody
from oidcservice.client_auth import BearerHeader
from oidcservice.client_auth import ClientSecretBasic
from oidcservice.client_auth import ClientSecretJWT
from oidcservice.client_auth import ClientSecretPost
from oidcservice.client_auth import PrivateKeyJWT
from oidcservice.client_auth import valid_service_context
from oidcservice.oidc import DEFAULT_SERVICES
from oidcservice.oidc import service
from oidcservice.oidc.service import factory
from oidcservice.service import build_services
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import State, InMemoryStateDataBase

from oidcmsg.oauth2 import AccessTokenRequest, AuthorizationRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import CCAccessTokenRequest
from oidcmsg.oauth2 import ResourceRequest

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
CLIENT_ID = "A"

CLIENT_CONF = {'issuer': 'https://example.com/as',
               'redirect_uris': ['https://example.com/cli/authz_cb'],
               'client_secret': 'white boarding pass',
               'client_id': CLIENT_ID}


def _eq(l1, l2):
    return set(l1) == set(l2)


def get_service_context():
    service_context = ServiceContext(keyjar=None, config=CLIENT_CONF)
    service_context.client_secret = "white boarding pass"
    return service_context


def get_service():
    service_context = ServiceContext(keyjar=None, config=CLIENT_CONF)
    service_context.client_secret = "white boarding pass"
    service = factory('AccessToken', state_db=InMemoryStateDataBase(),
                      service_context=service_context)
    return service


@pytest.fixture
def services():
    db = InMemoryStateDataBase()
    auth_request = AuthorizationRequest(redirect_uri="http://example.com",
                                        state='ABCDE').to_json()
    auth_response = AuthorizationResponse(access_token="token",
                                        state='ABCDE').to_json()
    db.set('ABCDE', State(iss='Issuer', auth_request=auth_request,
                          auth_response=auth_response).to_json())
    return build_services(DEFAULT_SERVICES, service.factory,
                          get_service_context(), db)


def test_quote():
    csb = ClientSecretBasic()
    http_args = csb.construct(
        Message(),
        password='MKEM/A7Pkn7JuU0LAcxyHVKvwdczsugaPU0BieLb4CbQAgQj+ypcanFOCb0/FA5h' ,
        user='796d8fae-a42f-4e4f-ab25-d6205b6d4fa2')

    assert http_args['headers'][
               'Authorization'] == 'Basic Nzk2ZDhmYWUtYTQyZi00ZTRmLWFiMjUtZDYyMDViNmQ0ZmEyOk1LRU0lMkZBN1BrbjdKdVUwTEFjeHlIVkt2d2RjenN1Z2FQVTBCaWVMYjRDYlFBZ1FqJTJCeXBjYW5GT0NiMCUyRkZBNWg='



class TestClientSecretBasic(object):
    def test_construct(self, services):
        request = services['accesstoken'].construct(
            redirect_uri="http://example.com", state='ABCDE')

        csb = ClientSecretBasic()
        http_args = csb.construct(request, services['accesstoken'])

        credentials = "{}:{}".format(quote_plus('A'),
                                     quote_plus('white boarding pass'))
        assert http_args == {"headers": {"Authorization": "Basic {}".format(
            base64.urlsafe_b64encode(credentials.encode("utf-8")).decode(
                "utf-8"))}}

    def test_does_not_remove_padding(self):
        request = AccessTokenRequest(code="foo",
                                     redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, user="ab", password="c")

        assert http_args["headers"]["Authorization"].endswith("==")

    def test_construct_cc(self):
        """CC == Client Credentials, the 4th OAuth2 flow"""
        request = CCAccessTokenRequest(grant_type="client_credentials")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, user="service1", password="secret")

        assert http_args["headers"]["Authorization"].startswith('Basic ')


class TestBearerHeader(object):
    def test_construct(self):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        http_args = bh.construct(request, service=get_service())

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        # Any HTTP args should just be passed on
        http_args = bh.construct(request, service=get_service(),
                                 http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers_in_http_args(self):
        request = ResourceRequest(access_token="Sesame")

        bh = BearerHeader()
        http_args = bh.construct(request, service=get_service(),
                                 http_args={"headers": {"x-foo": "bar"}})

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self):
        bh = BearerHeader()
        request = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(request, service=get_service())

        assert "access_token" not in request
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self, services):
        authz_service = services['authorization']
        _state = authz_service.create_state('Issuer')
        req = AuthorizationRequest(state=_state, response_type='code',
                                   redirect_uri='https://example.com',
                                   scope=['openid'])
        authz_service.store_item(req, 'auth_request', _state)

        # Add a state and bind a code to it
        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = services['authorization'].parse_response(
            resp1.to_urlencoded(), "urlencoded")
        services['authorization'].update_service_context(response, state=_state)

        # based on state find the code and then get an access token
        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state=_state)
        response = services['accesstoken'].parse_response(
            resp2.to_urlencoded(), "urlencoded")

        services['accesstoken'].update_service_context(response, state=_state)

        # and finally use the access token, bound to a state, to
        # construct the authorization header
        http_args = BearerHeader().construct(
            ResourceRequest(), services['accesstoken'], state=_state)
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):
    def test_construct(self, services):
        _srv = services['accesstoken']
        request = ResourceRequest(access_token="Sesame")
        http_args = BearerBody().construct(request, service=_srv)

        assert request["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self, services):
        _srv = services['authorization']
        _srv.state_db.set('FFFFF', State(iss='Issuer').to_json())

        resp = AuthorizationResponse(code="code", state="FFFFF")
        _srv.store_item(resp, 'auth_response', 'FFFFF')

        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example",
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value",
                                  scope=["inner", "outer"])
        _srv.store_item(atr, 'token_response', 'FFFFF')

        request = ResourceRequest()
        http_args = BearerBody().construct(request, service=_srv, state="FFFFF")
        assert request["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self, services):
        authz_service = services['authorization']
        authz_service.state_db.set('EEEE', State(iss='Issuer').to_json())
        resp1 = AuthorizationResponse(code="auth_grant", state="EEEE")
        response = authz_service.parse_response(resp1.to_urlencoded(),
                                                "urlencoded")
        authz_service.update_service_context(response, state='EEEE')

        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state="EEEE")
        response = services['accesstoken'].parse_response(
            resp2.to_urlencoded(), "urlencoded")
        services['accesstoken'].update_service_context(response, state='EEEE')

        request = ResourceRequest()
        BearerBody().construct(request, service=authz_service, state="EEEE")

        assert "access_token" in request
        assert request["access_token"] == "token1"


class TestClientSecretPost(object):
    def test_construct(self, services):
        token_service = services['accesstoken']
        request = token_service.construct(redirect_uri="http://example.com",
                                          state='ABCDE')
        csp = ClientSecretPost()
        http_args = csp.construct(request, service=token_service)

        assert request["client_id"] == "A"
        assert request["client_secret"] == "white boarding pass"
        assert http_args is None

        request = AccessTokenRequest(code="foo",
                                     redirect_uri="http://example.com")
        http_args = csp.construct(request, service=token_service,
                                  client_secret="another")
        assert request["client_id"] == "A"
        assert request["client_secret"] == "another"
        assert http_args is None


class TestPrivateKeyJWT(object):
    def test_construct(self, services):
        _service = services['accesstoken']
        kb_rsa = KeyBundle(source='file://{}'.format(
            os.path.join(BASE_PATH, "data/keys/rsa.key")), fileformat='der')
        _service.service_context.keyjar.add_kb('', kb_rsa)
        _service.service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}
        services['accesstoken'].endpoint = "https://example.com/token"

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        http_args = pkj.construct(request, service=_service, algorithm="RS256",
                                  authn_endpoint='token_endpoint')
        assert http_args == {}
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_kb(_service.service_context.client_id, kb_rsa)
        jso = JWT(key_jar=_kj).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        # assert _jwt.headers == {'alg': 'RS256'}
        assert jso['aud'] == [
            _service.service_context.provider_info['token_endpoint']]

    def test_construct_client_assertion(self, services):
        _service = services['accesstoken']

        kb_rsa = KeyBundle(source='file://{}'.format(
            os.path.join(BASE_PATH, "data/keys/rsa.key")), fileformat='der')

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        _ca = assertion_jwt(
            _service.service_context.client_id, kb_rsa.get('RSA'),
            "https://example.com/token", 'RS256')
        http_args = pkj.construct(request, client_assertion=_ca)
        assert http_args == {}
        assert request['client_assertion'] == _ca
        assert request['client_assertion_type'] == JWT_BEARER


class TestClientSecretJWT_TE(object):
    def test_client_secret_jwt(self, services):
        _service_context = services['accesstoken'].service_context
        _service_context.token_endpoint = "https://example.com/token"
        _service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request, service=services['accesstoken'],
                      algorithm="HS256", authn_endpoint='token_endpoint')
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(_service_context.client_id,
                          _service_context.client_secret,
                          ['sig'])
        jso = JWT(key_jar=_kj).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "exp", "iat", 'jti'])

        _rj = JWS()
        info = _rj.verify_compact(
            cas, _kj.get_signing_key(owner=_service_context.client_id))

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [_service_context.provider_info['token_endpoint']]


class TestClientSecretJWT_UI(object):
    def test_client_secret_jwt(self, services):
        _service_context = services['accesstoken'].service_context
        _service_context.token_endpoint = "https://example.com/token"
        _service_context.provider_info = {'issuer': 'https://example.com/',
                                         'token_endpoint':
                                             "https://example.com/token"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request, service=services['accesstoken'],
                      algorithm="HS256", authn_endpoint='userinfo')
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(_service_context.client_id,
                          _service_context.client_secret,
                          usage=['sig'])
        jso = JWT(key_jar=_kj).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])

        _rj = JWS()
        info = _rj.verify_compact(
            cas,
            _kj.get_signing_key(owner=_service_context.client_id))

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [_service_context.provider_info['issuer']]


class TestValidClientInfo(object):
    def test_valid_service_context(self, services):
        _service_context = services['accesstoken'].service_context
        _now = 123456  # At some time
        # Expiration time missing or 0, client_secret never expires
        # service_context.client_secret_expires_at
        assert valid_service_context(_service_context, _now)
        _service_context.client_secret_expires_at = 0
        assert valid_service_context(_service_context, _now)
        # Expired secret
        _service_context.client_secret_expires_at = 1
        assert valid_service_context(_service_context, _now) is not True

        _service_context.client_secret_expires_at = 123455
        assert valid_service_context(_service_context, _now) is not True

        # Valid secret
        _service_context.client_secret_expires_at = 123460
        assert valid_service_context({'client_secret_expires_at': 123460}, _now)
