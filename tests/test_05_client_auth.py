# pylint: disable=missing-docstring,no-self-use

import base64
import os

import pytest
from cryptojwt import as_bytes
from cryptojwt import b64e
from cryptojwt.jwk import SYMKey
from cryptojwt.jwk import rsa_load
from cryptojwt.jws import JWS
from cryptojwt.jwt import JWT

from oiccli import JWT_BEARER
from oiccli.client_auth import assertion_jwt
from oiccli.client_auth import BearerBody
from oiccli.client_auth import BearerHeader
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.client_auth import ClientSecretBasic
from oiccli.client_auth import ClientSecretJWT
from oiccli.client_auth import ClientSecretPost
from oiccli.client_auth import PrivateKeyJWT
from oiccli.client_auth import valid_client_info
from oiccli.oauth2 import Client
from oicmsg.key_bundle import KeyBundle
from oicmsg.key_jar import KeyJar
from oicmsg.oauth2 import AccessTokenRequest
from oicmsg.oauth2 import AccessTokenResponse
from oicmsg.oauth2 import AuthorizationResponse
from oicmsg.oauth2 import CCAccessTokenRequest
from oicmsg.oauth2 import ResourceRequest

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
CLIENT_ID = "A"

CLIENT_CONF = {'issuer': 'https://example.com/as',
               'redirect_uris': ['https://example.com/cli/authz_cb'],
               'client_secret': 'boarding pass',
               'client_id': CLIENT_ID}


def _eq(l1, l2):
    return set(l1) == set(l2)


@pytest.fixture
def client():
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                    config=CLIENT_CONF)
    _sdb = client.client_info.state_db
    _sdb['ABCDE'] = {'code': 'access_code'}
    client.client_info.client_secret = "boarding pass"
    return client


class TestClientSecretBasic(object):
    def test_construct(self, client):
        cis = client.service['accesstoken'].construct(client.client_info,
                                                      redirect_uri="http://example.com",
                                                      state='ABCDE')

        csb = ClientSecretBasic()
        http_args = csb.construct(cis, cli_info=client.client_info)

        assert http_args == {"headers": {"Authorization": "Basic {}".format(
            base64.urlsafe_b64encode("A:boarding pass".encode("utf-8")).decode(
                "utf-8"))}}

    def test_does_not_remove_padding(self, client):
        cis = AccessTokenRequest(code="foo", redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(cis, cli_info=client.client_info, user="ab",
                                  password="c")

        assert http_args["headers"]["Authorization"].endswith("==")

    def test_construct_cc(self, client):
        """CC == Client Credentials, the 4th OAuth2 flow"""
        cis = CCAccessTokenRequest(grant_type="client_credentials")

        csb = ClientSecretBasic()
        http_args = csb.construct(cis, cli_info=client.client_info,
                                  user="service1", password="secret")

        assert http_args["headers"]["Authorization"].startswith('Basic ')


class TestBearerHeader(object):
    def test_construct(self):
        request_args = {"access_token": "Sesame"}
        bh = BearerHeader()
        http_args = bh.construct(request_args=request_args)

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self):
        request_args = {"access_token": "Sesame"}
        bh = BearerHeader()
        http_args = bh.construct(request_args=request_args,
                                 http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers_in_http_args(self):
        request_args = {"access_token": "Sesame"}

        bh = BearerHeader()
        http_args = bh.construct(request_args=request_args,
                                 http_args={"headers": {"x-foo": "bar"}})

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self, client):
        bh = BearerHeader()
        cis = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(cis, cli_info=client.client_info)

        assert "access_token" not in cis
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self, client):
        # Add a state and bind a code to it
        client.client_info.state_db['AAAA'] = {}
        resp1 = AuthorizationResponse(code="auth_grant", state="AAAA")
        client.service['authorization'].parse_response(
            resp1.to_urlencoded(), client.client_info, "urlencoded")

        # based on state find the code and then get an access token
        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state="AAAA")
        client.service['accesstoken'].parse_response(
            resp2.to_urlencoded(), client.client_info, "urlencoded")

        # and finally use the access token, bound to a state, to
        # construct the authorization header
        http_args = BearerHeader().construct(
            ResourceRequest(), cli_info=client.client_info, state="AAAA")
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):
    def test_construct_with_request_args(self, client):
        request_args = {"access_token": "Sesame"}
        cis = ResourceRequest()
        http_args = BearerBody().construct(
            cis, cli_info=client.client_info, request_args=request_args)

        assert cis["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self, client):
        _sdb = client.client_info.state_db
        _sdb['FFFFF'] = {}
        resp = AuthorizationResponse(code="code", state="FFFFF")
        _sdb.add_response(resp)
        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example",
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value",
                                  scope=["inner", "outer"])
        _sdb.add_response(atr, state='FFFFF')

        cis = ResourceRequest()
        http_args = BearerBody().construct(
            cis, cli_info=client.client_info, request_args={}, state="FFFFF",
            scope="inner")
        assert cis["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self, client):
        client.client_info.state_db['EEEE'] = {}
        resp1 = AuthorizationResponse(code="auth_grant", state="EEEE")
        client.service['authorization'].parse_response(
            resp1.to_urlencoded(), client.client_info, "urlencoded")
        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state="EEEE")
        client.service['accesstoken'].parse_response(
            resp2.to_urlencoded(), client.client_info, "urlencoded")

        cis = ResourceRequest()
        BearerBody().construct(cis, cli_info=client.client_info, state="EEEE")

        assert "access_token" in cis
        assert cis["access_token"] == "token1"


class TestClientSecretPost(object):
    def test_construct(self, client):
        cis = client.service['accesstoken'].construct(
            cli_info=client.client_info, redirect_uri="http://example.com",
            state='ABCDE')
        csp = ClientSecretPost()
        http_args = csp.construct(cis, cli_info=client.client_info)

        assert cis["client_id"] == "A"
        assert cis["client_secret"] == "boarding pass"
        assert http_args is None

        cis = AccessTokenRequest(code="foo", redirect_uri="http://example.com")
        http_args = csp.construct(cis, cli_info=client.client_info,
                                  request_args={},
                                  http_args={"client_secret": "another"})
        assert cis["client_id"] == "A"
        assert cis["client_secret"] == "another"
        assert http_args == {}


class TestPrivateKeyJWT(object):
    def test_construct(self, client):
        _key = rsa_load(
            os.path.join(BASE_PATH, "data/keys/rsa.key"))
        kc_rsa = KeyBundle([{"key": _key, "kty": "RSA", "use": "ver"},
                            {"key": _key, "kty": "RSA", "use": "sig"}])
        client.client_info.keyjar[""] = kc_rsa
        client.client_info.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}
        client.service['accesstoken'].endpoint = "https://example.com/token"

        cis = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        http_args = pkj.construct(cis, cli_info=client.client_info,
                                  algorithm="RS256",
                                  authn_endpoint='token')
        assert http_args == {}
        cas = cis["client_assertion"]

        pub_kb = KeyBundle(
            [{"key": _key.public_key(), "kty": "RSA", "use": "ver"},
             {"key": _key.public_key(), "kty": "RSA", "use": "sig"}])

        jso = JWT(rec_keys={client.client_id: pub_kb.get('RSA')}).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        #assert _jwt.headers == {'alg': 'RS256'}
        assert jso['aud'] == [
            client.client_info.provider_info['token_endpoint']]

    def test_construct_client_assertion(self, client):
        _key = rsa_load(os.path.join(BASE_PATH, "data/keys/rsa.key"))
        kc_rsa = KeyBundle([{"key": _key, "kty": "RSA", "use": "ver"},
                            {"key": _key, "kty": "RSA", "use": "sig"}])

        cis = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        _ca = assertion_jwt(client.client_id, kc_rsa.get('RSA'),
                            "https://example.com/token", 'RS256')
        http_args = pkj.construct(cis, client_assertion=_ca)
        assert http_args == {}
        assert cis['client_assertion'] == _ca
        assert cis['client_assertion_type'] == JWT_BEARER


class TestClientSecretJWT_TE(object):
    def test_client_secret_jwt(self, client):
        _ci = client.client_info
        _ci.token_endpoint = "https://example.com/token"
        _ci.provider_info = {'issuer': 'https://example.com/',
                             'token_endpoint': "https://example.com/token"}

        csj = ClientSecretJWT()
        cis = AccessTokenRequest()

        csj.construct(cis, cli_info=client.client_info, algorithm="HS256",
                      authn_endpoint='token')
        assert cis["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in cis
        cas = cis["client_assertion"]

        _skey =  [SYMKey(k=b64e(as_bytes(_ci.client_secret)), use='sig')]
        jso = JWT(rec_keys={client.client_id: _skey}).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "exp", "iat", 'jti'])

        _rj = JWS()
        info = _rj.verify_compact(cas, _skey)

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [_ci.provider_info['token_endpoint']]


class TestClientSecretJWT_UI(object):
    def test_client_secret_jwt(self, client):
        _ci = client.client_info
        _ci.token_endpoint = "https://example.com/token"
        _ci.provider_info = {'issuer': 'https://example.com/',
                             'token_endpoint': "https://example.com/token"}

        csj = ClientSecretJWT()
        cis = AccessTokenRequest()

        csj.construct(cis, cli_info=client.client_info, algorithm="HS256",
                      authn_endpoint='userinfo')
        assert cis["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in cis
        cas = cis["client_assertion"]

        _skey =  [SYMKey(k=b64e(as_bytes(_ci.client_secret)), use='sig')]
        jso = JWT(rec_keys={client.client_id: _skey}).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])

        _rj = JWS()
        info = _rj.verify_compact(cas,
                                  [SYMKey(k=b64e(as_bytes(_ci.client_secret)))])

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [_ci.provider_info['issuer']]


class TestValidClientInfo(object):
    def test_valid_client_info(self):
        _now = 123456  # At some time
        # Expiration time missing or 0, client_secret never expires
        assert valid_client_info({}, _now)
        assert valid_client_info(
            {'client_id': 'test', 'client_secret': 'secret'}, _now)
        assert valid_client_info({'client_secret_expires_at': 0}, _now)
        # Expired secret
        assert valid_client_info({'client_secret_expires_at': 1},
                                 _now) is not True
        assert valid_client_info(
            {'client_id': 'test', 'client_secret_expires_at': 123455},
            _now) is not True
        # Valid secret
        assert valid_client_info({'client_secret_expires_at': 123460}, _now)
        assert valid_client_info(
            {'client_id': 'test', 'client_secret_expires_at': 123460}, _now)
