#!/usr/bin/env python
# from oic.oauth2 import KeyStore
from future.backports.urllib.parse import urlparse

import os
import time
from collections import Counter

import pytest
from jwkest.jws import alg2keytype
from jwkest.jwt import JWT

from requests import Response

from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.exception import OtherError
from oiccli.grant import Grant
from oiccli.grant import Token
from oicmsg.oic import AccessTokenRequest
from oicmsg.oic import AccessTokenResponse
from oicmsg.oic import AuthorizationRequest
from oicmsg.oic import AuthorizationResponse
from oicmsg.oic import Claims
from oicmsg.oic import ClaimsRequest
from oiccli.oic import Client
from oiccli.oic import DEF_SIGN_ALG
from oicmsg.oic import IdToken
from oicmsg.oic import OpenIDRequest
from oicmsg.oic import OpenIDSchema
from oicmsg.oic import SCOPE2CLAIMS
from oicmsg.oic import scope2claims
from oicmsg.key_bundle import KeyBundle
from oicmsg.key_jar import KeyJar
from oicmsg.key_bundle import rsa_load
from oicmsg.time_util import utc_time_sans_frac

__author__ = 'rohe0002'

KC_SYM_S = KeyBundle(
    {"kty": "oct", "key": "abcdefghijklmnop".encode("utf-8"), "use": "sig",
     "alg": "HS256"})

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))
_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

KEYJ = KeyJar()
KEYJ[""] = [KC_RSA, KC_SYM_S]
KEYJ["client_1"] = [KC_RSA, KC_SYM_S]

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oic.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


def _eq(l1, l2):
    return set(l1) == set(l2)


class HTTPResponse(object):
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class MockOP(object):
    def __init__(self, baseurl='http://example.com/'):
        self.baseurl = baseurl

    def __call__(self, url, method, **kwargs):
        if url.startswith(self.baseurl):
            path = url[len(self.baseurl):]
        else:
            path = url

        if '?' in path:
            what, req = path.split('?', 1)
            meth = getattr(self, what)
            return meth(req)
        else:
            meth = getattr(self, path)
            return meth(kwargs['data'])

    def discovery(self):
        pass

    def register(self, request):
        pass

    def authorization(self, request, **kwargs):
        areq = AuthorizationRequest().from_urlencoded(request)
        aresp = AuthorizationResponse()
        resp = HTTPResponse('OK')
        return resp

    def token(self, request, **kwargs):
        pass

    def userinfo(self, request, **kwargs):
        pass



# ----------------- CLIENT --------------------


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"
        self.client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD,
                             httplib=MockOP())
        self.client.redirect_uris = [self.redirect_uri]
        self.client.authorization_endpoint = "http://example.com/authorization"
        self.client.token_endpoint = "http://example.com/token"
        self.client.userinfo_endpoint = "http://example.com/userinfo"
        self.client.check_session_endpoint = "https://example.com/check_session"
        self.client.client_secret = "abcdefghijklmnop"
        self.client.keyjar[""] = KC_RSA
        self.client.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}

    def test_construct_authz_req_with_request_object(self, tmpdir):
        path = tmpdir.strpath
        request_uri_args = {
            "local_dir": path,
            "base_path": "http://example.com/"
        }
        areq = self.client.construct_AuthorizationRequest(request_method="file",
                                                          **request_uri_args)
        p = urlparse(areq["request_uri"])
        local_path = os.path.join(path, p.path.lstrip("/"))
        with open(local_path) as f:
            data = f.read()
        jwt = JWT().unpack(data)
        payload = jwt.payload()

        assert payload["redirect_uri"] == "http://example.com/redirect"
        assert payload["client_id"] == CLIENT_ID
        assert "nonce" in payload

        os.remove(local_path)

    def test_construct_authz_req_nonce_for_token(self):
        assert "nonce" in self.client.construct_AuthorizationRequest(
            response_type="token")
        assert "nonce" in self.client.construct_AuthorizationRequest(
            response_type="id_token")
        assert "nonce" in self.client.construct_AuthorizationRequest(
            response_type="token id_token")

    def test_do_authorization_request(self):
        args = {"response_type": ["code"], "scope": "openid"}
        result = self.client.do_authorization_request(state="state0",
                                                      request_args=args)
        assert result.status_code == 302
        _loc = result.headers["location"]
        assert _loc.startswith(self.client.redirect_uris[0])
        _, query = _loc.split("?")

        self.client.parse_response(AuthorizationResponse, info=query,
                                   sformat="urlencoded")

    def test_access_token_request(self):
        args = {"response_type": ["code"],
                "scope": ["openid"]}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)
        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")

        resp = self.client.do_access_token_request(scope="openid",
                                                   state="state0")
        assert isinstance(resp, AccessTokenResponse)
        assert _eq(resp.keys(),
                   ['token_type', 'state', 'access_token', 'scope'])

    def test_do_user_info_request(self):
        resp = AuthorizationResponse(code="code", state="state")
        grant = Grant(10)  # expired grant
        grant.add_code(resp)
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access",
                                   token_type="Bearer")
        token = Token(resp)
        grant.tokens.append(token)
        self.client.grant["state0"] = grant

        resp = self.client.do_user_info_request(state="state0")
        assert isinstance(resp, OpenIDSchema)
        assert _eq(resp.keys(),
                   ['name', 'email', 'verified', 'nickname', 'sub'])
        assert resp["name"] == "Melody Gardot"

    def test_do_access_token_refresh(self):
        args = {"response_type": ["code"],
                "scope": ["openid", "offline_access"],
                "prompt": ["consent"]}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)
        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")
        self.client.do_access_token_request(scope="openid offline_access",
                                            state="state0")

        resp = self.client.do_access_token_refresh(
            scope="openid offline_access",
            state="state0")
        assert isinstance(resp, AccessTokenResponse)
        assert _eq(resp.keys(), ['token_type', 'access_token', 'refresh_token',
                                 'scope', 'state'])

    def test_client_id(self):
        resp = AuthorizationResponse(code="code",
                                     state="stateX").to_urlencoded()
        self.client.parse_response(AuthorizationResponse, resp,
                                   sformat="urlencoded")
        args = {
            "code": "code",
            "redirect_uri": self.client.redirect_uris[0],
            "client_id": self.client.client_id,
        }

        url, query, ht_args, cis = self.client.request_info(
            AccessTokenRequest, method="POST", request_args=args,
            state='stateX', authn_method='client_secret_basic',
            grant_type='authorization_code')

        assert cis['client_id'] == self.client.client_id

        args = {
            "code": "code",
            "redirect_uri": self.client.redirect_uris[0],
            # "client_id": self.client.client_id,
        }

        url, query, ht_args, cis = self.client.request_info(
            AccessTokenRequest, method="POST", request_args=args,
            state='stateX', authn_method='client_secret_basic',
            grant_type='authorization_code')

        assert cis['client_id'] == self.client.client_id

    def test_do_check_session_request(self):
        # RSA signing
        alg = "RS256"
        ktyp = alg2keytype(alg)
        _sign_key = self.client.keyjar.get_signing_key(ktyp)
        args = {"id_token": IDTOKEN.to_jwt(key=_sign_key, algorithm=alg)}
        resp = self.client.do_check_session_request(request_args=args)

        assert isinstance(resp, IdToken)
        assert _eq(resp.keys(), ['nonce', 'sub', 'aud', 'iss', 'exp', 'iat'])

    def test_do_end_session_request(self):
        self.client.redirect_uris = ["https://www.example.com/authz"]
        self.client.client_id = "a1b2c3"
        self.client.end_session_endpoint = "https://example.org/end_session"

        # RSA signing
        alg = "RS256"
        ktyp = alg2keytype(alg)
        _sign_key = self.client.keyjar.get_signing_key(ktyp)
        args = {"id_token": IDTOKEN.to_jwt(key=_sign_key, algorithm=alg),
                "redirect_url": "http://example.com/end"}

        resp = self.client.do_end_session_request(request_args=args,
                                                  state="state1")

        assert resp.status_code == 302
        assert resp.headers["location"].startswith("http://example.com/end")

    def test_do_registration_request(self):
        self.client.registration_endpoint = "https://example.org/registration"

        args = {"operation": "register",
                "application_type": "web",
                "application_name": "my service",
                "redirect_uri": "http://example.com/authz"}
        resp = self.client.do_registration_request(request_args=args)
        assert _eq(resp.keys(), ['redirect_uris', u'redirect_uri',
                                 'application_type', 'registration_client_uri',
                                 'client_secret_expires_at',
                                 'registration_access_token', 'client_id',
                                 'application_name', 'client_secret',
                                 'response_types'])

    def test_do_user_info_request_with_access_token_refresh(self):
        args = {"response_type": ["code"],
                "scope": ["openid offline_access"],
                "prompt": "consent"}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)
        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")
        self.client.do_access_token_request(scope="openid offline_access",
                                            state="state0")

        token = self.client.get_token(state="state0",
                                      scope="openid offline_access")
        token.token_expiration_time = utc_time_sans_frac() - 86400

        resp = self.client.do_user_info_request(state="state0")
        assert isinstance(resp, OpenIDSchema)
        assert _eq(resp.keys(), ['name', 'email', 'verified', 'nickname',
                                 'sub'])
        assert resp["name"] == "Melody Gardot"

    def test_openid_request_with_claims_request(self):
        claims = {
            "name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "verified": {"essential": True},
            "picture": None
        }

        areq = self.client.construct_AuthorizationRequest(
            request_args={
                "scope": "openid",
                "response_type": ["code"],
                "claims": ClaimsRequest(userinfo=Claims(**claims),
                                        id_token=Claims(auth_time=None,
                                                        acr={"values": ["2"]})),
                "max_age": 86400,
            },
            request_param="request")

        assert "request" in areq

    def test_openid_request_with_id_token_claims_request(self):
        areq = self.client.construct_AuthorizationRequest(
            request_args={"scope": "openid",
                          "response_type": ["code"],
                          "claims": {
                              "id_token": {"sub": {"value": "248289761001"}}}},
            request_param="request"
        )

        jwtreq = OpenIDRequest().deserialize(areq["request"], "jwt",
                                             keyjar=self.client.keyjar)
        assert _eq(jwtreq.keys(), ['claims',
                                   'redirect_uri', 'response_type',
                                   'client_id', 'scope'])

    def test_construct_UserInfoRequest_with_req_args(self):
        uir = self.client.construct_UserInfoRequest(
            request_args={"access_token": "access_token"})
        assert uir["access_token"] == "access_token"

    def test_construct_UserInfoRequest_2_with_token(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access", id_token="IDTOKEN",
                                   scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))
        uir = self.client.construct_UserInfoRequest(state="foo",
                                                    scope=["openid"])
        assert uir["access_token"] == "access"

    def test_construct_CheckSessionRequest_with_req_args(self):
        csr = self.client.construct_CheckSessionRequest(
            request_args={"id_token": "id_token"})
        assert csr["id_token"] == "id_token"

    def test_construct_CheckSessionRequest_2(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(id_token="id_id_id_id",
                                   access_token="access", scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))

        csr = self.client.construct_CheckSessionRequest(state="foo",
                                                        scope=["openid"])
        assert csr["id_token"] == "id_id_id_id"

    def test_construct_RegistrationRequest(self):
        request_args = {
            "type": "client_associate",
            "client_id": CLIENT_ID,
            "contacts": ["foo@example.com"],
            "application_type": "web",
            "application_name": "EXAMPLE OIC service",
        }

        crr = self.client.construct_RegistrationRequest(
            request_args=request_args)
        assert _eq(crr.keys(), ['application_name', 'application_type', 'type',
                                'client_id', 'contacts', 'redirect_uris',
                                'response_types'])

    def test_construct_EndSessionRequest(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(id_token="id_id_id_id",
                                   access_token="access", scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))

        args = {"redirect_url": "http://example.com/end"}
        esr = self.client.construct_EndSessionRequest(state="foo",
                                                      request_args=args)
        assert _eq(esr.keys(), ['id_token', 'state', "redirect_url"])

    def test_construct_OpenIDRequest(self):
        self.client.scope = ["openid", "profile"]

        request_args = {"response_type": "code id_token",
                        "state": "af0ifjsldkj"}

        areq = self.client.construct_AuthorizationRequest(
            request_args=request_args)
        assert _eq(areq.keys(),
                   ['nonce', 'state', 'redirect_uri', 'response_type',
                    'client_id', 'scope'])

    def test_userinfo_request(self):
        aresp = AuthorizationResponse(code="code", state="state000")
        tresp = AccessTokenResponse(access_token="access_token",
                                    token_type="Bearer",
                                    expires_in=600, refresh_token="refresh",
                                    scope=["openid"])

        self.client.parse_response(AuthorizationResponse, aresp.to_urlencoded(),
                                   sformat="urlencoded", state="state0")
        self.client.parse_response(AccessTokenResponse, tresp.to_json(),
                                   state="state0")

        path, body, method, h_args = self.client.user_info_request(
            state="state0")
        assert path == "http://example.com/userinfo"
        assert method == "GET"
        assert body is None
        assert h_args == {'headers': {'Authorization': 'Bearer access_token'}}

    def test_userinfo_request_post(self):
        aresp = AuthorizationResponse(code="code", state="state000")
        tresp = AccessTokenResponse(access_token="access_token",
                                    token_type="bearer",
                                    expires_in=600, refresh_token="refresh",
                                    scope=["openid"])

        self.client.parse_response(AuthorizationResponse, aresp.to_urlencoded(),
                                   sformat="urlencoded", state="state0")
        self.client.parse_response(AccessTokenResponse, tresp.to_json(),
                                   state="state0")

        path, body, method, h_args = self.client.user_info_request(
            method="POST",
            state="state0")

        assert path == "http://example.com/userinfo"
        assert method == "POST"
        assert body == "access_token=access_token"
        assert h_args == {'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'}}

    def test_sign_enc_request(self):
        KC_RSA_ENC = KeyBundle({"key": _key, "kty": "RSA", "use": "enc"})
        self.client.keyjar["test_provider"] = [KC_RSA_ENC]

        request_args = {"redirect_uri": self.redirect_uri,
                        "client_id": self.client.client_id,
                        "scope": "openid",
                        "response_type": "code"}

        kwargs = {"request_object_signing_alg": "none",
                  "request_object_encryption_alg": "RSA1_5",
                  "request_object_encryption_enc": "A128CBC-HS256",
                  "request_method": "parameter",
                  "target": "test_provider"}

        areq = self.client.construct_AuthorizationRequest(
            request_args=request_args,
            **kwargs)

        assert areq["request"]

    def test_verify_id_token_reject_wrong_aud(self, monkeypatch):
        issuer = "https://provider.example.com"
        monkeypatch.setattr(self.client, "provider_info", {"issuer": issuer})
        id_token = IdToken(**dict(iss=issuer, aud=["nobody"]))

        with pytest.raises(OtherError) as exc:
            self.client._verify_id_token(id_token)
        assert "me" in str(exc.value)

    def test_verify_id_token_reject_wrong_azp(self, monkeypatch):
        issuer = "https://provider.example.com"
        monkeypatch.setattr(self.client, "provider_info", {"issuer": issuer})
        id_token = IdToken(
            **dict(iss=issuer,
                   aud=["nobody", "somebody", self.client.client_id],
                   azp="nobody"))

        with pytest.raises(OtherError) as exc:
            self.client._verify_id_token(id_token)
        assert "me" in str(exc.value)


class TestScope2Claims(object):
    def test_scope2claims(self):
        claims = scope2claims(['profile', 'email'])
        assert Counter(claims.keys()) == Counter(
            SCOPE2CLAIMS['profile'] + SCOPE2CLAIMS['email'])

    def test_scope2claims_with_non_standard_scope(self):
        claims = scope2claims(['my_scope', 'email'])
        assert Counter(claims.keys()) == Counter(SCOPE2CLAIMS['email'])


def test_request_attr_mis_match():
    redirect_uri = "http://example.com/redirect"
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)
    client.redirect_uris = [redirect_uri]
    client.authorization_endpoint = "http://example.com/authorization"
    client.client_secret = "abcdefghijklmnop"
    client.keyjar[""] = KC_RSA
    client.behaviour = {
        "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}

    areq = client.construct_AuthorizationRequest(
        request_args={
            "scope": "openid",
            "response_type": ["code"],
            "max_age": 86400,
            'state': 'foobar'
        },
        request_param="request")

    for attr in ['state', 'max_age', 'client_id']:
        del areq[attr]

    areq.lax = True
    req = AuthorizationRequest().from_urlencoded(areq.to_urlencoded())

    # with pytest.raises(MissingRequiredAttribute):
    assert req.verify(keyjar=KEYJ)


def test_request_1():
    areq = 'redirect_uri=https%3A%2F%2Fnode-openid-client.dev%2Fcb&request' \
           '=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0' \
           '.eyJzdGF0ZSI6ImZvb2JhciIsImlzcyI6Inp2bWk4UGdJbURiOSIsImF1ZCI6I' \
           'mh0dHBzOi8vcnAuY2VydGlmaWNhdGlvbi5vcGVuaWQubmV0OjgwODAvbm9kZS1' \
           'vcGVuaWQtY2xpZW50L3JwLXJlcXVlc3RfdXJpLXVuc2lnbmVkIiwiY2xpZW50X' \
           '2lkIjoienZtaThQZ0ltRGI5In0.&client_id=zvmi8PgImDb9&scope=openid' \
           '&response_type=code'

    req = AuthorizationRequest().from_urlencoded(areq)

    assert req.verify(keyjar=KEYJ)


def test_request_duplicate_state():
    areq = 'redirect_uri=https%3A%2F%2Fnode-openid-client.dev%2Fcb&state=barf' \
           '&request=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0' \
           '.eyJzdGF0ZSI6ImZvb2JhciIsImlzcyI6Inp2bWk4UGdJbURiOSIsImF1ZCI6Imh0dHBzOi8v' \
           'cnAuY2VydGlmaWNhdGlvbi5vcGVuaWQubmV0OjgwODAvbm9kZS1vcGVuaWQtY2xpZW50L3JwL' \
           'XJlcXVlc3RfdXJpLXVuc2lnbmVkIiwiY2xpZW50X2lkIjoienZtaThQZ0ltRGI5In0.&' \
           'client_id=zvmi8PgImDb9&scope=openid&response_type=code'

    req = AuthorizationRequest().from_urlencoded(areq)

    with pytest.raises(ValueError):
        assert req.verify(keyjar=KEYJ)


def test_do_userinfo_request_no_state_or_token():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    method = "GET"
    state = ""
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo'}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {}
    assert body is None
    assert method == 'GET'


def test_do_userinfo_request_token_no_state():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    method = "GET"
    state = ""
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo',
              "token": "abcdefgh"}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {'headers': {'Authorization': 'Bearer abcdefgh'}}
    assert method == 'GET'
    assert body is None


def test_do_userinfo_request_explicit_token_none():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    method = "GET"
    state = ""
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo',
              "token": None}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {}
    assert method == 'GET'
    assert body is None


def test_do_userinfo_request_with_state():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)
    client.grant['foxhound'] = Grant()
    resp = AccessTokenResponse(access_token="access", token_type="Bearer")
    _token = Token(resp)
    client.grant["foxhound"].tokens = [_token]

    method = "GET"
    state = "foxhound"
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo'}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {'headers': {'Authorization': 'Bearer access'}}
    assert method == 'GET'
    assert body is None


def token_callback(endp):
    return 'abcdef'


def fake_request(*args, **kwargs):
    r = Response()
    r.status_code = 200

    try:
        _token = kwargs['headers']['Authorization']
    except KeyError:
        r._content = b'{"shoe_size": 10}'
    else:
        _token = _token[7:]
        if _token == 'abcdef':
            r._content = b'{"shoe_size": 11}'
        else:
            r._content = b'{"shoe_size": 12}'

    r.headers = {'content-type': 'application/json'}
    return r


def test_fetch_distributed_claims_with_callback():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    client.http_request = fake_request
    userinfo = {
        'sub': 'foobar',
        '_claim_names': {'shoe_size': 'src1'},
        '_claim_sources': {
            "src1": {
                "endpoint": "https://bank.example.com/claim_source"}}
    }

    _ui = client.fetch_distributed_claims(userinfo, token_callback)

    assert _ui['shoe_size'] == 11
    assert _ui['sub'] == 'foobar'


def test_fetch_distributed_claims_with_no_callback():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    client.http_request = fake_request
    userinfo = {
        'sub': 'foobar',
        '_claim_names': {'shoe_size': 'src1'},
        '_claim_sources': {
            "src1": {
                "endpoint": "https://bank.example.com/claim_source"}}
    }

    _ui = client.fetch_distributed_claims(userinfo, callback=None)

    assert _ui['shoe_size'] == 10
    assert _ui['sub'] == 'foobar'


def test_fetch_distributed_claims_with_explicit_no_token():
    """ Mirrors the first lines in do_userinfo_request"""
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    client.http_request = fake_request
    userinfo = {
        'sub': 'foobar',
        '_claim_names': {'shoe_size': 'src1'},
        '_claim_sources': {
            "src1": {
                "access_token": None,
                "endpoint": "https://bank.example.com/claim_source"}}
    }

    _ui = client.fetch_distributed_claims(userinfo, callback=None)

    assert _ui['shoe_size'] == 10
    assert _ui['sub'] == 'foobar'
