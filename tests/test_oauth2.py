import os
import pytest
import time

import sys
from jwkest.jwk import rsa_load
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.grant import Grant, Token
from oiccli.oauth2 import Client, DEF_SIGN_ALG
from oicmsg.key_bundle import KeyBundle
from oicmsg.oauth2 import Message, AuthorizationRequest, AccessTokenRequest, \
    RefreshAccessTokenRequest, AccessTokenResponse, ResourceRequest
from oicmsg.oic import IdToken
from oicmsg.time_util import utc_time_sans_frac

sys.path.insert(0, '.')
from MockOP import MockOP

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oic.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


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

    def test_construct_Message(self):
        msg = self.client.construct_Message(request_args={'foo': 'bar'})
        assert isinstance(msg, Message)
        assert list(msg.keys()) == ['foo']
        assert msg['foo'] == 'bar'

    def test_construct_AuthorizationRequest(self):
        req_args = {'state': 'ABCDE'}
        msg = self.client.construct_AuthorizationRequest(request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg['client_id'] == 'client_1'
        assert msg['redirect_uri'] == 'http://example.com/redirect'

    def test_construct_AccessTokenRequest(self):
        # Bind access code to state
        self.client.grant['ABCDE'] = Grant(resp={'code': 'CODE'})

        req_args = {}
        msg = self.client.construct_AccessTokenRequest(request_args=req_args,
                                                       state='ABCDE')
        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'client_secret': 'abcdefghijklmnop',
                                 'code': 'CODE',
                                 'grant_type': 'authorization_code',
                                 'redirect_uri': 'http://example.com/redirect',
                                 'state': 'ABCDE'}

    def test_construct_RefreshAccessTokenRequest(self):
        # Bind access code to state
        self.client.grant['ABCDE'] = Grant(resp={'code': 'CODE'})

        # Bind token to state
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access")
        self.client.grant["ABCDE"].tokens.append(Token(resp))

        req_args = {}
        msg = self.client.construct_RefreshAccessTokenRequest(
            request_args=req_args, state='ABCDE')
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'refresh_token',
                                 'refresh_token': 'refresh_with_me'}

    def test_construct_ResourceRequest(self):
        # Bind access code to state
        self.client.grant['ABCDE'] = Grant(resp={'code': 'CODE'})

        # Bind token to state
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access")
        self.client.grant["ABCDE"].tokens.append(Token(resp))

        req_args = {}
        msg = self.client.construct_ResourceRequest(
            request_args=req_args, state='ABCDE')
        assert isinstance(msg, ResourceRequest)
        assert msg.to_dict() == {'access_token': 'access'}

    def test_request_info_authorization_request(self):
        req_args = {'state': 'ABCDE', 'response_type':'code'}
        _info = self.client.request_info(
            AuthorizationRequest, 'GET', request_args=req_args)

        assert _info['uri']
        base, req = _info['uri'].split('?')
        ar = AuthorizationRequest().from_urlencoded(req)
        assert base == 'http://example.com/authorization'
        assert _info['body'] is None
        assert _info['h_args'] == {}
        assert isinstance(_info['cis'], AuthorizationRequest)
        assert ar == _info['cis']

    def test_do_authorization_request_init(self):
        req_args={'response_type': ['code']}
        _info = self.client.do_authorization_request_init(state='ABCDE',
                                                          request_args=req_args)
        assert _info
        assert _info['algs'] == {}
        assert _info['body'] == None
        assert _info['http_args'] == {}
        assert _info['uri']
        base, req = _info['uri'].split('?')
        ar = AuthorizationRequest().from_urlencoded(req)
        assert isinstance(_info['cis'], AuthorizationRequest)
        assert ar == _info['cis']
