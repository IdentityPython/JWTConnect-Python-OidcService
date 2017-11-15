import json
import os
import pytest
import time

import sys

from jwkest import as_unicode
from jwkest.jwk import rsa_load
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.exception import SubMismatch
from oiccli.http_util import Response, SeeOther, BadRequest
from oicmsg.key_bundle import KeyBundle
from oicmsg.oauth2 import AccessTokenRequest, ErrorResponse
from oicmsg.oauth2 import AccessTokenResponse
from oicmsg.oauth2 import AuthorizationRequest
from oiccli.oauth2 import authz_error, exception_to_error_mesg
from oiccli.oauth2 import Client
from oiccli.oauth2 import error
from oiccli.oauth2 import error_response
from oiccli.oauth2 import redirect_authz_error
from oicmsg.oauth2 import RefreshAccessTokenRequest
from oicmsg.oic import IdToken
from oicmsg.time_util import utc_time_sans_frac

sys.path.insert(0, '.')

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oic.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


def test_error_response():
    resp = error_response('invalid_request')
    assert isinstance(resp, Response, )

    def start_response(status, headers):
        assert status == "400 Bad Request"
        assert headers == [('Content-type', 'application/json')]

    assert resp({}, start_response) == [
        '{"error": "invalid_request"}'.encode('utf8')]


def test_error():
    resp = error('invalid_grant', 'Grant has expired')
    assert isinstance(resp, Response, )

    def start_response(status, headers):
        assert status == "400 Bad Request"
        assert headers == [('Content-type', 'application/json')]

    _res = json.loads(as_unicode(resp({}, start_response)[0]))
    assert set(_res.keys()) == {'error', 'error_description'}


def test_authz_error():
    resp = authz_error('unauthorized_client', 'Not in my family')
    assert isinstance(resp, Response, )

    def start_response(status, headers):
        assert status == "400 Bad Request"
        assert headers == [('Content-type', 'application/json')]

    _res = json.loads(as_unicode(resp({}, start_response)[0]))
    assert set(_res.keys()) == {'error', 'error_description'}
    assert _res['error'] == 'unauthorized_client'


def test_redirect_authz_error():
    resp = redirect_authz_error('unauthorized_client', 'https://example.com/cb',
                                state='ABCDEF')
    assert isinstance(resp, SeeOther)
    assert resp.status == '303 See Other'
    assert resp.headers == [('Content-type', 'text/html')]
    _url, _qp = resp.message.split('?')
    assert _url == 'https://example.com/cb'
    _msg = ErrorResponse().from_urlencoded(_qp)
    assert _msg['state'] == 'ABCDEF'
    assert _msg['error'] == 'unauthorized_client'


def test_exception_to_error_mesg():
    resp = exception_to_error_mesg(SubMismatch('Not the same'))
    assert isinstance(resp, BadRequest)
    _msg = ErrorResponse().from_json(resp.message)
    assert _msg.to_dict() == {"error_description": "SubMismatch: Not the same",
                              "error": "service_error"}
    assert resp.headers == [('Content-type', 'application/json')]


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"
        conf = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop'
        }
        self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                             config=conf)

    def test_construct_authorization_request(self):
        req_args = {'state': 'ABCDE',
                    'redirect_uri': 'https://example.com/auth_cb',
                    'response_type': ['code']}
        msg = self.client.service['authorization'].construct(
            self.client.client_info, request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg['client_id'] == 'client_1'
        assert msg['redirect_uri'] == 'https://example.com/auth_cb'

    def test_construct_accesstoken_request(self):
        # Bind access code to state
        req_args = {}
        self.client.client_info.state_db['ABCDE'] = {'code': 'access_code'}
        msg = self.client.service['accesstoken'].construct(
            self.client.client_info, request_args=req_args, state='ABCDE')
        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'code': 'access_code',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'authorization_code'}

    def test_construct_refresh_token_request(self):
        # Bind access code to state
        self.client.client_info.state_db['ABCDE'] = {'code': 'access_code'}
        # Bind token to state
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access")
        self.client.client_info.state_db.add_message_info(resp, "ABCDE")

        req_args = {}
        msg = self.client.service['refresh_token'].construct(
            self.client.client_info, request_args=req_args, state='ABCDE')
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'refresh_token',
                                 'refresh_token': 'refresh_with_me'}
