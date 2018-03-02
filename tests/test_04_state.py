import pytest
from oidccli.state import State, ExpiredToken
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.time_util import utc_time_sans_frac

ATR = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                          token_type="example",
                          refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                          example_parameter="example_value",
                          scope=["inner", "outer"])
REQ_ARGS = {'redirect_uri': 'https://example.com/rp/cb',
            'response_type': "code"}


class TestState(object):
    @pytest.fixture(autouse=True)
    def create_state_db(self):
        self.state_db = State('client_id', db_name='state')

    def test_create_state(self):
        request = AuthorizationRequest(**REQ_ARGS)
        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)
        assert state
        for key, val in REQ_ARGS.items():
            assert self.state_db[state][key] == val

    def test_add_mesg_code(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)

        aresp = AuthorizationResponse(code="access grant", state=state)

        self.state_db.add_response(aresp)

        assert self.state_db[state]['code'] == 'access grant'

    def test_read_state(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)

        _info = self.state_db[state]
        assert _info['client_id'] == 'client_id'
        assert _info['as'] == 'https://example.org/op'
        assert _info['redirect_uri'] == 'https://example.com/rp/cb'
        assert _info['response_type'] == 'code'
        assert 'iat' in _info

    def test_add_mesg_code_token(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)

        aresp = AuthorizationResponse(
            code="access grant", state=state, access_token='access token',
            token_type='Bearer')

        self.state_db.add_response(aresp)

        assert self.state_db[state]['code'] == 'access grant'
        assert self.state_db[state]['token'] == {'access_token': 'access token',
                                                 'token_type': 'Bearer'}

    def test_add_mesg_code_id_token_token(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)

        aresp = AuthorizationResponse(
            code="access grant", state=state, access_token='access token',
            token_type='Bearer', id_token='Dummy.JWT.foo')

        self.state_db.add_response(aresp)

        assert self.state_db[state]['code'] == 'access grant'
        assert self.state_db[state]['token'] == {'access_token': 'access token',
                                                 'token_type': 'Bearer'}
        assert self.state_db[state]['id_token'] == 'Dummy.JWT.foo'

    def test_add_mesg_id_token_token_authz(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)

        aresp = AuthorizationResponse(
            state=state, access_token='access token',
            token_type='Bearer', id_token='Dummy.JWT.foo')

        self.state_db.add_response(aresp)

        assert self.state_db[state]['token'] == {'access_token': 'access token',
                                                 'token_type': 'Bearer'}
        assert self.state_db[state]['id_token'] == 'Dummy.JWT.foo'

    def test_add_mesg_id_token_token(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)
        aresp = AuthorizationResponse(state=state, code="access grant")

        self.state_db.add_response(aresp)

        aresp = AccessTokenResponse(access_token='access token',
                                    token_type='Bearer',
                                    id_token='Dummy.JWT.foo',
                                    expires_in=600)
        _now = utc_time_sans_frac()

        self.state_db.add_response(aresp, state=state)

        assert set(self.state_db[state]['token'].keys()) == {'access_token',
                                                             'token_type',
                                                             'exp',
                                                             'expires_in'}
        assert self.state_db[state]['id_token'] == 'Dummy.JWT.foo'
        assert _now <= self.state_db[state]['token']['exp']

    def test_get_valid_token(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)
        aresp = AuthorizationResponse(state=state, code="access grant")

        self.state_db.add_response(aresp)

        aresp = AccessTokenResponse(access_token='access token',
                                    token_type='Bearer',
                                    id_token='Dummy.JWT.foo',
                                    expires_in=600)
        self.state_db.add_response(aresp, state=state)

        ti = self.state_db.get_token_info(state)

    def test_get_expired_token(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)
        aresp = AuthorizationResponse(state=state, code="access grant")

        self.state_db.add_response(aresp)

        aresp = AccessTokenResponse(access_token='access token',
                                    token_type='Bearer',
                                    id_token='Dummy.JWT.foo',
                                    expires_in=600)
        self.state_db.add_response(aresp, state=state)

        _now = utc_time_sans_frac() + 900

        with pytest.raises(ExpiredToken):
            self.state_db.get_token_info(state, _now)

    def test_update_token(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)
        aresp = AuthorizationResponse(state=state, code="access grant")

        self.state_db.add_response(aresp)

        aresp1 = AccessTokenResponse(access_token='access token',
                                     token_type='Bearer',
                                     id_token='Dummy.JWT.foo',
                                     expires_in=600)

        self.state_db.add_response(aresp1, state=state)

        aresp1 = AccessTokenResponse(access_token='2nd access token',
                                     token_type='Bearer',
                                     expires_in=120)

        self.state_db.add_response(aresp1, state=state)

        _tinfo = self.state_db.get_token_info(state)

        assert _tinfo['access_token'] == '2nd access token'

        _now = utc_time_sans_frac() + 200

        with pytest.raises(ExpiredToken):
            self.state_db.get_token_info(state, _now)

    def test_get_access_token_response_args(self):
        request = AuthorizationRequest(**REQ_ARGS)

        state = self.state_db.create_state(receiver='https://example.org/op',
                                           request=request)
        aresp = AuthorizationResponse(state=state, code="access grant")

        self.state_db.add_response(aresp)

        resp_args = self.state_db.get_response_args(state, AccessTokenRequest)

        assert set(resp_args.keys()) == {'code', 'client_id', 'redirect_uri'}