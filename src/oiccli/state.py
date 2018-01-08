import shelve

from oiccli.exception import ParameterError
from oicmsg.jwt import JWT
from oicmsg.message import Message
from oicmsg.message import SINGLE_OPTIONAL_STRING
from oicmsg.message import SINGLE_REQUIRED_STRING
from oicmsg.oauth2 import AuthorizationResponse
from oicmsg.oic import JsonWebToken
from oicmsg.time_util import utc_time_sans_frac

from oiccli import rndstr


# draft-bradley-oauth-jwt-encoded-state-05


class StateJwt(JsonWebToken):
    c_param = JsonWebToken.c_param.copy()
    c_param.update({
        "rfp": SINGLE_REQUIRED_STRING,
        'kid': SINGLE_OPTIONAL_STRING,
        'target_link_uri': SINGLE_OPTIONAL_STRING,
        'as': SINGLE_OPTIONAL_STRING,
        'at_hash': SINGLE_OPTIONAL_STRING,
        'c_hash': SINGLE_OPTIONAL_STRING
    })


class UnknownNode(KeyError):
    pass


class UnknownState(KeyError):
    pass


class ExpiredToken(KeyError):
    pass


class State(object):
    """
    Given state I need to be able to find valid access token and id_token
    and to whom it was sent.
    """

    def __init__(self, client_id, db=None, db_name='', lifetime=600):
        self.client_id = client_id
        self._db = db
        # self._db_name = db_name
        if self._db is None:
            if db_name:
                self._db = shelve.open(db_name, writeback=True)
            else:
                self._db = {}
        self.lifetime = lifetime

    def create_state(self, receiver, request):
        _state = rndstr(24)
        _now = utc_time_sans_frac()
        _info = {'client_id': self.client_id, 'as': receiver, 'iat': _now}
        if isinstance(request, Message):
            _info.update(request.to_dict())
        else:
            _info.update(request)
        self._db['state_{}'.format(_state)] = _info
        return _state

    def _update_token_info(self, info, msg):
        try:
            _tinfo = info['token']
        except KeyError:
            _tinfo = {}

        try:
            _token = msg['access_token']
        except KeyError:
            pass
        else:
            _tinfo['access_token'] = _token
            try:
                _exp = int(msg['expires_in'])
            except KeyError:
                try:
                    _tinfo['exp'] = utc_time_sans_frac() + _tinfo['expires_in']
                except KeyError:
                    pass
            else:
                _tinfo['exp'] = utc_time_sans_frac() + _exp
                _tinfo['expires_in'] = _exp

            for claim in ['token_type', 'scope']:
                try:
                    _tinfo[claim] = msg[claim]
                except KeyError:
                    pass

        info['token'] = _tinfo
        return info

    def add_message_info(self, msg, state=''):
        if not state:
            state = msg['state']

        _info = self[state]
        if isinstance(msg, AuthorizationResponse):
            try:
                _info['code'] = msg['code']
            except KeyError:
                pass

        self._update_token_info(_info, msg)
        for claim in ['id_token', 'refresh_token']:
            try:
                _info[claim] = msg[claim]
            except KeyError:
                pass

        self[state] = _info
        return _info

    def add_info(self, state, **kwargs):
        try:
            _info = self[state]
        except KeyError:
            _info = self[state] = kwargs
        else:
            _info.update(kwargs)
            self[state] = _info
        return _info

    def __getitem__(self, state):
        return self._db['state_{}'.format(state)]

    def __setitem__(self, state, value):
        self._db['state_{}'.format(state)] = value

    def bind_nonce_to_state(self, nonce, state):
        self._db['nonce_{}'.format(nonce)] = state

    def nonce_to_state(self, nonce):
        return self._db['nonce_{}'.format(nonce)]

    def get_token_info(self, state, now=0, **kwargs):
        _tinfo = self[state]['token']
        try:
            _exp = _tinfo['exp']
        except KeyError:
            pass
        else:
            if not now:
                now = utc_time_sans_frac()
            if now > _exp:
                raise ExpiredToken('Passed best before')
        return _tinfo

    def get_request_args(self, state, request, now=0, **kwargs):
        """

        :param state:
        :param request:
        :param now:
        :return:
        """
        _sinfo = self[state]

        req_args = {}
        for claim in request.c_param:
            if claim == 'access_token':
                try:
                    tinfo = self.get_token_info(state, now=now)
                except KeyError:
                    continue
                else:
                    req_args[claim] = tinfo['access_token']
            else:
                try:
                    req_args[claim] = _sinfo[claim]
                except KeyError:
                    pass

        return req_args

    def get_id_token(self, state):
        return self[state]['id_token']


# class StateLess(State):
#     def __init__(self, issuer, db=None, db_name='', lifetime=600, keyjar=None):
#         State.__init__(self, issuer, db=db, db_name=db_name, lifetime=lifetime)
#         self.keyjar = keyjar
#         self.jwt = JWT(keyjar, issuer, lifetime=3600, sign_alg='RS256',
#                        encrypt=True, enc_enc="A128GCM", enc_alg="ECDH-ES")
#         self.active = []
#
#     def create_state(self, receiver, request):
#         _req_args = {'as': receiver}
#         if isinstance(request, Message):
#             _req_args.update(request.to_dict())
#         else:
#             _req_args.update(request)
#         return self.jwt.pack(payload=_req_args)
#
#     def __getitem__(self, token):
#         return self.jwt.unpack(token)
