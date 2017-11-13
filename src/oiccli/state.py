import shelve

from oicmsg.jwt import JWT
from oicmsg.time_util import utc_time_sans_frac

from oiccli import rndstr


class State(object):
    """
    Given state I need to be able to find valid access token and id_token
    and to whom it was sent.
    """
    def __init__(self, db=None, db_name='', lifetime=600):
        self.db = db
        self.db_name = db_name
        if self.db is None:
            self.db = shelve.open(db_name, writeback=True)
        self.lifetime = lifetime

    def create_state(self, issuer, receiver, request):
        _state = rndstr(24)
        _now = utc_time_sans_frac()
        _info = {'iss': issuer, 'receiver': receiver, 'iat': _now}
        if self.lifetime:
            _info['exp'] = _now + self.lifetime
        _info.update(request.to_dict())
        self.db[_state] = _info
        return _state

    def add_info(self, state, **kwargs):
        _info = self.db[state]
        _info.update(kwargs)
        self.db[state] = _info
        return _info

    def get_info(self, state):
        return self.db[state]


class StateLess(State):
    def __init__(self, iss, keyjar=None):
        self.keyjar = keyjar
        self.jwt = JWT(keyjar, iss, lifetime=3600, sign_alg='RS256',
                       encrypt=True, enc_enc="A128GCM", enc_alg="ECDH-ES")

    def create_state(self, issuer):
        self.jwt.pack()
