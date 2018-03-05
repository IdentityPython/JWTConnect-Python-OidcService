import shelve

from oidcmsg.message import Message
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oidc import JsonWebToken
from oidcmsg.time_util import utc_time_sans_frac

from oidcservice import rndstr


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
    Given a state value I need to be able to find valid access token and
    id_token.
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

    def create_state(self, receiver, request, state=''):
        """
        Construct a state value. In this class it's just a random string.
        Also store information about the request using the state value
        as key.

        :param receiver: Who is the receiver of a request with this
            state value.
        :param request: The request
        :param state: state value that someone else has created
        :return: a random string
        """
        if state:
            _state = state
        else:
            _state = rndstr(24)

        _now = utc_time_sans_frac()

        # gather the information I want to store
        _state_info = {'client_id': self.client_id, 'as': receiver, 'iat': _now}

        # Add the request to the info
        if isinstance(request, Message):
            _state_info.update(request.to_dict())
        else:
            _state_info.update(request)

        # store the info
        self[_state] = _state_info
        return _state

    def update_token_info(self, state_info, response):
        """
        Add information about an access token to the state information

        :param state_info: The state information
        :param response: A response, typically a access token request response.
        :return: The updated state information
        """

        # Fetch the information I have about an access tokens right now.
        # The response I'm dealing with may be a refresh token response
        # in which case I already have information base on a previous response.
        try:
            _tinfo = state_info['token']
        except KeyError:
            _tinfo = {}

        # If the response doesn't contain an access token then there is
        # nothing to be done
        try:
            _token = response['access_token']
        except KeyError:
            pass
        else:
            _tinfo['access_token'] = _token

            # if there is an access token then look for other claims
            # that I need to store.

            # calculate when the token will expire based on present time
            # and how long it's valid.
            try:
                _exp = int(response['expires_in'])
            except KeyError:
                # If no new expires_in is given use an old one if available
                try:
                    _tinfo['exp'] = utc_time_sans_frac() + _tinfo['expires_in']
                except KeyError:
                    pass
            else:
                _tinfo['exp'] = utc_time_sans_frac() + _exp
                _tinfo['expires_in'] = _exp

            # extra info
            for claim in ['token_type', 'scope']:
                try:
                    _tinfo[claim] = response[claim]
                except KeyError:
                    pass

            state_info['token'] = _tinfo

        return state_info

    def add_response(self, response, state=''):
        """
        Add relevant information from a response to the state information

        :param response: The response
        :param state: State value
        :return: state information
        """
        if not state:
            state = response['state']

        try:
            _state_info = self[state]
        except KeyError:
            raise UnknownState(state)

        if isinstance(response, AuthorizationResponse):
            try:
                _state_info['code'] = response['code']
            except KeyError:
                pass

        # If there is information about an access token in the response
        # add that information too
        self.update_token_info(_state_info, response)

        for claim in ['id_token', 'refresh_token']:
            try:
                _state_info[claim] = response[claim]
            except KeyError:
                pass

        # Updated the state database
        self[state] = _state_info
        return _state_info

    def add_info(self, state, **kwargs):
        """
        Add unspecific state information

        :param state: State value
        :param kwargs: information to be added
        :return: The present state information
        """
        _state_info = self[state]
        _state_info.update(kwargs)

        self[state] = _state_info
        return _state_info

    def __getitem__(self, state):
        return self._db['state_{}'.format(state)]

    def __setitem__(self, state, value):
        self._db['state_{}'.format(state)] = value

    def bind_nonce_to_state(self, nonce, state):
        """
        Bind a nonce value to a state value such that I later given a nonce
        value I can find the state information

        :param nonce: Nonce value
        :param state: State value
        """
        self._db['nonce_{}'.format(nonce)] = state

    def nonce_to_state(self, nonce):
        """
        Given a nonce value return the state value.

        :param nonce: Nonce value
        :return: State value
        """
        return self._db['nonce_{}'.format(nonce)]

    def get_token_info(self, state, now=0):
        """
        Get information about a access token bound to a specific state value

        :param state: The state value
        :param now: A timestamp used to verify if the token is expired or not
        :return: Token information
        """
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

    def get_response_args(self, state, response_class, now=0, **kwargs):
        """
        Get the claims returned in a response connected to a specific state
        value.

        :param state: The state value
        :param response_class: The type of response that is bound to a state
        :param now: A time stamp
        :return: The response arguments
        """
        _state_info = self[state]

        resp_args = {}
        # only return the claims that are defined in the response class
        # doesn't matter if they are required or optional.
        for claim in response_class.c_param:
            if claim == 'access_token':
                try:
                    tinfo = self.get_token_info(state, now=now)
                except KeyError:
                    continue
                else:
                    resp_args[claim] = tinfo['access_token']
            else:
                try:
                    resp_args[claim] = _state_info[claim]
                except KeyError:
                    pass

        return resp_args

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
#         _resp_args = {'as': receiver}
#         if isinstance(request, Message):
#             _resp_args.update(request.to_dict())
#         else:
#             _resp_args.update(request)
#         return self.jwt.pack(payload=_resp_args)
#
#     def __getitem__(self, token):
#         return self.jwt.unpack(token)
