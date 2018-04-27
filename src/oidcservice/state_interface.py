from oidcmsg.message import Message
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_REQUIRED_STRING

from oidcservice import rndstr


class State(Message):
    c_param = {
        'iss': SINGLE_REQUIRED_STRING,
        'auth_request': SINGLE_OPTIONAL_JSON,
        'auth_response': SINGLE_OPTIONAL_JSON,
        'token_response': SINGLE_OPTIONAL_JSON,
        'refresh_token_request': SINGLE_OPTIONAL_JSON,
        'refresh_token_response': SINGLE_OPTIONAL_JSON,
        'user_info': SINGLE_OPTIONAL_JSON
    }


class StateInterface(object):
    def __init__(self, state_db):
        self.state_db = state_db

    def get_state(self, key):
        """
        Get the state connected to a given key.

        :param key: Key into the state database
        :return: A :py:class:´oidcservice.state_interface.State` instance
        """
        _data = self.state_db.get(key)
        if not _data:
            raise KeyError(key)
        else:
            return State().from_json(_data)

    def store_item(self, item, item_type, key):
        """
        Store a service response.

        :param item: The item as a :py:class:`oidcmsg.message.Message`
            subclass instance or a JSON document.
        :param item_type: The type of request or response
        :param key: The key under which the information should be stored in
            the state database
        """
        try:
            _state = self.get_state(key)
        except KeyError:
            _state = State()

        try:
            _state[item_type] = item.to_json()
        except AttributeError:
            _state[item_type] = item

        self.state_db.set(key, _state.to_json())

    def get_iss(self, key):
        """
        Get the Issuer ID

        :param key: Key to the information in the state database
        :return: The issuer ID
        """
        _state = self.get_state(key)
        if not _state:
            raise KeyError(key)
        return _state['iss']

    def get_item(self, item_cls, item_type, key):
        """
        Get a piece of information (a request or a response) from the state
        database.

        :param item_cls: The :py:class:`oidcmsg.message.Message` subclass
            that described the item.
        :param item_type: Which request/response that is wanted
        :param key: The key to the information in the state database
        :return: A :py:class:`oidcmsg.message.Message` instance
        """
        _state = self.get_state(key)
        try:
            return item_cls(**_state[item_type])
        except TypeError:
            return item_cls().from_json(_state[item_type])

    def extend_request_args(self, args, item_cls, item_type, key,
                            parameters):
        """
        Add a set of parameters and their value to a set of request arguments.

        :param args: A dictionary
        :param item_cls: The :py:class:`oidcmsg.message.Message` subclass
            that describes the item
        :param item_type: The type of item, this is one of the parameter
            names in the :py:class:`oidcservice.state_interface.State` class.
        :param key: The key to the information in the database
        :param parameters: A list of parameters who's values this method
            will return.
        :return: A dictionary with keys from the list of parameters and
            values being the values of those parameters in the item.
            If the parameter does not a appear in the item it will not appear
            in the returned dictionary.
        """
        try:
            item = self.get_item(item_cls, item_type, key)
        except KeyError:
            pass
        else:
            for parameter in parameters:
                try:
                    args[parameter] = item[parameter]
                except KeyError:
                    pass

        return args

    def multiple_extend_request_args(self, args, key, parameters, item_types):
        """
        Go through a set of items (by their type) and add the attribute-value
        that match the list of parameters to the arguments
        If the same parameter occurs in 2 different items then the value in
        the later one will be the one used.

        :param args: Initial set of arguments
        :param key: Key to the State information in the state database
        :param parameters: A list of parameters that we're looking for
        :param item_types: A list of item_type specifying which items we
            are interested in.
        :return: A possibly augmented set of arguments.
        """
        _state = self.get_state(key)

        for typ in item_types:
            try:
                _item = Message(**_state[typ])
            except KeyError:
                continue

            for parameter in parameters:
                try:
                    args[parameter] = _item[parameter]
                except KeyError:
                    pass

        return args

    def store_nonce2state(self, nonce, state):
        """
        Store the connection between a nonce value and a state value.
        This allows us later in the game to find the state if we have the nonce.

        :param nonce: The nonce value
        :param state: The state value
        """
        self.state_db.set('__{}__'.format(nonce), state)

    def get_state_by_nonce(self, nonce):
        """
        Find the state value by providing the nonce value.
        Will raise an exception if the nonce value is absent from the state
        data base.

        :param nonce: The nonce value
        :return: The state value
        """
        _state = self.state_db.get('__{}__'.format(nonce))
        if _state:
            return _state
        else:
            raise KeyError('Unknown nonce: "{}"'.format(nonce))

    def create_state(self, iss):
        key = rndstr(32)
        _state = State(iss=iss)
        self.state_db.set(key, _state.to_json())
        return key
