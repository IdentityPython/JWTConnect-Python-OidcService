.. _oidcservice_statedb:

*******************
The state data base
*******************

All services are running in a context. A set of services that runs in a
sequence defines a session. Each such session must be able to keep information
on what has happened in order to be able to know what the next step should be.
So each service instance must be able to access a data storage.
This data storage is in our model provided by the RP
implementation. What is defined here is the interface to that data storage.


-----------
Data format
-----------

The data store is of the key-value format where the keys are strings
and the values are JSON documents (http://json.org).
We reuse our knowledge on how to construct messages and serialise/deserialise
them that we have from oidcmsg.

The basic message is defined by::

    from oidcmsg.message import Message
    from oidcmsg.message import SINGLE_OPTIONAL_JSON
    from oidcmsg.message import SINGLE_REQUIRED_STRING


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

Additional attributes and values may be added to this base class by service
extensions.

-------
Methods
-------

We defined two methods; *set* and get* to be used like this::

    $ from oidcservice.service import State
    $ _state = State(iss='issuer_id')
    $ state_db.set('abcdef', _state.to_json())

and then sometime later::

    $ _json = state_db.get('abcdef')
    $ _state = State().from_json(_json)
    $ print(_state['iss'])
    'issuer_id'


If a get is done with a key that does not exist in the data base, a None value
will be returned.

If something stored in the database must be modified it has to be read from
the database, modified locally and then written back to the database.

Anything in the database will be silently overwritten by a new *set* command.