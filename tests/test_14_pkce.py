from oidcmsg.message import Message
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oidc import AuthorizationResponse
from oidcservice.state_interface import State

from oidcservice.oidc.service import factory
from oidcservice.service import Service
from oidcservice.service_context import ServiceContext
from oidcservice.oidc.pkce import add_code_challenge
from oidcservice.oidc.pkce import add_code_verifier
from oidcservice.oidc.pkce import put_state_in_post_args
from oidcservice.state_interface import InMemoryStateDataBase


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
    }


class DummyService(Service):
    msg_type = DummyMessage


def test_add_code_challenge_default_values():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'longer_client_secret',
        'base_url': 'https://example.com',
        'requests_dir': 'requests',
    }
    service_context = ServiceContext(client_id='client_id',
                                     issuer='https://www.example.org/as',
                                     config=config)
    service = DummyService(service_context, state_db=InMemoryStateDataBase())
    _state = State(iss='Issuer')
    service.state_db.set('state', _state.to_json())
    spec = add_code_challenge({'state': 'state'}, service)

    # default values are length:64 method:S256
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method',
                                'state'}
    assert spec['code_challenge_method'] == 'S256'

    request_args = add_code_verifier({}, service, state='state')
    assert len(request_args['code_verifier']) == 64


def test_add_code_challenge_spec_values():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'longer_client_secret',
        'base_url': 'https://example.com',
        'requests_dir': 'requests',
        'code_challenge': {'length': 128, 'method': 'S384'}
    }
    service_context = ServiceContext(config=config)

    service = DummyService(service_context, state_db=InMemoryStateDataBase())
    _state = State(iss='Issuer')
    service.state_db.set('state', _state.to_json())

    spec = add_code_challenge({'state': 'state'}, service)
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method',
                                'state'}
    assert spec['code_challenge_method'] == 'S384'

    request_args = add_code_verifier({}, service, state='state')
    assert len(request_args['code_verifier']) == 128


def test_authorization_and_pkce():
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'password example one',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'behaviour': {'response_types': ['code']}
    }
    service_context = ServiceContext(config=client_config)
    service = factory('Authorization', state_db=InMemoryStateDataBase(),
                      service_context=service_context)
    service.post_construct.append(add_code_challenge)
    request = service.construct_request()
    assert set(request.keys()) == {'client_id', 'code_challenge',
                                   'code_challenge_method', 'state', 'nonce',
                                   'redirect_uri', 'response_type', 'scope'}


def test_access_token_and_pkce():
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'password example one',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'behaviour': {'response_types': ['code']}
    }
    service_context = ServiceContext(config=client_config)
    db = InMemoryStateDataBase()
    # Construct an authorization request.
    # Gives us a state value and stores code_verifier in state_db
    authz_service = factory('Authorization', state_db=db,
                            service_context=service_context)
    authz_service.post_construct.append(add_code_challenge)
    request = authz_service.construct_request()
    _state = request['state']

    auth_response = AuthorizationResponse(code='access code')
    authz_service.store_item(auth_response, 'auth_response', _state)
    service = factory('AccessToken', state_db=db,
                      service_context=service_context)

    # If I don't have this then state is not carried over to post_construct
    service.pre_construct.append(put_state_in_post_args)
    service.post_construct.append(add_code_verifier)

    request = service.construct_request(state=_state)
    assert set(request.keys()) == {'client_id', 'redirect_uri', 'grant_type',
                                   'client_secret', 'code_verifier', 'code',
                                   'state'}
