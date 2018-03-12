from oidcservice.client_auth import CLIENT_AUTHN_METHOD
from oidcservice.oidc.service import factory
from oidcservice.service_context import ServiceContext
from oidcservice.oidc.pkce import add_code_challenge, put_state_in_post_args
from oidcservice.oidc.pkce import add_code_verifier


def test_add_code_challenge_default_values():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests',
    }
    service_context = ServiceContext(config=config)
    service_context.state_db['state'] = {}
    spec = add_code_challenge(service_context, {'state': 'state'})

    # default values are length:64 method:S256
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method',
                                'state'}
    assert spec['code_challenge_method'] == 'S256'

    request_args = add_code_verifier(service_context, {}, state='state')
    assert len(request_args['code_verifier']) == 64


def test_add_code_challenge_spec_values():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests',
        'code_challenge': {'length': 128, 'method': 'S384'}
    }
    service_context = ServiceContext(config=config)
    service_context.state_db['state'] = {}

    spec = add_code_challenge(service_context, {'state': 'state'})
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method',
                                'state'}
    assert spec['code_challenge_method'] == 'S384'

    request_args = add_code_verifier(service_context, {}, state='state')
    assert len(request_args['code_verifier']) == 128


def test_authorization_and_pkce():
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'behaviour': {'response_types': ['code']}
    }
    service_context = ServiceContext(config=client_config)
    service = factory('Authorization', service_context=service_context,
                      client_authn_method=CLIENT_AUTHN_METHOD)
    service.post_construct.append(add_code_challenge)
    request = service.construct_request()
    assert set(request.keys()) == {'client_id', 'code_challenge',
                                   'code_challenge_method', 'state', 'nonce',
                                   'redirect_uri', 'response_type', 'scope'}


def test_access_token_and_pkce():
    client_config = {
        'client_id': 'client_id',
        'client_secret': 'password',
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'behaviour': {'response_types': ['code']}
    }
    service_context = ServiceContext(config=client_config)
    service_context.state_db['state'] = {}

    # Construct an authorization request.
    # Gives us a state value and stores code_verifier in state_db
    authz_service = factory('Authorization', service_context=service_context,
                            client_authn_method=CLIENT_AUTHN_METHOD)
    authz_service.post_construct.append(add_code_challenge)
    request = authz_service.construct_request()
    _state = request['state']

    service = factory('AccessToken', service_context=service_context,
                      client_authn_method=CLIENT_AUTHN_METHOD)
    # If I don't have this then state is not carried over to post_construct
    service.pre_construct.append(put_state_in_post_args)
    service.post_construct.append(add_code_verifier)

    request = service.construct_request(state=_state)
    assert set(request.keys()) == {'client_id', 'redirect_uri', 'grant_type',
                                   'client_secret', 'code_verifier'}
