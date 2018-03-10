from oidcservice.service_context import ServiceContext
from oidcservice.oidc.pkce import add_code_challenge
from oidcservice.oidc.pkce import get_code_verifier


def test_add_code_challenge_default_values():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests',
    }
    ci = ServiceContext(config=config)
    ci.state_db['state'] = {}
    spec = add_code_challenge(ci, 'state')

    # default values are length:64 method:S256
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method'}
    assert spec['code_challenge_method'] == 'S256'

    code_verifier = get_code_verifier(ci, 'state')
    assert len(code_verifier) == 64


def test_add_code_challenge_spec_values():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests',
        'code_challenge': {'length': 128, 'method': 'S384'}
    }
    ci = ServiceContext(config=config)
    ci.state_db['state'] = {}

    spec = add_code_challenge(ci, 'state')
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method'}
    assert spec['code_challenge_method'] == 'S384'

    code_verifier = get_code_verifier(ci, 'state')
    assert len(code_verifier) == 128
