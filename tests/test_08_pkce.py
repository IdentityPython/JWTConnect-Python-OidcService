from oiccli.client_info import ClientInfo
from oiccli.oic.pkce import add_code_challenge


def test_add_code_challenge_default():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests',
    }
    ci = ClientInfo(config=config)

    spec, verifier = add_code_challenge(ci)
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method'}
    assert spec['code_challenge_method'] == 'S256'