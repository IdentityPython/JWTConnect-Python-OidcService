from oiccli.client_info import ClientInfo
from oiccli.oic.utils import construct_request_uri
from oiccli.oic.utils import request_object_encryption

from oicmsg.key_jar import build_keyjar
from oicmsg.oic import AuthorizationRequest

from cryptojwt.jwe import factory


KEYSPEC = [
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

RECEIVER = 'https://example.org/op'

keyjar = build_keyjar(KEYSPEC)[1]
keyjar[RECEIVER] = keyjar['']


def test_request_object_encryption():
    msg = AuthorizationRequest(state='ABCDE',
                               redirect_uri='https://example.com/cb',
                               response_type='code')

    conf = {
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'client_id': 'client_1',
        'client_secret': 'abcdefghijklmnop',
    }
    client_info = ClientInfo(keyjar=keyjar, config=conf)
    client_info.behaviour["request_object_encryption_alg"] = 'RSA1_5'
    client_info.behaviour["request_object_encryption_enc"] = "A128CBC-HS256"
    _jwe = request_object_encryption(msg.to_json(), client_info,
                                     target=RECEIVER)
    assert _jwe

    _jw = factory(_jwe)

    assert _jw.jwt.headers['alg'] == 'RSA1_5'
    assert _jw.jwt.headers['enc'] == 'A128CBC-HS256'


def test_construct_request_uri():
    local_dir = 'home'
    base_path = 'https://example.com/'
    a, b = construct_request_uri(local_dir, base_path)
    assert a.startswith('home') and a.endswith('.jwt')
    d,f = a.split('/')
    assert b == '{}{}'.format(base_path, f)
