from cryptojwt import b64e
from oiccli import unreserved, CC_METHOD
from oiccli.exception import Unsupported


def add_code_challenge(client_info):
    """
    PKCE RFC 7636 support

    :return:
    """
    try:
        cv_len = client_info.config['code_challenge']['length']
    except KeyError:
        cv_len = 64  # Use default

    code_verifier = unreserved(cv_len)
    _cv = code_verifier.encode()

    try:
        _method = client_info.config['code_challenge']['method']
    except KeyError:
        _method = 'S256'

    try:
        _h = CC_METHOD[_method](_cv).hexdigest()
        code_challenge = b64e(_h.encode()).decode()
    except KeyError:
        raise Unsupported(
            'PKCE Transformation method:{}'.format(_method))

    # TODO store code_verifier

    return {"code_challenge": code_challenge,
            "code_challenge_method": _method}, code_verifier
