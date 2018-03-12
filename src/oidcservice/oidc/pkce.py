from cryptojwt import b64e
from oidcservice import unreserved, CC_METHOD
from oidcservice.exception import Unsupported
from oidcservice.oauth2.service import get_state


def add_code_challenge(service_context, request_args, **kwargs):
    """
    PKCE RFC 7636 support
    To be added as a post_construct method to an
    :py:class:`oidcservice.oidc.service.Authorization` instance

    :return: request arguments
    """
    try:
        cv_len = service_context.config['code_challenge']['length']
    except KeyError:
        cv_len = 64  # Use default

    # code_verifier: string of length cv_len
    code_verifier = unreserved(cv_len)
    _cv = code_verifier.encode()

    try:
        _method = service_context.config['code_challenge']['method']
    except KeyError:
        _method = 'S256'

    try:
        # Pick hash method
        _hash_method = CC_METHOD[_method]
        # Use it on the code_verifier
        _hv = _hash_method(_cv).hexdigest()
        # base64 encode the hash value
        code_challenge = b64e(_hv.encode()).decode()
    except KeyError:
        raise Unsupported(
            'PKCE Transformation method:{}'.format(_method))

    service_context.state_db.add_info(request_args['state'],
                                      code_verifier=code_verifier,
                                      code_challenge_method=_method)

    request_args.update({"code_challenge": code_challenge,
                         "code_challenge_method": _method})
    return request_args


def add_code_verifier(service_context, request_args, **kwargs):
    """
    PKCE RFC 7636 support
    To be added as a post_construct method to an
    :py:class:`oidcservice.oidc.service.AccessToken` instance

    :param service_context:
    :param request_args:
    :return:
    """
    code_verifier = service_context.state_db[kwargs['state']]['code_verifier']
    request_args.update({'code_verifier': code_verifier})
    return request_args


def put_state_in_post_args(service_context, request_args, **kwargs):
    state = get_state(request_args, kwargs)
    return request_args, {'state': state}
