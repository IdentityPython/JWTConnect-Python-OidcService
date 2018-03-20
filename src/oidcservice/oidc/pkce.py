from cryptojwt import b64e
from oidcmsg.message import Message

from oidcservice import unreserved, CC_METHOD
from oidcservice.exception import Unsupported
from oidcservice.oauth2.service import get_state_parameter


def add_code_challenge(request_args, service, **kwargs):
    """
    PKCE RFC 7636 support
    To be added as a post_construct method to an
    :py:class:`oidcservice.oidc.service.Authorization` instance

    :param service: The service that uses this function
    :param request_args: Set of request arguments
    :param kwargs: Extra set of keyword arguments
    :return: Updated set of request arguments
    """
    try:
        cv_len = service.service_context.config['code_challenge']['length']
    except KeyError:
        cv_len = 64  # Use default

    # code_verifier: string of length cv_len
    code_verifier = unreserved(cv_len)
    _cv = code_verifier.encode()

    try:
        _method = service.service_context.config['code_challenge']['method']
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

    _item = Message(code_verifier=code_verifier,code_challenge_method=_method)
    service.store_item(_item, 'pkce', request_args['state'])

    request_args.update({"code_challenge": code_challenge,
                         "code_challenge_method": _method})
    return request_args


def add_code_verifier(request_args, service, **kwargs):
    """
    PKCE RFC 7636 support
    To be added as a post_construct method to an
    :py:class:`oidcservice.oidc.service.AccessToken` instance

    :param service: The service that uses this function
    :param request_args: Set of request arguments
    :return: updated set of request arguments
    """
    _item = service.get_item(Message, 'pkce', kwargs['state'])
    request_args.update({'code_verifier': _item['code_verifier']})
    return request_args


def put_state_in_post_args(request_args, **kwargs):
    state = get_state_parameter(request_args, kwargs)
    return request_args, {'state': state}
