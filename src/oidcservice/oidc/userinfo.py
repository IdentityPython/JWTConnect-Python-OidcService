import logging

from oidcmsg import oidc
from oidcmsg.exception import MissingSigningKey
from oidcmsg.message import Message

from oidcservice.oauth2.utils import get_state_parameter
from oidcservice.service import Service


logger = logging.getLogger(__name__)

UI2REG = {
    'sigalg': 'userinfo_signed_response_alg',
    'encalg': 'userinfo_encrypted_response_alg',
    'encenc': 'userinfo_encrypted_response_enc'
}


def carry_state(request_args=None, **kwargs):
    """
    Make sure post_construct_methods have access to state

    :param request_args:
    :param kwargs:
    :return: The value of the state parameter
    """
    return request_args, {'state': get_state_parameter(request_args, kwargs)}


class UserInfo(Service):
    msg_type = Message
    response_cls = oidc.OpenIDSchema
    error_msg = oidc.ResponseMessage
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    service_name = 'userinfo'
    default_authn_method = 'bearer_header'
    http_method = 'GET'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct = [self.oidc_pre_construct, carry_state]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            request_args = self.multiple_extend_request_args(
                request_args, kwargs['state'], ['access_token'],
                ['auth_response', 'token_response', 'refresh_token_response']
            )

        return request_args, {}

    def post_parse_response(self, response, **kwargs):
        _args = self.multiple_extend_request_args(
            {}, kwargs['state'], ['id_token'],
            ['auth_response', 'token_response', 'refresh_token_response']
        )

        try:
            _sub = _args['id_token']['sub']
        except KeyError:
            logger.warning("Can not verify value on sub")
        else:
            if response['sub'] != _sub:
                raise ValueError('Incorrect "sub" value')

        try:
            _csrc = response["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "JWT" in spec:
                    try:
                        aggregated_claims = Message().from_jwt(
                            spec["JWT"].encode("utf-8"),
                            keyjar=self.service_context.keyjar)
                    except MissingSigningKey as err:
                        logger.warning(
                            'Error encountered while unpacking aggregated '
                            'claims'.format(err))
                    else:
                        claims = [value for value, src in
                                  response["_claim_names"].items() if
                                  src == csrc]

                        for key in claims:
                            response[key] = aggregated_claims[key]
                elif 'endpoint' in spec:
                    _info = {
                        "headers": self.get_authn_header(
                            {}, self.default_authn_method,
                            authn_endpoint=self.endpoint_name),
                        "url": spec["endpoint"]
                    }

        self.store_item(response, 'user_info', kwargs['state'])
        return response

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _ctx = self.service_context
        kwargs = {
            'client_id': _ctx.client_id, 'iss': _ctx.issuer,
            'keyjar': _ctx.keyjar, 'verify': True,
            'skew': _ctx.clock_skew
        }

        for attr, param in UI2REG.items():
            try:
                kwargs[attr] = _ctx.registration_response[param]
            except KeyError:
                pass

        try:
            kwargs['allow_missing_kid'] = self.service_context.allow[
                'missing_kid']
        except KeyError:
            pass

        return kwargs

