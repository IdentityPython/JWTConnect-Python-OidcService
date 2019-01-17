import logging

from oidcmsg.oauth2 import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import session

from oidcservice.service import Service

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


class CheckSession(Service):
    msg_type = session.CheckSessionRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = ''
    synchronous = True
    service_name = 'check_session'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        request_args = self.multiple_extend_request_args(
            request_args, kwargs['state'], ['id_token'],
            ['auth_response', 'token_response', 'refresh_token_response'])
        return request_args, {}
