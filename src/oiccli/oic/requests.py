import inspect
import logging

import sys

from oic.oauth2 import ErrorResponse
from oiccli.request import Request
from oicmsg import oic
from oiccli.oauth2 import requests
from oicmsg.oauth2 import Message

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


class AuthorizationRequest(requests.AuthorizationRequest):
    msg_type = oic.AuthorizationRequest
    response_cls = oic.AuthorizationResponse
    error_msg = oic.AuthorizationErrorResponse


class AccessTokenRequest(requests.AccessTokenRequest):
    msg_type = oic.AccessTokenRequest
    response_cls = oic.AccessTokenResponse
    error_msg = oic.TokenErrorResponse


class RefreshAccessTokenRequest(requests.RefreshAccessTokenRequest):
    msg_type = oic.RefreshAccessTokenRequest
    response_cls = oic.AccessTokenResponse
    error_msg = oic.TokenErrorResponse


class ProviderInfoDiscovery(requests.ProviderInfoDiscovery):
    msg_type = oic.Message
    response_cls = oic.ProviderConfigurationResponse
    error_msg = ErrorResponse


class UserInfoRequest(Request):
    msg_type = Message
    response_cls = oic.OpenIDSchema
    error_msg = oic.UserInfoErrorResponse
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    request = 'userinfo'


class RegistrationRequest(Request):
    msg_type = oic.RegistrationRequest
    response_cls = oic.RegistrationResponse
    error_msg = oic.ClientRegistrationErrorResponse
    endpoint_name = 'registration_endpoint'
    synchronous = True
    request = 'registration'


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Request):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass
