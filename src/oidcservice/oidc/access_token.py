import logging
from typing import Optional

from oidcmsg import oidc
from oidcmsg.oidc import verified_claim_name
from oidcmsg.time_util import time_sans_frac

from oidcservice.exception import ParameterError
from oidcservice.oauth2 import access_token
from oidcservice.oidc import IDT2REG

__author__ = 'Roland Hedberg'

LOGGER = logging.getLogger(__name__)


class AccessToken(access_token.AccessToken):
    msg_type = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage

    def __init__(self,
                 service_context,
                 client_authn_factory=None,
                 conf: Optional[dict]=None):
        access_token.AccessToken.__init__(self, service_context,
                                          client_authn_factory=client_authn_factory, conf=conf)

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _ctx = self.service_context
        # Default is RS256

        kwargs = {
            'client_id': _ctx.get('client_id'), 'iss': _ctx.get('issuer'),
            'keyjar': _ctx.keyjar, 'verify': True,
            'skew': _ctx.clock_skew,
        }

        _reg_resp = _ctx.get('registration_response')
        if _reg_resp:
            for attr, param in IDT2REG.items():
                try:
                    kwargs[attr] = _reg_resp[param]
                except KeyError:
                    pass

        try:
            kwargs['allow_missing_kid'] = self.service_context.allow['missing_kid']
        except KeyError:
            pass

        _verify_args = _ctx.get('behaviour').get("verify_args")
        if _verify_args:
            if _verify_args:
                kwargs.update(_verify_args)

        return kwargs

    def update_service_context(self, resp, key='', **kwargs):
        _state_interface = self.service_context.state
        try:
            _idt = resp[verified_claim_name('id_token')]
        except KeyError:
            pass
        else:
            try:
                if _state_interface.get_state_by_nonce(_idt['nonce']) != key:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError('Invalid nonce value')

            _state_interface.store_sub2state(_idt['sub'], key)

        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(
                resp['expires_in'])

        _state_interface.store_item(resp, 'token_response', key)

    def get_authn_method(self):
        try:
            return self.service_context.get('behaviour')[
                'token_endpoint_auth_method']
        except KeyError:
            return self.default_authn_method
