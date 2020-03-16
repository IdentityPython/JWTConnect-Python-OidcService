import logging

from oidcmsg import oidc
from oidcmsg.oidc import verified_claim_name
from oidcmsg.time_util import time_sans_frac

from oidcservice.oauth2 import access_token
from oidcservice.exception import ParameterError
from oidcservice.oidc import IDT2REG

__author__ = 'Roland Hedberg'

LOGGER = logging.getLogger(__name__)


class AccessToken(access_token.AccessToken):
    msg_type = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        access_token.AccessToken.__init__(self, service_context, state_db,
                                          client_authn_factory=client_authn_factory,
                                          conf=conf)

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _ctx = self.service_context
        # Default is RS256
        _allowed_sign_alg = _ctx.registration_response.get("id_token_signed_response_alg", "RS256")

        kwargs = {
            'client_id': _ctx.client_id, 'iss': _ctx.issuer,
            'keyjar': _ctx.keyjar, 'verify': True,
            'skew': _ctx.clock_skew, 'allowed_sign_alg': _allowed_sign_alg
        }

        for attr, param in IDT2REG.items():
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

    def update_service_context(self, resp, key='', **kwargs):
        try:
            _idt = resp[verified_claim_name('id_token')]
        except KeyError:
            pass
        else:
            try:
                if self.get_state_by_nonce(_idt['nonce']) != key:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError('Invalid nonce value')

            self.store_sub2state(_idt['sub'], key)

        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(
                resp['expires_in'])

        self.store_item(resp, 'token_response', key)

    def get_authn_method(self):
        try:
            return self.service_context.behaviour['token_endpoint_auth_method']
        except KeyError:
            return self.default_authn_method
