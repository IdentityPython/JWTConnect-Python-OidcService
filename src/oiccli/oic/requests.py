import inspect
import logging
import sys
import six

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oic.oauth2 import ErrorResponse
from oiccli import sanitize
from oiccli.exception import ConfigurationError
from oiccli.request import Request
from oicmsg import oic
from oiccli.oauth2 import requests
from oicmsg.exception import RegistrationError
from oicmsg.oauth2 import Message

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg":
        "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc":
        "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg":
        "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc":
        "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg":
        "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc":
        "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg":
        "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    'grant_types': 'grant_types_supported'
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


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

    def match_preferences(self, cli_info, pcr=None):
        """
        Match the clients preferences against what the provider can do.

        :param cli_info: Client information
        :param pcr: Provider configuration response if available
        """
        if not pcr:
            pcr = cli_info.provider_info

        regreq = oic.RegistrationRequest

        for _pref, _prov in PREFERENCE2PROVIDER.items():
            try:
                vals = cli_info.client_prefs[_pref]
            except KeyError:
                continue

            try:
                _pvals = pcr[_prov]
            except KeyError:
                try:
                    cli_info.behaviour[_pref] = PROVIDER_DEFAULT[_pref]
                except KeyError:
                    # cli_info.behaviour[_pref]= vals[0]
                    if isinstance(pcr.c_param[_prov][0], list):
                        cli_info.behaviour[_pref] = []
                    else:
                        cli_info.behaviour[_pref] = None
                continue

            if isinstance(vals, six.string_types):
                if vals in _pvals:
                    cli_info.behaviour[_pref] = vals
            else:
                vtyp = regreq.c_param[_pref]

                if isinstance(vtyp[0], list):
                    cli_info.behaviour[_pref] = []
                    for val in vals:
                        if val in _pvals:
                            cli_info.behaviour[_pref].append(val)
                else:
                    for val in vals:
                        if val in _pvals:
                            cli_info.behaviour[_pref] = val
                            break

            if _pref not in cli_info.behaviour:
                raise ConfigurationError(
                    "OP couldn't match preference:%s" % _pref, pcr)

        for key, val in cli_info.client_prefs.items():
            if key in cli_info.behaviour:
                continue

            try:
                vtyp = regreq.c_param[key]
                if isinstance(vtyp[0], list):
                    pass
                elif isinstance(val, list) and not isinstance(val,
                                                              six.string_types):
                    val = val[0]
            except KeyError:
                pass
            if key not in PREFERENCE2PROVIDER:
                cli_info.behaviour[key] = val

    def store_registration_info(self, reginfo):
        self.registration_response = reginfo
        if "token_endpoint_auth_method" not in self.registration_response:
            self.registration_response[
                "token_endpoint_auth_method"] = "client_secret_basic"
        self.client_id = reginfo["client_id"]
        try:
            self.client_secret = reginfo["client_secret"]
        except KeyError:  # Not required
            pass
        else:
            try:
                self.registration_expires = reginfo["client_secret_expires_at"]
            except KeyError:
                pass
        try:
            self.registration_access_token = reginfo[
                "registration_access_token"]
        except KeyError:
            pass

    def handle_registration_info(self, response):
        err_msg = 'Got error response: {}'
        unk_msg = 'Unknown response: {}'
        if response.status_code in [200, 201]:
            resp = oic.RegistrationResponse().deserialize(response.text, "json")
            # Some implementations sends back a 200 with an error message inside
            try:
                resp.verify()
            except Exception:
                resp = ErrorResponse().deserialize(response.text, "json")
                if resp.verify():
                    logger.error(err_msg.format(sanitize(resp.to_json())))
                    if self.events:
                        self.events.store('protocol response', resp)
                    raise RegistrationError(resp.to_dict())
                else:  # Something else
                    logger.error(unk_msg.format(sanitize(response.text)))
                    raise RegistrationError(response.text)
            else:
                # got a proper registration response
                self.store_registration_info(resp)
        elif 400 <= response.status_code <= 499:
            try:
                resp = ErrorResponse().deserialize(response.text, "json")
            except _decode_err:
                logger.error(unk_msg.format(sanitize(response.text)))
                raise RegistrationError(response.text)

            if resp.verify():
                logger.error(err_msg.format(sanitize(resp.to_json())))
                if self.events:
                    self.events.store('protocol response', resp)
                raise RegistrationError(resp.to_dict())
            else:  # Something else
                logger.error(unk_msg.format(sanitize(response.text)))
                raise RegistrationError(response.text)
        else:
            raise RegistrationError(response.text)

        return resp


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Request):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass

    return requests.factory(req_name, **kwargs)
