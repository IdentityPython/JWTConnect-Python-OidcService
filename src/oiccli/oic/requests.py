import inspect
import logging
import sys
import six
from jwkest import jws
from oiccli.oauth2.requests import get_state

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oiccli import rndstr
from oiccli.exception import ConfigurationError
from oiccli.exception import ParameterError
from oiccli.oauth2 import requests
from oiccli.oic.utils import construct_redirect_uri
from oiccli.oic.utils import request_object_encryption
from oiccli.request import Request
from oicmsg import oic
from oicmsg.exception import MissingParameter
from oicmsg.exception import MissingRequiredAttribute
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oicmsg.oic import make_openid_request

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

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
        requests.AuthorizationRequest.__init__(self, httplib, keyjar,
                                               client_authn_method)
        self.default_request_args = {'scope': ['openid']}

    def pre_construct(self, cli_info, request_args=None, **kwargs):
        if request_args is not None:
            _rt = request_args["response_type"]
            if "token" in _rt or "id_token" in _rt:
                if "nonce" not in request_args:
                    request_args["nonce"] = rndstr(32)
        else:  # Never wrong to specify a nonce
            request_args = {"nonce": rndstr(32)}

        post_args = {}
        for attr in ["request_object_signing_alg", "algorithm", 'sig_kid']:
            try:
                post_args[attr] = kwargs[attr]
            except KeyError:
                pass
            else:
                del kwargs[attr]

        if "request_method" in kwargs:
            if kwargs["request_method"] == "reference":
                post_args['request_param'] = "request_uri"
            else:
                post_args['request_param'] = "request"
            del kwargs["request_method"]

        return request_args, post_args

    def post_construct(self, cli_info, req, **kwargs):
        try:
            _request_param = kwargs['request_param']
        except KeyError:
            return req
        else:
            del kwargs['request_param']

            alg = None
            for arg in ["request_object_signing_alg", "algorithm"]:
                try:  # Trumps everything
                    alg = kwargs[arg]
                except KeyError:
                    pass
                else:
                    break

            if not alg:
                try:
                    alg = cli_info.behaviour["request_object_signing_alg"]
                except KeyError:
                    alg = "RS256"

            kwargs["request_object_signing_alg"] = alg

            if "keys" not in kwargs and alg and alg != "none":
                _kty = jws.alg2keytype(alg)
                try:
                    _kid = kwargs["sig_kid"]
                except KeyError:
                    _kid = cli_info.kid["sig"].get(_kty, None)

                kwargs["keys"] = cli_info.keyjar.get_signing_key(_kty, kid=_kid)

            _req = make_openid_request(req, **kwargs)

            # Should the request be encrypted
            _req = request_object_encryption(_req, cli_info, **kwargs)

            if _request_param == "request":
                req["request"] = _req
            else:
                try:
                    _webname = cli_info.registration_response['request_uris'][0]
                    filename = cli_info.filename_from_webname(_webname)
                except KeyError:
                    filename, _webname = construct_redirect_uri(**kwargs)
                fid = open(filename, mode="w")
                fid.write(_req)
                fid.close()
                req["request_uri"] = _webname

        return req

        # def do_request_init(self, cli_info, scope="", body_type="json",
        #                     method="GET", request_args=None, http_args=None,
        #                     authn_method="", **kwargs):
        #
        #     kwargs['algs'] = cli_info.sign_enc_algs("id_token")
        #
        #     if 'code_challenge' in cli_info.config:
        #         _args, code_verifier = cli_info.add_code_challenge()
        #         request_args.update(_args)
        #
        #     return requests.AuthorizationRequest.do_request_init(
        #         self, cli_info, scope=scope, body_type=body_type,
        # method=method,
        #         request_args=request_args, http_args=http_args,
        #         authn_method=authn_method, **kwargs)


class AccessTokenRequest(requests.AccessTokenRequest):
    msg_type = oic.AccessTokenRequest
    response_cls = oic.AccessTokenResponse
    error_msg = oic.TokenErrorResponse

    # def pre_construct(self, cli_info, request_args=None, **kwargs):
    #     kwargs['algs'] = cli_info.sign_enc_algs("id_token")
    #
    #     if 'code_challenge' in cli_info.config:
    #         _args, code_verifier = cli_info.add_code_challenge()
    #         request_args.update(_args)

    def _post_parse_response(self, resp, cli_info, state='', **kwargs):
        try:
            _idt = resp['id_token']
        except KeyError:
            pass
        else:
            try:
                if cli_info.state_db.nonce_to_state(_idt['nonce']) != state:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                pass


class RefreshAccessTokenRequest(requests.RefreshAccessTokenRequest):
    msg_type = oic.RefreshAccessTokenRequest
    response_cls = oic.AccessTokenResponse
    error_msg = oic.TokenErrorResponse


class ProviderInfoDiscovery(requests.ProviderInfoDiscovery):
    msg_type = oic.Message
    response_cls = oic.ProviderConfigurationResponse
    error_msg = ErrorResponse

    def _post_parse_response(self, resp, cli_info, **kwargs):
        self.match_preferences(cli_info, resp, cli_info.issuer)
        requests.ProviderInfoDiscovery._post_parse_response(self, resp,
                                                            cli_info, **kwargs)

    @staticmethod
    def match_preferences(cli_info, pcr=None, issuer=None):
        """
        Match the clients preferences against what the provider can do.
        This is to prepare for later client registration and or what 
        functionality the client actually will use.
        In the client configuration the client preferences are expressed.
        These are then compared with the Provider Configuration information.
        If the Provider has left some claims out, defaults specified in the
        standard will be used.

        :param pcr: Provider configuration response if available
        :param issuer: The issuer identifier
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
                    # If the provider have not specified use what the
                    # standard says is mandatory if at all.
                    _pvals = PROVIDER_DEFAULT[_pref]
                except KeyError:
                    logger.info(
                        'No info from provider on {} and no default'.format(
                            _pref))
                    # Don't know what the right thing to do here
                    # Fail or hope for the best, made it configurable
                    if cli_info.strict_on_preferences:
                        raise ConfigurationError(
                            "OP couldn't match preference:%s" % _pref, pcr)
                    else:
                        _pvals = vals

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


class RegistrationRequest(Request):
    msg_type = oic.RegistrationRequest
    response_cls = oic.RegistrationResponse
    error_msg = ErrorResponse
    endpoint_name = 'registration_endpoint'
    synchronous = True
    request = 'registration'

    def pre_construct(self, cli_info, request_args, **kwargs):
        """
        Create a registration request

        :param kwargs: parameters to the registration request
        :return:
        """
        for prop in self.msg_type.c_param.keys():
            if prop in request_args:
                continue
            try:
                request_args[prop] = cli_info.behaviour[prop]
            except KeyError:
                pass

        if "post_logout_redirect_uris" not in request_args:
            try:
                request_args[
                    "post_logout_redirect_uris"] = \
                    cli_info.post_logout_redirect_uris
            except AttributeError:
                pass

        if "redirect_uris" not in request_args:
            try:
                request_args["redirect_uris"] = cli_info.redirect_uris
            except AttributeError:
                raise MissingRequiredAttribute("redirect_uris", request_args)

        try:
            if cli_info.provider_info[
                    'require_request_uri_registration'] is True:
                request_args['request_uris'] = cli_info.generate_request_uris(
                    cli_info.requests_dir)
        except KeyError:
            pass

        return request_args, {}

    def _post_parse_response(self, resp, cli_info, **kwargs):
        cli_info.registration_response = resp
        if "token_endpoint_auth_method" not in cli_info.registration_response:
            cli_info.registration_response[
                "token_endpoint_auth_method"] = "client_secret_basic"
        cli_info.client_id = resp["client_id"]
        try:
            cli_info.client_secret = resp["client_secret"]
        except KeyError:  # Not required
            pass
        else:
            try:
                cli_info.registration_expires = resp["client_secret_expires_at"]
            except KeyError:
                pass
        try:
            cli_info.registration_access_token = resp[
                "registration_access_token"]
        except KeyError:
            pass


class UserInfoRequest(Request):
    msg_type = Message
    response_cls = oic.OpenIDSchema
    error_msg = oic.UserInfoErrorResponse
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    request = 'userinfo'
    default_authn_method = 'bearer_header'

    def pre_construct(self, cli_info, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            _tinfo = cli_info.state_db.get_token_info(**kwargs)
            request_args["access_token"] = _tinfo['access_token']

        return request_args, {}

    def _post_parse_response(self, resp, client_info, **kwargs):
        self.unpack_aggregated_claims(resp, client_info)
        self.fetch_distributed_claims(resp, client_info)

    def unpack_aggregated_claims(self, userinfo, cli_info):
        try:
            _csrc = userinfo["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "JWT" in spec:
                    aggregated_claims = Message().from_jwt(
                        spec["JWT"].encode("utf-8"),
                        keyjar=cli_info.keyjar)
                    claims = [value for value, src in
                              userinfo["_claim_names"].items() if
                              src == csrc]

                    for key in claims:
                        userinfo[key] = aggregated_claims[key]

        return userinfo

    def fetch_distributed_claims(self, userinfo, cli_info, callback=None):
        try:
            _csrc = userinfo["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "endpoint" in spec:
                    if "access_token" in spec:
                        _uinfo = self.request_and_return(
                            spec["endpoint"], method='GET',
                            token=spec["access_token"], client_info=cli_info)
                    else:
                        if callback:
                            _uinfo = self.request_and_return(
                                spec["endpoint"],
                                method='GET',
                                token=callback(spec['endpoint']),
                                client_info=cli_info)
                        else:
                            _uinfo = self.request_and_return(
                                spec["endpoint"],
                                method='GET',
                                client_info=cli_info)

                    claims = [value for value, src in
                              userinfo["_claim_names"].items() if src == csrc]

                    if set(claims) != set(list(_uinfo.keys())):
                        logger.warning(
                            "Claims from claim source doesn't match what's in "
                            "the userinfo")

                    for key, vals in _uinfo.items():
                        userinfo[key] = vals

        return userinfo


def set_id_token(cli_info, request_args, **kwargs):
    if request_args is None:
        request_args = {}

    try:
        _prop = kwargs["prop"]
    except KeyError:
        _prop = "id_token"

    if _prop in request_args:
        pass
    else:
        _state = get_state(request_args, kwargs)
        id_token = cli_info.state_db.get_id_token(_state)
        if id_token is None:
            raise MissingParameter("No valid id token available")

        request_args[_prop] = id_token
    return request_args


class CheckSessionRequest(Request):
    msg_type = oic.CheckSessionRequest
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = 'check_session'

    def pre_construct(self, cli_info, request_args=None, **kwargs):
        request_args = set_id_token(cli_info, request_args, **kwargs)
        return request_args, {}


class CheckIDRequest(Request):
    msg_type = oic.CheckIDRequest
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = 'check_id'

    def pre_construct(self, cli_info, request_args=None, **kwargs):
        request_args = set_id_token(cli_info, request_args, **kwargs)
        return request_args, {}


class EndSessionRequest(Request):
    msg_type = oic.EndSessionRequest
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = 'end_session_endpoint'
    synchronous = True
    request = 'end_session'

    def pre_construct(self, cli_info, request_args=None, **kwargs):
        request_args = set_id_token(cli_info, request_args, **kwargs)
        return request_args, {}


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Request):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass

    return requests.factory(req_name, **kwargs)
