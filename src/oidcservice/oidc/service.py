import inspect
import logging
import re
import sys
from urllib.parse import urlencode, urlparse

from cryptojwt import jws

from oidcservice import rndstr, OIDCONF_PATTERN
from oidcservice.exception import ConfigurationError, WebFingerError, \
    MissingEndpoint
from oidcservice.exception import ParameterError
from oidcservice.oauth2 import service
from oidcservice.oauth2.service import get_state
from oidcservice.oidc import OIC_ISSUER, WF_URL
from oidcservice.oidc.utils import construct_request_uri
from oidcservice.oidc.utils import request_object_encryption
from oidcservice.service import Service

from oidcmsg import oidc
from oidcmsg.exception import MissingParameter
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.oauth2 import ErrorResponse
from oidcmsg.oauth2 import Message
from oidcmsg.oidc import JRD
from oidcmsg.oidc import make_openid_request

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


def store_id_token(cli_info, resp, **kwargs):
    """
    Store the verified ID Token in the state database.

    :param resp: The response
    :param cli_info: A :py:class:`oidcservice.client_info.ClientInfo` instance
    :param kwargs: Extra keyword arguments. In this case the state claim
        is supposed to be represented.
    """
    try:
        cli_info.state_db.add_info(
            kwargs['state'],
            verified_id_token=resp['verified_id_token'].to_dict())
    except KeyError:
        pass


class Authorization(service.Authorization):
    msg_type = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_msg = oidc.AuthorizationErrorResponse

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        service.Authorization.__init__(self, keyjar,
                                       client_authn_method, conf=conf)
        self.default_request_args = {'scope': ['openid']}
        self.pre_construct = [self.oidc_pre_construct]
        self.post_construct = [self.oidc_post_construct]

    def update_client_info(self, cli_info, resp, state='', **kwargs):
        cli_info.state_db.add_response(resp, state)
        store_id_token(cli_info, resp, **kwargs)

    def oidc_pre_construct(self, cli_info, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        try:
            _rt = request_args["response_type"]
        except KeyError:
            _rt = cli_info.behaviour['response_types'][0]
            request_args["response_type"] = _rt

        # For OIDC 'openid' is required in scope
        if 'scope' not in request_args:
            request_args['scope'] = ['openid']
        elif 'openid' not in request_args['scope']:
            request_args['scope'].append('openid')

        # 'code' and/or 'id_token' in response_type means an ID Roken
        # will eventually be returnedm, hence the need for a nonce
        if "code" in _rt or "id_token" in _rt:
            if "nonce" not in request_args:
                request_args["nonce"] = rndstr(32)

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

        try:
            response_mod = cli_info.behaviour['response_mode']
        except KeyError:
            pass
        else:
            if response_mod == 'form_post':
                request_args['response_mode'] = response_mod

        try:
            cli_info.state_db.create_state(
                cli_info.issuer, request_args, request_args['state'])
        except KeyError:
            request_args['state'] = cli_info.state_db.create_state(
                cli_info.issuer, request_args)

        return request_args, post_args

    def oidc_post_construct(self, cli_info, req, **kwargs):
        cli_info.state_db.add_info(req['state'],
                                   redirect_uri=req['redirect_uri'])

        if 'openid' in req['scope']:
            _response_type = req['response_type'][0]
            if 'id_token' in _response_type or 'code' in _response_type:
                try:
                    _nonce = req['nonce']
                except KeyError:
                    _nonce = rndstr(32)
                    req['nonce'] = _nonce

                cli_info.state_db.bind_nonce_to_state(_nonce, req['state'])

        try:
            _request_method = kwargs['request_method']
        except KeyError:
            return req
        else:
            del kwargs['request_method']

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
                except KeyError:  # Use default
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

            if _request_method == "request":
                req["request"] = _req
            else:  # MUST be request_uri
                try:
                    _webname = cli_info.registration_response['request_uris'][0]
                    filename = cli_info.filename_from_webname(_webname)
                except KeyError:
                    filename, _webname = construct_request_uri(**kwargs)
                fid = open(filename, mode="w")
                fid.write(_req)
                fid.close()
                req["request_uri"] = _webname

        return req


class AccessToken(service.AccessToken):
    msg_type = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.TokenErrorResponse

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        service.AccessToken.__init__(
            self, keyjar=keyjar,
            client_authn_method=client_authn_method,
            conf=conf)

    def update_client_info(self, cli_info, resp, state='', **kwargs):
        try:
            _idt = resp['verified_id_token']
        except KeyError:
            pass
        else:
            try:
                if cli_info.state_db.nonce_to_state(_idt['nonce']) != state:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError('Unknown nonce value')

        cli_info.state_db.add_response(resp, state)
        store_id_token(cli_info, resp, **kwargs)


class RefreshAccessToken(service.RefreshAccessToken):
    msg_type = oidc.RefreshAccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.TokenErrorResponse


class URINormalizer(object):
    @staticmethod
    def has_scheme(inp):
        if "://" in inp:
            return True
        else:
            authority = inp.replace('/', '#').replace('?', '#').split("#")[0]

            if ':' in authority:
                scheme_or_host, host_or_port = authority.split(':', 1)
                # Assert it's not a port number
                if re.match('^\d+$', host_or_port):
                    return False
            else:
                return False
        return True

    @staticmethod
    def acct_scheme_assumed(inp):
        if '@' in inp:
            host = inp.split('@')[-1]
            return not (':' in host or '/' in host or '?' in host)
        else:
            return False

    def normalize(self, inp):
        if self.has_scheme(inp):
            pass
        elif self.acct_scheme_assumed(inp):
            inp = "acct:%s" % inp
        else:
            inp = "https://%s" % inp
        return inp.split("#")[0]  # strip fragment


class WebFinger(Service):
    """
    Implements RFC 7033
    """
    msg_type = Message
    response_cls = JRD
    error_msg = ErrorResponse
    synchronous = True
    request = 'webfinger'
    http_method = 'GET'
    response_body_type = 'json'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None, **kwargs):
        Service.__init__(self, keyjar=keyjar,
                         client_authn_method=client_authn_method, conf=conf,
                         **kwargs)
        self.rel = OIC_ISSUER

    def update_client_info(self, client_info, resp, state='', **kwargs):
        try:
            links = resp['links']
        except KeyError:
            raise MissingRequiredAttribute('links')
        else:
            for link in links:
                if link['rel'] == self.rel:
                    _href = link['href']
                    if not self.get_conf_attr('allow_http_links'):
                        if _href.startswith('http://'):
                            raise ValueError(
                                'http link not allowed ({})'.format(_href))
                    client_info.issuer = link['href']
                    break
        return resp

    def query(self, resource, rel=None):
        resource = URINormalizer().normalize(resource)

        info = [("resource", resource)]

        if rel is None:
            if self.rel:
                info.append(("rel", self.rel))
        elif isinstance(rel, str):
            info.append(("rel", rel))
        else:
            for val in rel:
                info.append(("rel", val))

        if resource.startswith("http"):
            part = urlparse(resource)
            host = part.hostname
            if part.port is not None:
                host += ":" + str(part.port)
        elif resource.startswith("acct:"):
            host = resource.split('@')[-1]
            host = host.replace('/', '#').replace('?', '#').split("#")[0]
        elif resource.startswith("device:"):
            host = resource.split(':')[1]
        else:
            raise WebFingerError("Unknown schema")

        return "%s?%s" % (WF_URL % host, urlencode(info))

    def get_request_information(self, cli_info, request_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        try:
            _resource = request_args['resource']
        except KeyError:
            try:
                _resource = cli_info.config['resource']
            except KeyError:
                raise MissingRequiredAttribute('resource')

        if 'rel' in kwargs:
            return {'url': self.query(_resource, rel=kwargs['rel'])}
        else:
            return {'url': self.query(_resource)}


ENDPOINT2SERVICE = {
    'authorization': ['authorization'],
    'token': ['accesstoken', 'refresh_token'],
    'userinfo': ['userinfo'],
    'registration': ['registration'],
    'end_sesssion': ['end_session']
}

class ProviderInfoDiscovery(service.ProviderInfoDiscovery):
    msg_type = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    error_msg = ErrorResponse

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        service.ProviderInfoDiscovery.__init__(
            self, keyjar=keyjar, client_authn_method=client_authn_method,
            conf=conf)

    def update_client_info(self, cli_info, resp, **kwargs):
        cli_info.provider_info = resp

        for endp, srvs in ENDPOINT2SERVICE.items():
            try:
                endpoint_url = resp['{}_endpoint'.format(endp)]
            except KeyError:
                continue

            for srv in srvs:
                try:
                    cli_info.service[srv].endpoint = endpoint_url
                except KeyError:
                    pass

        self.match_preferences(cli_info, resp, cli_info.issuer)
        if 'pre_load_keys' in self.conf and self.conf['pre_load_keys']:
            _jwks = self.keyjar.export_jwks_as_json(issuer=resp['issuer'])
            logger.info(
                'Preloaded keys for {}: {}'.format(resp['issuer'], _jwks))

    def get_endpoint(self, **kwargs):
        try:
            return self._endpoint(**kwargs)
        except MissingEndpoint:
            try:
                issuer = kwargs['iss']
            except KeyError:
                raise MissingEndpoint
            else:
                return OIDCONF_PATTERN.format(issuer)

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

        :param cli_info: :py:class:`oidcservice.client_info.ClientInfo` instance
        :param pcr: Provider configuration response if available
        :param issuer: The issuer identifier
        """

        if not pcr:
            pcr = cli_info.provider_info

        regreq = oidc.RegistrationRequest

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

            if isinstance(vals, str):
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
                elif isinstance(val, list) and not isinstance(val, str):
                    val = val[0]
            except KeyError:
                pass
            if key not in PREFERENCE2PROVIDER:
                cli_info.behaviour[key] = val

        logger.debug('cli_info behaviour: {}'.format(cli_info.behaviour))


rt2gt = {
    'code': ['authorization_code'],
    'id_token': ['implicit'],
    'id_token token': ['implicit'],
    'code id_token': ['authorization_code', 'implicit'],
    'code token': ['authorization_code', 'implicit'],
    'code id_token token': ['authorization_code', 'implicit']
}


def response_types_to_grant_types(response_types):
    _res = set()

    for response_type in response_types:
        _rt = response_type.split(' ')
        _rt.sort()
        try:
            _gt = rt2gt[" ".join(_rt)]
        except KeyError:
            raise ValueError(
                'No such response type combination: {}'.format(response_types))
        else:
            _res.update(set(_gt))

    return list(_res)


class Registration(Service):
    msg_type = oidc.RegistrationRequest
    response_cls = oidc.RegistrationResponse
    error_msg = ErrorResponse
    endpoint_name = 'registration_endpoint'
    synchronous = True
    request = 'registration'
    body_type = 'json'
    http_method = 'POST'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        Service.__init__(self, keyjar=keyjar,
                         client_authn_method=client_authn_method,
                         conf=conf)
        self.pre_construct = [self.oidc_pre_construct]
        self.post_construct = [self.oidc_post_construct]

    def oidc_pre_construct(self, cli_info, request_args=None, **kwargs):
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

        if cli_info.requests_dir:
            try:
                if cli_info.provider_info[
                    'require_request_uri_registration'] is True:
                    request_args[
                        'request_uris'] = cli_info.generate_request_uris(
                        cli_info.requests_dir)
            except KeyError:
                pass

        return request_args, {}

    def oidc_post_construct(self, cli_info, request_args=None, **kwargs):
        try:
            request_args['grant_types'] = response_types_to_grant_types(
                request_args['response_types'])
        except KeyError:
            pass

        return request_args

    def update_client_info(self, client_info, resp, state='', **kwargs):
        client_info.registration_response = resp
        if "token_endpoint_auth_method" not in \
                client_info.registration_response:
            client_info.registration_response[
                "token_endpoint_auth_method"] = "client_secret_basic"
        client_info.client_id = resp["client_id"]

        try:
            client_info.client_secret = resp["client_secret"]
        except KeyError:  # Not required
            pass
        else:
            try:
                client_info.registration_expires = resp[
                    "client_secret_expires_at"]
            except KeyError:
                pass

        try:
            client_info.registration_access_token = resp[
                "registration_access_token"]
        except KeyError:
            pass


class UserInfo(Service):
    msg_type = Message
    response_cls = oidc.OpenIDSchema
    error_msg = oidc.UserInfoErrorResponse
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    request = 'userinfo'
    default_authn_method = 'bearer_header'
    http_method = 'GET'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        Service.__init__(self, keyjar=keyjar,
                         client_authn_method=client_authn_method, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, cli_info, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            _tinfo = cli_info.state_db.get_token_info(kwargs['state'])
            request_args["access_token"] = _tinfo['access_token']

        return request_args, {}

    def post_parse_response(self, client_info, response, **kwargs):
        try:
            _sub = client_info.state_db[kwargs['state']]['verified_id_token'][
                'sub']
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
                    aggregated_claims = Message().from_jwt(
                        spec["JWT"].encode("utf-8"),
                        keyjar=client_info.keyjar)
                    claims = [value for value, src in
                              response["_claim_names"].items() if
                              src == csrc]

                    for key in claims:
                        response[key] = aggregated_claims[key]

        return response


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


class CheckSession(Service):
    msg_type = oidc.CheckSessionRequest
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = 'check_session'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        Service.__init__(self, keyjar=keyjar,
                         client_authn_method=client_authn_method, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, cli_info, request_args=None, **kwargs):
        request_args = set_id_token(cli_info, request_args, **kwargs)
        return request_args, {}


class CheckID(Service):
    msg_type = oidc.CheckIDRequest
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = 'check_id'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        Service.__init__(self, keyjar=keyjar,
                         client_authn_method=client_authn_method, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, cli_info, request_args=None, **kwargs):
        request_args = set_id_token(cli_info, request_args, **kwargs)
        return request_args, {}


class EndSession(Service):
    msg_type = oidc.EndSessionRequest
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = 'end_session_endpoint'
    synchronous = True
    request = 'end_session'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None):
        Service.__init__(self, keyjar=keyjar,
                         client_authn_method=client_authn_method, conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, cli_info, request_args=None, **kwargs):
        request_args = set_id_token(cli_info, request_args, **kwargs)
        return request_args, {}


def factory(req_name, **kwargs):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and (
                issubclass(obj, Service) or issubclass(obj, service.Service)):
            try:
                if obj.__name__ == req_name:
                    return obj(**kwargs)
            except AttributeError:
                pass

    return service.factory(req_name, **kwargs)
