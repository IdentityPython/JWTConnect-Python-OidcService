import inspect
import logging
import re
import sys
from urllib.parse import urlencode
from urllib.parse import urlparse

from cryptojwt import jws
from oidcservice.state_interface import State

from oidcservice import OIDCONF_PATTERN
from oidcservice import rndstr
from oidcservice.exception import ConfigurationError
from oidcservice.exception import WebFingerError
from oidcservice.exception import ParameterError
from oidcservice.oauth2 import service
from oidcservice.oauth2.service import get_state_parameter
from oidcservice.oauth2.service import pick_redirect_uris
from oidcservice.oidc import OIC_ISSUER
from oidcservice.oidc import WF_URL
from oidcservice.oidc.utils import construct_request_uri
from oidcservice.oidc.utils import request_object_encryption
from oidcservice.service import Service

from oidcmsg import oidc
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.oauth2 import ResponseMessage
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

IDT2REG = {'sigalg': 'id_token_signed_response_alg',
           'encalg': 'id_token_encrypted_response_alg',
           'encenc': 'id_token_encrypted_response_enc'}

UI2REG = {'sigalg': 'userinfo_signed_response_alg',
          'encalg': 'userinfo_encrypted_response_alg',
          'encenc': 'userinfo_encrypted_response_enc'}


class Authorization(service.Authorization):
    msg_type = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_msg = oidc.ResponseMessage

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        service.Authorization.__init__(self, service_context, state_db,
                                       client_authn_factory, conf=conf)
        self.default_request_args = {'scope': ['openid']}
        self.pre_construct = [self.set_state, pick_redirect_uris,
                              self.oidc_pre_construct]
        self.post_construct = [self.oidc_post_construct]

    def set_state(self, request_args, **kwargs):
        try:
            _state = kwargs['state']
        except KeyError:
            try:
                _state = request_args['state']
            except KeyError:
                _state = rndstr(24)

        request_args['state'] = _state
        _item = State(iss=self.service_context.issuer)
        self.state_db.set(_state, _item.to_json())
        return request_args, {}

    def update_service_context(self, resp, state='', **kwargs):
        try:
            _idt = resp['verified_id_token']
        except KeyError:
            pass
        else:
            try:
                if self.get_state_by_nonce(_idt['nonce']) != state:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError('Invalid nonce value')

        self.store_item(resp.to_json(), 'auth_response', state)

    def oidc_pre_construct(self, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        try:
            _rt = request_args["response_type"]
        except KeyError:
            _rt = self.service_context.behaviour['response_types'][0]
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

        return request_args, post_args

    def oidc_post_construct(self, req, **kwargs):

        if 'openid' in req['scope']:
            _response_type = req['response_type'][0]
            if 'id_token' in _response_type or 'code' in _response_type:
                try:
                    _nonce = req['nonce']
                except KeyError:
                    _nonce = rndstr(32)
                    req['nonce'] = _nonce

                self.store_nonce2state(_nonce, req['state'])

        try:
            _request_method = kwargs['request_method']
        except KeyError:
            pass
        else:
            del kwargs['request_method']

            alg = 'RS256'
            for arg in ["request_object_signing_alg", "algorithm"]:
                try:  # Trumps everything
                    alg = kwargs[arg]
                except KeyError:
                    pass
                else:
                    break

            if not alg:
                try:
                    alg = self.service_context.behaviour[
                        "request_object_signing_alg"]
                except KeyError:  # Use default
                    alg = "RS256"

            kwargs["request_object_signing_alg"] = alg

            if "keys" not in kwargs and alg and alg != "none":
                _kty = jws.alg2keytype(alg)
                try:
                    _kid = kwargs["sig_kid"]
                except KeyError:
                    _kid = self.service_context.kid["sig"].get(_kty, None)

                kwargs["keys"] = self.service_context.keyjar.get_signing_key(
                    _kty, kid=_kid)

            _req = make_openid_request(req, **kwargs)

            # Should the request be encrypted
            _req = request_object_encryption(_req, self.service_context,
                                             **kwargs)

            if _request_method == "request":
                req["request"] = _req
            else:  # MUST be request_uri
                try:
                    _webname = self.service_context.registration_response[
                        'request_uris'][0]
                    filename = self.service_context.filename_from_webname(
                        _webname)
                except KeyError:
                    filename, _webname = construct_request_uri(**kwargs)
                fid = open(filename, mode="w")
                fid.write(_req)
                fid.close()
                req["request_uri"] = _webname

        self.store_item(req, 'auth_request', req['state'])
        return req

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _ctx = self.service_context
        kwargs = {'client_id': _ctx.client_id, 'iss': _ctx.issuer,
                  'keyjar': _ctx.keyjar, 'verify': True,
                  'skew': _ctx.clock_skew}

        for attr, param in IDT2REG.items():
            try:
                kwargs[attr] = _ctx.registration_response[param]
            except KeyError:
                pass

        try:
            kwargs['allow_missing_kid'] = _ctx.allow['missing_kid']
        except KeyError:
            pass

        return kwargs


class AccessToken(service.AccessToken):
    msg_type = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        service.AccessToken.__init__(self, service_context, state_db,
                                     client_authn_factory=client_authn_factory,
                                     conf=conf)

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _ctx = self.service_context
        kwargs = {'client_id': _ctx.client_id, 'iss': _ctx.issuer,
                  'keyjar': _ctx.keyjar, 'verify': True,
                  'skew': _ctx.clock_skew}

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

    def update_service_context(self, resp, state='', **kwargs):
        try:
            _idt = resp['verified_id_token']
        except KeyError:
            pass
        else:
            try:
                if self.get_state_by_nonce(_idt['nonce']) != state:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError('Invalid nonce value')

        self.store_item(resp, 'token_response', state)

    def get_authn_method(self):
        try:
            return self.service_context.behaviour['token_endpoint_auth_method']
        except KeyError:
            return self.default_authn_method


class RefreshAccessToken(service.RefreshAccessToken):
    msg_type = oidc.RefreshAccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage

    def get_authn_method(self):
        try:
            return self.service_context.behaviour['token_endpoint_auth_method']
        except KeyError:
            return self.default_authn_method


class URINormalizer(object):
    @staticmethod
    def has_scheme(inp):
        """
        Verify that the given string (URI) has a scheme specification

        :param inp: The string to check
        :return: True if there is a scheme specification otherwise False
        """
        if "://" in inp:
            return True
        else:
            # basically get everything before the first '/', '?' or '#'
            authority = inp.replace('/', '#').replace('?', '#').split("#")[0]

            if ':' in authority:
                scheme_or_host, host_or_port = authority.split(':', 1)
                # Assert that the second part is not a port number
                if not host_or_port:
                    return False
                if re.match('^\d+$', host_or_port):
                    return False
            else:
                return False
        return True

    @staticmethod
    def acct_scheme_assumed(inp):
        if '@' in inp:
            # get what's behind the last '@'. This should be a host/domain name
            host = inp.split('@')[-1]
            # host/domain name not allowed to contain ':','/' or '?'
            return not (':' in host or '/' in host or '?' in host)
        else:
            return False

    def normalize(self, inp):
        if self.has_scheme(inp):
            # If there is a scheme specification then just pass on
            pass
        elif self.acct_scheme_assumed(inp):
            # No scheme specification but looks like an acct so add acct as
            # scheme
            inp = "acct:%s" % inp
        else:
            # No scheme specification and doesn't look like an acct assume
            # it's a URL
            inp = "https://%s" % inp
        return inp.split("#")[0]  # strip fragment


class WebFinger(Service):
    """
    Implements RFC 7033
    """
    msg_type = Message
    response_cls = JRD
    error_msg = ResponseMessage
    synchronous = True
    service_name = 'webfinger'
    http_method = 'GET'
    response_body_type = 'json'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None, rel='', **kwargs):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory, conf=conf,
                         **kwargs)

        self.rel = rel or OIC_ISSUER

    def update_service_context(self, resp, state='', **kwargs):
        try:
            links = resp['links']
        except KeyError:
            raise MissingRequiredAttribute('links')
        else:
            for link in links:
                if link['rel'] == self.rel:
                    _href = link['href']
                    try:
                        _http_allowed = self.get_conf_attr(
                            'allow', default={})['http_links']
                    except KeyError:
                        _http_allowed = False

                    if _href.startswith('http://') and not _http_allowed:
                        raise ValueError(
                            'http link not allowed ({})'.format(_href))

                    self.service_context.issuer = link['href']
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
            host = host.replace('/', '#').replace('?', '#').split("#")[0]
        else:
            raise WebFingerError("Unknown schema")

        return "%s?%s" % (WF_URL % host, urlencode(info))

    def get_request_parameters(self, request_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        try:
            _resource = request_args['resource']
        except KeyError:
            try:
                _resource = kwargs['resource']
            except KeyError:
                try:
                    _resource = self.service_context.config['resource']
                except KeyError:
                    raise MissingRequiredAttribute('resource')

        if 'rel' in kwargs:
            return {'url': self.query(_resource, rel=kwargs['rel']),
                    'method': 'GET'}
        else:
            return {'url': self.query(_resource), 'method': 'GET'}


ENDPOINT2SERVICE = {
    'authorization': ['authorization'],
    'token': ['accesstoken', 'refresh_token'],
    'userinfo': ['userinfo'],
    'registration': ['registration'],
    'end_sesssion': ['end_session']
}


def add_redirect_uris(request_args, service=None, **kwargs):
    _context = service.service_context
    if "redirect_uris" not in request_args:
        if _context.callback:
            request_args['redirect_uris'] = _context.callback.values()
        else:
            request_args['redirect_uris'] = _context.redirect_uris
    return request_args, {}


class ProviderInfoDiscovery(service.ProviderInfoDiscovery):
    msg_type = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    error_msg = ResponseMessage

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        service.ProviderInfoDiscovery.__init__(
            self, service_context, state_db,
            client_authn_factory=client_authn_factory, conf=conf)

    def update_service_context(self, resp, **kwargs):
        self._update_service_context(resp, **kwargs)
        self.match_preferences(resp, self.service_context.issuer)
        if 'pre_load_keys' in self.conf and self.conf['pre_load_keys']:
            _jwks = self.service_context.keyjar.export_jwks_as_json(
                issuer=resp['issuer'])
            logger.info(
                'Preloaded keys for {}: {}'.format(resp['issuer'], _jwks))

    def get_endpoint(self):
        try:
            _iss = self.service_context.issuer
        except AttributeError:
            _iss = self.endpoint

        if _iss.endswith('/'):
            return OIDCONF_PATTERN.format(_iss[:-1])
        else:
            return OIDCONF_PATTERN.format(_iss)

    def match_preferences(self, pcr=None, issuer=None):
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
            pcr = self.service_context.provider_info

        regreq = oidc.RegistrationRequest

        for _pref, _prov in PREFERENCE2PROVIDER.items():
            try:
                vals = self.service_context.client_preferences[_pref]
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
                    if self.service_context.strict_on_preferences:
                        raise ConfigurationError(
                            "OP couldn't match preference:%s" % _pref, pcr)
                    else:
                        _pvals = vals

            if isinstance(vals, str):
                if vals in _pvals:
                    self.service_context.behaviour[_pref] = vals
            else:
                vtyp = regreq.c_param[_pref]

                if isinstance(vtyp[0], list):
                    self.service_context.behaviour[_pref] = []
                    for val in vals:
                        if val in _pvals:
                            self.service_context.behaviour[_pref].append(val)
                else:
                    for val in vals:
                        if val in _pvals:
                            self.service_context.behaviour[_pref] = val
                            break

            if _pref not in self.service_context.behaviour:
                raise ConfigurationError(
                    "OP couldn't match preference:%s" % _pref, pcr)

        for key, val in self.service_context.client_preferences.items():
            if key in self.service_context.behaviour:
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
                self.service_context.behaviour[key] = val

        logger.debug(
            'service_context behaviour: {}'.format(
                self.service_context.behaviour))


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


def add_request_uri(request_args=None, service=None, **kwargs):
    _context = service.service_context
    if _context.requests_dir:
        try:
            if _context.provider_info[
                    'require_request_uri_registration'] is True:
                request_args['request_uris'] = _context.generate_request_uris(
                    _context.requests_dir)
        except KeyError:
            pass

    return request_args, {}


def add_post_logout_redirect_uris(request_args=None, service=None, **kwargs):
    """

    :param request_args:
    :param service: pointer to the :py:class:`oidcservice.service.Service`
        instance that is running this function
    :param kwargs: parameters to the registration request
    :return:
    """

    if "post_logout_redirect_uris" not in request_args:
        try:
            _uris = service.service_context.post_logout_redirect_uris
        except AttributeError:
            pass
        else:
            request_args["post_logout_redirect_uris"] = _uris

    return request_args, {}


def add_jwks_uri_or_jwks(request_args=None, service=None, **kwargs):
    if 'jwks_uri' in request_args:
        if 'jwks' in request_args:
            del request_args['jwks']  # only one of jwks_uri and jwks allowed
        return request_args, {}
    elif 'jwks' in request_args:
        return request_args, {}

    for attr in ['jwks_uri', 'jwks']:
        _val = getattr(service.service_context, attr, 0)
        if _val:
            request_args[attr] = _val
            break
        else:
            try:
                _val = service.service_context.config[attr]
            except KeyError:
                pass
            else:
                request_args[attr] = _val
                break

    return request_args, {}


class Registration(Service):
    msg_type = oidc.RegistrationRequest
    response_cls = oidc.RegistrationResponse
    error_msg = ResponseMessage
    endpoint_name = 'registration_endpoint'
    synchronous = True
    service_name = 'registration'
    request_body_type = 'json'
    http_method = 'POST'

    def __init__(self, service_context, state_db, client_authn_factory=None,
                 conf=None):
        Service.__init__(self, service_context, state_db,
                         client_authn_factory=client_authn_factory,
                         conf=conf)
        self.pre_construct = [self.add_client_behaviour_preference,
                              add_redirect_uris, add_request_uri,
                              add_post_logout_redirect_uris,
                              add_jwks_uri_or_jwks]
        self.post_construct = [self.oidc_post_construct]

    def add_client_behaviour_preference(self, request_args=None, **kwargs):
        for prop in self.msg_type.c_param.keys():
            if prop in request_args:
                continue

            try:
                request_args[prop] = self.service_context.client_preferences[
                    prop]
            except KeyError:
                try:
                    request_args[prop] = self.service_context.behaviour[prop]
                except KeyError:
                    pass
        return request_args, {}

    def oidc_post_construct(self, request_args=None, **kwargs):
        try:
            request_args['grant_types'] = response_types_to_grant_types(
                request_args['response_types'])
        except KeyError:
            pass

        return request_args

    def update_service_context(self, resp, state='', **kwargs):
        self.service_context.registration_response = resp
        if "token_endpoint_auth_method" not in \
                self.service_context.registration_response:
            self.service_context.registration_response[
                "token_endpoint_auth_method"] = "client_secret_basic"

        self.service_context.client_id = resp["client_id"]

        try:
            self.service_context.client_secret = resp["client_secret"]
        except KeyError:  # Not required
            pass
        else:
            try:
                self.service_context.client_secret_expires_at = resp[
                    "client_secret_expires_at"]
            except KeyError:
                pass

        try:
            self.service_context.registration_access_token = resp[
                "registration_access_token"]
        except KeyError:
            pass


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
            {}, kwargs['state'], ['verified_id_token'],
            ['auth_response', 'token_response', 'refresh_token_response']
        )

        try:
            _sub = _args['verified_id_token']['sub']
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
                        keyjar=self.service_context.keyjar)
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
        kwargs = {'client_id': _ctx.client_id, 'iss': _ctx.issuer,
                  'keyjar': _ctx.keyjar, 'verify': True,
                  'skew': _ctx.clock_skew}

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


class CheckSession(Service):
    msg_type = oidc.CheckSessionRequest
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


class CheckID(Service):
    msg_type = oidc.CheckIDRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = ''
    synchronous = True
    service_name = 'check_id'

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


class EndSession(Service):
    msg_type = oidc.EndSessionRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = 'end_session_endpoint'
    synchronous = True
    service_name = 'end_session'

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
