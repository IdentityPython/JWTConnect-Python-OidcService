"""
Implements a service context. A Service context is used to keep information that are
common to all the services by an OpenID Connect Relying Party.
"""
import copy
import hashlib
import os

from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import build_keyjar
from cryptojwt.utils import as_bytes
# This represents a map between the local storage of algorithm choices
# and how they are represented in a provider info response.
from oidcmsg.message import Message
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.context import OidcContext


CLI_REG_MAP = {
    "userinfo": {
        "sign": "userinfo_signed_response_alg",
        "alg": "userinfo_encrypted_response_alg",
        "enc": "userinfo_encrypted_response_enc"
    },
    "id_token": {
        "sign": "id_token_signed_response_alg",
        "alg": "id_token_encrypted_response_alg",
        "enc": "id_token_encrypted_response_enc"
    },
    "request_object": {
        "sign": "request_object_signing_alg",
        "alg": "request_object_encryption_alg",
        "enc": "request_object_encryption_enc"
    }
}

PROVIDER_INFO_MAP = {
    "id_token": {
        "sign": "id_token_signing_alg_values_supported",
        "alg": "id_token_encryption_alg_values_supported",
        "enc": "id_token_encryption_enc_values_supported"
    },
    "userinfo": {
        "sign": "userinfo_signing_alg_values_supported",
        "alg": "userinfo_encryption_alg_values_supported",
        "enc": "userinfo_encryption_enc_values_supported"
    },
    "request_object": {
        "sign": "request_object_signing_alg_values_supported",
        "alg": "request_object_encryption_alg_values_supported",
        "enc": "request_object_encryption_enc_values_supported"
    },
    "token_enpoint_auth": {
        "sign": "token_endpoint_auth_signing_alg_values_supported"
    }
}

DEFAULT_VALUE = {
    'client_secret': '',
    'client_id': '',
    'redirect_uris': [],
    'provider_info': {},
    'behaviour': {},
    'callback': {},
    'issuer': ''
}


def add_issuer(conf, issuer):
    res = {}
    for key, val in conf.items():
        if key == 'abstract_storage_cls':
            res[key] = val
        else:
            _val = copy.deepcopy(val)
            _val['issuer'] = issuer
            res[key] = _val
    return res


class ServiceContext(OidcContext):
    """
    This class keeps information that a client needs to be able to talk
    to a server. Some of this information comes from configuration and some
    from dynamic provider info discovery or client registration.
    But information is also picked up during the conversation with a server.
    """

    def __init__(self, keyjar=None, config=None, **kwargs):
        if config is None:
            config = {}
        self.config = config

        OidcContext.__init__(self, config, keyjar, entity_id=config.get('client_id', ''))

        # For my Dev environment
        self.state_db = None

        self.add_boxes({'state': 'state_db'}, self.db_conf)

        self.kid = {"sig": {}, "enc": {}}

        # Below so my IDE won't complain
        self.base_url = ''
        self.requests_dir = ''
        self.register_args = {}
        self.allow = {}
        self.client_preferences = {}
        self.args = {}
        self.add_on = {}
        self.httpc_params = {}

        _def_value = copy.deepcopy(DEFAULT_VALUE)
        # Dynamic information
        for param in ['client_secret', 'client_id', 'redirect_uris', 'provider_info',
                      'behaviour', 'callback', 'issuer']:
            if param in config:
                self.set(param, config[param])
                if param == 'client_secret':
                    self.keyjar.add_symmetric('', config[param])
            else:
                self.set(param, _def_value[param])

        try:
            self.clock_skew = config['clock_skew']
        except KeyError:
            self.clock_skew = 15

        for key, val in kwargs.items():
            setattr(self, key, val)

        for attr in ['base_url', 'requests_dir', 'allow', 'client_preferences', 'verify_args']:
            try:
                setattr(self, attr, config[attr])
            except KeyError:
                pass

        for attr in RegistrationRequest.c_param:
            try:
                self.register_args[attr] = config[attr]
            except KeyError:
                pass

        if self.requests_dir:
            # make sure the path exists. If not, then make it.
            if not os.path.isdir(self.requests_dir):
                os.makedirs(self.requests_dir)

        try:
            self.import_keys(config['keys'])
        except KeyError:
            pass

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def filename_from_webname(self, webname):
        """
        A 1<->1 map is maintained between a URL pointing to a file and
        the name of the file in the file system.

        As an example if the base_url is 'https://example.com' and a jwks_uri
        is 'https://example.com/jwks_uri.json' then the filename of the
        corresponding file on the local filesystem would be 'jwks_uri'.
        Relative to the directory from which the RP instance is run.

        :param webname: The published URL
        :return: local filename
        """
        if not webname.startswith(self.base_url):
            raise ValueError("Webname doesn't match base_url")

        _name = webname[len(self.base_url):]
        if _name.startswith('/'):
            return _name[1:]

        return _name

    def generate_request_uris(self, path):
        """
        Need to generate a redirect_uri path that is unique for a OP/RP combo
        This is to counter the mix-up attack.

        :param path: Leading path
        :return: A list of one unique URL
        """
        _hash = hashlib.sha256()
        try:
            _hash.update(as_bytes(self.get('provider_info')['issuer']))
        except KeyError:
            _hash.update(as_bytes(self.get('issuer')))
        _hash.update(as_bytes(self.base_url))

        if not path.startswith('/'):
            redirs = ['{}/{}/{}'.format(self.base_url, path, _hash.hexdigest())]
        else:
            redirs = ['{}{}/{}'.format(self.base_url, path, _hash.hexdigest())]

        self.set('redirect_uris', redirs)
        return redirs

    def import_keys(self, keyspec):
        """
        The client needs it's own set of keys. It can either dynamically
        create them or load them from local storage.
        This method can also fetch other entities keys provided the
        URL points to a JWKS.

        :param keyspec:
        """
        for where, spec in keyspec.items():
            if where == 'file':
                for typ, files in spec.items():
                    if typ == 'rsa':
                        for fil in files:
                            _key = RSAKey(
                                key=import_private_rsa_key_from_file(fil),
                                use='sig')
                            _bundle = KeyBundle()
                            _bundle.append(_key)
                            self.keyjar.add_kb('', _bundle)
            elif where == 'url':
                for iss, url in spec.items():
                    _bundle = KeyBundle(source=url)
                    self.keyjar.add_kb(iss, _bundle)

    def get_sign_alg(self, typ):
        """

        :param typ: ['id_token', 'userinfo', 'request_object']
        :return:
        """

        try:
            return self.get('behaviour')[CLI_REG_MAP[typ]['sign']]
        except KeyError:
            try:
                return self.get('provider_info')[PROVIDER_INFO_MAP[typ]['sign']]
            except (KeyError, TypeError):
                pass

        return None

    def get_enc_alg_enc(self, typ):
        """

        :param typ:
        :return:
        """

        res = {}
        for attr in ['enc', 'alg']:
            try:
                _alg = self.get('behaviour')[CLI_REG_MAP[typ][attr]]
            except KeyError:
                try:
                    _alg = self.get('provider_info')[PROVIDER_INFO_MAP[typ][attr]]
                except KeyError:
                    _alg = None

            res[attr] = _alg

        return res

    def get(self, key, default=None):
        return self.db.get(key, default)

    def set(self, key, value):
        if isinstance(value, Message):
            self.db[key] = value.to_dict()
        else:
            self.db[key] = value

    def __contains__(self, item):
        return item in self.db
