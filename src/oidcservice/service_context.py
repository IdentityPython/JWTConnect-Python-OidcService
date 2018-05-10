import hashlib
import os

from cryptojwt import as_bytes
from cryptojwt.jwk import import_private_rsa_key_from_file
from cryptojwt.jwk import RSAKey
from oidcmsg.key_bundle import KeyBundle
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import KeyJar

# This represents a map between the local storage of algorithm choices
# and how they are represented in a provider info response.

ATTRMAP = {
    "userinfo": {
        "sign": "userinfo_signed_response_alg",
        "alg": "userinfo_encrypted_response_alg",
        "enc": "userinfo_encrypted_response_enc"},
    "id_token": {
        "sign": "id_token_signed_response_alg",
        "alg": "id_token_encrypted_response_alg",
        "enc": "id_token_encrypted_response_enc"},
    "request": {
        "sign": "request_object_signing_alg",
        "alg": "request_object_encryption_alg",
        "enc": "request_object_encryption_enc"}
}


class ServiceContext(object):
    """
    This class keeps information that a client needs to be able to talk
    to a server. Some of this information comes from configuration and some
    from dynamic provider info discovery or client registration.
    But information is also picked up during the conversation with a server.
    """

    def __init__(self, keyjar=None, config=None, **kwargs):
        self.keyjar = keyjar or KeyJar()
        self.provider_info = {}
        self.registration_response = {}
        self.kid = {"sig": {}, "enc": {}}

        if config is None:
            config = {}
        self.config = config

        # Below so my IDE won't complain
        self.base_url = ''
        self.requests_dir = ''
        self.allow = {}
        self.behaviour = {}
        self.client_preferences = {}
        self.client_id = ''
        self._c_secret = ''
        self.issuer = ''

        try:
            self.clock_skew = config['clock_skew']
        except KeyError:
            self.clock_skew = 15

        for key, val in kwargs.items():
            setattr(self, key, val)

        for attr in ['client_id', 'issuer', 'client_secret', 'base_url',
                     'requests_dir']:
            try:
                setattr(self, attr, config[attr])
            except:
                setattr(self, attr, '')

        for attr in ['allow', 'client_preferences', 'behaviour',
                     'provider_info']:
            try:
                setattr(self, attr, config[attr])
            except:
                setattr(self, attr, {})

        if self.requests_dir:
            # make sure the path exists. If not, then make it.
            if not os.path.isdir(self.requests_dir):
                os.makedirs(self.requests_dir)

        try:
            self.redirect_uris = config['redirect_uris']
        except:
            self.redirect_uris = []

        try:
            self.callback = config['callback']
        except KeyError:
            self.callback = {}

        try:
            self.import_keys(config['keys'])
        except KeyError:
            pass

        if 'keydefs' in config:
            self.keyjar = build_keyjar(config['keydefs'], keyjar=self.keyjar)[1]

    def get_client_secret(self):
        return self._c_secret

    def set_client_secret(self, val):
        if not val:
            self._c_secret = ""
        else:
            self._c_secret = val
            # client uses it for signing
            # Server might also use it for signing which means the
            # client uses it for verifying server signatures
            if self.keyjar is None:
                self.keyjar = KeyJar()
            self.keyjar.add_symmetric("", str(val))

    # since client secret is used as a symmetric key in some instances
    # some special handling is needed for the client_secret attribute
    client_secret = property(get_client_secret, set_client_secret)

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
        else:
            return _name

    def generate_request_uris(self, path):
        """
        Need to generate a redirect_uri path that is unique for a OP/RP combo
        This is to counter the mix-up attack.

        :param path: Leading path
        :return: A list of one unique URL
        """
        m = hashlib.sha256()
        try:
            m.update(as_bytes(self.provider_info['issuer']))
        except KeyError:
            m.update(as_bytes(self.issuer))
        m.update(as_bytes(self.base_url))
        if not path.startswith('/'):
            return ['{}/{}/{}'.format(self.base_url, path, m.hexdigest())]
        else:
            return ['{}{}/{}'.format(self.base_url, path, m.hexdigest())]

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
                            _kb = KeyBundle()
                            _kb.append(_key)
                            self.keyjar.add_kb('', _kb)
            elif where == 'url':
                for iss, url in spec.items():
                    kb = KeyBundle(source=url)
                    self.keyjar.add_kb(iss, kb)
