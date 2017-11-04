import os

from jwkest import b64e
from oiccli import CC_METHOD
from oiccli import DEF_SIGN_ALG, unreserved
from oiccli.exception import Unsupported
from oiccli.grant import GrantDB
from oicmsg.key_jar import KeyJar

PARAMMAP = {
    "sign": "%s_signed_response_alg",
    "alg": "%s_encrypted_response_alg",
    "enc": "%s_encrypted_response_enc",
}


class ClientInfo(object):
    def __init__(self, keyjar=None, config=None, events=None, **kwargs):
        self.keyjar = keyjar or KeyJar()
        self.grant_db = GrantDB()
        self.state2nonce = {}
        self.provider_info = {}
        self.registration_response = {}
        self.kid = {"sig": {}, "enc": {}}

        # the OAuth issuer is the URL of the authorization server's
        # configuration information location
        self.config = config or {}

        self.base_url = ''
        self.requestsdir = ''
        for attr in ['client_id', 'issuer', 'client_secret', 'base_url',
                     'requests_dir']:
            try:
                setattr(self, attr, config[attr])
            except:
                setattr(self, attr, '')

        try:
            self.redirect_uris = config['redirect_uris']
        except:
            self.redirect_uris = [None]

        self.allow = {}
        self.provider_info = {}
        self.events = events
        self.behaviour = {}
        self.client_prefs = {}

        for key, val in kwargs.items():
            setattr(self, key, val)

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

    client_secret = property(get_client_secret, set_client_secret)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def filename_from_webname(self, webname, ):
        if not os.path.isdir(self.requestsdir):
            os.makedirs(self.requestsdir)

        assert webname.startswith(self.base_url)
        return webname[len(self.base_url):]

    def sign_enc_algs(self, typ):
        resp = {}
        for key, val in PARAMMAP.items():
            try:
                resp[key] = self.registration_response[val % typ]
            except (TypeError, KeyError):
                if key == "sign":
                    resp[key] = DEF_SIGN_ALG["id_token"]
        return resp

    def add_code_challenge(self):
        """
        PKCE RFC 7636 support

        :return:
        """
        try:
            cv_len = self.config['code_challenge']['length']
        except KeyError:
            cv_len = 64  # Use default

        code_verifier = unreserved(cv_len)
        _cv = code_verifier.encode()

        try:
            _method = self.config['code_challenge']['method']
        except KeyError:
            _method = 'S256'

        try:
            _h = CC_METHOD[_method](_cv).hexdigest()
            code_challenge = b64e(_h.encode()).decode()
        except KeyError:
            raise Unsupported(
                'PKCE Transformation method:{}'.format(_method))

        # TODO store code_verifier

        return {"code_challenge": code_challenge,
                "code_challenge_method": _method}, code_verifier

    def verify_alg_support(self, alg, usage, other):
        """
        Verifies that the algorithm to be used are supported by the other side.

        :param alg: The algorithm specification
        :param usage: In which context the 'alg' will be used.
            The following values are supported:
            - userinfo
            - id_token
            - request_object
            - token_endpoint_auth
        :param other: The identifier for the other side
        :return: True or False
        """

        try:
            supported = self.provider_info["%s_algs_supported" % usage]
        except KeyError:
            try:
                supported = getattr(self, "%s_algs_supported" % usage)
            except AttributeError:
                supported = None

        if supported is None:
            return True
        else:
            if alg in supported:
                return True
            else:
                return False
