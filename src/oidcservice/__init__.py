import hashlib
import string

# Since SystemRandom is not available on all systems
try:
    import random.SystemRandom as rnd
except ImportError:
    import random as rnd

__author__ = 'Roland Hedberg'
__version__ = '0.5.8'


OIDCONF_PATTERN = "{}/.well-known/openid-configuration"
CC_METHOD = {
    'S256': hashlib.sha256,
    'S384': hashlib.sha384,
    'S512': hashlib.sha512,
}

# Map the signing context to a signing algorithm
DEF_SIGN_ALG = {"id_token": "RS256",
                "userinfo": "RS256",
                "request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}

HTTP_ARGS = ["headers", "redirections", "connection_type"]

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SAML2_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer"


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([rnd.choice(_basech) for _ in range(size)])


BASECH = string.ascii_letters + string.digits + '-._~'


def unreserved(size=64):
    """
    Returns a string of random ascii characters, digits and unreserved
    characters

    :param size: The length of the string
    :return: string
    """

    return "".join([rnd.choice(BASECH) for _ in range(size)])


def sanitize(str):
    return str
