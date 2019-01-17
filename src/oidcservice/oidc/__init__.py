#
import inspect
import sys
from glob import glob
from os.path import basename
from os.path import dirname
from os.path import join

from oidcservice.service import Service
# from oidcservice.oauth2 import factory as oauth2_factory


DEFAULT_SERVICES = {
    'ProviderInfoDiscovery': {},
    'Registration': {},
    'Authorization': {},
    'AccessToken': {},
    'RefreshAccessToken': {},
    'UserInfo': {}
}

WF_URL = "https://{}/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

IDT2REG = {
    'sigalg': 'id_token_signed_response_alg',
    'encalg': 'id_token_encrypted_response_alg',
    'encenc': 'id_token_encrypted_response_enc'
}

ENDPOINT2SERVICE = {
    'authorization': ['authorization'],
    'token': ['accesstoken', 'refresh_token'],
    'userinfo': ['userinfo'],
    'registration': ['registration'],
    'end_sesssion': ['end_session']
}


# def factory(req_name, **kwargs):
#     pwd = dirname(__file__)
#     if pwd not in sys.path:
#         sys.path.insert(0, pwd)
#     for x in glob(join(pwd, '*.py')):
#         _mod = basename(x)[:-3]
#         if not _mod.startswith('__'):
#             # _mod = basename(x)[:-3]
#             if _mod not in sys.modules:
#                 __import__(_mod, globals(), locals())
#
#             for name, obj in inspect.getmembers(sys.modules[_mod]):
#                 if inspect.isclass(obj) and issubclass(obj, Service):
#                     try:
#                         if obj.__name__ == req_name:
#                             return obj(**kwargs)
#                     except AttributeError:
#                         pass
#
#     return oauth2_factory(req_name, **kwargs)