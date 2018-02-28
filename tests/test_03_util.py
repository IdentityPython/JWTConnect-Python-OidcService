import json
import pytest

from urllib.parse import parse_qs
from urllib.parse import urlparse

from oiccli import util
from oiccli.util import JSON_ENCODED

from oicmsg.exception import UnSupported
from oicmsg.oic import AuthorizationRequest
from oicmsg.oic import AccessTokenRequest

__author__ = 'DIRG'


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def test_get():
    uri = u'https://localhost:8092/authorization'
    method = 'GET'
    values = {'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'redirect_uri':
                  'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
              'response_type': 'code',
              'client_id': u'ok8tx7ulVlNV',
              'scope': 'openid profile email address phone'}
    request = AuthorizationRequest(**values)

    resp = util.get_or_post(uri, method, request)

    assert set(resp.keys()) == {'url'}
    assert url_compare(resp['url'],
                       u"https://localhost:8092/authorization?state=urn%3A"
                       "uuid%3A92d81fb3-72e8-4e6c-9173-c360b782148a&"
                       "redirect_uri=https%3A%2F%2Flocalhost%3A8666"
                       "%2F919D3F697FDAAF138124B83E09ECB0B7&"
                       "response_type=code&client_id=ok8tx7ulVlNV&scope"
                       "=openid+profile+email+address+phone")


def test_post():
    method = 'POST'
    uri = u'https://localhost:8092/token'
    values = {
        'redirect_uri':
            'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
        'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl',
        'grant_type': 'authorization_code'}
    request = AccessTokenRequest(**values)
    kwargs = {'scope': '',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'authn_method': 'client_secret_basic', 'key': [],
              'headers': {'Authorization': 'Basic aGVqOmhvcHA='}}

    resp = util.get_or_post(uri, method, request, content_type=JSON_ENCODED,
                            **kwargs)
    assert set(resp.keys()) == {'url', 'body', 'kwargs'}

    assert resp['url'] == u'https://localhost:8092/token'
    assert json.loads(resp['body']) == request.to_dict()

    assert resp['kwargs'] == {
        'scope': '',
        'state':
            'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
        'authn_method': 'client_secret_basic', 'key': [],
        'headers': {'Content-Type':'application/json',
                    'Authorization': 'Basic aGVqOmhvcHA='}}


def test_unsupported():
    uri = u'https://localhost:8092/token'
    values = {
        'redirect_uri':
            'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
        'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl'
                '/YLBBZDB9wefNExQlLDUIIDM2rT'
                '2t+gwuoRoapEXJyY2wrvg9cWTW2vxsZU+SuWzZlMDXc=',
        'grant_type': 'authorization_code'}
    request = AccessTokenRequest(**values)
    kwargs = {'scope': '',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'authn_method': 'client_secret_basic', 'key': [],
              'headers': {
                  'Authorization': 'Basic '
                                   'b2s4dHg3dWxWbE5WOjdlNzUyZDU1MTc0NzA0NzQzYjZiZWJk'
                                   'YjU4ZjU5YWU3MmFlMGM5NDM4YTY1ZmU0N2IxMDA3OTM1'}
              }
    method = 'UNSUPPORTED'
    with pytest.raises(UnSupported):
        util.get_or_post(uri, method, request, **kwargs)


def test_match_to():
    str0 = "abc"
    str1 = "123"
    str3 = "a1b2c3"

    test_string = "{}{}{}".format(str0, str1, str3)
    assert util.match_to_(str0, test_string)
    assert not util.match_to_(str3, test_string)

    list_of_str = ["test_0", test_string, "test_1", str1]
    assert util.match_to_(str0, list_of_str)
    assert util.match_to_(str1, list_of_str)
    assert not util.match_to_(str3, list_of_str)
