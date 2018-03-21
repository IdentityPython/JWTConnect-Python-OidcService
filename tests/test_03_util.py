import json
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AuthorizationRequest

from oidcservice import util
from oidcservice.util import JSON_ENCODED
from oidcservice.util import URL_ENCODED

__author__ = 'Roland Hedberg'


def test_get_http_url():
    url = u'https://localhost:8092/authorization'
    method = 'GET'
    values = {'acr_values': 'PASSWORD',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'redirect_uri':
                  'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
              'response_type': 'code', 'client_id': 'ok8tx7ulVlNV',
              'scope': 'openid profile email address phone'}
    request = AuthorizationRequest(**values)

    _url = util.get_http_url(url, request, method)
    _part = urlsplit(_url)
    _req = parse_qs(_part.query)
    assert set(_req.keys()) == {'acr_values', 'state', 'redirect_uri',
                                'response_type', 'client_id', 'scope'}


def test_get_http_body_default_encoding():
    values = {
        'redirect_uri':
            'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
        'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl'
                '/YLBBZDB9wefNExQlLDUIIDM2rT'
                '2t+gwuoRoapEXJyY2wrvg9cWTW2vxsZU+SuWzZlMDXc=',
        'grant_type': 'authorization_code'}
    request = AccessTokenRequest(**values)

    body = util.get_http_body(request)

    _req = parse_qs(body)
    assert set(_req.keys()) == {'code', 'grant_type', 'redirect_uri'}


def test_get_http_body_url_encoding():
    values = {
        'redirect_uri':
            'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
        'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl'
                '/YLBBZDB9wefNExQlLDUIIDM2rT'
                '2t+gwuoRoapEXJyY2wrvg9cWTW2vxsZU+SuWzZlMDXc=',
        'grant_type': 'authorization_code'}
    request = AccessTokenRequest(**values)

    body = util.get_http_body(request, URL_ENCODED)

    _req = parse_qs(body)
    assert set(_req.keys()) == {'code', 'grant_type', 'redirect_uri'}


def test_get_http_body_json():
    values = {
        'redirect_uri':
            'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
        'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl'
                '/YLBBZDB9wefNExQlLDUIIDM2rT'
                '2t+gwuoRoapEXJyY2wrvg9cWTW2vxsZU+SuWzZlMDXc=',
        'grant_type': 'authorization_code'}
    request = AccessTokenRequest(**values)

    body = util.get_http_body(request, JSON_ENCODED)

    _req = json.loads(body)
    assert set(_req.keys()) == {'code', 'grant_type', 'redirect_uri'}


def test_get_http_url_with_qp():
    url = u'https://localhost:8092/authorization?test=testslice'
    method = 'GET'
    values = {'acr_values': 'PASSWORD',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'redirect_uri':
                  'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
              'response_type': 'code', 'client_id': 'ok8tx7ulVlNV',
              'scope': 'openid profile email address phone'}
    request = AuthorizationRequest(**values)

    _url = util.get_http_url(url, request, method)
    _part = urlsplit(_url)
    _req = parse_qs(_part.query)
    assert set(_req.keys()) == {'acr_values', 'state', 'redirect_uri',
                                'response_type', 'client_id', 'scope',
                                'test'}
