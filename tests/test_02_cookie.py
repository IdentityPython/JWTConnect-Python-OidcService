from future.backports.http.cookies import SimpleCookie
from future.builtins import str as newstr

import datetime

import pytest
from six import PY2

from oiccli.exception import ImproperlyConfigured
from oiccli.cookie import CookieDealer
from oiccli.cookie import InvalidCookieSign
from oiccli.cookie import cookie_parts
from oiccli.cookie import cookie_signature
from oiccli.cookie import parse_cookie
from oiccli.cookie import verify_cookie_signature

__author__ = 'roland'


@pytest.fixture
def cookie_dealer():
    class DummyServer():
        def __init__(self):
            self.symkey = b"0123456789012345"

    return CookieDealer(DummyServer())


class TestCookieDealer(object):
    def test_create_cookie_value(self, cookie_dealer):
        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        value, timestamp, typ = cookie_dealer.get_cookie_value(kaka[1],
                                                               "Foobar")

        assert (value, typ) == (cookie_value, cookie_typ)

    def test_delete_cookie(self, cookie_dealer):
        cookie_name = "Foobar"
        kaka = cookie_dealer.delete_cookie(cookie_name)
        cookie_expiration = kaka[1].split(";")[1].split("=")[1]

        now = datetime.datetime.utcnow()  #
        cookie_timestamp = datetime.datetime.strptime(
            cookie_expiration, "%a, %d-%b-%Y %H:%M:%S GMT")
        assert cookie_timestamp < now

    def test_cookie_dealer_improperly_configured(self):
        class BadServer():
            def __init__(self):
                self.symkey = ""
        with pytest.raises(ImproperlyConfigured) as err:
            CookieDealer(BadServer())
        expected_msg = "CookieDealer.srv.symkey cannot be an empty value"
        assert expected_msg in str(err.value)

    def test_cookie_dealer_with_domain(self):
        class DomServer():
            def __init__(self):
                self.symkey = b"0123456789012345"
                self.cookie_domain = "op.example.org"

        cookie_dealer = CookieDealer(DomServer())

        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        C = SimpleCookie()
        if PY2:
            # the backported SimpleCookie wants py3 str
            C.load(newstr(kaka[1]))
        else:
            C.load(kaka[1])

        assert C[cookie_name]["domain"] == "op.example.org"

    def test_cookie_dealer_with_path(self):
        class DomServer():
            def __init__(self):
                self.symkey = b"0123456789012345"
                self.cookie_path = "/oidc"

        cookie_dealer = CookieDealer(DomServer())

        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        C = SimpleCookie()
        if PY2:
            # the backported SimpleCookie wants py3 str
            C.load(newstr(kaka[1]))
        else:
            C.load(kaka[1])

        assert C[cookie_name]["path"] == "/oidc"


def test_cookie_signature():
    key = b'1234567890abcdef'
    parts = ['abc', 'def']
    sig = cookie_signature(key, *parts)
    assert verify_cookie_signature(sig, key, *parts)


def test_broken_cookie_signature():
    key = b'1234567890abcdef'
    parts = ['abc', 'def']
    sig = cookie_signature(key, *parts)
    parts.reverse()
    assert not verify_cookie_signature(sig, key, *parts)


def test_parse_cookie():
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = b''
    name = 'pyoidc'
    result = parse_cookie(name, seed, kaka)
    assert result == ('bjmc::1463043535::upm', '1463043535')


def test_parse_manipulated_cookie_payload():
    kaka = ('pyoidc=bjmc::1463043536::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = b''
    name = 'pyoidc'
    with pytest.raises(InvalidCookieSign):
        parse_cookie(name, seed, kaka)


def test_parse_manipulated_cookie_timestamp():
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043537|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = b''
    name = 'pyoidc'
    with pytest.raises(InvalidCookieSign):
        parse_cookie(name, seed, kaka)


def test_cookie_parts():
    name = 'pyoidc'
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    result = cookie_parts(name, kaka)
    assert result == ['bjmc::1463043535::upm',
                      '1463043535',
                      '18a201305fa15a96ce4048e1fbb03f7715f86499']

