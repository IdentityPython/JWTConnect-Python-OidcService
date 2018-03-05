import pytest

from oidcservice.client_info import ClientInfo
from oidcservice.service import Service

from oidcmsg.oauth2 import Message
from oidcmsg.oauth2 import SINGLE_OPTIONAL_INT
from oidcmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oidcmsg.oauth2 import SINGLE_REQUIRED_STRING


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
    }


class Response(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/plain"}


class DummyService(Service):
    msg_type = DummyMessage


class TestDummyService(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = DummyService()
        self.cli_info = ClientInfo(client_id='client_id',
                                   issuer='https://www.example.org/as')
        self.cli_info.state_db['state'] = {}

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, Message)
        assert list(_req.keys()) == ['foo']

    def test_construct_cli_info(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, Message)
        assert set(_req.keys()) == {'foo', 'req_str'}

    def test_get_request_parameters(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = DummyMessage().from_urlencoded(
            self.service.get_urlinfo(_info['url']))

    def test_request_init(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.get_request_parameters(self.cli_info,
                                             request_args=req_args)
        assert set(_info.keys()) == {'url', 'method'}
        msg = DummyMessage().from_urlencoded(
            self.service.get_urlinfo(_info['url']))
        assert msg.to_dict() == {'foo': 'bar', 'req_str': 'some string'}


class TestRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = Service(httplib=None, keyjar=None,
                               client_authn_method=None)
        self.cli_info = ClientInfo(None)

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.service.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, Message)
        assert list(_req.keys()) == ['foo']
