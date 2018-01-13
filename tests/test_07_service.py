import pytest
from oiccli.exception import WrongContentType
from oiccli.oauth2 import ClientInfo
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oicmsg.oauth2 import SINGLE_OPTIONAL_INT
from oicmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oicmsg.oauth2 import SINGLE_REQUIRED_STRING
from oiccli.service import Service


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

    def test_request_info(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.request_info(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'uri', 'cis'}
        assert _info['cis'].to_dict() == {'foo': 'bar',
                                          'req_str': 'some string'}
        msg = DummyMessage().from_urlencoded(
            self.service.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        self.service.endpoint = 'https://example.com/authorize'
        _info = self.service.do_request_init(self.cli_info,
                                             request_args=req_args)
        assert set(_info.keys()) == {'uri', 'cis', 'http_args'}
        assert _info['cis'].to_dict() == {'foo': 'bar',
                                          'req_str': 'some string'}
        assert _info['http_args'] == {}
        msg = DummyMessage().from_urlencoded(
            self.service.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        req_resp = Response(200, Message(foo='bar').to_urlencoded())
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   state='state')
        assert isinstance(resp, Message)
        assert set(resp.keys()) == {'foo'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(200, ErrorResponse(error='barsoap').to_urlencoded())
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   state='state')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(400, ErrorResponse(error='barsoap').to_urlencoded())
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   state='state')
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_json(self):
        req_resp = Response(200, Message(foo='bar').to_json(),
                            headers={'content-type': 'application/json'})
        resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                   response_body_type='json',
                                                   state='state')
        assert isinstance(resp, Message)
        assert set(resp.keys()) == {'foo'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(200, Message(foo='bar').to_json(),
                            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.service.parse_request_response(req_resp, self.cli_info,
                                                       response_body_type='json',
                                                       state='state')


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
