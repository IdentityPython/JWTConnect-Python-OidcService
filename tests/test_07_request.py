import pytest
from oiccli.exception import WrongContentType
from oiccli.oauth2 import ClientInfo
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oicmsg.oauth2 import SINGLE_OPTIONAL_INT
from oicmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oicmsg.oauth2 import SINGLE_REQUIRED_STRING
from oiccli.request import Request


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


class DummyRequest(Request):
    msg_type = DummyMessage


class TestDummyRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = DummyRequest()
        self.cli_info = ClientInfo(None, client_id='client_id',
                                   issuer='https://www.example.org/as')

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, Message)
        assert list(_req.keys()) == ['foo']

    def test_construct_cli_info(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, Message)
        assert set(_req.keys()) == {'foo', 'req_str'}

    def test_request_info(self):
        req_args = {'foo': 'bar', 'req_str': 'some string'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.request_info(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'body', 'uri', 'cis', 'h_args'}
        assert _info['body'] is None
        assert _info['cis'].to_dict() == {'foo': 'bar',
                                          'req_str': 'some string'}
        assert _info['h_args'] == {}
        msg = DummyMessage().from_urlencoded(self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_request_init(self):
        req_args = {'foo': 'bar', 'req_str':'some string'}
        self.req.endpoint = 'https://example.com/authorize'
        _info = self.req.do_request_init(self.cli_info, request_args=req_args)
        assert set(_info.keys()) == {'body', 'uri', 'cis', 'h_args',
                                     'http_args'}
        assert _info['body'] is None
        assert _info['cis'].to_dict() == {'foo': 'bar',
                                          'req_str': 'some string'}
        assert _info['h_args'] == {}
        assert _info['http_args'] == {}
        msg = DummyMessage().from_urlencoded(self.req.get_urlinfo(_info['uri']))
        assert msg == _info['cis']

    def test_parse_request_response_urlencoded(self):
        req_resp = Response(200, Message(foo='bar').to_urlencoded())
        resp = self.req.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, Message)
        assert set(resp.keys()) == {'foo'}

    def test_parse_request_response_200_error(self):
        req_resp = Response(200, ErrorResponse(error='barsoap').to_urlencoded())
        resp = self.req.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_400_error(self):
        req_resp = Response(400, ErrorResponse(error='barsoap').to_urlencoded())
        resp = self.req.parse_request_response(req_resp, self.cli_info)
        assert isinstance(resp, ErrorResponse)
        assert set(resp.keys()) == {'error'}

    def test_parse_request_response_json(self):
        req_resp = Response(200, Message(foo='bar').to_json(),
                            headers={'content-type': 'application/json'})
        resp = self.req.parse_request_response(req_resp, self.cli_info,
                                               body_type='json')
        assert isinstance(resp, Message)
        assert set(resp.keys()) == {'foo'}

    def test_parse_request_response_wrong_content_type(self):
        req_resp = Response(200, Message(foo='bar').to_json(),
                            headers={'content-type': "text/plain"})
        with pytest.raises(WrongContentType):
            resp = self.req.parse_request_response(req_resp, self.cli_info,
                                                   body_type='json')


class TestRequest(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self.req = Request(httplib=None, keyjar=None, client_authn_method=None)
        self.cli_info = ClientInfo(None)

    def test_construct(self):
        req_args = {'foo': 'bar'}
        _req = self.req.construct(self.cli_info, request_args=req_args)
        assert isinstance(_req, Message)
        assert list(_req.keys()) == ['foo']
