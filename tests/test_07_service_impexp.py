from oidcmsg.item import DLDict
from oidcmsg.oauth2 import Message
from oidcmsg.oauth2 import SINGLE_OPTIONAL_INT
from oidcmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oidcmsg.oauth2 import SINGLE_REQUIRED_STRING
import pytest

from oidcservice.oidc import DEFAULT_SERVICES
from oidcservice.service import Service
from oidcservice.service import init_services
from oidcservice.service_context import ServiceContext


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


class TestRequest(object):
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service_context = ServiceContext(None)
        self.service = Service(self.service_context, client_authn_method=None)

    def test_construct(self):
        _srv = Service(service_context=self.service_context).load(
            self.service.dump(exclude_attributes=["service_context"]))

        req_args = {'foo': 'bar'}
        _req = _srv.construct(request_args=req_args)
        assert isinstance(_req, Message)
        assert list(_req.keys()) == ['foo']


def test_init_service_imp_exp_dict():
    service_context = ServiceContext(None)
    service = init_services(DEFAULT_SERVICES, service_context,
                            client_authn_factory=None)
    assert set(service.keys()) == {'provider_info', 'registration', 'authorization',
                                   'accesstoken', 'refresh_token', 'userinfo'}
    auth_service = service["authorization"]
    auth_service.default_authn_method = "foobar"
    dump = service.dump(exclude_attributes=["service_context"])

    service_copy = DLDict()
    service_copy.load(dump, init_args={"service_context": service_context})

    assert set(service_copy.keys()) == {'provider_info', 'registration', 'authorization',
                                        'accesstoken', 'refresh_token', 'userinfo'}
    auth_service_copy = service_copy["authorization"]

    assert auth_service_copy.default_authn_method == "foobar"
