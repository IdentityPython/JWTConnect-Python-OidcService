import pytest

from oidcservice.service_factory import service_factory
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase

KEYDEF = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]


class TestRP():
    @pytest.fixture(autouse=True)
    def create_service(self):
        client_config = {
            'client_id': 'client_id',
            'client_secret': 'another password'
        }
        service_context = ServiceContext(config=client_config)
        db = InMemoryStateDataBase()
        self.service = {
            'token': service_factory("CCAccessToken",
                                     ['oauth2/client_credentials', 'oauth2'],
                                     state_db=db,
                                     service_context=service_context),
            'refresh_token': service_factory("CCRefreshAccessToken",
                                             ['oauth2/client_credentials',
                                              'oauth2'],
                                             state_db=db,
                                             service_context=service_context)
        }
        self.service['token'].endpoint = 'https://example.com/token'
        self.service['refresh_token'].endpoint = 'https://example.com/token'

    def test_token_get_request(self):
        request_args = {'grant_type': 'client_credentials'}
        _srv = self.service['token']
        _info = _srv.get_request_parameters(request_args=request_args)
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://example.com/token'
        assert _info['body'] == 'grant_type=client_credentials'
        assert _info['headers'] == {
            'Authorization': 'Basic Y2xpZW50X2lkOmFub3RoZXIrcGFzc3dvcmQ=',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def test_refresh_token_get_request(self):
        _srv = self.service['token']
        _srv.update_service_context({
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value"
        })
        _srv = self.service['refresh_token']
        _info = _srv.get_request_parameters()
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://example.com/token'
        assert _info[
                   'body'] == 'grant_type=refresh_token'
        assert _info['headers'] == {
            'Authorization': 'Bearer tGzv3JOkF0XG5Qx2TlKWIA',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
