import json
import os

import pytest
import responses
from cryptojwt.key_jar import init_key_jar

from oidcservice.client_auth import factory as ca_factory
from oidcservice.oauth2 import DEFAULT_SERVICES
from oidcservice.oidc.add_on import do_add_ons
from oidcservice.service import init_services
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = 'https://example.com'

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYSPEC, owner='')


class TestPushedAuth:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'behaviour': {'response_types': ['code']},
            'add_ons': {
                "pushed_authorization": {
                    "function":
                        "oidcservice.oidc.add_on.pushed_authorization"
                        ".add_pushed_authorization_support",
                    "kwargs": {
                        "body_format": "jws",
                        "signing_algorthm": "RS256",
                        "http_client": None,
                        "merge_rule": "lax"
                    }
                }
            }
        }
        _cam = ca_factory
        _srvs = DEFAULT_SERVICES
        service_context = ServiceContext(CLI_KEY, client_id='client_id',
                                         issuer='https://www.example.org/as',
                                         config=config)

        self.service = init_services(_srvs, service_context, InMemoryStateDataBase(), _cam)

        if 'add_ons' in config:
            do_add_ons(config['add_ons'], self.service)

        service_context.service = self.service
        service_context.provider_info = {
            "pushed_authorization_request_endpoint": "https://as.example.com/push"
        }

    def test_authorization(self):
        auth_service = self.service["authorization"]
        req_args = {'foo': 'bar', "response_type": "code"}
        with responses.RequestsMock() as rsps:
            _resp = {
                "request_uri": "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2",
                "expires_in": 3600
            }
            rsps.add("GET",
                     auth_service.service_context.provider_info[
                         "pushed_authorization_request_endpoint"],
                     body=json.dumps(_resp), status=200)

            _req = auth_service.construct(request_args=req_args, state='state')

        assert set(_req.keys()) == {"request_uri", "response_type", "client_id"}
