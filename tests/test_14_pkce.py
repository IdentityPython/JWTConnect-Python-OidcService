import os

import pytest
from cryptojwt.key_jar import init_key_jar
from oidcmsg.message import Message
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oauth2 import AuthorizationResponse

from oidcservice.client_auth import factory as ca_factory
from oidcservice.oauth2 import DEFAULT_SERVICES
from oidcservice.oidc.add_on import do_add_ons
from oidcservice.oidc.add_on.pkce import add_code_challenge
from oidcservice.oidc.add_on.pkce import add_code_verifier
from oidcservice.service import Service
from oidcservice.service import init_services
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase
from oidcservice.state_interface import State


class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
    }


class DummyService(Service):
    msg_type = DummyMessage


_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = 'https://example.com'

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYSPEC, owner='client_id')


class TestPKCE256:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'behaviour': {'response_types': ['code']},
            'add_ons': {
                "pkce": {
                    "function": "oidcservice.oidc.add_on.pkce.add_pkce_support",
                    "kwargs": {
                        "code_challenge_length": 64,
                        "code_challenge_method": "S256"
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

    def test_add_code_challenge_default_values(self):
        auth_serv = self.service["authorization"]
        _state = State(iss='Issuer')
        auth_serv.state_db.set('state', _state.to_json())
        request_args, _ = add_code_challenge({'state': 'state'}, auth_serv)

        # default values are length:64 method:S256
        assert set(request_args.keys()) == {'code_challenge', 'code_challenge_method',
                                            'state'}
        assert request_args['code_challenge_method'] == 'S256'

        request_args = add_code_verifier({}, auth_serv, state='state')
        assert len(request_args['code_verifier']) == 64

    def test_authorization_and_pkce(self):
        auth_serv = self.service["authorization"]
        _state = State(iss='Issuer')
        auth_serv.state_db.set('state', _state.to_json())

        request = auth_serv.construct_request({"state": 'state', "response_type": "code"})
        assert set(request.keys()) == {'client_id', 'code_challenge',
                                       'code_challenge_method', 'state',
                                       'redirect_uri', 'response_type'}

    def test_access_token_and_pkce(self):
        authz_service = self.service["authorization"]
        request = authz_service.construct_request({"state": 'state', "response_type": "code"})
        _state = request['state']
        auth_response = AuthorizationResponse(code='access code')
        authz_service.store_item(auth_response, 'auth_response', _state)

        token_service = self.service["accesstoken"]
        request = token_service.construct_request(state=_state)
        assert set(request.keys()) == {'client_id', 'redirect_uri', 'grant_type',
                                       'client_secret', 'code_verifier', 'code',
                                       'state'}


class TestPKCE384:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'add_ons': {
                "pkce": {
                    "function": "oidcservice.oidc.add_on.pkce.add_pkce_support",
                    "kwargs": {
                        "code_challenge_length": 128,
                        "code_challenge_method": "S384"
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

    def test_add_code_challenge_spec_values(self):
        auth_serv = self.service["authorization"]
        request_args, _ = add_code_challenge({'state': 'state'}, auth_serv)
        assert set(request_args.keys()) == {'code_challenge', 'code_challenge_method',
                                            'state'}
        assert request_args['code_challenge_method'] == 'S384'

        request_args = add_code_verifier({}, auth_serv, state='state')
        assert len(request_args['code_verifier']) == 128
