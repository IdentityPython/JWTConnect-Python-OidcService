from oiccli.client_info import ClientInfo, add_code_challenge


def test_client_info_init():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests'
    }
    ci = ClientInfo(config=config)
    for attr in config.keys():
        val = getattr(ci, attr)
        assert val == config[attr]


def test_client_secret():
    ci = ClientInfo()
    ci.client_secret = 'supersecret'
    assert ci.client_secret == 'supersecret'


def test_client_filename():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests'
    }
    ci = ClientInfo(config=config)
    fname = ci.filename_from_webname('https://example.com/rq12345')
    assert fname == 'rq12345'


def test_sign_enc_algs():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests'
    }
    ci = ClientInfo(config=config)
    ci.registration_response = {
        "application_type": "web",
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example",
        "client_name#ja-Jpan-JP": "クライアント名",
        "logo_uri": "https://client.example.org/logo.png",
        "subject_type": "pairwise",
        "sector_identifier_uri":
            "https://other.example.net/file_of_redirect_uris.json",
        "token_endpoint_auth_method": "client_secret_basic",
        "jwks_uri": "https://client.example.org/my_public_keys.jwks",
        "userinfo_encrypted_response_alg": "RSA1_5",
        "userinfo_encrypted_response_enc": "A128CBC-HS256",
        "contacts": ["ve7jtb@example.org", "mary@example.org"],
        "request_uris": ["https://client.example.org/cb"]
    }

    res = ci.sign_enc_algs('userinfo')
    assert res == {'sign': 'RS256', 'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'}


def test_verify_alg_support():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests'
    }
    ci = ClientInfo(config=config)

    ci.provider_info = {
        "version": "3.0",
        "issuer": "https://server.example.com",
        "authorization_endpoint":
            "https://server.example.com/connect/authorize",
        "token_endpoint": "https://server.example.com/connect/token",
        "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                  "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "userinfo_endpoint": "https://server.example.com/connect/userinfo",
        "check_session_iframe":
            "https://server.example.com/connect/check_session",
        "end_session_endpoint":
            "https://server.example.com/connect/end_session",
        "jwks_uri": "https://server.example.com/jwks.json",
        "registration_endpoint":
            "https://server.example.com/connect/register",
        "scopes_supported": ["openid", "profile", "email", "address",
                             "phone", "offline_access"],
        "response_types_supported": ["code", "code id_token", "id_token",
                                     "token id_token"],
        "acr_values_supported": ["urn:mace:incommon:iap:silver",
                                 "urn:mace:incommon:iap:bronze"],
        "subject_types_supported": ["public", "pairwise"],
        "userinfo_signing_alg_values_supported": ["RS256", "ES256",
                                                  "HS256"],
        "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
        "userinfo_encryption_enc_values_supported": ["A128CBC+HS256",
                                                     "A128GCM"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256",
                                                  "HS256"],
        "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
        "id_token_encryption_enc_values_supported": ["A128CBC+HS256",
                                                     "A128GCM"],
        "request_object_signing_alg_values_supported": ["none", "RS256",
                                                        "ES256"],
        "display_values_supported": ["page", "popup"],
        "claim_types_supported": ["normal", "distributed"],
        "claims_supported": ["sub", "iss", "auth_time", "acr", "name",
                             "given_name", "family_name", "nickname",
                             "profile",
                             "picture", "website", "email",
                             "email_verified",
                             "locale", "zoneinfo",
                             "http://example.info/claims/groups"],
        "claims_parameter_supported": True,
        "service_documentation":
            "http://server.example.com/connect/service_documentation.html",
        "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR",
                                 "fr-CA"]
    }

    assert ci.verify_alg_support('RS256', 'id_token', 'signing_alg')
    assert ci.verify_alg_support('RS512', 'id_token', 'signing_alg') is False

    assert ci.verify_alg_support('RSA1_5', 'userinfo', 'encryption_alg')

    # token_endpoint_auth_signing_alg_values_supported
    assert ci.verify_alg_support('ES256', 'token_endpoint_auth', 'signing_alg')


def test_add_code_challenge_default():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests',
    }
    ci = ClientInfo(config=config)

    spec, verifier = add_code_challenge(ci)
    assert set(spec.keys()) == {'code_challenge', 'code_challenge_method'}
    assert spec['code_challenge_method'] == 'S256'