#!/usr/bin/env python3
import json

import time

from oidcmsg.jwt import JWT
from oidcmsg.key_jar import KeyJar
from oidcmsg.oidc import AuthorizationResponse

from oidcservice.oidc import DEFAULT_SERVICES
from oidcservice.oidc.service import factory
from oidcservice.service import build_services
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import State
from oidcservice.state_interface import InMemoryStateDataBase


KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

JWKS_OP = {
    'keys':[{
        'd': 'mcAW1xeNsjzyV1M7F7_cUHz0MIR-tcnKFJnbbo5UXxMRUPu17qwRHr8ttep1Ie64r2L9QlphcT9BjYd0KQ8ll3flIzLtiJv__MNPQVjk5bsYzb_erQRzSwLJU-aCcNFB8dIyQECzu-p44UVEPQUGzykImsSShvMQhcvrKiqqg7NlijJuEKHaKynV9voPsjwKYSqk6lH8kMloCaVS-dOkK-r7bZtbODUxx9GJWnxhX0JWXcdrPZRb29y9cdthrMcEaCXG23AxnMEfp-enDqarLHYTQrCBJXs_b-9k2d8v9zLm7E-Pf-0YGmaoJtX89lwQkO_SmFF3sXsnI2cFreqU3Q',
        'e': 'AQAB',
        'kid': 'c19uYlBJXzVfNjNZeGVnYmxncHZwUzZTZDVwUFdxdVJLU3AxQXdwaFdfbw',
        'kty': 'RSA',
        'n': '3ZblhNL2CjRktLM9vyDn8jnA4G1B1HCpPh-gv2AK4m9qDBZPYZGOGqzeW3vanvLTBlqnPm0GHg4rOrfMEwwLrfMcgmg1y4GD0vVU8G9HP1-oUPtKUqaKOp313tFKzFh9_OHGQ6EmhxG7gegPR9kQXduTDXqBFi81MzRplIQ8DHLM3-n2CyDW1V-dhRVh-AM0ZcJyzR_DvZ3mhG44DysPdHQOSeWnpdn1d81-PriqZfhAF9tn1ihgtjXd5swf1HTSjLd7xv1hitGf2245Xmr-V2pQFzeMukLM3JKbTYbElsB7Zm0wZx49hZMtgx35XMoO04bifdbO3yLtTA5ovXN3fQ',
        'p': '88aNu59aBn0elksaVznzoVKkdbT5B4euhOIEqJoFvFbEocw9mC4k-yozIAQSV5FEakoSPOl8lrymCoM3Q1fVHfaM9Rbb9RCRlsV1JOeVVZOE05HUdz8zOIqLBDEGM_oQqDwF_kp-4nDTZ1-dtnGdTo4Cf7QRuApzE_dwVabUCTc',
        'q': '6LOHuM7H_0kDrMTwUEX7Aubzr792GoJ6EgTKIQY25SAFTZpYwuC3NnqlAdy8foIa3d7eGU2yICRbBG0S_ITcooDFrOa7nZ6enMUclMTxW8FwwvBXeIHo9cIsrKYtOThGplz43Cvl73MK5M58ZRmuhaNYa6Mk4PL4UokARfEiDus',
        'use': 'sig'
    },
    {
        'crv': 'P-256',
        'd': 'N2dg0-DAROBF8owQA4-uY5s0Ab-Fep_42kEFQG4BNVQ',
        'kid': 'UnpYbi0tWC1HaEtyRFMtSmkyZDVHUHZVNDF0d21KTVk1dzEwYmhpNlVtQQ',
        'kty': 'EC',
        'use': 'sig',
        'x': 'Ls8SqX8Ti5QAKtw3rdGr5K537-tqQCIbhyebeE_2C38',
        'y': 'S-BrbPQkh8HVFLWg5Wid_5OAk4ewn5skHlHtG08ShaA'
    }
]}

OP_KEYJAR = KeyJar()
OP_KEYJAR.import_jwks(JWKS_OP, '')
OP_PUBLIC_JWKS = OP_KEYJAR.export_jwks()
OP_BASEURL = "https://example.org/op"

RP_JWKS = {
    "keys": [{
        "kty": "RSA", "use": "sig",
        "kid": "Mk0yN2w0N3BZLWtyOEpQWGFmNDZvQi1hbDl2azR3ai1WNElGdGZQSFd6MA",
        "e": "AQAB",
        "n": "yPrOADZtGoa9jxFCmDsJ1nAYmzgznUxCtUlb_ty33-AFNEqzW_pSLr5g6RQAPGsvVQqbsb9AB18QNgz-eG7cnvKIIR7JXWCuGv_Q9MwoRD0-zaYGRbRvFoTZokZMB6euBfMo6kijJ-gdKuSaxIE84X_Fcf1ESAKJ0EX6Cxdm8hKkBelGIDPMW5z7EHQ8OuLCQtTJnDvbjEOk9sKzkKqVj53XFs5vjd4WUhxS6xIDcWE-lTafUpm0BsobklLePidHxyAMGOunL_Pt3RCLZGlWeWOO9fZhLtydiDWiZlcNR0FQEX_mfV1kCOHHBFN1VKOY2pyJpjp9djdtHxPZ9fP35w",
        "d": "aRBTqGDLYFaXuba4LYSPe_5Vnq8erFg1dzfGU9Fmfi5KCjAS2z5cv_reBnpiNTODJt3Izn7AJhpYCyl3zdWGl8EJ0OabNalY2txoi9A-LI4nyrHEDaRpfkgszVwaWtYZbxrShMc8I5x_wvCGx7sX7Hoy6YgQreRFzw8Fy86MDncpmcUwQTnXVUMLgioeYz5gW6rwXkqj_NVyuHPiheykJG026cXFNBWplCk4ET1bvf_6ZB9QmLwO16Pu2O-dtu1HHDOqI7y6-YgKIC6mcLrQrF9-FO7NkilcOB7zODNiYzhDBQ2YJAbcdn_3M_lkhaFwR-n4WB7vCM0vNqz7lEg6QQ",
        "p": "_STNoJFkX9_uw8whytVmTrHP5K7vcZBIH9nuCTvj137lC48ZpR1UARx4qShxHLfK7DrufHd7TYnJkEMNUHFmdKvkaVQMY0_BsBSvCrUl10gzxsI08hg53L17E1Pe73iZp3f5nA4eB-1YB-km1Cc-Xs10OPWedJHf9brlCPDLAb8",
        "q": "yz9T0rPEc0ZPjSi45gsYiQL2KJ3UsPHmLrgOHq0D4UvsB6UFtUtOWh7A1UpQdmBuHjIJz-Iq7VH4kzlI6VxoXhwE69oxBXr4I7fBudZRvlLuIJS9M2wvsTVouj0DBYSR6ZlAQHCCou89P2P6zQCEaqu7bWXNcpyTixbbvOU1w9k"},
    {
        "kty": "EC", "use": "sig",
        "kid": "ME9NV3VQV292OTA4T1pNLXZoVjd2TldVSjNrNEkycjU2ZjkycldQOTcyUQ",
        "crv": "P-256",
        "x": "WWoO_Exim-LOD1k8QPi_CdU8M_VUSF7DkJCKR7PFWhQ",
        "y": "EpxHNZp6ykyeLiS6r7l9ly2in1Zju7hnLk7RFraklxE",
        "d": "pepDloEcTyHnoEuqFirZ8hpt861piMDgiuvHIhhRSpM"}]
}

RP_KEYJAR = KeyJar()
RP_KEYJAR.import_jwks(RP_JWKS, '')
RP_KEYJAR.import_jwks(OP_PUBLIC_JWKS, OP_BASEURL)
RP_BASEURL = "https://example.com/rp"

SERVICE_PUBLIC_JWKS = RP_KEYJAR.export_jwks('')
OP_KEYJAR.import_jwks(SERVICE_PUBLIC_JWKS, RP_BASEURL)

# ---------------------------------------------------

service_spec = DEFAULT_SERVICES.copy()
service_spec.update({'WebFinger': {}})

service_context = ServiceContext(
    RP_KEYJAR,
    {
        "client_preferences":
            {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.org"],
                "response_types": ["code"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic",
                                               'client_secret_post'],
            },
        "redirect_uris": ["{}/authz_cb".format(RP_BASEURL)],
        "jwks_uri": "{}/static/jwks.json".format(RP_BASEURL)
    }
)

service = build_services(service_spec, factory, service_context=service_context)

service_context.service = service

# ======================== WebFinger ========================

info = service['webfinger'].get_request_parameters(resource='foobar@example.org')

print(info)

webfinger_response = json.dumps({
    "subject": "acct:foobar@example.org",
    "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer",
               "href": "https://example.org/op"}],
    "expires": "2018-02-04T11:08:41Z",
    'requests_dir': 'static'})

response = service['webfinger'].parse_response(webfinger_response)

print(response)

service['webfinger'].update_service_context(response)
print('service_context.issuer: {}'.format(service_context.issuer))

# =================== Provider info discovery ====================

info = service['provider_info'].get_request_parameters()

print('uri: {}'.format(info['url']))

provider_info_response = json.dumps({
    "version": "3.0",
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": True,
    "grant_types_supported": ["authorization_code",
                              "implicit",
                              "urn:ietf:params:oauth:grant-type:jwt-bearer",
                              "refresh_token"],
    "response_types_supported": ["code", "id_token",
                                 "id_token token",
                                 "code id_token",
                                 "code token",
                                 "code id_token token"],
    "response_modes_supported": ["query", "fragment",
                                 "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "claim_types_supported": ["normal", "aggregated",
                              "distributed"],
    "claims_supported": ["birthdate", "address",
                         "nickname", "picture", "website",
                         "email", "gender", "sub",
                         "phone_number_verified",
                         "given_name", "profile",
                         "phone_number", "updated_at",
                         "middle_name", "name", "locale",
                         "email_verified",
                         "preferred_username", "zoneinfo",
                         "family_name"],
    "scopes_supported": ["openid", "profile", "email",
                         "address", "phone",
                         "offline_access", "openid"],
    "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "request_object_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512", "none"],
    "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512"],
    "userinfo_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "id_token_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "request_object_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "userinfo_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "id_token_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "request_object_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "acr_values_supported": ["PASSWORD"],
    "issuer": OP_BASEURL,
    "jwks_uri": "{}/static/jwks_tE2iLbOAqXhe8bqh.json".format(OP_BASEURL),
    "authorization_endpoint": "{}/authorization".format(OP_BASEURL),
    "token_endpoint": "{}/token".format(OP_BASEURL),
    "userinfo_endpoint": "{}/userinfo".format(OP_BASEURL),
    "registration_endpoint": "{}/registration".format(OP_BASEURL),
    "end_session_endpoint": "{}/end_session".format(OP_BASEURL)})

resp = service['provider_info'].parse_response(provider_info_response)

print(resp)
service['provider_info'].update_service_context(resp)

print("service_context.provider_info['issuer']: {}".format(
    service_context.provider_info['issuer']))

print("service_context.provider_info['authorization_endpoint']: {}".format(
    service_context.provider_info['authorization_endpoint']))

# =================== Client registration ====================

info = service['registration'].get_request_parameters()

print()
print('--- client registration, request ----')
print('uri: {}'.format(info['url']))
print('body: {}'.format(info['body']))
print('headers: {}'.format(info['headers']))

now = int(time.time())

op_client_registration_response = json.dumps({
    "client_id": "zls2qhN1jO6A",
    "client_secret": "c8434f28cf9375d9a7f3b50dcfdf6a20d6e702e310066874f794817f",
    "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
    "registration_client_uri": "{}/registration?client_id=zls2qhN1jO6A".format(RP_BASEURL),
    "client_secret_expires_at": now+3600,
    "client_id_issued_at": now,
    "application_type": "web",
    "response_types": ["code"],
    "contacts": ["ops@example.com"],
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": ["{}/authz_cb".format(RP_BASEURL)]})

response = service['registration'].parse_response(op_client_registration_response)
service['registration'].update_service_context(response)

print()
print('--- client registration, response ----')
print('service_context.client_id: {}'.format(service_context.client_id))
print('service_context.client_secret: {}'.format(service_context.client_secret))

# =================== Authorization ====================

STATE = 'Oh3w3gKlvoM2ehFqlxI3HIK5'
NONCE = 'UvudLKz287YByZdsY3AJoPAlEXQkJ0dK'

info = service['authorization'].get_request_parameters(
    request_args={'state': STATE, 'nonce': NONCE})

print()
print('--- Authorization, request ----')
print('uri: {}'.format(info['url']))

op_authz_resp = {
    'state': 'Oh3w3gKlvoM2ehFqlxI3HIK5',
    'scope': 'openid',
    'code': 'Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01',
    'iss': OP_BASEURL,
    'client_id': 'zls2qhN1jO6A'}

_authz_rep = AuthorizationResponse(**op_authz_resp)
print(_authz_rep.to_urlencoded())
_resp = service['authorization'].parse_response(_authz_rep.to_urlencoded())
service['authorization'].update_service_context(_resp, key=STATE)
print()
print('--- Authorization registration, response ----')
print(_resp)

_json = service['authorization'].state_db.get(STATE)
_state = State().from_json(_json)

print('code: {}'.format(_state['auth_response']['code']))

# =================== Access token ====================

request_args = {'state': STATE,
                'redirect_uri': service_context.redirect_uris[0]}

info = service['accesstoken'].get_request_parameters(request_args=request_args)
print()
print('--- Access token, request ----')
print('uri: {}'.format(info['url']))
print('body: {}'.format(info['body']))
print('headers: {}'.format(info['headers']))

_jwt = JWT(OP_KEYJAR, OP_BASEURL, lifetime=3600, sign=True, sign_alg='RS256')
payload = {'sub': '1b2fc9341a16ae4e30082965d537', 'acr': 'PASSWORD',
           'auth_time': 1517736988, 'nonce': 'UvudLKz287YByZdsY3AJoPAlEXQkJ0dK'}
_jws = _jwt.pack(payload=payload, recv='zls2qhN1jO6A')

kid= 'Q02_vqrHbQiFNdzfxhXTnXi1jazfaNQI2SMkco6c1tQ'

_resp = {
    "state": "Oh3w3gKlvoM2ehFqlxI3HIK5",
    "scope": "openid",
    "access_token": "Z0FBQUFBQmFkdFF",
    "token_type": "Bearer",
    "id_token": _jws}

service_context.issuer = OP_BASEURL
_resp = service['accesstoken'].parse_response(json.dumps(_resp), state=STATE)
service['accesstoken'].update_service_context(_resp, key=STATE)
print()
print('--- Access token, response ----')
print(_resp)

# =================== User info ====================

request_args = {'state': STATE}

info = service['userinfo'].get_request_parameters(state=STATE)
print()
print('--- User info, request ----')
print('uri: {}'.format(info['url']))
print('headers: {}'.format(info['headers']))

op_resp = {"sub": "1b2fc9341a16ae4e30082965d537"}

_resp = service['userinfo'].parse_response(json.dumps(op_resp), state=STATE)
service['userinfo'].update_service_context(_resp, key=STATE)
print()
print('--- User info, response ----')
print(_resp)

print(service['userinfo'].get_state(STATE).keys())