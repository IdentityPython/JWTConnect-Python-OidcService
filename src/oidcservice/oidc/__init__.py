#

DEFAULT_SERVICES = {
    "discovery": {
        'class': 'oidcservice.oidc.provider_info_discovery'
                 '.ProviderInfoDiscovery'
    },
    'registration': {
        'class': 'oidcservice.oidc.registration.Registration'
    },
    'authorization': {
        'class': 'oidcservice.oidc.authorization.Authorization'
    },
    'access_token': {
        'class': 'oidcservice.oidc.access_token.AccessToken'
    },
    'refresh_access_token': {
        'class': 'oidcservice.oidc.refresh_access_token.RefreshAccessToken'
    },
    'userinfo': {
        'class': 'oidcservice.oidc.userinfo.UserInfo'
    }
}

WF_URL = "https://{}/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

IDT2REG = {
    'sigalg': 'id_token_signed_response_alg',
    'encalg': 'id_token_encrypted_response_alg',
    'encenc': 'id_token_encrypted_response_enc'
}

ENDPOINT2SERVICE = {
    'authorization': ['authorization'],
    'token': ['accesstoken', 'refresh_token'],
    'userinfo': ['userinfo'],
    'registration': ['registration'],
    'end_sesssion': ['end_session']
}
