#

DEFAULT_SERVICES = {
    "discovery": {
        'class': 'oidcservice.oauth2.provider_info_discovery.ProviderInfoDiscovery'
    },
    'authorization': {
        'class': 'oidcservice.oauth2.authorization.Authorization'
    },
    'access_token': {
        'class': 'oidcservice.oauth2.access_token.AccessToken'
    },
    'refresh_access_token': {
        'class': 'oidcservice.oauth2.refresh_access_token.RefreshAccessToken'
    }
}
