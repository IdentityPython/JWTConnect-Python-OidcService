# oidcservice
#Implementation of OIDC/OAuth2 services

Oidcservice is the 3rd layer in the
JWTConnect stack (cryptojwt, oidcmsg, oidcservice, oidcrp)

An OIDC OP or an OAuth2 AS provides a set of services to be used by an
RP/client.

This package contains the necessary pieces to allow an RP/client to use those
services.

Each Service instance has 3 major methods:

  * get_request_parameters
  * parse_response
  * update_service_context

###get_request_parameters

This method will return a dictionary with the information you need to
do a HTTP request with your favorite HTTP client library.

For instance if you use the provider info dicovery Server subclass it could
look something like this:

```python
import requests

from oidcservice.service_context import ServiceContext
from oidcservice.oidc.service import ProviderInfoDiscovery

class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        try:
            return self.db[item]
        except KeyError:
            return None

service_context = ServiceContext
service_context.issuer = "https://accounts.google.com"
service_context.keyjar = None

service = ProviderInfoDiscovery(service_context, DB())

args = service.get_request_parameters(service_context)

# Do the HTTP request
http_resp = requests.request(**args)

# giassuming that we got a 200 response
oidc_response = service.parse_response(http_resp.text, service_context)

print(oidc_response.to_dict())
```

The output should then be a dictionary with the provider information for
Google's OP.