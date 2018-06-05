.. _oidcservice_conversation:

**************
A conversation
**************

This section will walk you through what might happen when a user wants to
use OIDC to authenticate/authorize and the Relying Party (RP) has never seen
the OpenID Connect Provider (OP) before. This is an example of how dynamic
the interaction between an RP and an OP can be using OIDC.

We start from knowing absolutely nothing, having to use WebFinger to find the
OP. Then follows dynamic provider info discovery and client registration before
the user can be brought in and do the authentication/authorization bit.
And lastly the RP will ask for an access token and after that information
about the user.

Initial setup
=============

We need a couple of things initiated before we start.

state_db instance
    For this example we have an in-memory data store::

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

service_context
    Which is where information common to more then one service is kept.
    A :py:class:`oidcservice.service_context.ServiceContext` instance::

        BASEURL = "https://example.org/rp
        service_context = ServiceContext(
            KEYJAR,
            {
                "client_prefs":
                    {
                        "application_type": "web",
                        "application_name": "rphandler",
                        "contacts": ["ops@example.org"],
                        "response_types": ["code"],
                        "scope": ["openid", "profile", "email", "address", "phone"],
                        "token_endpoint_auth_method": ["client_secret_basic",
                                                       'client_secret_post'],
                    },
                "redirect_uris": ["{}/authz_cb".format(BASEURL)],
                "jwks_uri": "{}/static/jwks.json".format(BASEURL)
            }
        )



service specifications
    A dictionary of service class names and service configurations::

        service_spec = {
            'WebFinger': {},
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }

To initiate the services we need to run::

    from oidcservice.oic.service import factory
    from oidcservice.state_interface import InMemoryStateDataBase

    service = build_services(service_spec, factory,
                             state_db=InMemoryStateDataBase(),
                             service_context=service_context)


The resulting **service** is a dictionary with services identifiers as keys and
:py:class:`oidcservice.service.Service` instances as values::

    $ set(service.keys())
    {'accesstoken', 'authorization', 'webfinger', 'registration', 'userinfo', 'provider_info'}

That's all we have to do when it comes to setup so now on to the actual
conversation.

Webfinger
=========

We will use WebFinger (RFC7033) to find out where we can learn more about the
OP. What we have to start with is an user identifier provided by the user.
The identifier we got was: **foobar@example.com** .
With this information we can do::

    info = service['webfinger'].get_request_parameters(service_context, resource='foobar@example.com')

service['webfinger'] will return the WebFinger service instance and running
the method *get_request_parameters* will return the information necessary to do
a HTTP request. In this case the value of *info* will be::

    {
        'url': 'https://example.com/.well-known/webfinger?resource=acct%3Afoobar%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer'
    }

as you can see the *get_request_parameters* constructed a URL that can be used
to get the wanted information.

Doing HTTP GET on this URL will return a JSON document that looks like this::

    {
    "subject": "acct:foobar@example.com",
    "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer",
               "href": "https://example.com"}],
    "expires": "2018-02-04T11:08:41Z"}

To parse and use it I can run another method provide by the service instance::

    response = service['webfinger'].parse_response(webfinger_response,
                                                   service_context)

It's assumed that *webfinger_response* contains the JSON document mentioned
above. *parse_response* only parses the response.
So apart from that method we also need to invoke *update_service_context*::

    service['webfinger'].update_service_context(response)

The result of this is that the information in **service_context** will change.
We now has this::

    service_context.issuer: "https://example.com"

And that is all we need to fetch the provider info

Provider info discovery
=======================

We use the same process as with webfinger but with another service instance::

    info = service['provider_info'].get_request_parameters()

*info* will now contain::

    {'url': 'https://example.com/.well-known/openid-configuration'}

And this is the first example of **magic** that you will see.

*get_request_parameters knows how to contruct the OpenID Connect providers discovery URL
from information stored in the service_context instance. Now, if you don't wanted to do
webfinger because for instance the other side did not provide that service.
Then you would have to set *service_context.issuer* to the correct value.

Doing HTTP GET on the provided URL should get us the provider info.
It does and we get a JSON document that looks something like this::

    {
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
    "issuer": "https://example.com",
    "jwks_uri": "https://example.com/static/jwks_tE2iLbOAqXhe8bqh.json",
    "authorization_endpoint": "https://example.com/authorization",
    "token_endpoint": "https://example.com/token",
    "userinfo_endpoint": "https://example.com/userinfo",
    "registration_endpoint": "https://example.com/registration",
    "end_session_endpoint": "https://example.com/end_session"}

Quite a lot of information as you can see.
We feed this information into *parse_response* and *update_service_context* and
let them do their business::

    resp = service['provider_info'].parse_response(json_document)

    service['provider_info'].update_service_context(resp)

*json_document* contains the JSON document from the HTTP response.
*parse_response* will parse and verify the response. One such verification is
to check that the value provided as **issuer** is the same as the URL used
to fetch the information without the '.well-known' part. In our case the
exact value that the webfinger query produced.

As with the *webfinger* service *update_service_context* adds things to **service_context**.
So we now have::

    service_context.provider_info['issuer']: https://example.com
    service_context.provider_info['authorization_endpoint']: https://example.com/authorization


As you can guess from the above the whole response from the OP was stored in
the service_context instance. Such that it is easily accessible in the future.

Now we know what we need to know to register the RP with the OP.
If the OP had not provided a 'registration_endpoint' it would not have
supported dynamic client registration but this one has so it does.

Client registration
===================

By now you should recognize the pattern::

    info = service['registration'].get_request_parameters()

Now *info* contains 3 parts:

    uri
        The URL to which the HTTP request should be sent
    body
        A JSON document that should go in the body of the HTTP request
    http_args:
        HTTP arguments to be used with the request

and we got::

    uri: https://example.com/registration
    body: {
        "application_type": "web",
        "response_types": ["code"],
        "contacts": ["ops@example.org"],
        "jwks_uri": "https://example.org/static/jwks.json",
        "token_endpoint_auth_method":
        "client_secret_basic",
        "redirect_uris": ["https://example.org/authz_cb"]
        }
    http_args: {'headers': {'Content-Type': 'application/json'}}

The information in the body comes from the client configuration.
If we use this information and does an HTTP POST to the provided URL we will
receive a response like this::

    {
    "client_id": "zls2qhN1jO6A",
    "client_secret": "c8434f28cf9375d9a7f3b50dcfdf6a20d6e702e310066874f794817f",
    "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
    "registration_client_uri": "https://localhost:8080/oicrp/registration?client_id=zls2qhN1jO6A",
    "client_secret_expires_at": 1517823388,
    "client_id_issued_at": 1517736988,
    "application_type": "web",
    "response_types": ["code"],
    "contacts": ["ops@example.com"],
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": ["https://example.com/authz_cb"]
    }

Again a JSON document. This is the OP's response to the RP's registration
request.

We stuff the response into *json_document* and feed it to
*parse_response* which will parse, verify and interpret the response and then
*update_service_context* which updates *service_context*::

    response = service['registration'].parse_response(json_document,
                                                      service_context)
    service['registration'].update_service_context(response)

The information stored in *service_context* is most under the heading
*registration_response* but some, more important, will be stored at a
directly reachable place::

    service_context.client_id: zls2qhN1jO6A
    service_context.client_secret: c8434f28cf9375d9a7f3b50dcfdf6a20d6e702e310066874f794817f

By that we have finalized the dynamic discovery and registration now we can get
down to doing the authentication/authorization bits.

Authorization
=============

In the following example I'm using code flow since that allows me to show
more of what the oidcservice package can do.

Like when I used the other services this one is no different::

    info = service['authorization'].get_request_parameters(service_context)

*info* will only contain one piece of data and that is a URL::

    uri: https://example.com/authorization?state=Oh3w3gKlvoM2ehFqlxI3HIK5&nonce=UvudLKz287YByZdsY3AJoPAlEXQkJ0dK&response_type=code&client_id=zls2qhN1jO6A&scope=openid&redirect_uri=https%3A%2F%2Fexample.org%2Fauthz_cb

Where did all the information come from ?:

    - the authorization endpoint comes from the dynamic provider info discovery,
    - client_id from the client registration,
    - response_type, scope and redirect_uri from the client configuration and
    - state and nonce are dynamically created by the service instance.

When this *service* instance creates a request it will also create a *session*
instance in *state_db* keyed on the state value.

I do HTTP GET on the provided URL and will eventually get redirected back to
the RP with the response in the query part of the redirect URL.
Below you have just the query component::

    state=Oh3w3gKlvoM2ehFqlxI3HIK5&scope=openid&code=Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01aQWJ1Y3Y1MWFfMTVXXzhEcll2a0lkd0Z2Qk9lOHYtTUZjRnRjUzhNc1FOdm9RMGJ5aXhNUUtYSkdldTItRnBFVFV5YkhIVE5Gbk1VY2x2YmRuQXhxTEFSV2d6Zi1IaHE3SklpdndGbzRHR2tfT0Rwck5RTW1TalRwRUg0SE5JSUJtSC1lZU5HTXRjdkZXWXUzT3VodF8tdFhtX2NURFNiRXVhX1pFTFk1SXZ6NWhvSEdyXzNQRXVfZU9uTS1GZnB1dnVkYmRZSkh4VDdPWENlQ240al9GSkdFa1I0Yz0%3D&iss=https%3A%2F%2Fexample.com&client_id=zls2qhN1jO6A

I feed the *query_part* into the *parse_response* method of the authorization
service instance and hope for the best::

    _resp = service['authorization'].parse_response(query_part)
    service['authorization'].update_service_context(_resp)

Now as mentioned above one thing that happened when the authorization request
was constructed was that some information of that request got stored away with
the *state* value as key. All in the state_db instance.

The response on the authorization query will be stored in the same place.
To get the code I can now use::

    from oidcmsg.oidc import AuthorizationResponse

    authn_response = service_context.get_item(AuthorizationResponse,
                                              'auth_response',
                                              'Oh3w3gKlvoM2ehFqlxI3HIK5')
    code = authn_response['code']

State information will be use when we take the next step, which is to get
an access token.

Access token
============

When sending an access token request I have to use the correct *code* value.
To accomplish that *get_request_parameters* need to get state as an argument::

    request_args = {'state': _state}

    info = service['accesstoken'].get_request_parameters(service_context,
                                                         request_args=request_args)

The OIDC standard says that the *redirect_uri* used for the authorization request
should be provided in the access token request, therefor the service will add it
if I don't.

This time *info* has these parts::

    uri: https://example.com/token
    body: grant_type=authorization_code&state=Oh3w3gKlvoM2ehFqlxI3HIK5&redirect_uri=https%3A%2F%2Fexample.org%2Fauthz_cb&code=Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01aQWJ1Y3Y1MWFfMTVXXzhEcll2a0lkd0Z2Qk9lOHYtTUZjRnRjUzhNc1FOdm9RMGJ5aXhNUUtYSkdldTItRnBFVFV5YkhIVE5Gbk1VY2x2YmRuQXhxTEFSV2d6Zi1IaHE3SklpdndGbzRHR2tfT0Rwck5RTW1TalRwRUg0SE5JSUJtSC1lZU5HTXRjdkZXWXUzT3VodF8tdFhtX2NURFNiRXVhX1pFTFk1SXZ6NWhvSEdyXzNQRXVfZU9uTS1GZnB1dnVkYmRZSkh4VDdPWENlQ240al9GSkdFa1I0Yz0%3D&client_id=zls2qhN1jO6A
    http_args: {'headers': {'Authorization': 'Basic emxzMnFoTjFqTzZBOmM4NDM0ZjI4Y2Y5Mzc1ZDlhN2YzYjUwZGNmZGY2YTIwZDZlNzAyZTMxMDA2Njg3NGY3OTQ4MTdm', 'Content-Type': 'application/x-www-form-urlencoded'}}

*uri* was picked from the discovered provider info.
The Authorization header looks like it does because the default client
authentication method is defined to be 'client_secret_basic'.
The body is, a bit surprising but according to the standard, urlencoded.

The response has this JSON document in the body::

    {
    'state': 'Oh3w3gKlvoM2ehFqlxI3HIK5',
    'scope': 'openid',
    'access_token': 'Z0FBQUFBQmFkdFFjc0hyU2lialZyUkhvQjliUjU2R3hTQWZ4cDZFMnRTdGxkV3VoQmppZllyN2htWHlhU2Ria0tRV2NqcjEwOG5acWEzbzR3ZUNYTlFGTUJ6T1hpOGhzZE5UTndaYV9WcmJBdFcwTmRIWjJPZXlKUHBXWVYteEM3aE9BMGF1YWQyeVZiZGVZZExtOGpHT1dpMHNVUzRCMkdFRVFROHJIMkNTdUp0X0xlWHlMeGRJUTh5cW5LMFF3ZG5FbzBpbWlrTFUxcFkzbG9ORl92cll1MC02RjFZMDBNbnB4enpNcHVEMXRxSmtHSEtWQXlrTT0=',
    'token_type': 'Bearer',
    'id_token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6IlEwMl92cXJIYlFpRk5kemZ4aFhUblhpMWphemZhTlFJMlNNa2NvNmMxdFEifQ.eyJpc3MiOiAiaHR0cHM6Ly9sb2NhbGhvc3Q6ODA4MC9vaWNycC9ycC11c2VyaW5mby1iZWFyZXItaGVhZGVyIiwgInN1YiI6ICIxYjJmYzkzNDFhMTZhZTRlMzAwODI5NjVkNTM3YWU0N2MyMWEwZjI3ZmQ0M2VhYjc4MzMwZWQ4MTc1MWFlNmRiIiwgImF1ZCI6IFsiemxzMnFoTjFqTzZBIl0sICJleHAiOiAxNTE3ODIzMzg4LCAiYWNyIjogIlBBU1NXT1JEIiwgImlhdCI6IDE1MTc3MzY5ODgsICJhdXRoX3RpbWUiOiAxNTE3NzM2OTg4LCAibm9uY2UiOiAiVXZ1ZExLejI4N1lCeVpkc1kzQUpvUEFsRVhRa0owZEsifQ.cOJYa-yNeVgHeitol2Zw3Z3TYh9Fxys8BwAmACSZEYzwNnt1DwSfvhLTOeSFcAh2vsrvmNh2HqOy4plnH5-uB-KIEJY3E9GTmmK5uZDGvtSfMXqq2M45MA-71lJx2xrWwE5aH59WWJkEOY9s-gl0KJyMh7VFFP-B86d_16rg2hB6y9ajH5ieR9mc_E0RdwZVDLF_uBcWj0tLiTH2AaZK4akCAiFUant261M2OQnreJ7D6WPfZl_UHYPCm_6nhazvrQuovj9ahxAnqkg3UFBSycX4qr1brfi1Ak-xKRdTQ08NYJwtC8JVxSM0ic3E2XsOIW0hThofKwQUiolWW4yq0Q',
    }

We will deal with this in the now well know fashion::

    _resp = service['accesstoken'].parse_response(json_document, state='Oh3w3gKlvoM2ehFqlxI3HIK5')

    service['accesstoken'].update_service_context(_resp, state='Oh3w3gKlvoM2ehFqlxI3HIK5')

Note that we need to provide the methods with the *state* parameter so they will
know where to find the correct information needed to verify the response and
later store the received information.

Once the verification has been done one parameter will be added to the
response before it is stored in the state database, namely::

    'verified_id_token': {
        'iss': 'https://localhost:8080/oicrp/rp-userinfo-bearer-header',
        'sub': '1b2fc9341a16ae4e30082965d537ae47c21a0f27fd43eab78330ed81751ae6db',
        'aud': ['zls2qhN1jO6A'],
        'exp': 1517823388,
        'acr': 'PASSWORD',
        'iat': 1517736988,
        'auth_time': 1517736988,
        'nonce': 'UvudLKz287YByZdsY3AJoPAlEXQkJ0dK'}

Here you have the content of the ID Token revealed.

And finally the last step, getting the user info.

User info
=========

Again we have to provide the *get_request_parameters* method with the correct state
value::

    info = service['userinfo'].get_request_parameters(service_context,
                                               state='Oh3w3gKlvoM2ehFqlxI3HIK5')

And the response is a JSON document::

    {"sub": "1b2fc9341a16ae4e30082965d537ae47c21a0f27fd43eab78330ed81751ae6db"}

Only the *sub* parameter because the asked for scope was 'openid'.

Parsing, verifying and storing away the information is done the usual way::

    _resp = service['userinfo'].parse_response(json_document,state='Oh3w3gKlvoM2ehFqlxI3HIK5')
    service['userinfo'].update_service_context(_resp, state='Oh3w3gKlvoM2ehFqlxI3HIK5')

And we are done !! :-)

In the state_db we have the following information::

    $ list(service['userinfo'].get_state(STATE).keys())
    ['iss', 'auth_request', 'auth_response', 'token_response', 'user_info']
