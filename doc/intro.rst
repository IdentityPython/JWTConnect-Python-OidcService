.. _oiccli_intro:

**********************
Introduction to oiccli
**********************

OpenID Connect and OAuth2 (O/O) are both request-response protocols.
The client sends a request and the server responds either direct on the
same connection or after a while on another connection.

The client here is a piece of software that implements O/O and works on behalf
of an application.

The client follows the same pattern disregarding which request/response
it is dealing with. I does the following when sending a request:

    1. Gathers the request arguments
    2. If client authentication is involved it gathers the necessary data for
        that
    3. If the chosen client authentication method involved adding information
        to the request it does so.
    4. Adds information to the HTTP headers like Content-Type
    5. Serializes the request into the expected format

after that follows the act of sending the request to the server and receiving
the response from it.
Once the response have been received, The client will follow this path:

    1. Deserialize the received message into a internal format
    2. Verify that the message was correct. That it contains the required
        claims and that all claims are of the correct data type. If it's signed
        and/or encrypted verify signature and/or decrypt.
    3. Store the received information in a data base and/or passes it on to
        the application.

oiccli is built to allow clients to be constructed that supports any number
and type of of request-response services. The basic Open ID Connect set is:

    - Webfinger
    - Dynamic provider information discovery
    - Dynamic client registration
    - Authorization/Authentication request
    - Access token request
    - User info request

To these one can add services like session management and token introspection.
The only thing we can be sure of is that this is not the final set of
services, there will be more. And there will be variants of the standard ones.
Like when you want to add multi lateral federation support to provider
information discovery and client registration.

Over all it seemed like a good idea to write a piece of code that implements
all the functionality that is needed to support any of this services and
any future services that follows the same pattern.

That is the thought behind :py:class:`oiccli.service.Service` .

This class contains 2 pipe lines, one for the request construction and one
for response parsing. The interface to HTTP is kept to a minimum to allow
users of oiccli to chose their favorite HTTP client/server libraries.

The class has a number of attributes:

    msg_type
        The message subclass that describes the request.
        Default is oicmsg.message.Message

    response_cls
        The message subclass that describes the response
        Default is oicmsg.message.Message

    error_msg
        The message subclass that describes an error response
        Default is oicmsg.message.oauth2.ErrorResponse

    endpoint_name
        The name of the endpoint on the server that the request should be
        sent to.
        No default

    synchronous
        *True* if the response will be returned as a direct response to the
        request. The only exception right now to this is the Authorization
        request where the response is delivered to the client at some later
        date.
        Default is *True*

    request
        A name of the service. Later when a RP/client is implemented instances
        of different services are found by using this name.
        No default

    default_authn_method
        The client authentication method to use if nothing else is specified.
        Default is '' which means none.

    http_method
        Which HTTP method to use when sending the request.
        Default is **GET**

    body_type
        The serialization method to be used for the request
        Default is *urlencoded*

    response_body_type
        The deserialization method to use on the response
        Default is *json*


--------------------
The request pipeline
--------------------

Below follows a desciption of the parts of the request pipeline in the order
they are called.

The overall call sequence looks like this:

   - `do_request_init`_
        + `request_info`_
            * `construct`_
                - `do_pre_construct`_ (#)
                - `gather_request_args`_
                - `do_post_construct`_ (#)
            * `init_authentication_method`_
            * `uri_and_body`_
                - `endpoint`_
        + `update_http_args`_

The result of the request pipeline is a dictionary that in its simplest form
will look something like this::

    {
        'uri' : 'https://example.com/authorize?response_type=code&state=state&client_id=client_id&scope=openid&redirect_uri=https%3A%2F%2Fexample.com%2Fcli%2Fauthz_cb&nonce=P1B1nPCnzU4Mwg1hjzxkrA3DmnMQKPWl'
    }

It will look like that when the request is to be transmitted as the urlencoded
query part of a HTTP GET operation. If instead a HTTP POST with a json body is
expected the outcome of `do_request_init`_ will be something like this::

    {
        'uri': 'https://example.com/token',
        'body': 'grant_type=authorization_code&redirect_uri=https%3A%2F%2Fexample.com%2Fcli%2Fauthz_cb&code=access_code&client_id=client_id',
        'h_args': {'headers': {'Authorization': 'Basic Y2xpZW50X2lkOnBhc3N3b3Jk', 'Content-Type': 'application/x-www-form-urlencoded'}}
    }

Here you have the url that the request should go to, the body of the request
and header arguments to add to the HTTP request.

do_request_init
===============

Implmented in :py:meth:`oiccli.service.Service.do_request_init`

Nothing much happens locally in this method, it starts with gathering
information about which HTTP method is used, the client authentication method
and the how the request should be serialized.

It the calls the next method

request_info
------------

Implemented in :py:meth:`oiccli.service.Service.request_info`

The method where most is done leading up to the sending of the request.
The request information is gathered and the where to and how of sending the
request is decided.

will do these things:

    1. Remove request arguments that is know at this point should not appear in
        the request
    2. Construct the request
    3. Do the client authentication setup if necessary
    4. Set the necessary HTTP headers

to do this the method will call 3 other methods:

    1. `construct`_
    2. `init_authentication_method`_
    3. `uri_and_body`_

construct
'''''''''

Implemented in :py:meth:`oiccli.service.Service.construct`

Instantiate the request as a message class instance with attribute values
from the message call and gathered by the *pre_construct* methods and the
`gather_request_args`_ method and possibly modified by a *post_construct*
method.

do_pre_construct
++++++++++++++++

Implemented in :py:meth:`oiccli.service.Service.do_pre_construct`

Updates the arguments in the method call with preconfigure argument from
the client configuration.

Then it will run the list of pre_construct methods one by one in the order
they appear in the list.

The call API that all the pre_construct methods must adhere to is::

    meth(cli_info, request_args, **_args)


cli_info is an instance of :py:class:`oiccli.client_info.ClientInfo`
The methods MUST return a tuple with request arguments and arguments to be
used by the post_construct methods.

gather_request_args
+++++++++++++++++++

Implemented in :py:meth:`oiccli.service.Service.gather_request_args`

Has a number of sources where it can get request arguments from.
In priority order:

    1. Arguments to the method call
    2. Information kept in the client information instance
    3. Information in the client configuration targeted for this method.
    4. Standard protocol defaults.

It will go through the list of possible (required/optional) attributes
as specified in the oicmsg.message.Message class that is defined to be used
for this request and add values to the attributes if any can be found.

do_post_construct
+++++++++++++++++

Implemented in :py:meth:`oiccli.service.Service.do_post_construct`

These methods are there to do modifications to the request that can not be done
until all request arguments have been gathered.
The prime example of this is to construct a signed Jason Web Token to be
add as value to the *request* parameter or referenced to by *request_uri*.

init_authentication_method
''''''''''''''''''''''''''
Implemented in :py:meth:`oiccli.service.Service.init_authentication_method`

oiccli supports 6 different client authentication/authorization methods

    - bearer_body
    - bearer_header
    - client_secret_basic
    - client_secret_jwt
    - client_secret_post
    - private_key_jwt

depending on which of these, if any, is supposed to be used different things
has to happen. Thos things will happen when this method is called.

uri_and_body
''''''''''''
Implemented in :py:meth:`oiccli.service.Service.uri_and_body`

Depending on where the request are to be placed in the request (part of the
URL or as a POST body) and the serialization used the request in it's proper
form will be constructed and tagged with destination.

uri_and_body will return a dictionary that a HTTP client library can use
to send the request.

endpoint
++++++++
Implemented in :py:meth:`oiccli.service.Service.endpoint`

Picks the endpoint (URL) to which the request will be sent.

update_http_args
----------------
Implemented in :py:meth:`oiccli.service.Service.update_http_args`

Will add the HTTP header arguments that has been added while the request
has been travelling through the pipe line to a possible starting set.


---------------------
The response pipeline
---------------------

Below follows a desciption of the methods of the response pipeline in the order
they are called.

The overall call sequence looks like this:

   - `parse_request_response`_
        + `parse_response`_
            * `get_urlinfo`_
            * `do_post_parse_response`_ (#)
        + `parse_error_mesg`_

parse_request_response
======================

Deal with a self.httplib response. The response are expected to
follow a special pattern, having the attributes:

    - headers (list of tuples with headers attributes and their values)
    - status_code (integer)
    - text (The text version of the response)
    - url (The calling URL)

Depending on the status_code in the HTTP response different things will happen.
If it's in in the 200 <= x < 300 range then based on the value of Content-Type
in the HTTP headers an appropriate deserializer method will be chosen and then
*parse_response* will be called.

parse_response
--------------

Will initiate a *response_cls* instance with the result of deserializing the
result.
If the response turned out to be an error response even though the status_code
was in the 200 <= x < 300 range that is dealt with and an *error_msg* instance
is instantiated with the response.

Either way the response is verified (checked for required parameters and
parameter values being of the correct data types) and if it was not an error
response *do_post_parse_response* is called.

get_urlinfo
'''''''''''
Picks out the query or fragment component from a URL

do_post_parse_response
''''''''''''''''''''''

Runs the list of *post_parse_response* methods in the order they appear in the
list.

The API of these methods are::

    method(response, client_info, state=state, **_args)

The parameters being:

    response
        A Message subclass instance
    client_info
        A :py:class:`oiccli.client_info.ClientInfo` instance
    state
        The state value that was used in the authorization request
    _args
        A set of extra keyword arguments

parse_error_mesg
----------------

Parses an error message return with a 4XX error message. OAuth2 expects
400 errors, OpenID Connect also uses a 402 error. But we accept the full
range since serves seems to be able to use them all.

--------------
A conversation
--------------

This section will walk you through what might happen when a user wants to
use OIDC to authenticate/authorize and the Relying Party (RP) has never seen
the OpenID Connect Provider (OP) before. This is an example of how dynamic
the interaction between an RP and an OP can be using OIDC.

We start from knowing absolutely nothing, having to use WebFinger to find the
OP. The follows dynamic provider info discovery and client registration before
the user can be brought in and do the authentication/authorization bit.
And lastly the RP will ask for an access token and after that information
about the user.

Initial setup
=============

We need a couple of things initiated before we start.
The first one is initiating the services that the RP is going to use.
For this example we need these services::

    service_spec = [
        ('WebFinger', {}),
        ('ProviderInfoDiscovery', {}),
        ('Registration', {}),
        ('Authorization', {}),
        ('AccessToken', {}),
        ('RefreshAccessToken', {}),
        ('UserInfo', {})
    ]

and to initiate these we need to run::

    from oiccli.client_auth import CLIENT_AUTHN_METHOD
    from oiccli.oic.service import factory

    service = build_services(service_spec, factory, None, KEYJAR,
                         client_authn_method=CLIENT_AUTHN_METHOD)

**KEYJAR** contains the RP's signing and encryting keys. It's an
:py:class:`oicmsg.keyjar.KeyJar` instance

**service** is a dictionary with services identifiers as keys and
:py:class:`oiccli.service.Service` instances as values.

Next the :py:class:`oiccli.client_info.ClientInfo` instance::

    client_info = ClientInfo(
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
        'behaviour':
            {
                "jwks_uri": "{}/static/jwks.json".format(BASEURL)
            }
        }
    )

    client_info.service = service

We will keep all the session information in the client_info instance

That's all we have to do when it comes to setup so now on to the actual
conversation.

Webfinger
=========

We will use WebFinger (RFC7033) to find out where we can learn more about the
OP. What we have to start with is an user identifier provided by the user.
The identifier we got was: **foobar@example.com** .
With this information we can do::

    info = service['webfinger'].do_request_init(client_info,
                                                resource='foobar@example.com')


service['webfinger'] will return the WebFinger service instance and running
the method do_request_init will return the information necessary to do a
HTTP request. In this case the value of *info* will be::

    {
        'uri': 'https://example.com/.well-known/webfinger?resource=acct%3Afoobar%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer'
    }

as you can see the *do_request_init* constructed a URL that can be used
to get the wanted information.

Doing HTTP GET on this URL will return a JSON document that looks like this::

    {
    "subject": "acct:foobar@example.com",
    "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer",
               "href": "https://example.com"}],
    "expires": "2018-02-04T11:08:41Z"}

To parse and use it I can run another method provide by the service instance::

    response = service['webfinger'].parse_response(webfinger_response,
                                                   client_info)

It's assumed that *webfinger_response* contains the JSON document mentioned
above.

*parse_response* doesn't just parse the response it also interprets it.
So the real result is that the information in **client_info** has changed.
We now has this::

    client_info.issuer: "https://example.com"

And that is all we need to fetch the provider info

Provider info discovery
=======================

We use the same process as with webfinger but with another service instance::

    info = service['provider_info'].do_request_init(client_info)

*info* will now contain::

    {'uri': 'https://example.com/.well-known/openid-configuration'}

And this is the first example of *magic* that you will see.

*do_request_init knows how to get the OpenID Connect providers discovery URL
from the client_info instance. Now, if you don't wanted to do webfinger because
perhaps the other side did not provide that service. Then you would have to
set *client_info.issuer* to the correct value.

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
We feed this information into *parse_response* and let it do its business::

    resp = service['provider_info'].parse_response(json_document,
                                                   client_info)

*json_document* contains the JSON document from the HTTP response.
*parse_response* will parse and verify the response. One such verification is
to check that the value provided as **issuer** is the same as the URL used
to fetch the information without the '.well-known' part. In our case the
exact value that the webfinger query produced.

As with the *webfinger* service this service also adds things to **client_info**.
So we now for instance have::

    client_info.provider_info['issuer']: https://example.com
    client_info.provider_info['authorization_endpoint']: https://example.com/authorization


As you can guess from the above the whole response from the OP was stored in
the client_info instance. Such that it is easily accessible in the future.

Now we know what we need to know to register the RP with the OP.
If the OP had not provided a 'registration_endpoint' it would not have
supported dynamic client registration but this one has so it does.

Client registration
===================

By now you should recognize the pattern::

    info = service['registration'].do_request_init(client_info)

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
*parse_response* which will parse, verify and interpret the response::

    response = service['registration'].parse_response(json_document,
                                                      client_info)

The response will be stored in client_info as usual. Most under the heading
*registration_response* but some, more important, will be stored at a
directly reachable place::

    client_info.client_id: zls2qhN1jO6A
    client_info.client_secret: c8434f28cf9375d9a7f3b50dcfdf6a20d6e702e310066874f794817f

By that we have finalized the dynamic discovery and registration now we can get
down to doing the authentication/authorization bits.

Authorization
=============

In the following example I'm using code flow since that allows me to show
more of what the oiccli package can do.

Like when I used the other services this one is no different::

    info = service['authorization'].do_request_init(client_info)

*info* will only contain one piece of data and that is a URL::

    uri: https://example.com/authorization?state=Oh3w3gKlvoM2ehFqlxI3HIK5&nonce=UvudLKz287YByZdsY3AJoPAlEXQkJ0dK&response_type=code&client_id=zls2qhN1jO6A&scope=openid&redirect_uri=https%3A%2F%2Fexample.org%2Fauthz_cb

Where did all the information come from ?:

    - the authorization endpoint comes from the dynamic provider info discovery,
    - client_id from the client registration,
    - response_type, scope and redirect_uri from the client configuration and
    - state and nonce are dynamically created by the service instance.

When this *service* instance creates a request it will also create a *session*
instance in client_info keyed on the state value.

I do HTTP GET on the provided URL and will eventually get redirected back to
the RP with the response in the query part of the redirect URL.
Below you have just the query component::

    state=Oh3w3gKlvoM2ehFqlxI3HIK5&scope=openid&code=Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01aQWJ1Y3Y1MWFfMTVXXzhEcll2a0lkd0Z2Qk9lOHYtTUZjRnRjUzhNc1FOdm9RMGJ5aXhNUUtYSkdldTItRnBFVFV5YkhIVE5Gbk1VY2x2YmRuQXhxTEFSV2d6Zi1IaHE3SklpdndGbzRHR2tfT0Rwck5RTW1TalRwRUg0SE5JSUJtSC1lZU5HTXRjdkZXWXUzT3VodF8tdFhtX2NURFNiRXVhX1pFTFk1SXZ6NWhvSEdyXzNQRXVfZU9uTS1GZnB1dnVkYmRZSkh4VDdPWENlQ240al9GSkdFa1I0Yz0%3D&iss=https%3A%2F%2Fexample.com&client_id=zls2qhN1jO6A

I feed the *query_part* into the *parse_response* method of the authorization
service instance and hope for the best::

    _resp = service['authorization'].parse_response(query_part,
                                                    client_info)

Now as mentioned above one thing that happened when the authorization request
was constructed was that some information of that request got stored away with
the *state* value as key. All in the client_info instance.

The response on the authorization query will be stored in the same place.
To get the code I can now use::

    client_info.state_db['Oh3w3gKlvoM2ehFqlxI3HIK5']['code']

State information will be use when we take the next step, which is to get
an access token.

Access token
============

When sending an access token request I have to use the correct *code* value.
To accomplish that *do_request_init* need to get state as an argument::

    _state = 'Oh3w3gKlvoM2ehFqlxI3HIK5'
    request_args = {
        'state': _state,
        'redirect_uri': client_info.state_db[_state]['redirect_uri']}

    info = service['accesstoken'].do_request_init(client_info,
                                                  request_args=request_args)

The OIDC standard says that the *redirect_uri* used for the authorization request
should be provided in the access token request so I need to add that too.

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

    _resp = service['accesstoken'].parse_response(
        json_document, client_info, state='Oh3w3gKlvoM2ehFqlxI3HIK5')

Note that we need to provide the method with the *state* parameter so it will
know where to find the correct information needed to verify the response.

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

Again we have to provide the *do_request_init* method with the correct state
value::

    info = service['userinfo'].do_request_init(client_info,
                                               state='Oh3w3gKlvoM2ehFqlxI3HIK5')

And the response is a JSON document::

    {"sub": "1b2fc9341a16ae4e30082965d537ae47c21a0f27fd43eab78330ed81751ae6db"}

Only the *sub* parameter because the asked for scope was 'openid'.

Parsing, verifying and storing away the information is done the usual way::

    _resp = service['userinfo'].parse_response(json_document,
                                               client_info,
                                               state='Oh3w3gKlvoM2ehFqlxI3HIK5')

And we are done !! :-)