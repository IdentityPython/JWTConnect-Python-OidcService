.. _oidcservice_what:

************************
What a service should do
************************

This document is a companion to oidcservice-service_ where the how is covered.
This document aims to tell you the what. What is divided into two part one is
what happens before the HTTP request is sent and the other is what happens
once the response has been reveived. In the following I am concentrating on
what happens after a positive response. What happens if an error message is
received is not covered here.

The services will be covered one by one it the order they normally appear in a
conversation between an OpenID Connect (OIDC) Relying Party (RP) and an
OpenID Provider (OP).

For the examples it will be assumed that we have an instance of
:py:class:`oidcservice.service_context.ServiceContext` called
*service_context* .
The service will also have access to a database (*state_db*) where information
about the communication between the RP and the OP is stored on a per End-User
basis.

Each service will verify the correctness of the response regarding:

- presence of required claims
- correct value types and in certain context also that the value is from a
  given set.
- If the response is a signed and/or encrypted JWT, decrypt and verify
  signature.

This is all done by using services provided by oidcmsg and cryptojwt.

--------------------------------
OpenID Provider Issuer discovery
--------------------------------

Service description
-------------------

OpenID Provider Issuer discovery is the process of determining the location of
the OpenID Provider as described in discovery_ . In this document it is
described how you can use Webfinger_ to implement this service.

OP issuer discovery is implemented in :py:class:`oidcservice.oidc.service.WebFinger`

Pre request work
----------------

The process starts with the End-User supplying the RP with an identifier. The
service will then apply normalization rules to the identifier to determine
the resource and the host. This together with the defined *rel* value allows
the service to construct the URL that can be used to get the location of the
requested service.

In discovery_ you can find a number of examples of how this is done.

Post request work
-----------------

A positive response from a WebFinger resource returns a JavaScript Object
Notation (json_) object describing the entity that is queried.
The JSON object is referred to as the JSON Resource Descriptor (JRD). An
example would be::

    {
        "subject": "https://example.com/joe",
        "links":
        [
            {
                "rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": "https://server.example.com"
            }
        ]
    }

The service will parse this JSON object and store the *href* value in the
oidcservice-service-context_ as value on *issuer*.::

    # _jrd is A parsed JRD response
    OIDC_REL = "http://openid.net/specs/connect/1.0/issuer"

    for link in _jrd['links']:
        if link['rel'] == OIDC_REL:
            service_context.issuer = link['href']
            break


---------------------------------------------------
Obtaining OpenID Provider Configuration Information
---------------------------------------------------

Service description
-------------------

Some way the RP has gotten the Issuer location. It could have been using
WebFinger as described above but there are many other ways of doing this too.
No matter what as used we assume the Issuer location is known to the RP
and we now want to find the metadata for the Issuer. This is where this service
comes in.

Obtaining OpenID Provider Configuration Information is implemented in
:py:class:`oidcservice.oidc.service.ProviderInfoDiscovery`

Pre request work
----------------

Not really anything to do here. The only thing necessary to do is to construct
the URL to use and that is done by adding a path component to the Issuer
location.

The path component is: */.well-known/openid-configuration*

Post request work
-----------------

The response is a JSON object that contains a set of claims that are a subset
of the Metadata values defined in section 3 of discovery_ . Other claims may
be returned.

This service parses the JSON object using
:py:class:`oidcmsg.oidc.ProviderConfigurationResponse`. Verifies it's
correctness and then it does a number of checks:

1. Validates that the value of *issuer* returned in the response is the same as
   the issuer location
2. Verifies that the RP will be able to talk to the OP. Like supporting the
   crypto algorithms favored by the OP.
3. Verifies that the endpoint URLs are HTTPS URLs
4. If a jwks_uri is given verify that it points to a syntactically correct JWKS

Using the information in the response the service is also expected to combine
what the OP can do and what the RP prefers to do (according to the
configuration) and produce a description of the behaviour of the RP.

And lastly set the correct endpoints for all the services.

----------------------
Authentication Request
----------------------

Service description
-------------------

The Authorization Endpoint performs Authentication of the End-User. This is
done by sending the User Agent to the Authorization Server's Authorization
Endpoint for Authentication and Authorization, using request parameters defined
by `OAuth 2.0`_ and additional parameters and parameter values defined by OpenID
Connect.

Authentication is implemented by
:py:class:`oidcservice.oidc.service.Authorization`

Pre request work
----------------

There are a number of things that must be done dynamically when the RP is
constructing an authentication request.

If it's the first time the RP sends such a request to the OP it should as
described by `oauth security`_ create OP specific redirect_uris.

For each request it **MUST** create a new *state* value and possibly also a
*nonce* if ID Token is expected to be returned by the OP.

These attributes it can pick from configuration and from the OP metadata:

- authorization_endpoint
- scope
- response_type
- response_mode (if different from the default given by the choice of
  response_type)

If the request or rrequest_uri parameters are used the this service will
construct the signed JSON Web Token.

And finally the service will store the request in the state_db using the
*state* value as key.

Post request work
-----------------

If *expires_in* is provided in the response and extra attribute *__expires_at*
is added to the response.

The response as a whole is added to the *state_db* database.

-------------
Token Request
-------------

Service description
-------------------

To obtain an Access Token, an ID Token, and optionally a Refresh Token, the RP
sends a Token Request to the Token Endpoint to obtain a Token Response.

Token request is implemented by
:py:class:`oidcservice.oidc.service.AccessToken`

Pre request work
----------------

Fetches the necessary claim values from the authentication
request/response copies in the *state_db*.

This includes claims like *code* and *redirect_uri*.

*client_id* and *client_secret* is picked from the client registration response.

Depending on which client authentication methods the RP is expected to use the
necessary information is constructed.

Post request work
-----------------

The ID Token is validated using the process described in section 3.1.3.7 in
`OIDC core`_.

If *expires_in* is provided in the response and extra attribute *__expires_at*
is added to the response.

The response as a whole is added to the *state_db* database.

---------------
Refresh Request
---------------

Service description
-------------------

To refresh an Access Token, the RP sends a Refresh Token Request to the Token
Endpoint to obtain a Token Response.

Token request is implemented by
:py:class:`oidcservice.oidc.service.RefreshAccessToken`


Pre request work
----------------

Fetches the necessary claim values from the authentication
request/response and possibly the access token response (depends on which
flow that was used) copies in the *state_db*.

This includes claims like *code*, *redirect_uri* and *refresh_token*.

*client_id* and *client_secret* is picked from the client registration response.

Depending on which client authentication methods the RP is expected to use the
necessary information is constructed.


Post request work
-----------------

If *expires_in* is provided in the response and extra attribute *__expires_at*
is added to the response.

The response as a whole is added to the *state_db* database.


----------------------------
User info Request
----------------------------

Service description
-------------------

The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns Claims
about the authenticated End-User. To obtain the requested Claims about the
End-User, the Client makes a request to the UserInfo Endpoint using an Access
Token obtained through OpenID Connect Authentication.

Pre request work
----------------

Fetches the access token from the authentication or the access token response
depending on which flow was used.

Post request work
-----------------

The response as a whole is added to the *state_db* database.


.. _WebFinger: https://tools.ietf.org/html/rfc7033
.. _discovery: http://openid.net/specs/openid-connect-discovery-1_0.html
.. _json: https://tools.ietf.org/html/rfc4627
.. _OAuth 2.0: http://tools.ietf.org/html/rfc6749
.. _oauth security: https://www.rfc-editor.org/internet-drafts/draft-ietf-oauth-security-topics-06.txt
.. _OIDC core: http://openid.net/specs/openid-connect-core-1_0.html
