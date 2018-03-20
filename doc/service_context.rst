++++++++++++++
ServiceContext
++++++++++++++

============
Introduction
============

ServiceContext holds information that is necessary for a OAUth2 client or an
OpenID Connect (OIDC) RP to work properly. When an RP/Client receives information
from an OP/AS it will store all or parts of it in the ServiceContext. When it
constructs requests it will use the ServiceContext to find values for parameters
in the request.

=============================
Content of the ServiceContext
=============================

There are a number of distinct parts of information in the ServiceContext.
One can group them into a couple of groups:

    + Information about the client
    + Information about the OP/AS

Information about the client and the OP/AS can be gotten in two different ways.
Either by static configuration or by dynamic discovery/registration.

Client Information
------------------

These are the ServiceContext parameters that deals with information about the client.

**Note:** Even though I talk about RPs below most of the things I describe is
equally valid for OAUth2 Clients.

The information can broadly be grouped into two groups. The first being
information about the client that is unconnected to which OP/AS the RP/Client
interacts with, those are:

base_url
    + This is the part of URLs that the client presents to the outside that
      doesn’t vary between the URLs.

requests_dir
    + If the request_uri parameter is used then signed JWTs will be stored in this
      directory.

The second group of parameters then is OP/AS dependent

allow
    + This is used to make the client allow divergence from the standards. The
      only present use if for non-matching issuer values. According to the OIDC
      standard the value of iss in an ID Token must be the same as the Issuer ID
      of the OP. The value of allow is a dictionary
    + example: allow={“issuer_missmatch”: True}

keyjar
    A container for all the keys that the RP needs. To begin with the key jar
    will only contain keys that is owned by the RP. Over time it will also be
    populated with keys used by the OP

client_id
    + The identifier of the client. This value is not globally unique but only unique for a special RP-OP combination.
    + The client ID can either be returned by a out-of-band registration service connected to the OP or during OIDC dynamic client registration.
    + There must be a client ID

client_secret
    + There may be a client secret.
    + The client secret can be used as a symmetric key in symmetric key cryptography or as a password while doing client authentication.
    + As with client_id the client secret can either be returned by some out-of-band registration service together with the client_id or obtained during OIDC dynamic client registration

redirect_uris
    + A list or URLs to where the OP should redirect the user agent after the authorization/authentication process has completed.

callback
    + Depending on the response_type and response_mode used you may want to
      pick one specific redirect_uri out of a given set.
    + The keys presently understood by the system are the ones listed in the
      example.
    + Example::

        {“code”: “https://example.com/authz_cb”,
         “implicit”: “https://example.com/authz_im_cb”,
         “form_post”: “https://example.com/authz_fp_cb” }


registration_response
    + A positive response received from the OP on a client registration request.
    + This is an oidcmsg.oidc.RegistrationResponse instance
    + The possible content here is described in http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

client_secret_expires_at
    + Set when a positive client registration has been received and the OP has added client_secret_expires_at to the response

registration_access_token
    + Set when a positive client registration has been received and the OP has added registration_access_token to the response

behaviour
    + If OIDC dynamic client registration is not supported by the OP or if
      dynamic registration is not used then this is where necessary
      information about how the RP should behave against the OP must be stored.
    + If dynamic client registration is used then the result after matching the
      registration response against the client_preferences are store here.
    + Example::

        {
           "response_types": ["code"],
           "scope": ["openid", "profile", "email"],
           "token_endpoint_auth_method": ["client_secret_basic",
                                          'client_secret_post']
        }

client_preferences
    + When dynamic client registration is used this is where it’s specified what
      should be sent in the registration request. This information will be
      added to before sending it to the OP, more about that below. The format
      is the same as for behaviour.
    + The possible content is described in
      http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
    + Example::

        {
           "application_type": "web",
           "application_name": "rphandler",
           "contacts": ["ops@example.com"],
           "response_types": ["code", "id_token", "id_token token", "code id_token",
                                  "code id_token token", "code token"],
           "scope": ["openid", "profile", "email", "address", "phone"],
           "token_endpoint_auth_method": ["client_secret_basic",
                 “Client_secret_post”],
        }

**NOTE:**
If you do static client configuration you **MUST** define
behaviour in configuration.

If you do dynamic client registration you **MAY** use *behaviour* and you
should use *client_preferences*.
The result of matching the client_preferences with registration response will
be used to update *behaviour*.

OP information
--------------

Basically only 2 pieces of information:

issuer
    + The issuer ID of the OP. This must be an URL.
    + This is found by using WebFinger, by some other issuer discovery service
        or by static configuration.

provider_info
    + This is either statically configured or obtained by using OIDC provider
        info discovery.
    + Should be a oidcmsg.oidc.ProviderConfigurationResponse instance
    + The possible content is described in
        http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

Session information
-------------------

Stored in the state_db database. The database should be some kind of persistent
data storage. For testing an in-memory database is OK but not for production.

The database must be of the key-value type. The key into the session state
information is the value of the state parameter in the authorization request.

The following data is stored per session:

client_id
    Client ID
iss
    Issuer ID
iat
    When the entry in the state_db was created
response_type
    The response_type specified in the authorization request
scope
    The scope specified in the authorization request
redirect_uri
    The redirect_uri used in the authorization request
token
    + Information about the access token received
    + Example::

         {‘access_token’: ‘Z0FBQUFBQmFkdFF’, ‘token_type’: ‘Bearer’,
          ‘scope’: [‘openid’]}

id_token
    The received ID Token as a signed JWT


========================
Using the ServiceContext
========================

The objects that use the ServiceContext are the oidcservice.service.Service
instances. These object read and write to the ServiceContext while a session is
active.

Below I’ll go through the interaction between a certain type of service and the
ServiceContext. There interaction takes place when the service is constructing
a request and when after having parsed the response it wants to update the
ServiceContext.

WebFinger
---------

Constructing request
....................

If Webfinger is used then nothing but an identifier for a user is in place so
the ServiceContext doesn’t contain any useful information.

Updating the ServiceContext
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the WebFinger request got a positive response then the URL which is the OP
issuer ID is now know and will be stored in ServiceContext.issuer .

ProviderInfoDiscovery
---------------------

There are 2 paths here, either the information is provided in the configuration
setup or the information is expected to be fetch using OIDC dynamic provider
info discovery.

If it’s in the configuration updating the Service Context consists of initiating
a oidcmsg.oidc.ProviderConfigurationResponse class with the provided information.
Setting ServiceContext.issuer to the issuer value provided in the configuration
and adding the oidcmsg.oidc.ProviderConfigurationResponse instance as value to
ServiceContext.provider_info.

If discovery is done then the following happens:

Constructing request
....................

The URL that is the Issuer ID is picked from ServiceContext.issuer and the
“.well-known/openid-configuration” path is added to the the URL. The resulting
URL is then used for the discovery request

Updating the ServiceContext
...........................

The parsed response, if it is an oidcmsg.oidc.ProviderConfigurationResponse
instance is added to ServiceContext.provider_info.
Also if dynamic client registration is to be used and therefor
ServiceContext.client_preferences has been define this is where the preferences
together with the provider info response are converted into a
ServiceContext.behaviour value.

Registration
------------

As for ProviderInfoDiscovery there are 2 possible path. The first using static
client registration in which case all the necessary information must be
included in the configuration. As a similar process to what happens in
ProviderInfoDiscovery a oidcmsg.oidc.RegistrationResponse instance is created
with the information in the configuration.

If dynamic client registration is to happen, then the following happens.

Constructing request
....................

Apart from the information given in client_preferences some more information
are gathered from the ServiceContext. From ServiceContext.provider_info we get:

authorization_endpoint
    This just so we know where to send the user-agent
require_request_uri_registration
    If this is set to True we need to construct request_uris and add them to
    the registration request

From ServiceContext you can get *redirect_uris* and/or *callback*. Depending on
what is configured a set of *redirect_uris* are added to the request

Same goes for *post_logout_redirect_uris*

Updating the ServiceContext
...........................

The parsed registration response if it was positive is stored in
ServiceContext.registration_response.
Sets the following parameters in ServiceContext if present in the registration
response:

    + client_id
    + client_secret
    + client_secret_expires_at
    + registration_access_token

Also if *token_endpoint_auth_method*

