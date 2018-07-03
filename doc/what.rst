.. _oidcservice_what:

************************
What a service should do
************************

This document is a companion to oidcservice_service_ where the how is covered.
This document aims to tell you the what.

The services will be covered one by one it the order they normally appear in a conversation between an
OpenID Connect (OIDC) Relying Party (RP) and an OpenID Provider (OP).

For the examples it will be assumed that we have an instance of :py:class:`oidcservice.service_context.ServiceContext`
called *service_context* .

--------------------------------
OpenID Provider Issuer discovery
--------------------------------

Service description
-------------------

OpenID Provider Issuer discovery is the process of determining the location of the OpenID Provider as described in
discovery_ . In this document it is described how you can use Webfinger_ to implement this service.

OP issuer discovery is implemented in :py:class:`oidcservice.oidc.service.WebFinger`

Pre request
-----------

The process starts with the End-User supplying the RP with an identifier. The service will then apply normalization
rules to the identifier to determine the resource and the host. This together with the defined *rel* value allows
the service to construct the URL that can be used to get the location of the requested service.

In discovery_ you can find a number of examples of how this is done.

Post request
------------

A positive response from a WebFinger resource returns a JavaScript Object
Notation (json_) object describing the entity that is queried.
The JSON object is referred to as the JSON Resource Descriptor (JRD). An example would be::

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

The service will parse this JSON object and store the *href* value in the oidcservice_service_context_
as value on *issuer*.::

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

Some way the RP has gotten the Issuer location. It could have been using WebFinger as described above but there
are many other ways of doing this too. No matter what as used we assume the Issuer location is known to the RP
and we now want to find the metadata for the Issuer. This is where this service comes in.

Obtaining OpenID Provider Configuration Information is implemented in
:py:class:`oidcservice.oidc.service.ProviderInfoDiscovery`

Pre request
-----------

Not really anything to do here. The only thing necessary to do is to construct the URL to use and that is done
by adding a path component to the Issuer location.

The path component is: */.well-known/openid-configuration*

Post request
------------

The response is a JSON object that contains a set of claims that are a subset of the Metadata values defined in
section 3 of discovery_ . Other claims may be returned.

This service parses the JSON object using :py:class:`oidcmsg.oidc.ProviderConfigurationResponse`. Verifies it's
correctness and then it does a number of checks:

1. Validates that the value of *issuer* returned is the same as the issuer location
2. Verifies that the RP will be able to talk to the OP. Like supporting the crypto algorithms favored by the OP.


.. _WebFinger: https://tools.ietf.org/html/rfc7033
.. _discovery: http://openid.net/specs/openid-connect-discovery-1_0.html
.. _json: https://tools.ietf.org/html/rfc4627
