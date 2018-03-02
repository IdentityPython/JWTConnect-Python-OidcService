What does oidccli
=================

When an OpenID Connect Relaying party or an OAuth2 client are interacting
with an OP/AS it is invoking a service. Each such interaction consists of
a request sent by the RP/client and a response returned by the OP/AS.

The :py:class:`oidccli.service.Service` class contains all the necessary
methods for creating an RP/client request and to parse an OP/AS response.

Furthermore it uses the :py:class:`oidccli.client_info.ClientInfo` class
to keep information that is necessary for the communication with a special
OP/AS.

Note that one of the design criteria here is that a new
:py:class:`oidccli.client_info.ClientInfo` instance is initiated for every
new AS/OP that a service wants to communicate with.

Contents:

.. toctree::
   :maxdepth: 2

   service
   oidc/index