.. oidccli documentation master file, created by
   sphinx-quickstart on Sat Dec 30 17:32:48 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to oidcservice's documentation!
=======================================

OpenID Connect and OAuth2 (O/O) are both request-response protocols.
The client sends a request and the server responds either direct on the
same connection or after a while on another connection.

When I use *client* below I refer to a piece of software that implements O/O and
works on behalf of an application.

The client follows the same pattern disregarding which request/response
it is dealing with. I does the following when sending a request:

    1. Gathers the request arguments
    2. If client authentication is involved it gathers the necessary data for that
    3. If the chosen client authentication method involved adding information to the request it does so.
    4. Adds information to the HTTP headers like Content-Type
    5. Serializes the request into the expected format

after that follows the act of sending the request to the server and receiving
the response from it.
Once the response have been received, The client will follow this path:

    1. Deserialize the received message into a internal format
    2. Verify that the message was correct. That it contains the required claims and that all claims are of the correct data type. If it's signed and/or encrypted verify signature and/or decrypt.
    3. Store the received information in a data base and/or passes it on to the application.

oidcservice is built to allow clients to be constructed that supports any number
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

That is the thought behind **oidcservice**.

.. toctree::
   :maxdepth: 2

   service_context
   service
   state_db
   what
   conversation
   modules
   oidcservice.rst
   oidcservice.oauth2
   oidcservice.oidc


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
