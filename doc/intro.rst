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
    2. If client authentication is involved it gathers the necessary data for that
    3. If the chosen client authentication method involved adding information to the
        request it does so.
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

It will look like that when the request is to be a urlendoded query part of a
HTTP GET operation. If instead a HTTP POST with a json body is expected the
outcome of `do_request_init`_ will be something like this::

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

    1. Remove request arguments that is know at this point should not appear in the
        request
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
from the message call and gathered by the pre_construct methods or the
`gather_request_args`_ method.

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
    3. Information in the client configuration targeted to this method.
    4. Standard protocol defaults.

It will go through the list of possible (required/optional) attributes
as specified in the oicmsg.message.Message class that is defined to be used
for this request.

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

parse_response
--------------

get_urlinfo
'''''''''''

do_post_parse_response
''''''''''''''''''''''

parse_error_mesg
----------------
