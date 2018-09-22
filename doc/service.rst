.. _oidcservice-service:

*****************
The Service class
*****************

This class contains 2 pipe lines, one for the request construction and one
for response parsing. The interface to HTTP is kept to a minimum to allow
users of oidcservice to chose their favorite HTTP client/server libraries.

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

    request_body_type
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

    + get_request_parameters
        - construct_request
            - construct
                - do_pre_construct (*)
                - gather_request_args
                - do_post_construct (*)
        - get_http_url
        - get_authn_header
        - get_http_body

The result of the request pipeline is a dictionary that in its simplest form
will look something like this::

    {
        'url' : 'https://example.com/authorize?response_type=code&state=state&client_id=client_id&scope=openid&redirect_uri=https%3A%2F%2Fexample.com%2Fcli%2Fauthz_cb&nonce=P1B1nPCnzU4Mwg1hjzxkrA3DmnMQKPWl'
    }

It will look like that when the request is to be transmitted as the urlencoded
query part of a HTTP GET operation. If instead a HTTP POST with a json body is
expected the outcome of `get_request_parameters`_ will be something like this::

    {
        'url': 'https://example.com/token',
        'body': 'grant_type=authorization_code&redirect_uri=https%3A%2F%2Fexample.com%2Fcli%2Fauthz_cb&code=access_code&client_id=client_id',
        'headers': {'Authorization': 'Basic Y2xpZW50X2lkOnBhc3N3b3Jk', 'Content-Type': 'application/x-www-form-urlencoded'}
    }

Here you have the url that the request should go to, the body of the request
and header arguments to add to the HTTP request.

get_request_parameters
=======================

Implemented in :py:meth:`oidcservice.service.Service.get_request_parameters`

Nothing much happens locally in this method, it starts with gathering
information about which HTTP method is used, the client authentication method
and the how the request should be serialized.

It the calls the next method

construct_request
-----------------

Implemented in :py:meth:`oidcservice.service.Service.construct_request`

The method where most is done leading up to the sending of the request.
The request information is gathered and the where to and how of sending the
request is decided.

construct
'''''''''

Implemented in :py:meth:`oidcservice.service.Service.construct`

Instantiate the request as a message class instance with attribute values
from the message call and gathered by the *pre_construct* methods and the
`gather_request_args`_ method and possibly modified by a *post_construct*
method.

do_pre_construct
++++++++++++++++

Implemented in :py:meth:`oidcservice.service.Service.do_pre_construct`

Updates the arguments in the method call with preconfigure argument from
the client configuration.

Then it will run the list of pre_construct methods one by one in the order
they appear in the list.

The call API that all the pre_construct methods must adhere to is::

    meth(request_args, service_context, **_args)


service_context is an instance of
:py:class:`oidcservice.service_context.ServiceContext`
The methods MUST return a tuple with request arguments and arguments to be
used by the post_construct methods.

gather_request_args
+++++++++++++++++++

Implemented in :py:meth:`oidcservice.service.Service.gather_request_args`

Has a number of sources where it can get request arguments from.
In priority order:

    1. Arguments to the method call
    2. Information kept in the service context instance
    3. Information in the client configuration targeted for this method.
    4. Standard protocol defaults.

It will go through the list of possible (required/optional) attributes
as specified in the oicmsg.message.Message class that is defined to be used
for this request and add values to the attributes if any can be found.

do_post_construct
+++++++++++++++++

Implemented in :py:meth:`oidcservice.service.Service.do_post_construct`

These methods are there to do modifications to the request that can not be done
until all request arguments have been gathered.
The prime example of this is to construct a signed Jason Web Token to be
add as value to the *request* parameter or referenced to by *request_uri*.

get_authn_header
----------------

Implemented in :py:meth:`oidcservice.service.Service.get_authn_header`

oidcservice supports 6 different client authentication/authorization methods.

2 from https://tools.ietf.org/html/rfc6750:

    - bearer_body
    - bearer_header

and these described in
http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication:

    - client_secret_basic
    - client_secret_jwt
    - client_secret_post
    - private_key_jwt

Depending on which of these, if any, is supposed to be used, different things
has to happen.

get_http_url
------------

Implemented in :py:meth:`oidcservice.service.Service.get_http_url`

Depending on where the request are to be placed in the request (part of the
URL or as a POST body) and which serialization is to be used, the request in
it's proper format will be constructed and tagged with destination.

---------------------
The response pipeline
---------------------

Below follows a description of the response pipeline methods in the order
they are called.

The overall call sequence looks like this:

    + `parse_response`_
        * `get_urlinfo`_
        * `do_post_parse_response`_ (#)
    + `parse_error_mesg`_

parse_response
==============

Will initiate a *response_cls* instance with the result of deserializing the
result.
If the response turned out to be an error response even though the status_code
was in the 200 <= x < 300 range that is dealt with and an *error_msg* instance
is instantiated with the response.

Either way the response is verified (checked for required parameters and
parameter values being of the correct data types) and if it was not an error
response *do_post_parse_response* is called.

get_urlinfo
-----------
Picks out the query or fragment component from an URL

do_post_parse_response
----------------------

Runs the list of *post_parse_response* methods in the order they appear in the
list.

The API of these methods are::

    method(response, service_context, state=state, **_args)

The parameters being:

    response
        A Message subclass instance
    service_context
        A :py:class:`oidcservice.service_context.ServiceContext` instance
    state
        The state value that was used in the authorization request
    _args
        A set of extra keyword arguments

parse_error_mesg
================

Parses an error message return with a 4XX error message. OAuth2 expects
400 errors, OpenID Connect also uses a 402 error. But we accept the full
range since serves seems to be able to use them all. Also there are OP/AS
implementations that return error messages in a HTTP 200 response.

