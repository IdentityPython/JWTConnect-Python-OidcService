.. _oiccli_service:

*****************
The Service class
*****************

The :py:class:`oiccli.service.Service` class should probably never be used as
is. What you should use are subclasses of it.

This packages contains service subclasses that covers all the services defined
in the OAuth2 and OpenID Connect standards.

If those doesn't cover your use case you can create your own subclass.
In the following sections we will go through how you create such a subclass.

Class attributes
----------------

There is a number of attributes defined for special service class, these are:

msg_type
   The request message class. :py:class:`oicmsg.message.Message` is the most
   general such class and is therefor the default.

response_cls
   The response message class. :py:class:`oicmsg.message.Message` is the default

error_msg
   The error message response class.
   :py:class:`oicmsg.oauth2.message.ErrorResponse` is the default class.

endpoint_name
   Which endpoint on the OP/AS this service is using.

synchronous
   Whether the request-response is synchronous or asynchronous. Among the
   standard service only authorization is asynchronous. The default is *True*

request
   A name used when refering to this service class instance among a set
   of service class instances used by an RP/client.

default_authn_method
   The client authentication method to use unless something else is specified.
   The default is "".

http_method
   Which HTTP method to use when sending the request. Default is 'GET'

body_type
   If the request uses the HTTP method POST then this is how the body should
   be encoded. Default is 'urlencoded'.

response_body_type
   If the response has a body part this is the how that body should be encoded.
   Default is 'json'


Call sequence
-------------

The call sequence for the Service methods is this:

    - do_request_init
        +  request_info
        + construct
            * do_pre_construct (#)
            * parse_args
            * do_post_construct (#)
        + init_authentication_method
        + uri_and_body
            * _endpoint
    - update_http_args

    - service_request
        + parse_request_response
            * parse_response
                - get_urlinfo
                - do_post_parse_response (#)
            * parse_error_mesg


Most of these methods you should not touch, that is rewrite your own version of.
The ones marked with (#) are the ones you should concentrate on.
As you can see these are placed before and after gathering attributes used to
construct a request and after a response has been parsed. So you should be
able to tailor your subclass to your content by hooking in specialised methods
in those places.
