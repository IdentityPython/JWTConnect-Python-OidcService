.. _oidccli_service:

*****************
The Service class
*****************

The :py:class:`oidccli.service.Service` class should probably never be used as
is. What you should use are subclasses of it.

This packages contains service subclasses that covers all the services defined
in the OAuth2 and OpenID Connect standards.

If those doesn't cover your use case you can create your own subclass.
In the following sections we will go through how you create such a subclass.

Class attributes
----------------

There is a number of attributes defined for special service class, these are:

msg_type
   The request message class. :py:class:`oidcmsg.message.Message` is the most
   general such class and is therefor the default.

response_cls
   The response message class. :py:class:`oidcmsg.message.Message` is the default

error_msg
   The error message response class.
   :py:class:`oidcmsg.oauth2.message.ErrorResponse` is the default class.

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


Take :py:class:`oidccli.oidc.service.UserInfo` as an example. The default
specification is::

    class UserInfo(Service):
        msg_type = Message
        response_cls = oidcmsg.oidc.OpenIDSchema
        error_msg = oidcmsg.oidc.UserInfoErrorResponse
        endpoint_name = 'userinfo_endpoint'
        synchronous = True
        request = 'userinfo'
        default_authn_method = 'bearer_header'
        http_method = 'GET'


Now if you want to talk to GitHub they do things a bit differently so
I had to construct a GitHub UserInfo class that looked like this::

    class GitHubUserInfo(oidccli.oidc.service.UserInfo):
        response_cls = Message
        error_msg = ErrorResponse
        default_authn_method = ''

First their set of user info doesn't contain a 'sub' claim which is a
required claim according to OIDC. Since OAUth2 doesn't have any notion of
user info there is of course no OAuth2 user info message to depend on.
And secondly there is no client authentication involved at all.
Changing *error_msg* was just a safety precaution. I don't know what error
types GitHub might return and if they are within the set OIDC defines for the
userinfo endpoint.

Luckily this was the only modifications necessary, so not to bad.

Call sequence
-------------

The call sequence for the Service methods is this for constructing a request:

    - do_request_init
        + request_info
            * construct
                - do_pre_construct (#)
                - gather_request_args
                - do_post_construct (#)
            * init_authentication_method
            * uri_and_body
                - _endpoint
        + update_http_args

and this for sending a request and parsing the response:

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

Let me give an example which actually contradicts to some extent what I
wrote above.

This is part of the source code::

    from oidcmsg import oauth2
    from oidccli import OIDCONF_PATTERN
    from oidccli.service import Service

    class ProviderInfoDiscovery(Service):
        msg_type = oauth2.Message
        response_cls = oauth2.ASConfigurationResponse
        error_msg = oauth2.ErrorResponse
        request = 'provider_info'

        def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
            Service.__init__(self, httplib=httplib, keyjar=keyjar,
                             client_authn_method=client_authn_method)
            self.post_parse_response.append(self.oauth_post_parse_response)

        def request_info(self, cli_info, method="GET", request_args=None,
                         lax=False, **kwargs):

            issuer = cli_info.issuer

            if issuer.endswith("/"):
                _issuer = issuer[:-1]
            else:
                _issuer = issuer

            return {'url': OIDCONF_PATTERN % _issuer}

        def oauth_post_parse_response(self, resp, cli_info, **kwargs):
            """
            Deal with Provider Config Response
            :param resp: The provider info response
            :param cli_info: Information about the client/server session
            """
            <left out>

First regarding the class attributes the values on some attributes has been
changed to something more appropriate for this specific service.

Secondly, I rewrote the *request_info* method because the request has
no parameters it is just a simple GET.

Thirdly, I added a method that will be excecuted after the response has been
parsed. This method will store the provider info in the
:py:class:`oidccli.client_info.ClientInfo` instance the cli_info is pointing to.
It will also update the service instances such that they will contain the
endpoint URLs given in the received provider info.

Note that this method is added to the method excution sequence in this line::

    self.post_parse_response.append(self.oauth_post_parse_response)

**post_parse_response** contains a list of methods which is executed in
sequence by the method *do_post_parse_response* listed in the call sequence
above.

**do_pre_construct** and **do_post_construct** works the same way.

Pipelines
---------

Both the *do_request_init* and *service_request* methods are the starting
points for a pipeline of where an incomming message is gradually modified
and/or transformed.

The *do_request_init* pipeline starts with a