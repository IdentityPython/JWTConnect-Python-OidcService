import logging
from urllib.parse import urlparse

from oidcservice.exception import MissingEndpoint
from oidcservice.exception import OidcServiceError
from oidcservice.exception import ResponseError
from oidcservice.util import get_http_body
from oidcservice.util import get_http_url
from oidcservice.util import JSON_ENCODED
from oidcservice.util import URL_ENCODED
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oauth2 import ErrorResponse
from oidcmsg.oauth2 import Message
from oidcmsg.oauth2 import TokenErrorResponse

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

"""

method call structure for Services.
This is for constructing requests:

get_request_information
    - construct_request
        - construct 
            - pre_construct (*)
            - gather_request_args
            - post_construct (*)
    - get_http_url
    - get_authn_header
    - get_http_body

and this for parsing the response.

parse_response
     - get_urlinfo 
     - post_parse_response   
or
parse_error_mesg

The methods marked with (*) are where service specific
behaviour is implemented.

update_client_info
"""

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]

RESPONSE2ERROR = {
    "AuthorizationResponse": [AuthorizationErrorResponse, TokenErrorResponse],
    "AccessTokenResponse": [TokenErrorResponse]
}

SPECIAL_ARGS = ['authn_endpoint', 'algs']

REQUEST_INFO = 'Doing request with: URL:{}, method:{}, data:{}, https_args:{}'


class Service(object):
    msg_type = Message
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = ''
    default_authn_method = ''
    http_method = 'GET'
    body_type = 'urlencoded'
    response_body_type = 'json'

    def __init__(self, keyjar=None, client_authn_method=None,
                 conf=None, **kwargs):
        self.keyjar = keyjar
        self.client_authn_method = client_authn_method
        self.events = None
        self.endpoint = ''
        self.default_request_args = {}
        if conf:
            self.conf = conf
            for param in ['msg_type', 'response_cls', 'error_msg',
                          'default_authn_method', 'http_method', 'body_type',
                          'response_body_type']:
                if param in conf:
                    setattr(self, param, conf[param])
        else:
            self.conf = {}

        # pull in all the modifiers
        self.pre_construct = []
        self.post_construct = []

    def gather_request_args(self, client_info, **kwargs):
        """
        Go through the attributes that the message class can contain and
        add values if they are missing and exists in the client info or
        when there are default values.

        :param client_info: Client info
        :param kwargs: Initial set of attributes.
        :return: Possibly augmented set of attributes
        """
        ar_args = kwargs.copy()

        # Go through the list of claims defined for the message class
        # there are a couple of places where informtation can be found
        # access them in the order of priority
        # 1. A keyword argument
        # 2. configured set of default attribute values
        # 3. default attribute values defined in the OIDC standard document
        for prop in self.msg_type.c_param.keys():
            if prop in ar_args:
                continue
            else:
                try:
                    ar_args[prop] = getattr(client_info, prop)
                except AttributeError:
                    try:
                        ar_args[prop] = self.conf['request_args'][prop]
                    except KeyError:
                        try:
                            ar_args[prop] = self.default_request_args[prop]
                        except KeyError:
                            pass

        return ar_args

    def method_args(self, context, **kwargs):
        try:
            _args = self.conf[context].copy()
        except KeyError:
            _args = kwargs
        else:
            _args.update(kwargs)
        return _args

    def do_pre_construct(self, client_info, request_args, **kwargs):
        """
        Will run the pre_construct methods one by one in the order given.

        :param client_info: Client Information as a
            :py:class:`oidcservice.client_info.ClientInfo` instance.
        :param request_args: Request arguments
        :param kwargs: Extra key word arguments
        :return: A tuple of request_args and post_args. post_args are to be
            used by the post_construct methods.
        """

        _args = self.method_args('pre_construct', **kwargs)
        post_args = {}
        for meth in self.pre_construct:
            request_args, _post_args = meth(client_info, request_args, **_args)
            post_args.update(_post_args)

        return request_args, post_args

    def do_post_construct(self, client_info, request_args, **kwargs):
        """
        Will run the post_construct methods one at the time in order.

        :param client_info: Client Information as a
            :py:class:`oidcservice.client_info.ClientInfo` instance.
        :param request_args: Request arguments
        :param kwargs: Arguments used by the post_construct method
        :return: Possible modified set of request arguments.
        """
        _args = self.method_args('post_construct', **kwargs)

        for meth in self.post_construct:
            request_args = meth(client_info, request_args, **_args)

        return request_args

    def update_client_info(self, client_info, resp, state='', **kwargs):
        """
        A method run after the response has been parsed and verified.

        :param resp: The response as a :py:class:`oidcmsg.Message` instance
        :param client_info: Client Information as a
            :py:class:`oidcservice.client_info.ClientInfo` instance.
        :param state: state value
        :param kwargs: Extra key word arguments
        """
        pass

    def construct(self, client_info, request_args=None, **kwargs):
        """
        Instantiate the request as a message class instance with
        attribute values gathered in a pre_construct method or in the
        gather_request_args method.

        :param client_info: Information about the client
        :param request_args:
        :param kwargs: extra keyword arguments
        :return: message class instance
        """
        if request_args is None:
            request_args = {}

        # run the pre_construct methods. Will return a possibly new
        # set of request arguments but also a set of arguments to
        # be used by the post_construct methods.
        request_args, post_args = self.do_pre_construct(client_info,
                                                        request_args,
                                                        **kwargs)

        # If 'state' appears among the keyword argument and is not
        # expected to appear in the request, remove it.
        if 'state' not in self.msg_type.c_param:
            try:
                del kwargs['state']
            except KeyError:
                pass

        # logger.debug("request_args: %s" % sanitize(request_args))
        _args = self.gather_request_args(client_info, **request_args)

        # logger.debug("kwargs: %s" % sanitize(kwargs))
        # initiate the request as in an instance of the self.msg_type
        # message type
        request = self.msg_type(**_args)

        return self.do_post_construct(client_info, request, **post_args)

    def _endpoint(self, **kwargs):
        """
        Find out which endpoint the request should be sent to

        :param kwargs: A possibly empty set of keyword arguments
        :return: The endpoint URL
        """
        try:
            uri = kwargs['endpoint']
            if uri:
                del kwargs['endpoint']
        except KeyError:
            uri = ""

        if not uri:
            try:
                uri = self.endpoint
            except Exception:
                raise MissingEndpoint("No '{}' endpoint specified".format(
                    self.__class__.__name__))

        if not uri:  # Only if self.endpoint has no value
            raise MissingEndpoint("No '{}' endpoint specified".format(
                self.__class__.__name__))

        return uri

    def get_endpoint(self, **kwargs):
        return self._endpoint(**kwargs)

    def init_authentication_method(self, request, client_info, authn_method,
                                   http_args=None, **kwargs):
        """
        Will run the proper client authentication method.
        Each such method will place the necessary information in the necessary
        place. A method may modify the request.

        :param request: The request, a Message class instance
        :param client_info: Client information, a
            :py:class:`oidcservice.client_info.ClientInfo` instance
        :param authn_method: Client authentication method
        :param http_args: HTTP header arguments
        :param kwargs: Extra keyword arguments
        :return: Extended set of HTTP header arguments
        """
        if http_args is None:
            http_args = {}

        if authn_method:
            logger.debug('Client authn method: {}'.format(authn_method))
            return self.client_authn_method[authn_method]().construct(
                request, client_info, http_args=http_args, **kwargs)
        else:
            return http_args

    def construct_request(self, client_info, request_args=None, **kwargs):
        """
        The method where everything is setup for sending the request.
        The request information is gathered and the where and how of sending the
        request is decided.

        :param client_info: Client information as a
            :py:class:`oidcservice.client_info.ClientInfo` instance
        :param request_args: Initial request arguments
        :param kwargs: Extra keyword arguments
        :return: A dictionary with the keys 'url' and possibly 'body', 'kwargs',
            'request' and 'ht_args'.
        """
        if request_args is None:
            request_args = {}

        # remove arguments that should not be included in the request
        # _args = dict(
        #    [(k, v) for k, v in kwargs.items() if v and k not in SPECIAL_ARGS])

        return self.construct(client_info, request_args, **kwargs)

    def get_authn_header(self, request, client_info, authn_method, **kwargs):

        headers = {}
        # If I should deal with client authentication
        if authn_method:
            h_arg = self.init_authentication_method(
                request, client_info, authn_method, **kwargs)
            try:
                headers = h_arg['headers']
            except KeyError:
                pass

        return headers

    def get_request_information(self, client_info, body_type="", method="",
                                     authn_method='', request_args=None,
                                     http_args=None,
                                     **kwargs):
        """
        Builds the request message and constructs the HTTP headers.

        This is the starting pont for a pipeline that will:

        - construct the request message
        - add/remove information to/from the request message in the way a
            specific client authentication method requires.
        - gather a set of HTTP headers like Content-type and Authorization.
        - serialize the request message into the necessary format (JSON,
            urlencoded, signed JWT)

        :param client_info: Client information
        :param body_type: Which serialization to use for the HTTP body
        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param http_args: Initial HTTP header arguments
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP
            request
        """
        if not method:
            method = self.http_method
        if not authn_method:
            authn_method = self.default_authn_method
        if not body_type:
            body_type = self.body_type

        request = self.construct_request(client_info, method=method,
                                         body_type=body_type,
                                         request_args=request_args,
                                         authn_method=authn_method, **kwargs)

        _info = {'method': method}

        # Find out where to send this request
        _args = kwargs.copy()
        if client_info.issuer:
            _args['iss'] = client_info.issuer

        if body_type == 'urlencoded':
            content_type = URL_ENCODED
        else:  # body_type == 'json'
            content_type = JSON_ENCODED

        _headers = self.get_authn_header(request, client_info,
                                                 authn_method, **kwargs)

        endpoint_url = self.get_endpoint(**_args)
        _info['url'] = get_http_url(endpoint_url, request, method=method)

        if method in ['POST', 'PUT']:
            _info['body'] = get_http_body(request, content_type)
            _headers.update({'Content-Type': content_type})
            # Collect HTTP headers

        if _headers:
            _info['headers'] = _headers

        return _info

    # ------------------ response handling -----------------------

    @staticmethod
    def get_urlinfo(info):
        """
        Pick out the fragment or query part from a URL.

        :param info: A URL possibly containing a query or a fragment part
        :return: the query/fragment part
        """
        # If info is a whole URL pick out the query or fragment part
        if '?' in info or '#' in info:
            parts = urlparse(info)
            scheme, netloc, path, params, query, fragment = parts[:6]
            # either query of fragment
            if query:
                info = query
            else:
                info = fragment
        return info

    def post_parse_response(self, client_info, response, **kwargs):
        return response

    def parse_response(self, info, client_info, sformat="", state="",
                       **kwargs):
        """
        This the start of a pipeline that will:

        - Deserializes a response into it's response message class.
            Or :py:class:`oidcmsg.oauth2.ErrorResponse` if it's an error message
        - verifies the correctness of the response by running the
            verify method belonging to the message class used.
        - runs the do_post_parse_response method iff the response was not
            an error response.

        :param info: The response, can be either in a JSON or an urlencoded
            format
        :param client_info: Information about client and server
        :param sformat: Which serialization that was used
        :param state: The state
        :param kwargs: Extra key word arguments
        :return: The parsed and to some extend verified response
        """

        if not sformat:
            sformat = self.response_body_type

        logger.debug('response format: {}'.format(sformat))

        # If format is urlencoded 'info' may be a URL
        # in which case I have to get at the query/fragment part
        if sformat == "urlencoded":
            info = self.get_urlinfo(info)

        if self.events:
            self.events.store('Response', info)

        logger.debug('response_cls: {}'.format(self.response_cls.__name__))
        try:
            resp = self.response_cls().deserialize(info, sformat, **kwargs)
        except Exception as err:
            logger.error('Error while deserializing: {}'.format(err))
            raise

        msg = 'Initial response parsing => "{}"'
        logger.debug(msg.format(resp.to_dict()))
        if self.events:
            self.events.store('Protocol Response', resp)

        # if it's an error message and I didn't expect it recast the
        # response as a :py:class:`oidcmsg.oauth2.ErrorResponse
        if "error" in resp and not isinstance(resp, ErrorResponse):
            resp = None
            # Gather error message classes that are expected if an
            # error was returned.
            try:
                errmsgs = [self.error_msg]
                if ErrorResponse not in errmsgs:
                    # Allow unspecified error response
                    errmsgs.append(ErrorResponse)
            except KeyError:
                errmsgs = [ErrorResponse]

            # loop through the error message classes and pick the one
            # that verifies OK.
            try:
                for errmsg in errmsgs:
                    try:
                        resp = errmsg().deserialize(info, sformat)
                        resp.verify()
                        break
                    except Exception:
                        resp = None
            except KeyError:
                pass

            if not resp:
                logger.debug('Could not map into an error message')
                raise ValueError('No error message: {}'.format(info))

            logger.debug('Error response: {}'.format(resp))
        else:
            # Need to add some information before running verify()
            kwargs["client_id"] = client_info.client_id
            kwargs['iss'] = client_info.issuer

            # If no keys where provided in the method call use the instance's
            # keyjar as default
            if "key" not in kwargs and "keyjar" not in kwargs:
                if self.keyjar:
                    kwargs["keyjar"] = self.keyjar
                else:
                    kwargs['keyjar'] = client_info.keyjar

            # add extra verify keyword arguments
            try:
                kwargs.update(self.conf['verify'])
            except KeyError:
                pass

            logger.debug("Verify response with {}".format(kwargs))
            try:
                # verify the message
                verf = resp.verify(**kwargs)
            except Exception as err:
                logger.error(
                    'Got exception while verifying response: {}'.format(err))
                raise

            if not verf:
                logger.error('Verification of the response failed')
                raise OidcServiceError("Verification of the response failed")

            # if it's an Authorization response and the scope claim was not
            # present in the response use the one I expected to be there.
            if resp.type() == "AuthorizationResponse" and "scope" not in resp:
                try:
                    resp["scope"] = kwargs["scope"]
                except KeyError:
                    pass

            resp = self.post_parse_response(client_info, resp)

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def parse_error_mesg(self, response, body_type):
        """
        Parse an error message.

        :param response: The response text
        :param body_type: How the body is encoded
        :return: A :py:class:`oidcmsg.message.Message` instance
        """
        if body_type == 'txt':
            _body_type = 'urlencoded'
        else:
            _body_type = body_type

        err = self.error_msg().deserialize(response, method=_body_type)
        try:
            err.verify()
        except OidcServiceError:
            raise
        else:
            return err

    def get_conf_attr(self, attr, default=None):
        if attr in self.conf:
            return self.conf[attr]
        else:
            return default


def build_services(srvs, service_factory, keyjar, client_authn_method):
    service = {}
    for serv, conf in srvs:
        _srv = service_factory(serv, keyjar=keyjar,
                               client_authn_method=client_authn_method,
                               conf=conf)
        service[_srv.request] = _srv

    # For any unspecified service
    service['any'] = Service(keyjar=keyjar,
                             client_authn_method=client_authn_method)
    return service
