import logging
from urllib.parse import urlparse

from oiccli.exception import MissingEndpoint
from oiccli.exception import OicCliError
from oiccli.exception import ResponseError
from oiccli.util import get_or_post
from oiccli.util import JSON_ENCODED
from oicmsg.oauth2 import AuthorizationErrorResponse
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oauth2 import Message
from oicmsg.oauth2 import TokenErrorResponse

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

"""

method call structure for Services.
This is for constructing requests:

do_request_init
    - request_info
        - construct 
            - pre_construct (*)
            - gather_request_args
            - post_construct (*)
        - init_authentication_method
        - uri_and_body
            - _endpoint
    - update_http_args

and this for parsing the response.

service_request
    - parse_request_response
        - parse_response
             - get_urlinfo
             - post_parse_response (*)
        - parse_error_mesg

The methods marked with (*) are where service specific
behaviour is implemented.


"""

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]

RESPONSE2ERROR = {
    "AuthorizationResponse": [AuthorizationErrorResponse, TokenErrorResponse],
    "AccessTokenResponse": [TokenErrorResponse]
}

SPECIAL_ARGS = ['authn_endpoint', 'algs']

REQUEST_INFO = 'Doing request with: URL:{}, method:{}, data:{}, https_args:{}'


def update_http_args(http_args, info):
    """
    Extending the header with information gathered during the request
    setup.

    :param http_args: Original HTTP header arguments
    :param info: Request info
    :return: Updated request info
    """
    try:
        h_args = info['h_args']
    except KeyError:
        h_args = {}

    if http_args is None:
        http_args = h_args
    else:
        http_args.update(info['h_args'])

    try:
        _headers = info['kwargs']['headers']
    except KeyError:
        pass
    else:
        http_args.update({'headers': _headers})

    info['http_args'] = http_args
    return info


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

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None,
                 conf=None, **kwargs):
        self.httplib = httplib
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
        self.post_parse_response = []

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
            :py:class:`oiccli.client_info.ClientInfo` instance.
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
            :py:class:`oiccli.client_info.ClientInfo` instance.
        :param request_args: Request arguments
        :param post_args: Arguments used by the post_construct method
        :return: Possible modified set of request arguments.
        """
        _args = self.method_args('post_construct', **kwargs)

        for meth in self.post_construct:
            request_args = meth(client_info, request_args, **_args)

        return request_args

    def do_post_parse_response(self, resp, client_info, state='', **kwargs):
        """
        A method run after the response has been parsed and verified.

        :param resp: The response as a :py:class:`oicmsg.Message` instance
        :param client_info: Client Information as a
            :py:class:`oiccli.client_info.ClientInfo` instance.
        :param state: state value
        :param kwargs: Extra key word arguments
        """
        _args = self.method_args('post_parse_response', **kwargs)

        for meth in self.post_parse_response:
            meth(resp, client_info, state=state, **_args)

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

    def uri_and_body(self, request, method="POST", **kwargs):
        """
        Based on the HTTP method place the protocol message in the right
        place.

        :param request: The request as a Message class instance
        :param method: HTTP method
        :param kwargs: Extra keyword argument
        :return: Dictionary with 'uri' and possibly also 'body' and 'kwargs'
            as keys
        """
        # Find out where to send this request
        uri = self._endpoint(**kwargs)

        # This is where the message gets assigned to its proper place
        info = get_or_post(uri, method, request, **kwargs)

        # transport independent version of the request
        info['request'] = request.to_dict()

        # If there are HTTP header arguments add them to *info* using
        # the key *h_args*
        try:
            info['h_args'] = {"headers": kwargs["headers"]}
        except KeyError:
            pass

        return info

    def init_authentication_method(self, request, client_info, authn_method,
                                   http_args=None, **kwargs):
        """
        Will run the proper client authentication method.
        Each such method will place the necessary information in the necessary
        place. A method may modify the request.

        :param request: The request, a Message class instance
        :param client_info: Client information, a
            :py:class:`oiccli.client_info.ClientInfo` instance
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

    def request_info(self, client_info, method="", request_args=None,
                     body_type='', authn_method='', lax=False, **kwargs):
        """
        The method where everything is setup for sending the request.
        The request information is gathered and the where and how of sending the
        request is decided.

        :param client_info: Client information as a
            :py:class:`oiccli.client_info.ClientInfo` instance
        :param method: The HTTP method to be used.
        :param request_args: Initial request arguments
        :param body_type: If the request is sent in the HTTP body this
            decides the encoding of the request
        :param authn_method: The client authentication method
        :param lax: If it should be allowed to send a request that doesn't
            completely conform to the standard.
        :param kwargs: Extra keyword arguments
        :return: A dictionary with the keys 'uri' and possibly 'body', 'kwargs',
            'request' and 'ht_args'.
        """
        if not method:
            method = self.http_method

        if request_args is None:
            request_args = {}

        # remove arguments that should not be included in the request
        _args = dict(
            [(k, v) for k, v in kwargs.items() if v and k not in SPECIAL_ARGS])

        request = self.construct(client_info, request_args, **_args)

        if self.events:
            self.events.store('Protocol request', request)

        # If I'm to be lenient when verifying the correctness of the request
        # message
        request.lax = lax
        h_arg = None

        # If I should deal with client authentication
        if authn_method:
            h_arg = self.init_authentication_method(
                request, client_info, authn_method, **kwargs)

        # Set the necessary HTTP headers
        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg["headers"])
            else:
                kwargs["headers"] = h_arg["headers"]

        if body_type == 'json':
            kwargs['content_type'] = JSON_ENCODED

        return self.uri_and_body(request, method, **kwargs)

    def do_request_init(self, client_info, body_type="", method="",
                        authn_method='', request_args=None, http_args=None,
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

        _info = self.request_info(client_info, method=method,
                                  body_type=body_type,
                                  request_args=request_args,
                                  authn_method=authn_method, **kwargs)

        return update_http_args(http_args, _info)

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

    def parse_response(self, info, client_info, sformat="", state="",
                       **kwargs):
        """
        This the start of a pipeline that will:

        - Deserializes a response into it's response message class.
            Or :py:class:`oicmsg.oauth2.ErrorResponse` if it's an error message
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
        # response as a :py:class:`oicmsg.oauth2.ErrorResponse
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
                kwargs["keyjar"] = self.keyjar

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
                raise OicCliError("Verification of the response failed")

            # if it's an Authorization response and the scope claim was not
            # present in the response use the one I expected to be there.
            if resp.type() == "AuthorizationResponse" and "scope" not in resp:
                try:
                    resp["scope"] = kwargs["scope"]
                except KeyError:
                    pass

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        if not isinstance(resp, ErrorResponse):
            try:
                self.do_post_parse_response(resp, client_info, state=state)
            except Exception as err:
                logger.error(
                    'Got exception on do_post_parse_result: {}'.format(err))
                raise

        return resp

    def parse_error_mesg(self, response, body_type):
        """
        Parse an error message.

        :param response: The response text
        :param body_type: How the body is encoded
        :return: A :py:class:`oicmsg.message.Message` instance
        """
        if body_type == 'txt':
            _body_type = 'urlencoded'
        else:
            _body_type = body_type

        err = self.error_msg().deserialize(response, method=_body_type)
        try:
            err.verify()
        except OicCliError:
            raise
        else:
            return err

    def get_conf_attr(self, attr, default=None):
        if attr in self.conf:
            return self.conf[attr]
        else:
            return default


def build_services(srvs, service_factory, http, keyjar, client_authn_method):
    service = {}
    for serv, conf in srvs:
        _srv = service_factory(serv, httplib=http, keyjar=keyjar,
                               client_authn_method=client_authn_method,
                               conf=conf)
        service[_srv.request] = _srv

    # For any unspecified service
    service['any'] = Service(httplib=http, keyjar=keyjar,
                             client_authn_method=client_authn_method)
    return service
