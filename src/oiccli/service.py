import logging

from future.backports.urllib.parse import urlparse
from oiccli.exception import HttpError
from oiccli.exception import MissingEndpoint
from oiccli.exception import OicCliError
from oiccli.exception import ParseError
from oiccli.exception import ResponseError
from oiccli.util import get_or_post
from oiccli.util import JSON_ENCODED
from oiccli.util import verify_header
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
                 **kwargs):
        self.httplib = httplib
        self.keyjar = keyjar
        self.client_authn_method = client_authn_method
        self.events = None
        self.endpoint = ''
        self.default_request_args = {}

        # pull in all the modifiers
        self.pre_construct = []
        self.post_construct = []
        self.post_parse_response = []

    def gather_request_args(self, cli_info, **kwargs):
        """
        Go through the attributes that the message class can contain and
        add values if they are missing and exists in the client info or
        when there are default values.

        :param cli_info: Client info
        :param kwargs: Initial set of attributes.
        :return: Possibly augmented set of attributes
        """
        ar_args = kwargs.copy()

        # Go through the list of claims defined for the message class
        for prop in self.msg_type.c_param.keys():
            if prop in ar_args:
                continue
            else:
                try:
                    ar_args[prop] = getattr(cli_info, prop)
                except AttributeError:
                    try:
                        ar_args[prop] = self.default_request_args[prop]
                    except KeyError:
                        pass

        return ar_args

    def do_pre_construct(self, cli_info, request_args, **kwargs):
        """
        Will run the pre_construct methods one at the time in order.

        :param cli_info: Client Information as a :py:class:`oiccli.Client`
            instance.
        :param request_args: Request arguments
        :param kwargs: Extra key word arguments
        :return: A tuple of request_args and post_args. post_args are to be
            used by the post_construct methods.
        """
        post_args = {}
        for meth in self.pre_construct:
            request_args, _post_args = meth(cli_info, request_args, **kwargs)
            post_args.update(_post_args)

        return request_args, post_args

    def do_post_construct(self, cli_info, request_args, **post_args):
        """
        Will run the post_construct methods one at the time in order.

        :param cli_info: Client Information as a :py:class:`oiccli.Client`
            instance.
        :param request_args: Request arguments
        :param kwargs: Extra key word arguments
        :return: request_args.
        """
        for meth in self.post_construct:
            request_args = meth(cli_info, request_args, **post_args)

        return request_args

    def do_post_parse_response(self, resp, cli_info, state='', **kwargs):
        """
        A method run after the response has been parsed and verified.

        :param resp: The response as a :py:class:`oicmsg.Message` instance
        :param cli_info: Client Information as a :py:class:`oiccli.Client`
            instance.
        :param state: state value
        :param kwargs: Extra key word arguments
        """
        for meth in self.post_parse_response:
            meth(resp, cli_info, state=state, **kwargs)

    def construct(self, cli_info, request_args=None, **kwargs):
        """
        Instantiate the request as a message class instance

        :param cli_info: Information about the client
        :param request_args:
        :param kwargs: extra keyword arguments
        :return: message class instance
        """
        if request_args is None:
            request_args = {}

        request_args, post_args = self.do_pre_construct(cli_info, request_args,
                                                        **kwargs)

        if 'state' not in self.msg_type.c_param:
            try:
                del kwargs['state']
            except KeyError:
                pass

        # logger.debug("request_args: %s" % sanitize(request_args))
        _args = self.gather_request_args(cli_info, **request_args)

        # logger.debug("kwargs: %s" % sanitize(kwargs))
        request = self.msg_type(**_args)

        return self.do_post_construct(cli_info, request, **post_args)

    def _endpoint(self, **kwargs):
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
        info['cis'] = request
        try:
            info['h_args'] = {"headers": info["headers"]}
        except KeyError:
            pass

        return info

    def init_authentication_method(self, request, cli_info, authn_method,
                                   http_args=None, **kwargs):
        """
        Place the necessary information in the necessary places depending on
        client authentication method.

        :param request: The request, a Message class instance
        :param cli_info: Client information, a
            :py:class:`oiccli.clinet_info.ClientInfo`instance
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
                request, cli_info, http_args=http_args, **kwargs)
        else:
            return http_args

    def request_info(self, cli_info, method="", request_args=None,
                     body_type='', authn_method='', lax=False, **kwargs):
        """
        The method where everything is setup for sending the request.
        The request information is gathered and the where and how of sending the
        request is decided.

        :param cli_info: Client information as a :py:class:`oiccli.Client`
            instance
        :param method: The HTTP method to be used.
        :param request_args: Initial request arguments
        :param body_type: If the request is sent in the HTTP body this
            decides the encoding of the request
        :param authn_method: The client authentication method
        :param lax: If it should be allowed to send a request that doesn't
            completely conform to the standard.
        :param kwargs: Extra keyword arguments
        :return: A dictionary with the keys 'uri' and possibly 'body', 'kwargs',
            'cis' and 'ht_args'.
        """
        if not method:
            method = self.http_method

        if request_args is None:
            request_args = {}

        _args = dict(
            [(k, v) for k, v in kwargs.items() if v and k not in SPECIAL_ARGS])

        request = self.construct(cli_info, request_args, **_args)

        if self.events:
            self.events.store('Protocol request', request)

        # If I'm to be lenient when verifying the message
        request.lax = lax
        h_arg = None

        if authn_method:
            h_arg = self.init_authentication_method(
                request, cli_info, authn_method, **kwargs)

        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg["headers"])
            else:
                kwargs["headers"] = h_arg["headers"]

        if body_type == 'json':
            kwargs['content_type'] = JSON_ENCODED

        return self.uri_and_body(request, method, **kwargs)

    def do_request_init(self, cli_info, body_type="", method="",
                        authn_method='', request_args=None, http_args=None,
                        **kwargs):
        """
        Builds the request message and constructs the HTTP headers.

        :param cli_info: Client information
        :param body_type: Which serialization to use for the HTTP body
        :param method: HTTP method used.
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

        _info = self.request_info(cli_info, method=method, body_type=body_type,
                                  request_args=request_args,
                                  authn_method=authn_method, **kwargs)

        return update_http_args(http_args, _info)

    # ------------------ response handling -----------------------

    @staticmethod
    def get_urlinfo(info):
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

    def parse_response(self, info, client_info, sformat="json", state="",
                       **kwargs):
        """
        Parse a response

        :param info: The response, can be either in a JSON or an urlencoded
            format
        :param client_info: Information about client and server
        :param sformat: Which serialization that was used
        :param state: The state
        :param kwargs: Extra key word arguments
        :return: The parsed and to some extend verified response
        """

        logger.debug('response format: {}'.format(sformat))

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

        if "error" in resp and not isinstance(resp, ErrorResponse):
            resp = None
            try:
                errmsgs = [self.error_msg]
                if ErrorResponse not in errmsgs:
                    # Allow unspecified error response
                    errmsgs.append(ErrorResponse)
            except KeyError:
                errmsgs = [ErrorResponse]

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

            logger.debug('Error response: {}'.format(resp))
        else:
            kwargs["client_id"] = client_info.client_id
            kwargs['iss'] = client_info.issuer

            if "key" not in kwargs and "keyjar" not in kwargs:
                kwargs["keyjar"] = self.keyjar

            logger.debug("Verify response with {}".format(kwargs))
            try:
                verf = resp.verify(**kwargs)
            except Exception as err:
                raise

            if not verf:
                logger.error('Verification of the response failed')
                raise OicCliError("Verification of the response failed")
            if resp.type() == "AuthorizationResponse" and "scope" not in resp:
                try:
                    resp["scope"] = kwargs["scope"]
                except KeyError:
                    pass

        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        try:
            self.do_post_parse_response(resp, client_info, state=state)
        except Exception as err:
            logger.error(
                'Got exception on do_post_parse_result: {}'.format(err))
            raise

        return resp

    def parse_error_mesg(self, reqresp, body_type):
        """
        Parse an error message.

        :param reqresp: The response
        :param body_type: How the body is encoded
        :return: A :py:class:`oicmsg.message.Message` instance
        """
        if body_type == 'txt':
            _body_type = 'urlencoded'
        else:
            _body_type = body_type

        err = self.error_msg().deserialize(reqresp.text, method=_body_type)
        try:
            err.verify()
        except OicCliError:
            raise
        else:
            return err

    def get_value_type(self, reqresp, body_type):
        """
        Get the encoding of the response.

        :param reqresp: The response
        :param body_type: Assumed body type
        :return: The calculated body type
        """
        if body_type:
            return verify_header(reqresp, body_type)
        else:
            return 'urlencoded'

    def parse_request_response(self, reqresp, client_info,
                               response_body_type='',
                               state="", **kwargs):
        """
        Deal with a request response
         
        :param reqresp: The HTTP request response
        :param client_info: Information about the client/server session
        :param response_body_type: If response in body one of 'json', 'jwt' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return: 
        """

        if reqresp.status_code in SUCCESSFUL:
            logger.debug('response_body_type: "{}"'.format(response_body_type))
            value_type = self.get_value_type(reqresp, response_body_type)

            logger.debug('Successful response: {}'.format(reqresp.text))
            try:
                return self.parse_response(reqresp.text, client_info,
                                           value_type, state, **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif 400 <= reqresp.status_code < 500:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            # expecting an error response
            value_type = self.get_value_type(reqresp, response_body_type)

            try:
                err_resp = self.parse_error_mesg(reqresp, value_type)
            except OicCliError:
                return reqresp.text
            else:
                return err_resp
        else:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            raise HttpError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

    def service_request(self, url, method="GET", body=None,
                        response_body_type="", http_args=None, client_info=None,
                        **kwargs):
        """
        The method that sends the request and handles the response returned.
        This assumes a synchronous request-response exchange.

        :param url: The URL to which the request should be sent
        :param response: Response type
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param response_body_type: The expected format of the body of the
            return message
        :param http_args: Arguments for the HTTP client
        :return: A cls or ErrorResponse instance or the HTTP response
            instance if no response body was expected.
        """

        if http_args is None:
            http_args = {}

        logger.debug(REQUEST_INFO.format(url, method, body, http_args))

        try:
            resp = self.httplib(url, method, data=body, **http_args)
        except Exception as err:
            logger.error('Exception on request: {}'.format(err))
            raise

        if "keyjar" not in kwargs:
            kwargs["keyjar"] = self.keyjar
        if not response_body_type:
            response_body_type = self.response_body_type

        return self.parse_request_response(resp, client_info,
                                           response_body_type, **kwargs)
