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

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]

RESPONSE2ERROR = {
    "AuthorizationResponse": [AuthorizationErrorResponse, TokenErrorResponse],
    "AccessTokenResponse": [TokenErrorResponse]
}

SPECIAL_ARGS = ['authn_endpoint', 'algs']

"""
method call structure for Requests:

do_request_init
    - request_info
        - construct 
            - pre_construct (*)
            - _parse_args
            - post_construct (*)
        - init_authentication_method
        - uri_and_body
            - _endpoint
    - update_http_args

request_and_return
    - parse_request_response
        - parse_response
             - get_urlinfo
             - post_parse_response (*)
        - parse_error_mesg
        
"""


class Request(object):
    msg_type = Message
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = ''
    default_authn_method = ''
    http_method = 'GET'
    body_type = 'urlencoded'

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
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
        self.setup()

    def _parse_args(self, cli_info, **kwargs):
        """
        Go through the attributes that the message class can contain and
        add values if they are missing and exists in the client info or
        when there are default values.

        :param cli_info: Client info
        :param kwargs: Initial set of attributes.
        :return: Possibly augmented set of attributes
        """
        ar_args = kwargs.copy()

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
        post_args = {}
        for meth in self.pre_construct:
            request_args, _post_args = meth(cli_info, request_args, **kwargs)
            post_args.update(_post_args)

        return request_args, post_args

    def do_post_construct(self, cli_info, request_args, **post_args):
        for meth in self.post_construct:
            request_args = meth(cli_info, request_args, **post_args)

        return request_args

    def do_post_parse_response(self, resp, cli_info, state='', **kwargs):
        for meth in self.post_parse_response:
            meth(resp, cli_info, state=state, **kwargs)

    def setup(self):
        pass

    def construct(self, cli_info, request_args=None, **kwargs):
        """
        Instantiate the message class instance

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
        _args = self._parse_args(cli_info, **request_args)

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
                    self.__name__))

        if not uri:
            raise MissingEndpoint("No '{}' endpoint specified".format(
                self.__name__))

        return uri

    def uri_and_body(self, cis, method="POST", request_args=None, **kwargs):
        """
        Based on the HTTP method place the protocol message in the right
        place.

        :param cis: Message class instance
        :param method: HTTP method
        :param request_args: Message arguments
        :param kwargs: Extra keyword argument
        :return: Dictionary
        """
        uri = self._endpoint(**request_args)

        uri, body, kwargs = get_or_post(uri, method, cis, **kwargs)
        try:
            h_args = {"headers": kwargs["headers"]}
        except KeyError:
            h_args = {}

        return {'uri': uri, 'body': body, 'h_args': h_args, 'cis': cis}

    def init_authentication_method(self, cis, cli_info, authn_method,
                                   request_args=None, http_args=None, **kwargs):
        """
        Place the necessary information in the necessary places depending on
        client authentication method.

        :param cis: Message class instance
        :param cli_info: Client information
        :param authn_method: Client authentication method
        :param request_args: Message argument
        :param http_args: HTTP header arguments
        :param kwargs: Extra keyword arguments
        :return: Extended set of HTTP header arguments
        """
        if http_args is None:
            http_args = {}
        if request_args is None:
            request_args = {}

        if authn_method:
            return self.client_authn_method[authn_method]().construct(
                cis, cli_info, request_args, http_args, **kwargs)
        else:
            return http_args

    def request_info(self, cli_info, method="", request_args=None,
                     body_type='', authn_method='', lax=False, **kwargs):

        if not method:
            method = self.http_method

        if request_args is None:
            request_args = {}

        _args = dict(
            [(k, v) for k, v in kwargs.items() if v and k not in SPECIAL_ARGS])

        cis = self.construct(cli_info, request_args, **_args)

        if self.events:
            self.events.store('Protocol request', cis)

        # if 'nonce' in cis and 'state' in cis:
        #     self.state2nonce[cis['state']] = cis['nonce']

        cis.lax = lax
        h_arg = None

        if authn_method:
            h_arg = self.init_authentication_method(
                cis, cli_info, authn_method, request_args=request_args,
                **kwargs)

        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg["headers"])
            else:
                kwargs["headers"] = h_arg["headers"]

        if body_type == 'json':
            kwargs['content_type'] = JSON_ENCODED

        return self.uri_and_body(cis, method, request_args, **kwargs)

    def update_http_args(self, http_args, info):
        if http_args is None:
            http_args = info['h_args']
        else:
            http_args.update(info['h_args'])

        info['http_args'] = http_args
        return info

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

        return self.update_http_args(http_args, _info)

    # ------------------ response handling -----------------------

    @staticmethod
    def get_urlinfo(info):
        if '?' in info or '#' in info:
            parts = urlparse(info)
            scheme, netloc, path, params, query, fragment = parts[:6]
            # either query of fragment
            if query:
                info = query
            else:
                info = fragment
        return info

    def _post_parse_response(self, resp, client_info, state='', **kwargs):
        pass

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

        if sformat == "urlencoded":
            info = self.get_urlinfo(info)

        if self.events:
            self.events.store('Response', info)

        resp = self.response_cls().deserialize(info, sformat, **kwargs)

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
        # elif resp.only_extras():
        #     resp = None
        else:
            kwargs["client_id"] = client_info.client_id

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
            raise

        return resp

    def parse_error_mesg(self, reqresp, body_type):
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

    def parse_request_response(self, reqresp, client_info, body_type='',
                               state="", **kwargs):
        """
        Deal with a request response
         
        :param reqresp: The HTTP request response
        :param client_info: Information about the client/server session
        :param body_type: If response in body one of 'json', 'jwt' or 
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return: 
        """

        if body_type:
            value_type = verify_header(reqresp, body_type)
        else:
            value_type = 'urlencoded'

        if reqresp.status_code in SUCCESSFUL:
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

    def request_and_return(self, url, method="GET", body=None,
                           body_type="json", http_args=None,
                           client_info=None, **kwargs):
        """
        :param url: The URL to which the request should be sent
        :param response: Response type
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param body_type: The format of the body of the return message
        :param http_args: Arguments for the HTTP client
        :return: A cls or ErrorResponse instance or the HTTP response
            instance if no response body was expected.
        """

        if http_args is None:
            http_args = {}

        try:
            resp = self.httplib(url, method, data=body, **http_args)
        except Exception:
            raise

        if "keyjar" not in kwargs:
            kwargs["keyjar"] = self.keyjar

        return self.parse_request_response(resp, client_info, body_type,
                                           **kwargs)

