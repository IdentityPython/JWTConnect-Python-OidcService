import logging

from future.backports.urllib.parse import urlparse
from oiccli.exception import HttpError
from oiccli.exception import MissingEndpoint
from oiccli.exception import OicCliError
from oiccli.exception import ParseError
from oiccli.exception import ResponseError
from oiccli.util import get_or_post
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

SPECIAL_ARGS = ['authn_endpoint', 'authn_endpoint']


class Request(object):
    msg_type = Message
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = ''
    synchronous = True
    request = ''

    def __init__(self, httplib=None, keyjar=None, client_authn_method=None):
        self.httplib = httplib
        self.keyjar = keyjar
        self.client_authn_method = client_authn_method
        self.events = None
        self.endpoint = ''
        self.default_request_args = {}

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

        # logger.debug("request_args: %s" % sanitize(request_args))
        _args = self._parse_args(cli_info, **request_args)

        if kwargs:
            _args.update(kwargs)

        # logger.debug("kwargs: %s" % sanitize(kwargs))
        return self.msg_type(**_args)

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

    def init_authentication_method(self, cis, authn_method, request_args=None,
                                   http_args=None, **kwargs):
        """
        Place the necessary information in the necessary places depending on
        client authentication method.

        :param cis: Message class instance
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
            return self.client_authn_method[authn_method](self).construct(
                cis, request_args, http_args, **kwargs)
        else:
            return http_args

    def request_info(self, cli_info, method="GET", request_args=None,
                     lax=False, **kwargs):

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

        if "authn_method" in kwargs:
            h_arg = self.init_authentication_method(cis,
                                                    request_args=request_args,
                                                    **kwargs)
        else:
            h_arg = None

        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg["headers"])
            else:
                kwargs["headers"] = h_arg["headers"]

        return self.uri_and_body(cis, method, request_args, **kwargs)

    def update_http_args(self, http_args, info):
        if http_args is None:
            http_args = info['h_args']
        else:
            http_args.update(info['h_args'])

        info['http_args'] = http_args
        return info

    def do_request_init(self, cli_info, body_type="", method="GET",
                        request_args=None, http_args=None, **kwargs):
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
        try:
            authn_method = kwargs['authn_method']
        except:
            authn_method = ''

        _info = self.request_info(cli_info, method=method,
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

    def _post_parse_response(self, resp, client_info, state=''):
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
            try:
                kwargs['iss'] = client_info.provider_info['issuer']
            except (KeyError, AttributeError):
                try:
                    kwargs['iss'] = client_info.issuer
                except KeyError:
                    pass

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
            self._post_parse_response(resp, client_info, state=state)
        except Exception as err:
            raise

        return resp

    def _parse_error_mesg(self, reqresp, body_type):
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
            # expecting an error response
            try:
                err_resp = self._parse_error_mesg(reqresp, value_type)
            except OicCliError:
                return reqresp.text
            else:
                return err_resp
        else:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise HttpError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))
