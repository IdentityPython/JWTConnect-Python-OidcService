import logging
from urllib.parse import parse_qs
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from oicmsg.exception import UnSupported

logger = logging.getLogger(__name__)

__author__ = 'roland'

URL_ENCODED = 'application/x-www-form-urlencoded'
JSON_ENCODED = "application/json"

DEFAULT_POST_CONTENT_TYPE = URL_ENCODED

PAIRS = {
    "port": "port_specified",
    "domain": "domain_specified",
    "path": "path_specified"
}

ATTRS = {"version": None,
         "name": "",
         "value": None,
         "port": None,
         "port_specified": False,
         "domain": "",
         "domain_specified": False,
         "domain_initial_dot": False,
         "path": "",
         "path_specified": False,
         "secure": False,
         "expires": None,
         "discard": True,
         "comment": None,
         "comment_url": None,
         "rest": "",
         "rfc2109": True}


def get_or_post(uri, method, req, content_type=DEFAULT_POST_CONTENT_TYPE,
        accept=None, **kwargs):
    """
    Create the information pieces necessary for sending a request.
    Depending on whether the request is done using GET or POST the request
    is placed in different places and serialized into different formats.

    :param uri: The URL pointing to where the request should be sent
    :param method: Which method that should be used to send the request
    :param req: The request as a :py:class:`oicmsg.message.Message` instance
    :param content_type: Which content type to use for the body
    :param accept: Whether an Accept header should be added to the HTTP request
    :param kwargs: Extra keyword arguments.
    :return:
    """
    resp = {}
    if method in ["GET", "DELETE"]:
        if req.keys():
            _req = req.copy()
            comp = urlsplit(str(uri))
            if comp.query:
                _req.update(parse_qs(comp.query))

            _query = str(_req.to_urlencoded())
            resp['uri'] = urlunsplit((comp.scheme, comp.netloc, comp.path,
                                      _query, comp.fragment))
        else:
            resp['uri'] = uri
    elif method in ["POST", "PUT"]:
        resp['uri'] = uri
        if content_type == URL_ENCODED:
            resp['body'] = req.to_urlencoded()
        elif content_type == JSON_ENCODED:
            resp['body'] = req.to_json()
        else:
            raise UnSupported(
                "Unsupported content type: '%s'" % content_type)

        header_ext = {"Content-Type": content_type}
        if accept:
            header_ext = {"Accept": accept}

        if "headers" in kwargs.keys():
            kwargs["headers"].update(header_ext)
        else:
            kwargs["headers"] = header_ext
        resp['kwargs'] = kwargs
    else:
        raise UnSupported("Unsupported HTTP method: '%s'" % method)

    return resp


def match_to_(val, vlist):
    if isinstance(vlist, str):
        if vlist.startswith(val):
            return True
    else:
        for v in vlist:
            if v.startswith(val):
                return True
    return False


SORT_ORDER = {'RS': 0, 'ES': 1, 'HS': 2, 'PS': 3, 'no': 4}


def sort_sign_alg(alg1, alg2):
    if SORT_ORDER[alg1[0:2]] < SORT_ORDER[alg2[0:2]]:
        return -1
    elif SORT_ORDER[alg1[0:2]] > SORT_ORDER[alg2[0:2]]:
        return 1
    else:
        if alg1 < alg2:
            return -1
        elif alg1 > alg2:
            return 1
        else:
            return 0
