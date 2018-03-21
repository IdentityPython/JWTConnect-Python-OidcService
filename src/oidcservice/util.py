import logging
from urllib.parse import parse_qs
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from oidcmsg.exception import UnSupported

logger = logging.getLogger(__name__)

__author__ = 'roland'

URL_ENCODED = 'application/x-www-form-urlencoded'
JSON_ENCODED = "application/json"


def get_http_url(url, req, method='GET'):
    """
    Add a query part representing the request to a url that may already contain
    a query part. Only done if the HTTP method used is 'GET' or 'DELETE'.

    :param url: The URL
    :param req: The request as a :py:class:`oidcmsg.message.Message` instance
    :param method: The HTTP method
    :return: A possibly modified URL
    """
    if method in ["GET", "DELETE"]:
        if req.keys():
            _req = req.copy()
            comp = urlsplit(str(url))
            if comp.query:
                _req.update(parse_qs(comp.query))

            _query = str(_req.to_urlencoded())
            return urlunsplit((comp.scheme, comp.netloc, comp.path,
                               _query, comp.fragment))
        else:
            return url
    else:
        return url


def get_http_body(req, content_type=URL_ENCODED):
    """
    Get the message into the format that should be places in the body part
    of a HTTP request.

    :param req: The service request as a  :py:class:`oidcmsg.message.Message`
        instance
    :param content_type: The format of the body part.
    :return: The correctly formatet service request.
    """
    if content_type == URL_ENCODED:
        return req.to_urlencoded()
    elif content_type == JSON_ENCODED:
        return req.to_json()
    else:
        raise UnSupported(
            "Unsupported content type: '%s'" % content_type)


def add_path(url, path):
    if url.endswith('/'):
        if path.startswith('/'):
            return '{}{}'.format(url, path[1:])
        else:
            return '{}{}'.format(url, path)
    else:
        if path.startswith('/'):
            return '{}{}'.format(url, path)
        else:
            return '{}/{}'.format(url, path)
