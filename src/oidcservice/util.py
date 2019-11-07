"""Utilities"""
import importlib
import logging
from urllib.parse import parse_qs
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import yaml
from oidcmsg.exception import UnSupported

LOGGER = logging.getLogger(__name__)

__author__ = 'roland'

URL_ENCODED = 'application/x-www-form-urlencoded'
JSON_ENCODED = "application/json"
JOSE_ENCODED = "application/jose"


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

        return url

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
    if URL_ENCODED in content_type:
        return req.to_urlencoded()

    if JSON_ENCODED in content_type:
        return req.to_json()

    if JOSE_ENCODED in content_type:
        return req  # already packaged

    raise UnSupported(
        "Unsupported content type: '%s'" % content_type)


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding='utf-8') as file:
        config_dict = yaml.safe_load(file)
    return config_dict


def modsplit(name):
    """Split importable"""
    if ':' in name:
        _part = name.split(':')
        if len(_part) != 2:
            raise ValueError("Syntax error: {s}")
        return _part[0], _part[1]

    _part = name.split('.')
    if len(_part) < 2:
        raise ValueError("Syntax error: {s}")

    return '.'.join(_part[:-1]), _part[-1]


def importer(name):
    """Import by name"""
    _part = modsplit(name)
    module = importlib.import_module(_part[0])
    return getattr(module, _part[1])
