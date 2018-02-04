
__author__ = 'roland'


# The base exception class for oiccli specific exceptions
class OicCliError(Exception):
    def __init__(self, errmsg, content_type="", *args):
        Exception.__init__(self, errmsg, *args)
        self.content_type = content_type


class MissingRequiredAttribute(OicCliError):
    pass


class VerificationError(OicCliError):
    pass


class ResponseError(OicCliError):
    pass


class TimeFormatError(OicCliError):
    pass


class CapabilitiesMisMatch(OicCliError):
    pass


class MissingEndpoint(OicCliError):
    pass


class TokenError(OicCliError):
    pass


class GrantError(OicCliError):
    pass


class ParseError(OicCliError):
    pass


class OtherError(OicCliError):
    pass


class NoClientInfoReceivedError(OicCliError):
    pass


class InvalidRequest(OicCliError):
    pass


class NonFatalException(OicCliError):
    """
    :param resp: A response that the function/method would return on non-error
    :param msg: A message describing what error has occurred.
    """

    def __init__(self, resp, msg):
        self.resp = resp
        self.msg = msg


class Unsupported(OicCliError):
    pass


class UnsupportedResponseType(Unsupported):
    pass


class AccessDenied(OicCliError):
    pass


class ImproperlyConfigured(OicCliError):
    pass


class UnsupportedMethod(OicCliError):
    pass


class AuthzError(OicCliError):
    pass


class AuthnToOld(OicCliError):
    pass


class ParameterError(OicCliError):
    pass


class SubMismatch(OicCliError):
    pass


class ConfigurationError(OicCliError):
    pass


class WrongContentType(OicCliError):
    pass