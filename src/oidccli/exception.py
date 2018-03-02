
__author__ = 'roland'


# The base exception class for oidccli specific exceptions
class OidcCliError(Exception):
    def __init__(self, errmsg, content_type="", *args):
        Exception.__init__(self, errmsg, *args)
        self.content_type = content_type


class MissingRequiredAttribute(OidcCliError):
    pass


class VerificationError(OidcCliError):
    pass


class ResponseError(OidcCliError):
    pass


class TimeFormatError(OidcCliError):
    pass


class CapabilitiesMisMatch(OidcCliError):
    pass


class MissingEndpoint(OidcCliError):
    pass


class TokenError(OidcCliError):
    pass


class GrantError(OidcCliError):
    pass


class ParseError(OidcCliError):
    pass


class OtherError(OidcCliError):
    pass


class NoClientInfoReceivedError(OidcCliError):
    pass


class InvalidRequest(OidcCliError):
    pass


class NonFatalException(OidcCliError):
    """
    :param resp: A response that the function/method would return on non-error
    :param msg: A message describing what error has occurred.
    """

    def __init__(self, resp, msg):
        self.resp = resp
        self.msg = msg


class Unsupported(OidcCliError):
    pass


class UnsupportedResponseType(Unsupported):
    pass


class AccessDenied(OidcCliError):
    pass


class ImproperlyConfigured(OidcCliError):
    pass


class UnsupportedMethod(OidcCliError):
    pass


class AuthzError(OidcCliError):
    pass


class AuthnToOld(OidcCliError):
    pass


class ParameterError(OidcCliError):
    pass


class SubMismatch(OidcCliError):
    pass


class ConfigurationError(OidcCliError):
    pass


class WrongContentType(OidcCliError):
    pass