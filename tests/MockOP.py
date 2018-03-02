from oidcmsg.exception import OidcMsgError
from oidcmsg.oauth2 import AuthorizationRequest


class HTTPResponse(object):
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class MockOP(object):
    def __init__(self, baseurl='http://example.com/'):
        self.baseurl = baseurl

    def __call__(self, url, method, **kwargs):
        if url.startswith(self.baseurl):
            path = url[len(self.baseurl):]
        else:
            path = url

        if '?' in path:
            what, req = path.split('?', 1)
            meth = getattr(self, what)
            return meth(req)
        else:
            meth = getattr(self, path)
            return meth(kwargs['data'])

    def discovery(self):
        pass

    def register(self, request):
        pass

    def authorization(self, request, **kwargs):
        areq = AuthorizationRequest().from_urlencoded(request)

        if not areq.verify():
            raise OidcMsgError('Verification failed')

        resp = HTTPResponse('OK')
        return resp

    def token(self, request, **kwargs):
        pass

    def userinfo(self, request, **kwargs):
        pass
