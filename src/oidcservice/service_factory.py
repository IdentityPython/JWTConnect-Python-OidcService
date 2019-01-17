import inspect
import sys
from glob import glob
from os.path import basename, dirname, join

from oidcservice.service import Service


def service_factory(req_name, module_dirs, **kwargs):
    pwd = dirname(__file__)
    if pwd not in sys.path:
        sys.path.insert(0, pwd)

    for dir in module_dirs:
        for x in glob(join(pwd, dir, '*.py')):
            _mod = basename(x)[:-3]
            if not _mod.startswith('__'):
                if '/' in dir:
                    dir = dir.replace('/', '.')
                _dir_mod = '{}.{}'.format(dir, basename(x)[:-3])
                if _dir_mod not in sys.modules:
                    __import__(_dir_mod, globals(), locals())

                for name, obj in inspect.getmembers(sys.modules[_dir_mod]):
                    if inspect.isclass(obj) and issubclass(obj, Service):
                        try:
                            if obj.__name__ == req_name:
                                return obj(**kwargs)
                        except AttributeError:
                            pass


if __name__ == "__main__":
    from oidcservice.state_interface import InMemoryStateDataBase

    srv = service_factory('AccessToken', ['oidc'], state_db=InMemoryStateDataBase(),
                          service_context=None)
    print(srv.service_name)
