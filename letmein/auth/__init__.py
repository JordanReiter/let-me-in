import os
import importlib

GROUPS_WITH_ACCESS = os.environ.get('GROUPS_WITH_ACCESS', '').split()
GROUPS_WITH_ADMIN = os.environ.get('GROUPS_WITH_ADMIN', '').split()

def get_backend():
    try:
        backend = os.environ['AUTH_BACKEND']
    except KeyError:
        raise RuntimeError("AUTH_BACKEND not specified.")
    module, klass = backend.rsplit('.', 1)
    try:
        module = importlib.import_module(module)
        return getattr(module, klass)
    except (ImportError, AttributeError) as err:
        raise RuntimeError("Error importing auth backend {}: {}".format(backend, err))

def get_auth(*args, **kwargs):
    return get_backend()(*args, **kwargs)

Auth = get_auth

