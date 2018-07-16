import os

from .base import Auth


class NoAuth(Auth):
    def __init__(self, app):
        super(NoAuth, self).__init__(app)

    def has_access(self, check_groups=None):
        return True

    def login_required(self, func):
        # login isn't required, so this is just an empty decorator
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)
        return decorator

    @property
    def user(self):
        return None

    @property
    def logout_url(self):
        return None
