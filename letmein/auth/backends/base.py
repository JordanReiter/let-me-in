import os

class Auth(object):
    def __init__(self, app):
        self.app = app
        self._logout_url = os.environ.get('LOGOUT_URL') or None

    def has_access(self, check_groups=None):
        '''
        Checks for access, optionally limiting by scope.
        If either GROUPS_WITH_ADMIN or GROUPS_WITH_ACCESS is set to *,
        then all logged in users have access.
        '''
        raise NotImplementedError()

    def login_required(self, *args, **kwargs):
        raise NotImplementedError()

    @property
    def logout_url(self):
        return self._logout_url
