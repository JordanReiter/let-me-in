import os

import flask
from flask_cas import CAS, login_required as cas_login_required

from .base import Auth

CAS_SETTINGS = [
    'CAS_SERVER' , 'CAS_TOKEN_SESSION_KEY', 'CAS_USERNAME_SESSION_KEY',
    'CAS_ATTRIBUTES_SESSION_KEY', 'CAS_AFTER_LOGIN', 'CAS_LOGIN_ROUTE',
    'CAS_LOGOUT_ROUTE', 'CAS_VALIDATE_ROUTE', 'CAS_AFTER_LOGOUT',
]


class CASAuth(Auth):
    def __init__(self, app):
        super(CASAuth, self).__init__(app)
        for setting in CAS_SETTINGS:
            if setting in os.environ:
                self.app.config[setting] = os.environ[setting]
        self.cas = CAS(app, '/cas')

    def has_access(self, check_groups=None):
        '''
        Checks for access, optionally limiting by scope.
        If either GROUPS_WITH_ADMIN or GROUPS_WITH_ACCESS is set to *,
        then all logged in users have access.
        '''
        if not check_groups:
            return False
        if check_groups=='*':
            return True
        if 'CAS_USERNAME' not in flask.session or not self.cas.attributes:
            return False
        groups = self.cas.attributes.get('cas:memberOf', [])
        return any(gg in check_groups for gg in groups)

    @property
    def login_required(self):
        return cas_login_required

    @property
    def user(self):
        return self.cas.username

    @property
    def logout_url(self):
        return os.environ.get("LOGOUT_URL") or '{}/logout/'.format(self.app.config.get('CAS_SERVER', ''))


auth_class = CASAuth
