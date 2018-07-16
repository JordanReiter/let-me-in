import os
from unittest import TestCase

try:
    from unittest import mock
except ImportError:
    import mock

import flask
from flask_cas import login_required, CAS

import letmein.auth

class BaseAuthTestMixin(object):
    pass

TEST_CAS_SERVER = 'https://login.example.com'


class FakeApp(mock.Mock):
    def __init__(self, *args, **kwargs):
        super(FakeApp, self).__init__(*args, **kwargs)
        self.config = {}


class TestAuth(BaseAuthTestMixin, TestCase):
    def setUp(self):
        from letmein.auth.backends import base
        super(TestAuth, self).setUp()
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        self.backend = base


    def test_backend_config_required(self):
        OLD_BACKEND = os.environ.pop('AUTH_BACKEND', None)
        with self.assertRaises(RuntimeError):
            letmein.auth.get_backend()
        os.environ['AUTH_BACKEND'] = OLD_BACKEND

    def test_backend_bad_module(self):
        OLD_BACKEND = os.environ.pop('AUTH_BACKEND', None)
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.fake.FakeAuth'
        with self.assertRaises(RuntimeError):
            letmein.auth.get_backend()
        os.environ['AUTH_BACKEND'] = OLD_BACKEND

    def test_backend_bad_class(self):
        OLD_BACKEND = os.environ.pop('AUTH_BACKEND', None)
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.base.NonexistentAuth'
        with self.assertRaises(RuntimeError):
            letmein.auth.get_backend()
        os.environ['AUTH_BACKEND'] = OLD_BACKEND

    def test_get_backend(self):
        from letmein.auth.backends import cas
        self.assertEqual(
            letmein.auth.get_backend(),
            cas.CASAuth
        )

    def test_get_auth(self):
        from letmein.auth.backends import cas
        fake_app = FakeApp()
        self.assertIsInstance(
            letmein.auth.get_auth(fake_app),
            cas.CASAuth
        )

    def test_base_login_url(self):
        os.environ['LOGOUT_URL'] = '/test-logout/'
        base_auth = self.backend.Auth(None)
        self.assertEqual(
            base_auth.logout_url,
            '/test-logout/'
        )

    def test_base_init(self):
        base_auth = self.backend.Auth('Foo')
        self.assertEqual(base_auth.app, 'Foo')

    def test_has_access_not_implemented(self):
        base_auth = self.backend.Auth('Foo')
        with self.assertRaises(NotImplementedError):
            base_auth.has_access()

    def test_login_required_not_implemented(self):
        base_auth = self.backend.Auth('Foo')
        with self.assertRaises(NotImplementedError):
            base_auth.login_required()



class TestCASAuth(BaseAuthTestMixin, TestCase):
    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.testing = True
        self.app.secret_key = "SECRET_KEY"
        super(TestCASAuth, self).setUp()
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'
        from letmein.auth.backends import cas
        self.backend = cas
        self.auth = self.backend.CASAuth(self.app)

    def test_config_settings(self):
        other_fake_app = FakeApp()
        os.environ['CAS_AFTER_LOGIN'] = 'test-value-after-login'
        other_auth = self.backend.CASAuth(other_fake_app)
        self.assertEqual(
            other_auth.app.config['CAS_AFTER_LOGIN'],
            'test-value-after-login'
        )

    def test_login_required(self):
        self.assertEqual(
            self.auth.login_required,
            login_required
        )

    def test_logout_url_no_setting(self):
        os.environ.pop('LOGOUT_URL', None)
        self.assertEqual(
            self.auth.logout_url,
            '{}/logout/'.format(os.environ['CAS_SERVER'])
        )

    def test_username(self):
        with self.app.test_request_context():
            self.assertEqual(
                self.auth.user,
                self.auth.cas.username
            )

    def test_has_access_no_groups(self):
        self.assertFalse(self.auth.has_access())

    def test_has_access_all_groups(self):
        self.assertTrue(self.auth.has_access('*'))

    def test_has_access_no_user(self):
        with self.app.test_request_context() as ctx:
            self.assertFalse(self.auth.has_access(['admin']))

    def test_has_access_user_no_attributes(self):
        with self.app.test_request_context() as ctx:
            ctx.session['CAS_USERNAME'] = 'test-user'
            ctx.session['cas-attributes'] = None
            self.assertFalse(self.auth.has_access(['admin']))

    def test_has_access_user_attributes_wrong_group(self):
        with self.app.test_request_context() as ctx:
            ctx.session['CAS_USERNAME'] = 'test-user'
            ctx.session['cas-attributes'] = { 'cas:memberOf': ['user'] }
            self.assertFalse(self.auth.has_access(['admin']))

    def test_has_access_user_attributes_right_group(self):
        with self.app.test_request_context() as ctx:
            ctx.session['CAS_USERNAME'] = 'test-user'
            ctx.session['cas-attributes'] = { 'cas:memberOf': ['admin'] }
            self.assertTrue(self.auth.has_access(['admin']))




class TestNoAuth(BaseAuthTestMixin, TestCase):
    def setUp(self):
        from letmein.auth.backends import noauth
        self.backend = noauth
        super(TestNoAuth, self).setUp()
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.noauth.NoAuth'
        self.auth = self.backend.NoAuth(None)


    def test_login_required(self):
        class FakeRequest(object):
            pass
        @self.auth.login_required
        def func_with_login_required(request, *args, **kwargs):
            return (request, args, kwargs)
        def func_without_login_required(request, *args, **kwargs):
            return (request, args, kwargs)
        req = FakeRequest()
        args = (True, 100, "Green")
        kwargs = {
            'language': "en-US",
            'version': 1.05
        }
        self.assertEqual(
            func_with_login_required(req, *args, **kwargs),
            func_without_login_required(req, *args, **kwargs)
        )

    def test_user_blank(self):
        self.assertIsNone(self.auth.user)

    def test_logout_url(self):
        self.assertIsNone(self.auth.logout_url)

    def test_has_access(self):
        self.assertTrue(self.auth.has_access())
