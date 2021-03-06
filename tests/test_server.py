import os
import re
import tempfile
from unittest import TestCase

import boto3
from moto import mock_ec2
import pytest

from .base import TEST_REGION, ManageIPMixin, FlashTestingMixin, \
    TEST_SECURITY_GROUP_DESC, TEST_SECURITY_GROUP_NAME

TEST_ACCESS_GROUP = 'test-user-has-access'
TEST_ADMIN_GROUP = 'test-user-as-admin'

os.environ['SECURITY_GROUP'] = TEST_SECURITY_GROUP_NAME
os.environ['GROUPS_WITH_ACCESS'] = '{0},other-{0}'.format(TEST_ACCESS_GROUP)
os.environ['GROUPS_WITH_ADMIN'] = '{0},other-{0}'.format(TEST_ADMIN_GROUP)

TEST_PREFIX = '/test-knock'

import letmein.server


PRESERVE_CONTEXT_ON_EXCEPTION = False

@mock_ec2
class TestServer(ManageIPMixin, FlashTestingMixin, TestCase):

    @classmethod
    def setUpClass(self):
        """ Sets up a test database before each set of tests """
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'
        self.app = letmein.server.app
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'

    def setUp(self):
        super(TestServer, self).setUp()
        os.environ['SECURITY_GROUP'] = self.target_security_group.group_name
        from letmein.auth.backends import cas
        letmein.server.auth = cas.CASAuth(self.app)

    def tearDown(self):
        super(TestServer, self).tearDown()


    def test_get_hello_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/')
            self.assertEqual(
                response.status_code,
                302
            )

    def test_get_hello_logged_in(self):
        client_ip = '12.34.56.78'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get('/', environ_base={'REMOTE_ADDR': client_ip})
            self.assertEqual(
                response.status_code,
                200
            )
            self.assertIn(
                '<button class="btn btn-success" type="submit">'
                'Add access for {}</button>'.format(client_ip),
                response.data.decode()
            )

    def test_get_hello_logged_in_ip_in_group(self):
        client_ip = '12.34.56.78'
        self.add_ips(self.target_security_group, [client_ip])
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get('/', environ_base={'REMOTE_ADDR': client_ip})
            self.assertEqual(
                response.status_code,
                200
            )
            self.assertIn(
                '<h3>{ip} currently has ssh access.</h3> '
                '<form class="container form" method="POST" action="/goodbye/"> '
                '<button class="btn btn-primary" type="submit">Remove access for {ip}</button> '
                '</form>'.format(ip=client_ip),
                ' '.join(response.data.decode().split())
            )

    def test_get_knock_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/knock/')
            self.assertEqual(
                response.status_code,
                302
            )

    def test_get_knocked_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/knocked/')
            self.assertEqual(
                response.status_code,
                302
            )

    def test_get_goodbye_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/goodbye/')
            self.assertEqual(
                response.status_code,
                302
            )

    def test_get_left_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/left/')
            self.assertEqual(
                response.status_code,
                302
            )

    def test_get_clear_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/clear/')
            self.assertEqual(
                response.status_code,
                302
            )

    def test_get_cleared_not_logged_in(self):
        with self.app.test_client() as client:
            response = client.get('/cleared/')
            self.assertEqual(
                response.status_code,
                302
            )


    def test_get_knock_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/knock/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_knocked_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/knocked/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_knock_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/knock/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_knocked_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/knocked/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_goodbye_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/goodbye/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_left_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/left/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_goodbye_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/goodbye/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_left_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/left/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_hello_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_hello_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/')
            self.assertEqual(
                response.status_code,
                403
            )


    def test_get_clear_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/clear/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_cleared_logged_in_no_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
            response = client.get('/cleared/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_clear_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/clear/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_get_cleared_logged_in_bad_group(self):
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': ['wrong-group'] }
            response = client.get('/cleared/')
            self.assertEqual(
                response.status_code,
                403
            )

    def test_post_knock_logged_in_access_group(self):
        ip_to_add = '12.34.56.78'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.post('/knock/', environ_base={'REMOTE_ADDR': ip_to_add})
            self.assertEqual(
                response.status_code,
                302
            )
            location = re.sub(r'https?://[^/]+', '', response.headers['Location'])
            self.assertEqual('/knocked/', location)
            redir_response = client.get(location, environ_base={'REMOTE_ADDR': ip_to_add})
            self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_add))
            self.assertIn(
                "You can now access this server from {} by ssh.".format(ip_to_add),
                ' '.join(redir_response.data.decode().split())
            )

    def test_get_knocked_not_actually_knocked(self):
        ip_to_add = '12.34.56.78'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get('/knocked/', environ_base={'REMOTE_ADDR': ip_to_add})
            self.assertEqual(
                response.status_code,
                302
            )
            location = re.sub(r'https?://[^/]+', '', response.headers['Location'])
            self.assertEqual('/knock/', location)
            self.assertFlashes(client, 'Your IP address was not added. Please try again.', 'warning')


    def test_post_knock_logged_in_access_group_remove(self):
        ip_to_keep = '11.22.33.44'
        ip_to_remove = '99.88.77.66'
        ips_to_add = [ ip_to_keep, ip_to_remove ]
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            for ip_to_add in ips_to_add:
                response = client.post('/knock/', environ_base={'REMOTE_ADDR': ip_to_add})
                self.assertEqual(
                    response.status_code,
                    302
                )
            self.assertTrue(all(
                self.group_contains_ip(self.target_security_group, ip_to_add)
                for ip_to_add in ips_to_add
            ))
            response = client.post('/goodbye/', environ_base={'REMOTE_ADDR': ip_to_remove})
            self.assertEqual(
                response.status_code,
                302
            )
            location = re.sub(r'https?://[^/]+', '', response.headers['Location'])
            self.assertEqual('/left/', location)
            self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_keep))
            self.assertFalse(self.group_contains_ip(self.target_security_group, ip_to_remove))
            redir_response = client.get(location, environ_base={'REMOTE_ADDR': ip_to_remove})
            self.assertIn(
                'SSH Access for {} has been removed.'.format(ip_to_remove),
                ' '.join(redir_response.data.decode().split())
            )

    def test_get_left_not_actually_left(self):
        ip_to_keep = '11.22.33.44'
        ip_to_remove = '99.88.77.66'
        ips_to_add = [ ip_to_keep, ip_to_remove ]
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            for ip_to_add in ips_to_add:
                response = client.post('/knock/', environ_base={'REMOTE_ADDR': ip_to_add})
                self.assertEqual(
                    response.status_code,
                    302
                )
            self.assertTrue(all(
                self.group_contains_ip(self.target_security_group, ip_to_add)
                for ip_to_add in ips_to_add
            ))
            response = client.get('/left/', environ_base={'REMOTE_ADDR': ip_to_remove})
            self.assertEqual(
                response.status_code,
                302
            )
            location = re.sub(r'https?://[^/]+', '', response.headers['Location'])
            self.assertEqual('/goodbye/', location)
            self.assertFlashes(client, 'Your IP address was not removed. Please try again.', 'warning')


    def test_post_knock_logged_in_access_group_clear(self):
        ips = ['11.22.33.44', '22.44.66.88', '11.33.66.99']
        self.add_ips(self.target_security_group, ips)
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ADMIN_GROUP] }
            response = client.post('/clear/', environ_base={'REMOTE_ADDR': ips[0]})
            self.assertEqual(
                response.status_code,
                302
            )
            location = re.sub(r'https?://[^/]+', '', response.headers['Location'])
            self.assertEqual('/cleared/?count=3', location)
            self.assertFalse(
                any(
                    self.group_contains_ip(self.target_security_group, ip)
                    for ip in ips
                )
            )
            redir_response = client.get(location, environ_base={'REMOTE_ADDR': ips[0]})
            self.assertIn(
                'A total of {} IPs were removed.'.format(len(ips)),
                ' '.join(redir_response.data.decode().split())
            )

    def test_get_cleared_not_actually_cleared(self):
        ip = '12.34.56.78'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ADMIN_GROUP] }
            response = client.get('/cleared/', environ_base={'REMOTE_ADDR': ip})
            self.assertEqual(
                response.status_code,
                302
            )
            location = re.sub(r'https?://[^/]+', '', response.headers['Location'])
            self.assertEqual('/clear/', location)
            self.assertFlashes(client, 'No IP addresses were cleared. Please try again.', 'warning')


    def test_get_knock_logged_in_access_group(self):
        ip_to_add = '12.34.56.78'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get('/knock/', environ_base={'REMOTE_ADDR': ip_to_add})
            self.assertFalse(self.group_contains_ip(self.target_security_group, ip_to_add))
            self.assertEqual(
                response.status_code,
                200
            )
            self.assertIn('POST', response.data.decode())
            self.assertIn('action="/knock/"', response.data.decode())
            self.assertIn(ip_to_add, response.data.decode())

    def test_get_clear_logged_in_access_group(self):
        ips = ['11.22.33.44', '22.44.66.88', '11.33.66.99']
        self.add_ips(self.target_security_group, ips)
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ADMIN_GROUP] }
            response = client.get('/clear/', environ_base={'REMOTE_ADDR': ips[0]})
            self.assertTrue(all(
                self.group_contains_ip(self.target_security_group, ip)
                for ip in ips
            ))
            self.assertEqual(
                response.status_code,
                200
            )
            self.assertIn('POST', response.data.decode())
            self.assertIn('action="/clear/"', response.data.decode())



@mock_ec2
class TestSchemeServer(ManageIPMixin, TestCase):

    @classmethod
    def setUpClass(self):
        """ Sets up a test database before each set of tests """
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'
        self.app = letmein.server.app
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'

    def setUp(self):
        super(TestSchemeServer, self).setUp()
        os.environ['SECURITY_GROUP'] = self.target_security_group.group_name
        from letmein.auth.backends import cas
        letmein.server.auth = cas.CASAuth(self.app)

    def test_scheme(self):
        ip = '55.66.77.88'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get(
                '/',
                environ_base={
                    'HTTP_X_SCHEME': 'https',
                    'REMOTE_ADDR': ip
                }
            )
            self.assertEqual(
                response.status_code,
                200
            )



@mock_ec2
class TestPrefixServer(ManageIPMixin, TestCase):
    prefix = TEST_PREFIX

    @classmethod
    def setUpClass(self):
        """ Sets up a test database before each set of tests """
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'
        self.app = letmein.server.app
        os.environ['AUTH_BACKEND'] = 'letmein.auth.backends.cas.CASAuth'
        os.environ['CAS_SERVER'] = 'https://login.example.com'
        os.environ['CAS_ATTRIBUTES_SESSION_KEY'] = 'cas-attributes'

    def setUp(self):
        os.environ['HTTP_X_SCRIPT_NAME'] = self.prefix
        super(TestPrefixServer, self).setUp()
        os.environ['SECURITY_GROUP'] = self.target_security_group.group_name
        from letmein.auth.backends import cas
        letmein.server.auth = cas.CASAuth(self.app)

    def test_get_knock_logged_in_access_group_remove_prefix(self):
        ip_to_leave_alone = '99.88.77.66'
        self.add_ips(self.target_security_group, [ip_to_leave_alone])
        self.assertTrue(
            self.group_contains_ip(self.target_security_group, ip_to_leave_alone)
        )
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get(
                self.prefix + '/goodbye/',
                environ_base={
                    'HTTP_X_SCRIPT_NAME': TEST_PREFIX,
                    'REMOTE_ADDR': ip_to_leave_alone
                }
            )
            self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_leave_alone))
            self.assertEqual(
                response.status_code,
                200
            )
            self.assertIn('POST', response.data.decode())
            self.assertIn('action="{}/goodbye/"'.format(self.prefix), response.data.decode())
            self.assertIn(ip_to_leave_alone, response.data.decode())

    def test_get_hello_logged_in_access_group_prefix(self):
        ip = '12.34.56.78'
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session['CAS_USERNAME'] = 'test-user'
                session['cas-attributes'] = { 'cas:memberOf': [TEST_ACCESS_GROUP] }
            response = client.get(self.prefix + '/', environ_base={'HTTP_X_SCRIPT_NAME': TEST_PREFIX, 'REMOTE_ADDR': ip})
            self.assertEqual(
                response.status_code,
                200
            )
            self.assertIn('POST', response.data.decode())
            self.assertIn('action="{}/knock/"'.format(self.prefix), response.data.decode())
            self.assertIn(ip, response.data.decode())
            self.assertIn('action="{}/clear/"'.format(self.prefix), response.data.decode())


