import os
from unittest import TestCase

try:
    from unittest import mock
except ImportError:
    import mock

from botocore.exceptions import ClientError
from moto import mock_ec2

from letmein.utils import remove_ip, clear_ips, add_ip, get_group, ip_is_in_group
from .base import TEST_REGION, ManageIPMixin

@mock_ec2
class TestUtils(ManageIPMixin, TestCase):
    def test_get_group(self):
        self.assertEqual(
            self.target_security_group,
            get_group(self.target_security_group.group_name)
        )

    def test_get_group_nonexistent(self):
        with self.assertRaises(RuntimeError):
            get_group('Nonexistent-Group-Name')


    def test_remove_ip(self):
        ips_to_keep = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ip_to_remove = '12.34.56.78'
        self.add_ips(self.target_security_group, ips_to_keep + [ip_to_remove])
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_remove))
        remove_ip(self.target_security_group, ip_to_remove)
        for ip in ips_to_keep:
            self.assertTrue(self.group_contains_ip(self.target_security_group, ip))
        self.assertFalse(self.group_contains_ip(self.target_security_group, ip_to_remove))

    def test_remove_ip_group_name(self):
        ips_to_keep = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ip_to_remove = '12.34.56.78'
        self.add_ips(self.target_security_group, ips_to_keep + [ip_to_remove])
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_remove))
        remove_ip(self.target_security_group.group_name, ip_to_remove)
        for ip in ips_to_keep:
            self.assertTrue(self.group_contains_ip(self.target_security_group, ip))
        self.assertFalse(self.group_contains_ip(self.target_security_group, ip_to_remove))

    def test_ip_is_in_group(self):
        normal_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ip_to_check = '12.34.56.78'
        self.add_ips(self.target_security_group, normal_ips + [ip_to_check])
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_check))
        self.assertTrue(ip_is_in_group(self.target_security_group, ip_to_check))

    def test_ip_is_in_group_missing_values(self):
        not_in_ip = '44.55.66.77'
        in_ip='77.66.55.44'
        missing_values_ip='77.66.55.44'
        self.add_ips(self.target_security_group, [in_ip])
        self.add_ips(self.target_security_group, [missing_values_ip], to_port=None, from_port=None, protocol=None)
        self.assertFalse(ip_is_in_group(self.target_security_group, not_in_ip))
        self.assertTrue(ip_is_in_group(self.target_security_group, missing_values_ip, port=None, protocol=None))

    def test_is_not_in_group(self):
        normal_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ip_to_check = '12.34.56.78'
        self.add_ips(self.target_security_group, normal_ips)
        self.assertFalse(self.group_contains_ip(self.target_security_group, ip_to_check))
        self.assertFalse(ip_is_in_group(self.target_security_group, ip_to_check))

    def test_is_not_in_group_ignore_ranges(self):
        normal_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ip_to_check = '12.34.56.78'
        ignore_ranges = [
            '{}/24'.format(ip_to_check),
        ]
        self.add_ips(self.target_security_group, normal_ips + ignore_ranges)
        self.assertFalse(self.group_contains_ip(self.target_security_group, ip_to_check))
        self.assertFalse(ip_is_in_group(self.target_security_group, ip_to_check))

    def test_is_not_in_group_ignore_ports(self):
        normal_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ip_to_check = '111.222.33.88'
        ignore_ports = [
            ip_to_check
        ]
        self.add_ips(self.target_security_group, normal_ips)
        self.add_ips(self.target_security_group, ignore_ports, to_port=80)
        self.add_ips(self.target_security_group, ignore_ports, from_port=80)
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_check))
        self.assertFalse(ip_is_in_group(self.target_security_group, ip_to_check))

    def test_clear_ips(self):
        all_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ignore_ips = [
            '1.2.3.4',
            '87.65.43.21'
        ]
        self.add_ips(self.target_security_group, all_ips)
        self.add_ips(self.admin_security_group, ignore_ips)
        self.assertTrue(
            all(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips)
        )
        self.assertTrue(
            all(self.group_contains_ip(self.admin_security_group, ip) for ip in ignore_ips)
        )
        cleared_ips = clear_ips(self.target_security_group)
        self.assertEqual(
            sorted(all_ips),
            sorted(cleared_ips)
        )
        self.assertFalse(
            any(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips)
        )
        self.assertTrue(
            all(self.group_contains_ip(self.admin_security_group, ip) for ip in ignore_ips)
        )

    def test_clear_ips_missing_values(self):
        missing_values_ip='77.66.55.44'
        all_ips = ['44.55.66.77', '55.66.77.88']
        self.add_ips(self.target_security_group, all_ips)
        self.add_ips(self.target_security_group, [missing_values_ip], to_port=None, from_port=None, protocol=None)
        cleared_ips = clear_ips(self.target_security_group)
        self.assertEqual(
            sorted(all_ips),
            sorted(cleared_ips)
        )
        self.assertTrue(ip_is_in_group(self.target_security_group, missing_values_ip, port=None, protocol=None))

    def test_clear_ips_ignore_ranges(self):
        all_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        keep_ips = [
             '56.78.99.99/20',
             '12.34.56.78/31'
        ]
        self.add_ips(self.target_security_group, all_ips + keep_ips)
        self.assertTrue(
            all(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips + keep_ips)
        )
        cleared_ips = clear_ips(self.target_security_group)
        self.assertEqual(
            sorted(all_ips),
            sorted(cleared_ips)
        )
        self.assertFalse(
            any(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips)
        )
        self.assertTrue(
            all(self.group_contains_ip(self.target_security_group, ip) for ip in keep_ips)
        )


    def test_clear_ips_ignore_ports(self):
        all_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        keep_ports = [
            (443, 443),
            (22, 443),
            (443, 22)
        ]
        keep_ips = [
             '56.78.99.99',
             '12.34.56.78',
             '123.45.67.89',
        ]
        self.add_ips(self.target_security_group, all_ips)
        for kidx, keep_ip in enumerate(keep_ips):
            to_port, from_port = keep_ports[kidx]
            self.add_ips(self.target_security_group, [keep_ip], from_port=from_port, to_port=to_port)
        self.assertTrue(
            all(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips + keep_ips)
        )
        cleared_ips = clear_ips(self.target_security_group)
        self.assertEqual(
            sorted(all_ips),
            sorted(cleared_ips)
        )
        self.assertFalse(
            any(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips)
        )
        self.assertTrue(
            all(self.group_contains_ip(self.target_security_group, ip) for ip in keep_ips)
        )



    def test_clear_ips_name(self):
        all_ips = [
            '1.2.3.4',
            '1.2.3.5',
        ]
        ignore_ips = [
            '1.2.3.4',
            '87.65.43.21'
        ]
        self.add_ips(self.target_security_group, all_ips)
        self.add_ips(self.admin_security_group, ignore_ips)
        self.assertTrue(
            all(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips)
        )
        self.assertTrue(
            all(self.group_contains_ip(self.admin_security_group, ip) for ip in ignore_ips)
        )
        cleared_ips = clear_ips(self.target_security_group.group_name)
        self.assertEqual(
            sorted(all_ips),
            sorted(cleared_ips)
        )
        self.assertFalse(
            any(self.group_contains_ip(self.target_security_group, ip) for ip in all_ips)
        )
        self.assertTrue(
            all(self.group_contains_ip(self.admin_security_group, ip) for ip in ignore_ips)
        )

    def test_clear_ips_name_nonexistent(self):
        with self.assertRaises(RuntimeError):
            clear_ips('nonexistent-group')

    def test_add_ip(self):
        ip_to_add = '123.45.67.89'
        add_ip(self.target_security_group, ip_to_add)
        self.target_security_group.reload()
        self.admin_security_group.reload()
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_add))
        self.assertFalse(self.group_contains_ip(self.admin_security_group, ip_to_add))

    def test_add_ip_bad_ip(self):
        ip_to_add = '123.45.67.899'
        with self.assertRaises(ClientError):
            add_ip(self.target_security_group, ip_to_add)

    def test_add_ip_name(self):
        ip_to_add = '123.45.67.89'
        add_ip(self.target_security_group.group_name, ip_to_add)
        self.target_security_group.reload()
        self.admin_security_group.reload()
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_add))
        self.assertFalse(self.group_contains_ip(self.admin_security_group, ip_to_add))

    def test_add_ip_dont_add_twicee(self):
        ip_to_add = '123.45.67.89'
        add_ip(self.target_security_group.group_name, ip_to_add)
        self.target_security_group.reload()
        self.admin_security_group.reload()
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_add))
        self.assertFalse(self.group_contains_ip(self.admin_security_group, ip_to_add))
        # now add the same IP a second time
        add_ip(self.target_security_group.group_name, ip_to_add)
        self.assertTrue(self.group_contains_ip(self.target_security_group, ip_to_add))
        self.assertFalse(self.group_contains_ip(self.admin_security_group, ip_to_add))
