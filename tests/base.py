TEST_REGION='us-east-1'

import boto3

TEST_SECURITY_GROUP_DESC = "SSH Users"
TEST_SECURITY_GROUP_NAME = 'ssh-users'


class FlashTestingMixin(object):
    # credit Paulo Poiati
    # http://blog.paulopoiati.com/2013/02/22/testing-flash-messages-in-flask/
    def assertFlashes(self, client, expected_message, expected_category='message'):
        with client.session_transaction() as session:
            try:
                category, message = session['_flashes'][0]
            except KeyError:
                raise AssertionError('nothing flashed')
        self.assertIn(expected_message, message, msg="Flash did not contain expected content.")
        self.assertEqual(expected_category, category, msg="Flash category did not match expected category.")


class ManageIPMixin(object):
    def setUp(self):
        super(ManageIPMixin, self).setUp()
        self.client = boto3.client('ec2', region_name=TEST_REGION)
        self.resource = boto3.resource('ec2', region_name=TEST_REGION)
        result = self.client.create_security_group(
            Description=TEST_SECURITY_GROUP_DESC,
            GroupName=TEST_SECURITY_GROUP_NAME
        )
        self.target_security_group = self.resource.SecurityGroup(result['GroupId'])
        result = self.client.create_security_group(
            Description="{} (Administrator)".format(TEST_SECURITY_GROUP_DESC),
            GroupName="{}-admin".format(TEST_SECURITY_GROUP_NAME)
        )
        self.admin_security_group = self.resource.SecurityGroup(result['GroupId'])
        return True

    def tearDown(self):
        super(ManageIPMixin, self).tearDown()
        self.target_security_group.delete()
        self.admin_security_group.delete()

    def group_contains_ip(self, group, ip):
        if '/' not in ip:
            ip = ip + '/32'
        group.reload()
        return any(
            [
                ip in [rr.get('CidrIp') for rr in perm['IpRanges']] 
                for perm in group.ip_permissions
            ]
        )

    def add_ips(self, group, ip_ranges, to_port=22, from_port=22, protocol='tcp'):
        ranges = []
        for ip in ip_ranges:
            try:
                ip, description = ip
            except (ValueError, TypeError):
                description = "Test IP"
            if '/' not in ip:
                ip += '/32'
            self.client.authorize_security_group_ingress(
                GroupId=group.group_id,
                IpPermissions = [{
                    'IpProtocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IpRanges': [{
                        'CidrIp': ip,
                        'Description': description
                    }]
                }]
            )
        group.reload()

