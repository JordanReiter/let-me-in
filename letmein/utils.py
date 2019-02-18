import os
import copy

import boto3
from botocore.exceptions import ClientError

APP_NAME = os.environ.get('APP_NAME') or 'AWS Log In'
AWS_REGION = os.environ.get('AWS_REGION') or 'us-east-1'


def remove_ip(group, ip, port=22, protocol='tcp'):
    try:
        group = group.group_name
    except AttributeError:
        pass
    if '/' not in ip:
        ip += '/32'
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    perms = [
            {
                'IpProtocol': protocol,
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [
                    {'CidrIp': ip}
                ]
            }
    ]
    ec2.revoke_security_group_ingress(
        GroupName=group,
        IpPermissions=perms
    )

def get_group(group, client=None, resource=None):
    try:
        group = group.group_name
    except AttributeError:
        pass
    ec2 = client or boto3.client('ec2', region_name=AWS_REGION)
    ec2r = resource or boto3.resource('ec2', region_name=AWS_REGION)
    GroupId = None
    for group_data in ec2.describe_security_groups()['SecurityGroups']:
        if group_data['GroupName'] == group:
            GroupId = group_data['GroupId']
    if not GroupId:
        raise RuntimeError("Invalid security group name. {} not found.".format(group))
    return ec2r.SecurityGroup(GroupId)

def ip_is_in_group(group, ip_to_find, port=22, protocol='tcp'):
    security_group = get_group(group)
    perms = copy.deepcopy(security_group.ip_permissions)
    for perm in perms:
        if perm.get('ToPort') != port or perm.get('FromPort') != port:
            continue
        for range in perm.get('IpRanges', []):
            ip = range.get('CidrIp', "")
            if not ip.endswith('/32'):
                continue
            if ip_to_find == ip.split('/')[0]:
                return True
    return False

def clear_ips(group, port=22, protocol='tcp'):
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    ec2r = boto3.resource('ec2', region_name=AWS_REGION)
    security_group = get_group(group, client=ec2, resource=ec2r)
    perms = copy.deepcopy(security_group.ip_permissions)
    clear_perms = []
    cleared_ips = []
    for perm in perms:
        if perm.get('ToPort') != port or perm.get('FromPort') != port:
            continue
        for range in perm.get('IpRanges', []):
            ip = range.get('CidrIp', "")
            if not ip.endswith('/32'):
                perm['IpRanges'].remove(range)
                continue
            cleared_ips.append(ip.split('/')[0])
        if perm['IpRanges']:
            clear_perms.append(perm)
    if clear_perms:
        ec2.revoke_security_group_ingress(
            GroupId=security_group.group_id,
            IpPermissions=clear_perms
        )
    return cleared_ips


def add_ip(group, ip, port=22, protocol='tcp', description=None):
    try:
        group = group.group_name
    except AttributeError:
        pass
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    if '/' not in ip:
        ip += '/32'
    try:
        range_data = {'CidrIp': ip }
        if description:
            range_data['Description'] = description
        ec2.authorize_security_group_ingress(
            GroupName=group,
            IpPermissions = [{
                'IpProtocol': protocol,
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [range_data]
            }]
        )
    except ClientError as err:
        if 'exists' not in str(err):
            raise
