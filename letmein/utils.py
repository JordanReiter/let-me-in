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

def clear_ips(group, port=22, protocol='tcp'):
    try:
        group = group.group_name
    except AttributeError:
        pass
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    ec2r = boto3.resource('ec2', region_name=AWS_REGION)
    GroupId = None
    for group_data in ec2.describe_security_groups()['SecurityGroups']:
        if group_data['GroupName'] == group:
            GroupId = group_data['GroupId']
    if not GroupId:
        raise RuntimeError("Invalid security group name. {} not found.".format(group))
    security_group = ec2r.SecurityGroup(GroupId)
    perms = copy.deepcopy(security_group.ip_permissions)
    clear_perms = []
    cleared_ips = []
    for perm in perms:
        if perm['ToPort'] != port or perm['FromPort'] != port:
            continue
        for range in perm['IpRanges']:
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


def add_ip(group, ip, port=22, protocol='tcp'):
    try:
        group = group.group_name
    except AttributeError:
        pass
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    if '/' not in ip:
        ip += '/32'
    try:
        ec2.authorize_security_group_ingress(
            GroupName=group,
            IpPermissions = [{
                'IpProtocol': protocol,
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{
                    'CidrIp': ip
                }]
            }]
        )
    except ClientError as err:
        if 'exists' not in str(err):
            raise
