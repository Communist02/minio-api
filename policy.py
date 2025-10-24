import json
from aws_requests_auth.aws_auth import AWSRequestsAuth
import requests

import config


def create_policy_to_user(username: str, collections: list) -> str:
    policy = {
        'Version': '2012-10-17',
        'Statement': []
    }
    default_policy = {
        'Effect': 'Allow',
        'Action': [
            's3:CreateBucket',
            's3:ListAllMyBuckets'
        ],
        'Resource': ['arn:aws:s3:::*']
    }
    policy['Statement'].append(default_policy)

    for collection in collections:
        if collection['type'] != 'access_to_all':
            bucket_policy = {'Effect': 'Allow'}
            match collection['access_type_id']:
                case 1:
                    bucket_policy['Action'] = ['s3:*']
                case 2:
                    bucket_policy['Action'] = [
                        's3:GetBucketLocation',
                        's3:GetObject',
                        's3:ListBucket',
                        's3:PutObject',
                        's3:DeleteObject'
                    ]
                case 3:
                    bucket_policy['Action'] = [
                        's3:GetBucketLocation',
                        's3:GetObject',
                        's3:ListBucket'
                    ]
                case 4:
                    bucket_policy['Action'] = [
                        's3:GetBucketLocation',
                        's3:ListBucket',
                        's3:PutObject'
                    ]
            bucket_policy['Resource'] = [
                f'arn:aws:s3:::{collection['name']}',
                f'arn:aws:s3:::{collection['name']}/*'
            ]
            policy['Statement'].append(bucket_policy)

    auth = AWSRequestsAuth(
        aws_access_key=config.access_key,
        aws_secret_access_key=config.secret_key,
        aws_host=config.minio_url,
        aws_region='us-east-1',
        aws_service='s3'
    )
    print(policy)
    response = requests.put(
        f'https://{config.minio_url}/minio/admin/v3/add-canned-policy',
        params={'name': username},
        headers={'Content-Type': 'application/json'},
        auth=auth,
        json=policy,
        verify=False,
        timeout=5
    )
    if response.status_code != 200:
        print('Ошибка создания политики:', response.status_code)
        print(response.text)
    return json.dumps(policy)


def create_policy_to_all(collections: list) -> str:
    policy = {
        'Version': '2012-10-17',
        'Statement': []
    }
    default_policy = {
        'Effect': 'Allow',
        'Action': [
            's3:ListAllMyBuckets',
        ],
        'Resource': ['arn:aws:s3:::*']
    }
    policy['Statement'].append(default_policy)

    for collection in collections:
        bucket_policy = {'Effect': 'Allow'}
        bucket_policy['Action'] = [
            's3:GetBucketLocation',
            's3:GetObject',
            's3:ListBucket'
        ]
        bucket_policy['Resource'] = [
            f'arn:aws:s3:::{collection['name']}',
            f'arn:aws:s3:::{collection['name']}/*'
        ]
        policy['Statement'].append(bucket_policy)

    # date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    auth = AWSRequestsAuth(
        aws_access_key=config.access_key,
        aws_secret_access_key=config.secret_key,
        aws_host=config.minio_url,
        aws_region='us-east-1',
        aws_service='s3'
    )
    print(policy)
    response = requests.put(
        f'https://{config.minio_url}/minio/admin/v3/add-canned-policy',
        params={'name': 'all/system'},
        headers={'Content-Type': 'application/json'},
        auth=auth,
        json=policy,
        verify=False,
        timeout=5
    )
    if response.status_code != 200:
        print('Ошибка создания политики:', response.status_code)
        print(response.text)

    return json.dumps(policy)
