import json
from httpx_aws_auth import AwsSigV4Auth, AwsCredentials
import httpx
import config


async def create_policy_to_user(username: str, collections: list) -> str:
    policy = {
        'Version': '2012-10-17',
        'Statement': []
    }
    default_policy = {
        'Effect': 'Allow',
        'Action': ['s3:CreateBucket'],
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
                f'arn:aws:s3:::{collection['name']}/*']
            policy['Statement'].append(bucket_policy)

    auth = AwsSigV4Auth(
        credentials=AwsCredentials(config.access_key, config.secret_key),
        region='us-east-1',
        service='s3'
    )
    response = await httpx.AsyncClient(verify=not config.debug_mode).put(
        f'https://{config.minio_url}/minio/admin/v3/add-canned-policy',
        params={'name': username},
        headers={'Content-Type': 'application/json'},
        auth=auth,
        json=policy,
        timeout=5
    )
    if response.status_code != 200:
        print('Ошибка создания политики:', response.status_code)
        print(response.text)
    return json.dumps(policy)


async def create_policy_to_all(collections: list) -> str:
    policy = {
        'Version': '2012-10-17',
        'Statement': []
    }
    default_policy = {
        'Effect': 'Allow',
        'Action': ['s3:CreateBucket'],
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
        bucket_policy['Resource'] = [f'arn:aws:s3:::{collection['name']}/*']
        policy['Statement'].append(bucket_policy)

    # date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    auth = AwsSigV4Auth(
        credentials=AwsCredentials(config.access_key, config.secret_key),
        region='us-east-1',
        service='s3'
    )
    response = await httpx.AsyncClient(verify=not config.debug_mode).put(
        f'https://{config.minio_url}/minio/admin/v3/add-canned-policy',
        params={'name': 'all/system'},
        headers={'Content-Type': 'application/json'},
        auth=auth,
        json=policy,
        timeout=5
    )
    if response.status_code != 200:
        print('Ошибка создания политики:', response.status_code)
        print(response.text)

    return json.dumps(policy)
