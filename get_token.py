import requests
import xml.etree.ElementTree as ET


def get_sts_token(access_key: str, secret_key: str, endpoint: str = 'https://minio-s3-1.eco.dvo.ru:9000'):
    response = requests.post(
        f'{endpoint}/?Action=AssumeRoleWithLDAPIdentity&&LDAPUsername={access_key}&LDAPPassword={secret_key}&Version=2011-06-15&DurationSeconds={2592000}',
        verify=False
    )

    if response.status_code == 200:
        xml_response = response.text
        root = ET.fromstring(xml_response)
        access_key = root[0][0][0].text
        secret_key = root[0][0][1].text
        token = root[0][0][2].text
        expiration = root[0][0][3].text
        print(token)
        return {'access_key': access_key, 'secret_key': secret_key, 'sts_token': token, 'expiration': expiration}
    else:
        print('Ошибка получения STS токена:', response.status_code)
        print(response.text)
