import requests
import xml.etree.ElementTree as ET


def get_sts_token(token: str, endpoint: str, duration=2592000):
    response = requests.post(
        f'{endpoint}/?Action=AssumeRoleWithWebIdentity&WebIdentityToken={token}&Version=2011-06-15{f"&DurationSeconds={duration}" if duration != 0 else ""}',
        verify=False,
        timeout=5
    )

    if response.status_code == 200:
        xml_response = response.text
        # print(response.text)
        root = ET.fromstring(xml_response)
        access_key = root.find(
            './/{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId')
        secret_key = root.find(
            './/{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey')
        session_token = root.find(
            './/{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken')
        credentials = {'access_key': access_key.text,
                       'secret_key': secret_key.text, 'session_token': session_token.text}
        return credentials
    else:
        print('Ошибка получения STS токена:', response.status_code)
        print(token)
        print(response.text)
        print(response.status_code)
