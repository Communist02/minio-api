from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

user1 = {'login': 'user1', 'password': '123', 'token': client.get('/auth', auth=('user1', '123')).json()['token']}


def test_auth():
    response = client.get('/auth', auth=(user1['login'], user1['password']))
    assert response.status_code == 200
    assert len(response.json()['token']) > 32


def test_false_auth():
    response = client.get('/auth', auth=(user1['login'], '1234'))
    assert response.status_code == 401


def test_check_token():
    response = client.get('/check_token?token=' + user1['token'])
    assert response.status_code == 200


def test_false_check_token():
    response = client.get('/check_token?token=' + '1' + user1['token'])
    assert response.status_code == 401


def test_auth_log():
    response = client.get('/auth', auth=(user1['login'], user1['password']))
    assert response.status_code == 200
    token = response.json()['token']
    assert len(token) > 32
    response = client.get('/get_logs?token=' + token)
    last_action = sorted(response.json(), key=lambda x: x['id'])[-1]
    assert last_action['action'] == 'auth'
    assert last_action['result'] == 200

def test_access_log():
    response = client.get('/auth', auth=(user1['login'], user1['password']))
    assert response.status_code == 200
    token = response.json()['token']
    assert len(token) > 32
    response = client.get('/get_logs?token=' + token)
    last_action = sorted(response.json(), key=lambda x: x['id'])[-1]
    assert last_action['action'] == 'auth'
    assert last_action['result'] == 200
