import requests
import config
import base64


def create_metadata(collection_id: int, collection_name: str, encryption_key: bytes, jwt_token: str):
    encryption_key = base64.urlsafe_b64encode(encryption_key).decode()
    response = requests.post(
        f'{config.index_api_url}/indexing_collection',
        json={'collection_id': collection_id, 'collection_name': collection_name, 'encryption_key': encryption_key, 'jwt_token': jwt_token},
        verify=not config.debug_mode
    )
