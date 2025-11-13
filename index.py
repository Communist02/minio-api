import httpx
import config
import base64


async def create_index(collection_id: int, collection_name: str, encryption_key: bytes, jwt_token: str):
    encryption_key = base64.urlsafe_b64encode(encryption_key).decode()
    try:
        response = await httpx.AsyncClient(verify=not config.debug_mode).post(
            f'{config.index_api_url}/indexing_collection',
            json={'collection_id': collection_id, 'collection_name': collection_name,
                'encryption_key': encryption_key, 'jwt_token': jwt_token},
        )
    except httpx.TimeoutException as e:
        pass


async def delete_index(collection_id: int, collection_name: str, files: list[str]):
    try:
        response = await httpx.AsyncClient(verify=not config.debug_mode).post(
            f'{config.index_api_url}/delete_files',
            json={'collection_id': collection_id, 'collection_name': collection_name, 'files': files},
        )
    except httpx.TimeoutException as e:
        pass
