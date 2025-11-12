from opensearchpy import NotFoundError, AsyncOpenSearch

import config

# auth = ('admin', os.getenv('OPENSEARCH_PASS'))
# For testing only. Don't store credentials in code.
auth = ('admin', 'OTFiZDkwMGRiOWQw1!')


class OpenSearchManager:
    def __init__(self, host: str = config.open_search_host, port: int = config.open_search_port, auth: tuple = auth):
        self.client = AsyncOpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode,
        )

    # Не работает
    async def create_index(self, index_name: str = config.open_search_collections_index):
        response = await self.client.indices.create(
            index=index_name)

    async def update_document(self, doc_id: int, document: dict, index_name: str = config.open_search_collections_index):
        response = await self.client.index(
            index=index_name,
            body=document,
            id=doc_id,
            refresh=True,
        )

    async def delete_document(self, doc_id: int, index_name: str = config.open_search_collections_index):
        response = await self.client.delete(
            index=index_name,
            id=doc_id,
        )

    async def create_policy_to_user(self, role_name: str, role_content: dict):
        response = await self.client.security.create_role(
            role=role_name,
            body=role_content
        )

    async def get_document(self, doc_id: int, index_name: str = config.open_search_collections_index) -> dict | None:
        try:
            response = await self.client.get(
                index=index_name,
                id=doc_id,
            )
            return response['_source']
        except NotFoundError:
            return None

    async def search_documents(self, text: str, jwt_token: str, index_name: str = config.open_search_collections_index):
        auth_header = {'Authorization': f'Bearer {jwt_token}'}
        client = AsyncOpenSearch(
            hosts=[{'host': config.open_search_host,
                    'port': config.open_search_port}],
            http_compress=True,
            headers=auth_header,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode
        )
        query = {
            'query': {
                'query_string': {
                    'query': f'*{text}*',
                    'default_operator': 'OR'
                }
            }
        }

        response = await client.search(
            body=query,
            index=index_name,
        )
        return response['hits']['hits']
