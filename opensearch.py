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
    async def create_index(self, index_name: str = 's3-storage'):
        response = await self.client.indices.create(
            index=index_name)

    async def update_document(self, doc_id: int, document: dict, index_name: str = 's3-storage'):
        response = await self.client.index(
            index=index_name,
            body=document,
            id=doc_id,
            refresh=True,
        )

    async def delete_document(self, doc_id: int, index_name: str = 's3-storage'):
        response = await self.client.delete(
            index=index_name,
            id=doc_id,
        )

    async def get_document(self, doc_id: int, index_name: str = 's3-storage') -> dict | None:
        try:
            response = await self.client.get(
                index=index_name,
                id=doc_id,
            )
            return response['_source']
        except NotFoundError:
            return None

    async def search_documents(self, text: str, fields: list = ['title', 'description', 'tags', 'collection_id', 'collection_name'], index_name: str = 's3-storage'):
        query = {
            'query': {
                'query_string': {
                    'query': f'*{text}*',
                    'default_operator': 'OR'
                }
            }
        }

        response = await self.client.search(
            body=query,
            index=index_name,
        )
        return response['hits']['hits']
