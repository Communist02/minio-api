from opensearchpy import NotFoundError, OpenSearch

# auth = ('admin', os.getenv('OPENSEARCH_PASS'))
# For testing only. Don't store credentials in code.
auth = ('admin', 'OTFiZDkwMGRiOWQw1!')


class OpenSearchManager:
    def __init__(self, host: str = 'elastic-1.eco.dvo.ru', port: int = 9200, auth: tuple = auth):
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,  # enables gzip compression for request bodies
            http_auth=auth,
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )

    # Не работает
    def create_index(self, index_name: str = 's3-storage'):
        response = self.client.indices.create(
            index=index_name)

    def update_document(self, collection_id: int, document: dict, index_name: str = 's3-storage'):
        response = self.client.index(
            index=index_name,
            body=document,
            id=collection_id,
            refresh=True,
        )

    def delete_document(self, collection_id: int, index_name: str = 's3-storage'):
        response = self.client.delete(
            index=index_name,
            id=collection_id,
        )

    def get_document(self, collection_id: int, index_name: str = 's3-storage') -> dict | None:
        try:
            response = self.client.get(
                index=index_name,
                id=collection_id,
            )
            return response['_source']
        except NotFoundError:
            return None

    def search_documents(self, text: str, fields: list = ['name', 'description', 'tags'], index_name: str = 's3-storage'):
        query = {
            'size': 5,
            'query': {
                'multi_match': {
                    'query': text,
                    'fields': fields
                }
            }
        }

        response = self.client.search(
            body=query,
            index=index_name,
        )
        return response['hits']['hits']

# open_search = OpenSearchManager()
# s = open_search.search_document('Кошка')
# print(s)
