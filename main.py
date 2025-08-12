import asyncio
import base64
import io
from typing import Annotated
from minio import Minio
from minio.sse import SseCustomerKey
from minio.error import S3Error
from minio.commonconfig import CopySource
from fastapi import Depends, FastAPI, Form, HTTPException, UploadFile, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import quote
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sessions import WebSessionsBase
from database import MainBase
from crypt import hash_argon2_from_password, hash_division, hash_reconstruct
import secrets
from minio.deleteobjects import DeleteObject
import config
from ldap import LDAPManager
from get_token import get_sts_token


class Client:
    def __init__(self, endpoint: str, access_key: str, secret_key: str):
        self.endpoint = endpoint
        self.cert_check = False
        self.client = Minio(
            endpoint, access_key=access_key, secret_key=secret_key, secure=True, cert_check=False)

    async def get_files(self, bucket_name: str, access_key: str, secret_key: str, sts_token: str) -> list[dict]:
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        try:
            objects = client.list_objects(bucket_name, recursive=True)
            result = []
            processed_folders = set()

            for obj in objects:
                object_name = obj.object_name
                if not object_name.endswith('NODATA'):
                    result.append({
                        'name': object_name.split("/")[-1],
                        'isDirectory': obj.is_dir,
                        'path': f'/{object_name}',
                        'updatedAt': obj.last_modified.isoformat(),
                        'size': obj.size,
                    })

                current_path = ''
                for part in object_name.split('/')[:-1]:
                    current_path += part + '/'
                    if current_path not in processed_folders:
                        processed_folders.add(current_path)
                        result.append({
                            'name': part,
                            'isDirectory': True,
                            'path': f'/{current_path}'.rstrip('/'),
                        })
            return result
        except S3Error as error:
            print(f'Error fetching files: {error.message}')
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Failed to retrieve files',
                    'message': error.message
                }
            )

    async def get_buckets(self, access_key: str, secret_key: str, sts_token: str) -> list[str]:
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        try:
            buckets = client.list_buckets()
            result: list[str] = []

            for bucket in buckets:
                result.append(bucket.name)

            return result
        except S3Error as error:
            print(f'Error fetching files: {error.message}')
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Failed to retrieve files',
                    'message': error.message
                }
            )

    async def delete_files(self, bucket_name: str, paths: list[str], access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        try:
            objects_to_delete: list[DeleteObject] = []

            for path in paths:
                object_name = path.strip('/')

                if not path.endswith('/'):
                    objects_to_delete.append(DeleteObject(object_name))
                else:
                    objects = client.list_objects(
                        bucket_name, prefix=object_name, recursive=True)
                    objects_to_delete.extend(
                        [DeleteObject(obj.object_name) for obj in objects]
                    )

            if objects_to_delete:
                errors = await asyncio.to_thread(
                    lambda: list(client.remove_objects(
                        bucket_name, objects_to_delete))
                )

                if errors:
                    error_list = [e.__dict__ for e in errors]
                    raise HTTPException(
                        status_code=500,
                        detail={'error': 'Some files failed to delete',
                                'errors': error_list}
                    )

        except S3Error as error:
            print(f'Error deleting files: {error.message}')
            raise HTTPException(
                status_code=500,
                detail={'error': 'S3 error during delete',
                        'message': error.message}
            )

    # async def get_download_url(self, bucket_name: str, object_key: str, encryption_key: SseCustomerKey, expires_seconds: int = 3600) -> str:
    #     client = self.client

    #     try:
    #         object_name = object_key.lstrip('/')
    #         return client.presigned_get_object(
    #             bucket_name=bucket_name,
    #             object_name=object_name,
    #             expires=timedelta(seconds=expires_seconds),
    #             response_headers={
    #                 'response-content-type': 'application/octet-stream'},
    #             extra_query_params=encryption_key.copy_headers(),
    #         )
    #     except S3Error as error:
    #         print(f'Failed to generate download URL: {error.message}')
    #         raise HTTPException(
    #             status_code=404 if error.code == 'NoSuchKey' else 500,
    #             detail=f'Failed to generate download URL: {error.message}'
    #         )

    async def download_file(self, bucket_name: str, file_path: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str, range_header: str = None) -> StreamingResponse:
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        async def file_iterator(stream, chunk_size=1024 * 1024 * 4):
            while True:
                data = await asyncio.to_thread(stream.read, chunk_size)
                if not data:
                    break
                yield data

        object_name = file_path.lstrip('/')
        try:
            stat = client.stat_object(
                bucket_name, object_name, ssec=encryption_key)
        except S3Error:
            try:
                stat = client.stat_object(
                    bucket_name, object_name)
                encryption_key = None
            except S3Error as error:
                print(f'Failed to get the file: {error.message}')
                raise HTTPException(
                    status_code=403,
                    detail=f'Failed to get the file: {error.message}'
                )
        file_size = stat.size
        headers = {
            'Content-Disposition': f"attachment; filename*=UTF-8''{quote(object_name.split('/')[-1])}",
            'Content-Length': str(file_size),
            'Accept-Ranges': 'bytes',
        }
        try:
            if range_header:
                start_end = range_header.replace('bytes=', '').split('-')
                start = int(start_end[0])
                end = int(start_end[1]) if start_end[1] else file_size - 1

                obj = client.get_object(
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key,
                    offset=start,
                    length=end - start + 1
                )

                headers['Content-Length'] = str(end - start + 1)
                headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'

                return StreamingResponse(
                    file_iterator(obj),
                    media_type='application/octet-stream',
                    headers=headers,
                    status_code=206  # Partial Content
                )
            else:
                obj = client.get_object(
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key
                )
                return StreamingResponse(
                    file_iterator(obj),
                    media_type='application/octet-stream',
                    headers=headers
                )
        except S3Error as error:
            print(f'Failed to get the file: {error.message}')
            raise HTTPException(
                status_code=404 if error.code == 'NoSuchKey' else 403,
                detail=f'Failed to get the file: {error.message}'
            )

    async def copy_files(self, bucket_name: str, source_paths: list[str], destination_path: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        for source in source_paths:
            if source.endswith('/'):  # папка
                try:
                    prefix = source.strip('/')
                    objects = client.list_objects(
                        bucket_name, prefix=prefix, recursive=True)
                    for obj in objects:
                        object_name = obj.object_name
                        relative_path = prefix.split(
                            '/')[-1] + '/' + object_name[len(prefix):].lstrip('/')
                        destination_object_name = f'{destination_path.rstrip('/')}/{relative_path}'
                        client.copy_object(
                            bucket_name=bucket_name,
                            object_name=destination_object_name,
                            source=CopySource(
                                bucket_name, object_name, ssec=encryption_key),
                            sse=encryption_key,
                        )
                except S3Error as error:
                    print(f"Failed copy folder '{prefix}': {error.message}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed copy folder '{prefix}': {error.message}"
                    )
            else:  # файл
                try:
                    filename = source.split('/')[-1]
                    destination_object_name = f'{destination_path.rstrip('/')}/{filename}'
                    object_name = source.lstrip('/')
                    client.copy_object(
                        bucket_name=bucket_name,
                        object_name=destination_object_name,
                        source=CopySource(
                            bucket_name, object_name, ssec=encryption_key),
                        sse=encryption_key,
                    )
                except S3Error as error:
                    print(f"Failed copy file '{object_name}': {error.message}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed copy file '{object_name}': {error.message}"
                    )

    async def rename_file(self, bucket_name: str, path: str, new_name: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        object_name = path.strip('/')
        new_object_name = object_name[:-
                                      len(object_name.split('/')[-1])] + new_name
        if object_name == new_object_name:
            return

        if path.endswith('/'):  # папка
            try:
                prefix = path.strip('/')
                objects = client.list_objects(
                    bucket_name, prefix=prefix, recursive=True)
                for obj in objects:
                    object_name = obj.object_name
                    relative_path = object_name[len(prefix):].lstrip('/')
                    destination_object_name = f'{new_object_name}/{relative_path}'
                    client.copy_object(
                        bucket_name=bucket_name,
                        object_name=destination_object_name,
                        source=CopySource(
                            bucket_name, object_name, ssec=encryption_key),
                        sse=encryption_key,
                    )
            except S3Error as error:
                print(f"Failed copy folder '{prefix}': {error.message}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed copy folder '{prefix}': {error.message}"
                )
        else:  # файл
            try:
                client.copy_object(
                    bucket_name=bucket_name,
                    object_name=new_object_name,
                    source=CopySource(bucket_name, object_name,
                                      ssec=encryption_key),
                    sse=encryption_key,
                )
            except S3Error as error:
                print(f"Failed copy file '{object_name}': {error.message}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed copy file '{object_name}': {error.message}"
                )

        await self.delete_files(bucket_name, [path], access_key, secret_key, sts_token)

    async def upload_file(self, bucket_name: str, file: UploadFile, path: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        await asyncio.to_thread(
            client.put_object,
            bucket_name=bucket_name,
            object_name=path.strip('/') + '/' + file.filename,
            data=file.file,
            length=file.size,
            sse=encryption_key,
        )

    async def new_folder(self, bucket_name: str, name: str, path: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        client.put_object(
            bucket_name=bucket_name,
            object_name=f'{path.strip('/')}/{name}/NODATA',
            data=io.BytesIO(b''),
            length=0,
            sse=encryption_key,
        )

    async def create_bucket(self, bucket_name: str, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)
        try:
            client.make_bucket(bucket_name)
        except S3Error as error:
            print(f"Failed create bucket '{bucket_name}': {error.message}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed create bucket '{bucket_name}': {error.message}"
            )

    async def remove_bucket(self, bucket_name: str, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)
        try:
            client.remove_bucket(bucket_name)
        except S3Error as error:
            print(f"Failed remove bucket '{bucket_name}': {error.message}")
            if error.code == 'BucketNotEmpty':
                raise HTTPException(
                    status_code=406,
                    detail=f"Failed remove bucket '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed remove bucket '{bucket_name}': {error.message}"
                )


class CopyRequest(BaseModel):
    bucket: str
    sourcePaths: list[str]
    destinationPath: str
    token: str


class RenameRequest(BaseModel):
    bucket: str
    path: str
    newName: str
    token: str


class NewFolderRequest(BaseModel):
    bucket: str
    name: str
    path: str
    token: str


class CreateCollectionRequest(BaseModel):
    token: str
    name: str


class CreateGroupRequest(BaseModel):
    token: str
    title: str
    description: str


class GiveAccessUserToCollectionRequest(BaseModel):
    token: str
    collection_id: int
    user_id: int


class GiveAccessGroupToCollectionRequest(BaseModel):
    token: str
    collection_id: int
    group_id: int


class AddUserToGroupRequest(BaseModel):
    token: str
    group_id: int
    user_id: int


app = FastAPI()
security = HTTPBasic()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_credentials=True,
    allow_headers=["*"]
)
web_sessions = WebSessionsBase()
database = MainBase()
ldap = LDAPManager()

minio = Client(config.url, access_key=config.access_key,
               secret_key=config.secret_key)


@app.get('/')
async def get_list_files(bucket: str, token: str) -> list | None:
    session = web_sessions.get_session(token[:32])
    if session:
        return await minio.get_files(bucket, session['access_key'], session['secret_key'], session['sts_token'])


@app.get('/get_list_collections')
async def get_list_collections(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_collections(user_id)


@app.get('/download')
async def download(bucket: str, file: str, token: str, request: Request) -> StreamingResponse:
    token, hash2 = token[:32], token[32:]
    session = web_sessions.get_session(token)
    if session:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(session['hash1'], hash2)
        collection_key = database.get_collection_key(
            bucket, session['user_id'], key)
        file = file.strip('/')
        range_header = request.headers.get('Range')
        return await minio.download_file(bucket, file, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'], range_header=range_header)


@app.delete('/')
async def delete(bucket: str, files: str, token: str):
    session = web_sessions.get_session(token[:32])
    if session:
        await minio.delete_files(bucket, files.split('|'), session['access_key'], session['secret_key'], session['sts_token'])


@app.post('/copy')
async def copy(request: CopyRequest):
    token, hash2 = request.token[:32], request.token[32:]
    session = web_sessions.get_session(token)
    if session:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(session['hash1'], hash2)
        collection_key = database.get_collection_key(
            request.bucket, session['user_id'], key)
        await minio.copy_files(request.bucket, request.sourcePaths, request.destinationPath, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])


@app.post('/rename')
async def rename(request: RenameRequest):
    token, hash2 = request.token[:32], request.token[32:]
    session = web_sessions.get_session(token)
    if session:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(session['hash1'], hash2)
        collection_key = database.get_collection_key(
            request.bucket, session['user_id'], key)
        await minio.rename_file(request.bucket, request.path, request.newName, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])


@app.post('/folder')
async def folder(request: NewFolderRequest):
    token, hash2 = request.token[:32], request.token[32:]
    session = web_sessions.get_session(token)
    if session:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(session['hash1'], hash2)
        collection_key = database.get_collection_key(
            request.bucket, session['user_id'], key)
        await minio.new_folder(request.bucket, request.name, request.path, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])


@app.put('/')
async def upload(file: UploadFile, bucket: Annotated[str, Form()], path: Annotated[str, Form()], token: Annotated[str, Form()]) -> str | None:
    token, hash2 = token[:32], token[32:]
    session = web_sessions.get_session(token)
    if session:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(session['hash1'], hash2)
        collection_key = database.get_collection_key(bucket, session['user_id'], key)
        await minio.upload_file(bucket, file, path, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])
        return file.filename


@app.get('/auth')
async def auth(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> dict[str, int | str | bool]:
    user_id = ldap.auth(credentials.username, credentials.password)
    if user_id is not None:
        user_id_db = database.get_user_id(credentials.username)
        if user_id_db is None:
            database.add_user(user_id, credentials.username,
                              credentials.password)
        # Надо добавить если не совпадают id
    else:
        raise HTTPException(
            status_code=401,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    key = hash_argon2_from_password(credentials.password)
    hash1, hash2 = hash_division(key)
    token = secrets.token_urlsafe(24)[:32]
    temp_auth = get_sts_token(credentials.username, credentials.password)
    web_sessions.add_session(
        token, hash1, user_id, temp_auth['access_key'], temp_auth['secret_key'], temp_auth['sts_token'])
    hash2 = base64.urlsafe_b64encode(hash2).decode()

    return {
        'authenticated': True,
        'token': token + hash2,
        'user_id': user_id,
        'login': credentials.username,
    }


@app.get('/check')
async def check(token: str) -> dict[str, int | bool]:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return {'authenticated': True, 'user_id': user_id}
    raise HTTPException(status_code=401, detail='Token not found')


@app.get('/registration')
async def registration(login: str, password: str):
    database.add_user(login, password)


@app.post('/create_collection')
async def create_collection(request: CreateCollectionRequest):
    session = web_sessions.get_session(request.token[:32])
    if session:
        await minio.create_bucket(request.name, session['access_key'], session['secret_key'], session['sts_token'])
        return database.create_collection(request.name, session['user_id'])


@app.post('/give_access_user_to_collection')
async def give_access_user_to_collection(request: GiveAccessUserToCollectionRequest):
    token, hash2 = request.token[:32], request.token[32:]
    hash1, user_id = web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        database.give_access_user_to_collection(
            request.collection_id, user_id, request.user_id, key)


@app.post('/create_group')
async def create_group(request: CreateGroupRequest):
    token = request.token[:32]
    user_id = web_sessions.get_user_id(token)
    if user_id:
        database.create_group(user_id, request.title, request.description)


@app.post('/give_access_group_to_collection')
async def give_access_group_to_collection(request: GiveAccessGroupToCollectionRequest):
    token, hash2 = request.token[:32], request.token[32:]
    hash1, user_id = web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        database.give_access_group_to_collection(
            request.collection_id, user_id, request.group_id, key)


@app.post('/add_user_to_group')
async def add_user_to_group(request: AddUserToGroupRequest):
    token, hash2 = request.token[:32], request.token[32:]
    hash1, user_id = web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        database.add_user_to_group(
            request.group_id, user_id, request.user_id, key)


@app.get('/get_groups')
async def get_groups(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_groups(user_id)


@app.delete('/remove_collection')
async def remove_collection(token: str, collection: str):
    session = web_sessions.get_session(token[:32])
    if session:
        await minio.remove_bucket(collection, session['access_key'], session['secret_key'], session['sts_token'])
        database.remove_collection(collection, session['user_id'])


@app.get('/get_other_users')
async def get_other_users(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_other_users(user_id)


@app.get('/get_access_to_collection')
async def get_access_to_collection(token: str, collection_id: int) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_access_to_collection(collection_id)


@app.delete('/delete_access_to_collection')
async def delete_access_to_collection(token: str, access_id: int) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.delete_access_to_collection(access_id)


@app.get('/get_group_users')
async def get_group_users(token: str, group_id: int) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_group_users(group_id)
