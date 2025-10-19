import asyncio
import base64
import io
from typing import Annotated
from minio import Minio
from minio.sse import SseCustomerKey
from minio.error import S3Error
from minio.commonconfig import CopySource
from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import quote
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import requests
from sessions import WebSessionsBase
from database import MainBase
from crypt import hash_argon2_from_password, hash_division, hash_reconstruct
import secrets
from minio.deleteobjects import DeleteObject
import config
from ldap import LDAPManager
from get_token import get_sts_token
import zipstream
from opensearch import OpenSearchManager


class Client:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.cert_check = False

    async def get_list(self, bucket_name: str, path: str, recursive: bool, access_key: str, secret_key: str, sts_token: str) -> list[dict]:
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        try:
            if path:
                prefix = path.strip('/') + '/'
                objects = await asyncio.to_thread(
                    client.list_objects,
                    bucket_name,
                    recursive=recursive,
                    prefix=prefix
                )
            else:
                objects = await asyncio.to_thread(
                    client.list_objects,
                    bucket_name,
                    recursive=recursive
                )
            result = []
            processed_folders = set()

            for obj in objects:
                object_name = obj.object_name
                if not object_name.endswith('NODATA'):
                    file = {
                        'name': obj.object_name[obj.object_name.rfind('/', 0, -1 if obj.is_dir else -2) + 1:],
                        'isDirectory': obj.is_dir,
                        'path': f'/{object_name}',
                        'size': obj.size,
                    }
                    if obj.last_modified:
                        file['updatedAt'] = obj.last_modified.isoformat()
                    result.append(file)

                if recursive:
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
            buckets = await asyncio.to_thread(client.list_buckets)
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
                    objects = await asyncio.to_thread(
                        client.list_objects,
                        bucket_name, prefix=object_name + '/', recursive=True)
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

    async def download_file(self, bucket_name: str, file_path: str, preview: bool, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str, range_header: str = None) -> StreamingResponse:
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        async def file_iterator(stream, chunk_size=1024 * 1024):
            while True:
                data = await asyncio.to_thread(stream.read, chunk_size)
                if not data:
                    break
                yield data

        object_name = file_path.lstrip('/')
        try:
            stat = await asyncio.to_thread(client.stat_object, bucket_name, object_name, ssec=encryption_key)
        except S3Error:
            try:
                stat = await asyncio.to_thread(client.stat_object, bucket_name, object_name)
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

                obj = await asyncio.to_thread(
                    client.get_object,
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
                    media_type='application/octet-stream' if preview else None,
                    headers=headers,
                    status_code=206  # Partial Content
                )
            else:
                obj = await asyncio.to_thread(
                    client.get_object,
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key
                )
                return StreamingResponse(
                    file_iterator(obj),
                    media_type='application/octet-stream' if preview else None,
                    headers=headers
                )
        except S3Error as error:
            print(f'Failed to get the file: {error.message}')
            raise HTTPException(
                status_code=404 if error.code == 'NoSuchKey' else 403,
                detail=f'Failed to get the file: {error.message}'
            )

    async def download_files(self, bucket_name: str, file_paths: list, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str) -> StreamingResponse:
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        files_to_download = []

        try:
            for path in file_paths:
                object_name = path.strip('/')

                if not path.endswith('/'):
                    files_to_download.append(object_name)
                else:
                    objects = await asyncio.to_thread(
                        client.list_objects,
                        bucket_name,
                        prefix=object_name + '/',
                        recursive=True
                    )

                    for obj in objects:
                        if not obj.object_name.endswith('/NODATA'):
                            files_to_download.append(obj.object_name)

            # Создаём потоковый zip-архив
            z = zipstream.ZipFile(mode="w", compression=zipstream.ZIP_DEFLATED)

            for obj_name in files_to_download:
                # Оборачиваем поток MinIO в генератор
                def file_generator(obj_name=obj_name):
                    response = client.get_object(
                        bucket_name,
                        obj_name,
                        ssec=encryption_key
                    )
                    try:
                        for chunk in response.stream(1024 * 1024):
                            yield chunk
                    finally:
                        response.close()
                        response.release_conn()

                # Добавляем в архив "ленивый" источник данных
                await asyncio.to_thread(z.write_iter, obj_name, file_generator())

            # Отдаём как стрим
            return StreamingResponse(
                z,
                media_type="application/zip",
                headers={"Content-Disposition": 'attachment; filename="files.zip"'}
            )
        except S3Error as error:
            print(f'Failed to get the file: {error.message}')
            raise HTTPException(
                status_code=404 if error.code == 'NoSuchKey' else 403,
                detail=f'Failed to get the file: {error.message}'
            )

    async def copy_files(self, source_bucket_name: str, source_paths: list[str], destination_bucket_name: str, destination_path: str, source_encryption_key: SseCustomerKey, destination_encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        for source in source_paths:
            if source.endswith('/'):  # папка
                try:
                    prefix = source.lstrip('/')
                    objects = await asyncio.to_thread(
                        client.list_objects,
                        source_bucket_name,
                        prefix=prefix,
                        recursive=True
                    )
                    for obj in objects:
                        object_name = obj.object_name
                        relative_path = prefix.strip(
                            '/').split('/')[-1] + '/' + object_name[len(prefix):].lstrip('/')
                        destination_object_name = f'{destination_path.rstrip('/')}/{relative_path}'
                        await asyncio.to_thread(
                            client.copy_object,
                            bucket_name=destination_bucket_name,
                            object_name=destination_object_name,
                            source=CopySource(
                                source_bucket_name, object_name, ssec=source_encryption_key),
                            sse=destination_encryption_key,
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
                    await asyncio.to_thread(
                        client.copy_object,
                        bucket_name=destination_bucket_name,
                        object_name=destination_object_name,
                        source=CopySource(
                            source_bucket_name, object_name, ssec=source_encryption_key),
                        sse=destination_encryption_key,
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
                prefix = path.strip('/') + '/'
                objects = await asyncio.to_thread(
                    client.list_objects,
                    bucket_name, prefix=prefix, recursive=True
                )
                for obj in objects:
                    object_name = obj.object_name
                    relative_path = object_name[len(prefix):].lstrip('/')
                    destination_object_name = f'{new_object_name}/{relative_path}'
                    await asyncio.to_thread(
                        client.copy_object,
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
                await asyncio.to_thread(
                    client.copy_object,
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

    async def upload_file(self, bucket_name: str, file: UploadFile, path: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str, overwrite=True):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        object_name = path.strip('/') + '/' + file.filename
        if not overwrite:
            try:
                await asyncio.to_thread(
                    client.stat_object,
                    bucket_name=bucket_name,
                    object_name=object_name,
                    ssec=encryption_key
                )
                raise HTTPException(
                    status_code=403,
                    detail='You cannot overwrite the file'
                )
            except S3Error as error:
                pass

        await asyncio.to_thread(
            client.put_object,
            bucket_name=bucket_name,
            object_name=object_name,
            data=file.file,
            length=file.size,
            sse=encryption_key,
        )

    async def new_folder(self, bucket_name: str, name: str, path: str, encryption_key: SseCustomerKey, access_key: str, secret_key: str, sts_token: str):
        client = Minio(self.endpoint, access_key, secret_key,
                       sts_token, secure=True, cert_check=self.cert_check)

        await asyncio.to_thread(
            client.put_object,
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
            await asyncio.to_thread(
                client.make_bucket,
                bucket_name
            )
        except ValueError as error:
            print(f"Failed create bucket '{bucket_name}': {error}")
            raise HTTPException(
                status_code=406,
                detail=f"Failed create bucket '{bucket_name}': {error}"
            )
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
            await asyncio.to_thread(client.remove_bucket, bucket_name)
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
    source_collection_id: int
    source_paths: list[str]
    destination_collection_id: int
    destination_path: str
    token: str


class RenameRequest(BaseModel):
    path: str
    new_name: str
    token: str


class NewFolderRequest(BaseModel):
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
    access_type_id: int


class GiveAccessGroupToCollectionRequest(BaseModel):
    token: str
    collection_id: int
    group_id: int
    access_type_id: int


class AddUserToGroupRequest(BaseModel):
    token: str
    group_id: int
    user_id: int
    role_id: int


class ChangeGroupInfoRequest(BaseModel):
    token: str
    group_id: int
    title: str
    description: str


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
opensearch = OpenSearchManager()

minio = Client(config.minio_url)


@app.get('/collections/list/{token}')
async def get_list_collections(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_collections(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/collections/{collection_id}/list/{token}/{path:path}')  # access+
async def get_list_files(token: str, collection_id: int, path: str, recursive: bool = True) -> list | None:
    access = [1, 2, 3, 4]
    session = web_sessions.get_session(token[:32])
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            return await minio.get_list(database.get_collection_name(collection_id), path, recursive, session['access_key'], session['secret_key'], session['sts_token'])
        else:
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/collections/{collection_id}/file/{token}/{path:path}')  # access+
async def get_file(collection_id: int, path: str, token: str, request: Request, preview: bool = False) -> StreamingResponse:
    access = [1, 2, 3]
    token, hash2 = token[:32], token[32:]
    session = web_sessions.get_session(token)
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            path = path.strip('/')
            range_header = request.headers.get('Range')
            return await minio.download_file(database.get_collection_name(collection_id), path, preview, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'], range_header=range_header)
        else:
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/collections/{collection_id}/archive/{token}')  # access+
async def get_files(collection_id: int, files: str, token: str) -> StreamingResponse:
    access = [1, 2, 3]
    token, hash2 = token[:32], token[32:]
    session = web_sessions.get_session(token)
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            return await minio.download_files(database.get_collection_name(collection_id), files.split('|'), SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])
        else:
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


# access+
@app.get('/collections/{collection_id}/files/{token}', response_class=HTMLResponse)
@app.get('/collections/{collection_id}/files/{token}/{path:path}', response_class=HTMLResponse)
@app.head('/collections/{collection_id}/files/{token}/{path:path}')
async def get_list_files_http(collection_id: int, token: str, request: Request, path: str = ''):
    access = [1, 2, 3]
    hash2 = token[32:]
    session = web_sessions.get_session(token[:32])
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            if path:
                try:
                    if not path.endswith('/'):
                        hash2 = base64.urlsafe_b64decode(hash2.encode())
                        key = hash_reconstruct(session['hash1'], hash2)
                        collection_key = database.get_collection_key(
                            collection_id, session['user_id'], key)
                        response = await minio.download_file(database.get_collection_name(collection_id), path, True, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'], range_header=request.headers.get('Range'))
                        return response
                except Exception:
                    if request.method == 'HEAD':
                        return Response(headers={"Content-Type": "text/html; charset=utf-8", 'Content-Length': '0', 'Location': f'/{quote(path.strip('/'))}/'}, status_code=301)

            files = await minio.get_list(database.get_collection_name(collection_id), path, False, session['access_key'], session['secret_key'], session['sts_token'])
            html = f'<!DOCTYPE HTML><html lang="en"><head><meta charset="utf-8"><title>Directory listing for /{path}</title></head>'
            html += f"<body><h1>Directory listing for /{path}</h1><hr><ul>"
            if path:
                parent_path = '/'.join(path.strip('/').split('/')[:-1])
                parent_url = f'/collections/{collection_id}/files/{token}'
                if parent_path:
                    parent_url += f'/{parent_path}/'
                html += f'<li><a href="{parent_url}">../</a></li>'

            for file in files:
                if file['isDirectory']:
                    html += f'<li><a href="/collections/{collection_id}/files/{token}{file['path']}">{file["name"]}</a></li>'
                else:
                    html += f'<li><a href="/collections/{collection_id}/files/{token}{file['path']}">{file["name"]}</a></li>'
            html += '</ul><hr></body></html>'

            return HTMLResponse(html)
        else:
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.delete('/collections/{collection_id}/{token}')  # access+
async def delete_files(collection_id: int, files: str, token: str):
    access = [1, 2]
    session = web_sessions.get_session(token[:32])
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        files = files.split('|')
        if access_type in access:
            await minio.delete_files(database.get_collection_name(collection_id), files, session['access_key'], session['secret_key'], session['sts_token'])
            database.add_log(
                'delete', 200, {'files': files}, user_id=session['user_id'], collection_id=collection_id)
        else:
            database.add_log(
                'delete', 403, {'error': f'{access_type} not in {access}', 'files': files}, user_id=session['user_id'], collection_id=collection_id)
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/copy')  # access+
async def copy_files(request: CopyRequest):
    access = [1, 2, 3]
    access_dest = [1, 2, 4]
    token, hash2 = request.token[:32], request.token[32:]
    session = web_sessions.get_session(token)
    if session:
        if database.get_type_access(request.source_collection_id, session['user_id']) in access and database.get_type_access(request.destination_collection_id, session['user_id']) in access_dest:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            source_collection_key = database.get_collection_key(
                request.source_collection_id, session['user_id'], key)
            destination_collection_key = database.get_collection_key(
                request.destination_collection_id, session['user_id'], key)
            await minio.copy_files(database.get_collection_name(request.source_collection_id), request.source_paths, database.get_collection_name(request.destination_collection_id), request.destination_path, SseCustomerKey(source_collection_key), SseCustomerKey(destination_collection_key), session['access_key'], session['secret_key'], session['sts_token'])
            database.add_log('copy', 200, {'source_collection_id': request.source_collection_id, 'source_paths': request.source_paths,
                             'destination_path': request.destination_path}, user_id=session['user_id'], collection_id=request.destination_collection_id)
        else:
            database.add_log('copy', 403, {'source_collection_id': request.source_collection_id, 'source_paths': request.source_paths,
                             'destination_path': request.destination_path}, user_id=session['user_id'], collection_id=request.destination_collection_id)
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/collections/{collection_id}/rename')  # access+
async def rename_file(collection_id: int, request: RenameRequest):
    access = [1, 2]
    token, hash2 = request.token[:32], request.token[32:]
    session = web_sessions.get_session(token)
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        if access_type in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.rename_file(database.get_collection_name(collection_id), request.path, request.new_name, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])
            database.add_log(
                'rename', 200, {'path': request.path, 'new_name': request.new_name}, user_id=session['user_id'], collection_id=collection_id)
        else:
            database.add_log(
                'rename', 403, {'error': f'{access_type} not in {access}', 'collection_id': collection_id, 'path': request.path, 'new_name': request.new_name}, user_id=session['user_id'], collection_id=collection_id)
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/collections/{collection_id}/create_folder')  # access+
async def create_folder(collection_id: int, request: NewFolderRequest):
    access = [1, 2, 4]
    token, hash2 = request.token[:32], request.token[32:]
    session = web_sessions.get_session(token)
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        if access_type in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.new_folder(database.get_collection_name(collection_id), request.name, request.path, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'])
            database.add_log(
                'create_folder', 200, {'path': request.path, 'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
        else:
            database.add_log(
                'create_folder', 403, {'error': f'{access_type} not in {access}', 'path': request.path, 'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/collections/{collection_id}/upload/{token}/{path:path}')  # access+
async def upload_file(file: UploadFile, collection_id: int, path: str, token: str) -> str | None:
    access = [1, 2, 4]
    token, hash2 = token[:32], token[32:]
    session = web_sessions.get_session(token)
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        if access_type in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.upload_file(database.get_collection_name(collection_id), file, path, SseCustomerKey(collection_key), session['access_key'], session['secret_key'], session['sts_token'], overwrite=access_type != 4)
            database.add_log(
                'upload', 200, {'file_name': file.filename, 'path': path}, user_id=session['user_id'], collection_id=collection_id)
            return file.filename
        else:
            database.add_log(
                'upload', 403, {'error': f'{access_type} not in {access}', 'path': path, 'file_name': file.filename}, user_id=session['user_id'], collection_id=collection_id)
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/auth')  # safe+ logs+
async def auth(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> dict[str, int | str | bool]:
    username, org = credentials.username.split(
        '/')[0], credentials.username.split('/')[-1]
    if org == 'default' or org == '':
        credentials.username = username
    response = requests.post(
        f'{config.auth_api_url}/login?org={org}',
        auth=(username, credentials.password),
        verify=False
    )
    if response.status_code == 200:
        jwt_token = response.json()
        user_id_db = database.get_user_id(credentials.username)
        if user_id_db is None:
            user_id_db = database.add_user(
                credentials.username, credentials.password)
            database.add_log(
                'new_user', 200, {'login': credentials.username}, user_id=user_id_db)
    else:
        database.add_log(
            'auth', 401, {'login': credentials.username}, user_id=None)
        raise HTTPException(
            status_code=401,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    temp_auth = get_sts_token(jwt_token, 'https://' + config.minio_url)
    if temp_auth is None:
        database.add_log(
            'auth', 400, {'login': credentials.username}, user_id=None)
        raise HTTPException(
            status_code=400,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    key = hash_argon2_from_password(credentials.password)
    hash1, hash2 = hash_division(key)
    token = secrets.token_urlsafe(24)[:32]
    web_sessions.add_session(
        token, hash1, user_id_db, temp_auth['access_key'], temp_auth['secret_key'], temp_auth['sts_token'])
    hash2 = base64.urlsafe_b64encode(hash2).decode()

    database.add_log(
        'auth', 200, {'login': credentials.username}, user_id=user_id_db)
    return {
        'token': token + hash2,
        'user_id': user_id_db,
        'login': credentials.username,
    }


@app.get('/check_session')  # safe+
async def check(token: str) -> dict[str, int | bool]:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return {'authenticated': True, 'user_id': user_id}
    raise HTTPException(status_code=401, detail='Token not found')


@app.get('/delete_session')  # safe+
async def check(token: str) -> bool:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        web_sessions.delete_session(token[:32])
        return True
    else:
        return False

@app.get('/registration')  # develop
async def registration(login: str, password: str):
    database.add_user(login, password)


@app.post('/create_collection')  # safe+ logs+
async def create_collection(request: CreateCollectionRequest):
    session = web_sessions.get_session(request.token[:32])
    if session:
        try:
            await minio.create_bucket(request.name, session['access_key'], session['secret_key'], session['sts_token'])
            collection_id = database.create_collection(
                request.name, session['user_id'])
            database.add_log('create_collection', 200,
                             {'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
        except HTTPException as error:
            database.add_log('create_collection', error.status_code,
                             {'error': error.detail, 'name': request.name}, user_id=session['user_id'])
            raise error
        return collection_id
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/give_access_user_to_collection')  # safe+ access- logs+
async def give_access_user_to_collection(request: GiveAccessUserToCollectionRequest):
    token, hash2 = request.token[:32], request.token[32:]
    hash1, user_id = web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        try:
            database.give_access_user_to_collection(
                request.collection_id, user_id, request.user_id, request.access_type_id, key)
            database.add_log('give_access_user_to_collection',
                             200, {'access_type_id': request.access_type_id}, user_id=user_id, collection_id=request.collection_id)
        except Exception as error:
            database.add_log('give_access_user_to_collection',
                             500, {'error': str(error), 'access_type_id': request.access_type_id}, user_id=user_id, collection_id=request.collection_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/create_group')  # safe+ logs+
async def create_group(request: CreateGroupRequest):
    token = request.token[:32]
    user_id = web_sessions.get_user_id(token)
    if user_id:
        try:
            group_id = database.create_group(
                user_id, request.title, request.description)
            database.add_log(
                'create_group', 200, {'title': request.title, 'description': request.description}, user_id=user_id, group_id=group_id)
        except Exception as error:
            database.add_log('create_group', 500, {'error': str(
                error), 'title': request.title, 'description': request.description}, user_id=user_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/give_access_group_to_collection')  # safe+ access- logs+
async def give_access_group_to_collection(request: GiveAccessGroupToCollectionRequest):
    token, hash2 = request.token[:32], request.token[32:]
    hash1, user_id = web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        try:
            access_id = database.give_access_group_to_collection(
                request.collection_id, user_id, request.group_id, request.access_type_id, key)
            database.add_log('give_access_group_to_collection',
                             200, {'access_id': access_id}, user_id=user_id, group_id=request.group_id, collection_id=request.collection_id)
        except Exception as error:
            database.add_log('give_access_group_to_collection',
                             500, {'error': str(error)}, user_id=user_id, group_id=request.group_id, collection_id=request.collection_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/add_user_to_group')  # safe+ logs+
async def add_user_to_group(request: AddUserToGroupRequest):
    token, hash2 = request.token[:32], request.token[32:]
    hash1, user_id = web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        try:
            database.add_user_to_group(
                request.group_id, user_id, request.user_id, request.role_id, key)
            database.add_log('add_user_to_group', 200,
                             {'role_id': request.role_id, 'user_id': request.user_id}, user_id=user_id, group_id=request.group_id)
        except Exception as error:
            database.add_log('add_user_to_group', 500, {'error': str(
                error), 'role_id': request.role_id, 'user_id': request.user_id}, user_id=user_id, group_id=request.group_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_groups')  # safe+
async def get_groups(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_groups(user_id)


@app.delete('/remove_collection')  # safe+ logs+
async def remove_collection(token: str, collection_id: int):
    session = web_sessions.get_session(token[:32])
    if session:
        collection_name = database.get_collection_name(collection_id)
        try:
            await minio.remove_bucket(database.get_collection_name(collection_id), session['access_key'], session['secret_key'], session['sts_token'])
        except HTTPException as error:
            database.add_log('remove_collection', error.status_code, {
                             'error': error.detail, 'collection_id': collection_id, 'collection_name': collection_name}, user_id=session['user_id'])
            raise error
        database.remove_collection(collection_id, session['user_id'])
        database.add_log('remove_collection', 200, {
                         'collection_id': collection_id, 'collection_name': collection_name}, user_id=session['user_id'])
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_other_users')  # safe+
async def get_other_users(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_other_users(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_access_to_collection')  # safe+
async def get_access_to_collection(token: str, collection_id: int) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_access_to_collection(collection_id, user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.delete('/delete_access_to_collection')  # safe+ logs+
async def delete_access_to_collection(token: str, access_id: int) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        try:
            database.delete_access_to_collection(access_id, user_id)
            database.add_log('delete_access_to_collection', 200, {
                             'access_id': access_id}, user_id=user_id)
        except Exception as error:
            database.add_log('delete_access_to_collection', 500, {
                             'error': str(error), 'access_id': access_id}, user_id=user_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.delete('/delete_user_to_group')  # safe+ logs+
async def delete_user_to_group(token: str, group_id: int, user_id: int) -> list | None:
    req_user_id = web_sessions.get_user_id(token[:32])
    if req_user_id:
        try:
            database.delete_user_to_group(group_id, user_id, req_user_id)
            database.add_log('delete_user_to_group', 200, {
                             'user_id': user_id}, user_id=req_user_id, group_id=group_id)
        except Exception as error:
            database.add_log('delete_user_to_group', 500, {'error': str(
                error), 'user_id': user_id}, user_id=req_user_id, group_id=group_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_group_users')  # safe+
async def get_group_users(token: str, group_id: int) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_group_users(group_id, user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_access_types')  # safe+
async def get_access_types(token: str) -> list | None:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_access_types()
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/transfer_power_to_group')  # safe+
async def transfer_power_to_group(token: str, group_id: int, user_id: int):
    owner_user_id = web_sessions.get_user_id(token[:32])
    if owner_user_id:
        try:
            database.transfer_power_to_group(group_id, owner_user_id, user_id)
            database.add_log('transfer_power_to_group', 200, {
                             'user_id': user_id}, user_id=owner_user_id, group_id=group_id)
        except Exception as error:
            database.add_log('transfer_power_to_group', 500, {'error': str(
                error), 'user_id': user_id}, user_id=owner_user_id, group_id=group_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.delete('/exit_group')  # safe+ logs+
async def exit_group(token: str, group_id: int):
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        try:
            database.delete_user_to_group(group_id, user_id, user_id)
            database.add_log('exit_group', 200, {},
                             user_id=user_id, group_id=group_id)
        except Exception as error:
            database.add_log('exit_group', 500, {'error': str(error)},
                             user_id=user_id, group_id=group_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/change_role_in_group')  # safe+ logs+
async def change_role_in_group(token: str, group_id: int, user_id: int, role_id: int):
    owner_user_id = web_sessions.get_user_id(token[:32])
    if owner_user_id:
        try:
            database.change_role_in_group(
                group_id, owner_user_id, user_id, role_id)
            database.add_log('change_role_in_group', 200, {'user_id': user_id, 'role_id': role_id},
                             user_id=owner_user_id, group_id=group_id)
        except Exception as error:
            database.add_log('change_role_in_group', 500, {'error': str(error), 'user_id': user_id, 'role_id': role_id},
                             user_id=owner_user_id, group_id=group_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_user_info')  # safe+
async def get_user_info(token: str) -> dict[str, int | str]:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_user_info(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/change_access_type')  # safe+ logs+
async def change_access_type(token: str, access_id: int, access_type_id: int):
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        try:
            database.change_access_type(access_id, user_id, access_type_id)
            database.add_log('change_access_type', 200, {'access_id': access_id, 'access_type_id': access_type_id},
                             user_id=user_id)
        except Exception as error:
            database.add_log('change_access_type', 500, {'error': str(
                error), 'access_id': access_id, 'access_type_id': access_type_id}, user_id=user_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/change_group_info')  # safe+ logs+
async def change_group_info(request: ChangeGroupInfoRequest):
    user_id = web_sessions.get_user_id(request.token[:32])
    if user_id:
        try:
            database.change_group_info(
                user_id, request.group_id, request.title, request.description)
            database.add_log('change_group_info', 200, {'title': request.title, 'description': request.description},
                             user_id=user_id, group_id=request.group_id)
        except Exception as error:
            database.add_log('change_group_info', 500, {'error': str(
                error), 'title': request.title, 'description': request.description}, user_id=user_id, group_id=request.group_id)
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_logs')  # safe+
async def get_logs(token: str) -> list:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_logs(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_history_collection')  # safe+
async def get_history_collection(token: str, collection_id: int) -> list:
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_history_collection(user_id, collection_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/change_collection_info')  # safe+ logs+
async def change_collection_info(token: str, collection_id: int, data: dict):
    access = [1]
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        if database.get_type_access(collection_id, user_id) in access:
            try:
                opensearch.update_document(collection_id, data)
                database.add_log('change_collection_info', 200, None,
                                 user_id=user_id, collection_id=collection_id)
            except Exception as error:
                database.add_log('change_collection_info', 500, {'error': str(
                    error), 'data': data}, user_id=user_id, collection_id=collection_id)
                raise HTTPException(
                    status_code=500,
                    detail=''
                )
        else:
            raise HTTPException(
                status_code=403,
                detail='You not owner'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_collection_info')  # safe+ logs+
async def get_collection_info(token: str, collection_id: int):
    access = [1, 2, 3, 4]
    user_id = web_sessions.get_user_id(token[:32])
    if user_id:
        if database.get_type_access(collection_id, user_id) in access:
            try:
                return opensearch.get_document(collection_id)
            except Exception as error:
                database.add_log('get_collection_info', 500, {'error': str(
                    error), 'collection_id': collection_id}, user_id=user_id)
                raise HTTPException(
                    status_code=500,
                    detail=''
                )
        else:
            raise HTTPException(
                status_code=403,
                detail='No access'
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/change_access_to_all')  # safe+ logs+
async def change_access_to_all(token: str, collection_id: int, is_access: bool):
    token, hash2 = token[:32], token[32:]
    session = web_sessions.get_session(token)
    if session:
        if database.get_type_access(collection_id, session['user_id']) == 1:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            try:
                database.change_access_to_all(
                    session['user_id'], collection_id, is_access, key)
                database.add_log('change_access_to_all', 200, {'is_access': is_access},
                                 user_id=session['user_id'], collection_id=collection_id)
            except Exception as error:
                database.add_log('change_access_to_all', 500, {'error': str(
                    error), 'is_access': is_access}, user_id=session['user_id'], collection_id=collection_id)
                raise HTTPException(
                    status_code=500,
                    detail=''
                )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )
