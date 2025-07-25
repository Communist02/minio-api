import asyncio
import base64
from datetime import timedelta
import io
from typing import Annotated
from minio import Minio
from minio.sse import SseCustomerKey
from minio.error import S3Error
from fastapi import Depends, FastAPI, Form, HTTPException, UploadFile, Request
from fastapi.responses import StreamingResponse
import json
from pydantic import BaseModel
from minio.commonconfig import CopySource
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import quote
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sessions import WebSessionsBase
from crypt import hash_argon2_password, hash_division, hash_reconstruct
import secrets
import urllib3


class Client:
    def __init__(self, endpoint_url: str, access_key: str, secret_key: str):
        http_client = urllib3.PoolManager(cert_reqs='CERT_NONE')
        self.client = Minio(
            endpoint_url, access_key=access_key, secret_key=secret_key, secure=True, http_client=http_client)

    async def get_files(self, bucket_name) -> list[dict]:
        client = self.client

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

    async def get_buckets(self) -> list[str]:
        client = self.client

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

    async def delete_files(self, bucket_name: str, paths: list[str]):
        client = self.client

        for path in paths:
            object_name = path.strip('/')
            if not path.endswith('/'):
                try:
                    client.remove_object(bucket_name, object_name=object_name)
                except S3Error as error:
                    print(f'Error deleting files: {error.message}')
                    raise HTTPException(
                        status_code=500,
                        detail={'error': 'Error deleting files',
                                'message': error.message}
                    )
            else:
                objects = client.list_objects(
                    bucket_name, prefix=object_name, recursive=True)
                for obj in objects:
                    client.remove_object(bucket_name, obj.object_name)

    async def get_download_url(self, bucket_name: str, object_key: str, encryption_key: SseCustomerKey, expires_seconds: int = 3600) -> str:
        client = self.client

        try:
            object_name = object_key.lstrip('/')
            return client.presigned_get_object(
                bucket_name=bucket_name,
                object_name=object_name,
                expires=timedelta(seconds=expires_seconds),
                response_headers={
                    'response-content-type': 'application/octet-stream'},
                extra_query_params=encryption_key.copy_headers(),
            )
        except S3Error as error:
            print(f'Failed to generate download URL: {error.message}')
            raise HTTPException(
                status_code=404 if error.code == 'NoSuchKey' else 500,
                detail=f'Failed to generate download URL: {error.message}'
            )

    async def download_file(self, bucket_name: str, file_path: str, encryption_key: SseCustomerKey, range_header: str = None) -> StreamingResponse:
        client = self.client

        try:
            object_name = file_path.lstrip('/')
            objects = client.list_objects(
                bucket_name=bucket_name, prefix=object_name)
            for obj in objects:
                file_size = obj.size
            headers = {
                'Content-Disposition': f"attachment; filename*=UTF-8''{quote(object_name.split('/')[-1])}",
                'Content-Length': str(file_size),
                'Accept-Ranges': 'bytes',
            }
            if range_header:
                # Парсим заголовок Range (формат "bytes=start-end")
                start_end = range_header.replace('bytes=', '').split('-')
                start = int(start_end[0])
                end = int(start_end[1]) if start_end[1] else file_size - 1

                # Получаем только запрошенный диапазон байтов
                obj = client.get_object(
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key,
                    offset=start,
                    length=end - start + 1
                )

                # Устанавливаем соответствующие заголовки для частичного контента
                headers['Content-Length'] = str(end - start + 1)
                headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'

                return StreamingResponse(
                    obj,
                    media_type='application/octet-stream',
                    headers=headers,
                    status_code=206  # Partial Content
                )
            else:
                # Полный файл, если нет заголовка Range
                obj = client.get_object(
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key
                )
                return StreamingResponse(
                    obj,
                    media_type='application/octet-stream',
                    headers=headers
                )
        except S3Error as error:
            print(f'Failed to generate download URL: {error.message}')
            raise HTTPException(
                status_code=404 if error.code == 'NoSuchKey' else 500,
                detail=f'Failed to generate download URL: {error.message}'
            )

    async def copy_files(self, bucket_name: str, source_paths: list[str], destination_path: str, encryption_key: SseCustomerKey):
        client = self.client

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

    async def rename_file(self, bucket_name: str, path: str, new_name: str, encryption_key: SseCustomerKey):
        client = self.client

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

        await self.delete_files([path])

    async def upload_file(self, bucket_name: str, file: UploadFile, path: str, encryption_key: SseCustomerKey):
        client = self.client

        await asyncio.to_thread(client.put_object, bucket_name, path.strip(
            '/') + '/' + file.filename, file.file, file.size, sse=encryption_key)

    async def new_folder(self, bucket_name: str, name: str, path: str, encryption_key: SseCustomerKey):
        client = self.client
        client.put_object(
            bucket_name, f'{path.strip('/')}/{name}/NODATA', io.BytesIO(b''), 0, sse=encryption_key)


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

minio = Client('localhost:9000', access_key='minioadmin',
               secret_key='minioadmin')


@app.get('/')
async def get_all_files(bucket: str, token: str) -> str:
    hash1 = web_sessions.check_token(token[:22])
    if hash1:
        return json.dumps(await minio.get_files(bucket))


@app.get('/buckets')
async def get_buckets() -> str:
    return json.dumps(await minio.get_buckets())


@app.get('/download')
async def download(bucket: str, file: str, token: str, request: Request) -> StreamingResponse:
    token, hash2 = token[:22], token[22:]
    hash1 = web_sessions.check_token(token)
    if hash1:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        hash = hash_reconstruct(hash1, hash2)
        file = file.strip('/')
        range_header = request.headers.get('Range')
        return await minio.download_file(bucket, file, SseCustomerKey(hash), range_header)


@app.delete('/')
async def delete(bucket: str, files: str, token: str):
    hash1 = web_sessions.check_token(token[:22])
    if hash1:
        await minio.delete_files(bucket, files.split('|'))
        return True


@app.post('/copy')
async def copy(request: CopyRequest):
    token, hash2 = request.token[:22], request.token[22:]
    hash1 = web_sessions.check_token(token)
    if hash1:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        hash = hash_reconstruct(hash1, hash2)
        await minio.copy_files(request.bucket, request.sourcePaths, request.destinationPath, SseCustomerKey(hash))
        return True


@app.post('/rename')
async def rename(request: RenameRequest):
    token, hash2 = request.token[:22], request.token[22:]
    hash1 = web_sessions.check_token(token)
    if hash1:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        hash = hash_reconstruct(hash1, hash2)
        await minio.rename_file(request.bucket, request.path, request.newName, SseCustomerKey(hash))
        return True


@app.post('/folder')
async def folder(request: NewFolderRequest):
    token, hash2 = request.token[:22], request.token[22:]
    hash1 = web_sessions.check_token(token)
    if hash1:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        hash = hash_reconstruct(hash1, hash2)
        await minio.new_folder(request.bucket, request.name, request.path, SseCustomerKey(hash))
        return True


@app.put('/')
async def upload(file: UploadFile, bucket: Annotated[str, Form()], path: Annotated[str, Form()], token: Annotated[str, Form()]):
    token, hash2 = token[:22], token[22:]
    hash1 = web_sessions.check_token(token)
    if hash1:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        hash = hash_reconstruct(hash1, hash2)
        await minio.upload_file(bucket, file, path, SseCustomerKey(hash))
        return file.filename


@app.get('/auth')
async def auth(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    correct_username = credentials.username == 'admin'
    correct_password = credentials.password == 'password'
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    hash = hash_argon2_password(credentials.password, b']j235#4&')
    token = secrets.token_urlsafe(16)
    hash1, hash2 = hash_division(hash)
    web_sessions.add_session(token, hash1)
    hash2 = base64.urlsafe_b64encode(hash2).decode()

    return {
        'authenticated': True,
        'token': token + hash2,
    }


@app.get('/check')
async def auth(token: str):
    token = token[:22]
    if web_sessions.check_token(token):
        return {'authenticated': True}
    raise HTTPException(status_code=401, detail='Token not found')
