import base64
from contextlib import asynccontextmanager
from typing import Annotated
from minio.sse import SseCustomerKey
from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import quote
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import httpx
from metadata import create_metadata
from minio_client import MinIOClient
from policy import create_policy_to_all, create_policy_to_user
from sessions import WebSessionsBase
from database import MainBase
from crypt import hash_argon2_from_password, hash_division, hash_reconstruct
import secrets
import config
from opensearch import OpenSearchManager


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


class SpecificListCollectionsRequest(BaseModel):
    token: str
    collection_ids: list[int]


web_sessions = WebSessionsBase()
database = MainBase()
opensearch = OpenSearchManager()
minio = MinIOClient(config.minio_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализация при запуске
    await web_sessions.initialize()
    yield
    # Завершение при остановке
    await web_sessions.close()

app = FastAPI(lifespan=lifespan)
security = HTTPBasic()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_credentials=True,
    allow_headers=["*"]
)


@app.get('/collections/list/{token}')
async def get_list_collections(token: str) -> list | None:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_collections(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/collections/specific_list')
async def get_specific_list_collections(request: SpecificListCollectionsRequest) -> list:
    user_id = await web_sessions.get_user_id(request.token[:32])
    if user_id:
        return database.get_specific_access_to_all_collections(user_id, request.collection_ids)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/collections/{collection_id}/list/{token}/{path:path}')  # access+
async def get_list_files(token: str, collection_id: int, path: str, recursive: bool = True) -> list | None:
    access = [1, 2, 3, 4]
    session = await web_sessions.get_session(token[:32])
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            return await minio.get_list_files(database.get_collection_name(collection_id), path, recursive, session['jwt_token'])
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
    session = await web_sessions.get_session(token)
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            path = path.strip('/')
            range_header = request.headers.get('Range')
            return await minio.download_file(database.get_collection_name(collection_id), path, preview, SseCustomerKey(collection_key), session['jwt_token'], range_header=range_header)
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
    session = await web_sessions.get_session(token)
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            return await minio.download_files(database.get_collection_name(collection_id), files.split('|'), SseCustomerKey(collection_key), session['jwt_token'])
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
    session = await web_sessions.get_session(token[:32])
    if session:
        if database.get_type_access(collection_id, session['user_id']) in access:
            if path:
                try:
                    if not path.endswith('/'):
                        hash2 = base64.urlsafe_b64decode(hash2.encode())
                        key = hash_reconstruct(session['hash1'], hash2)
                        collection_key = database.get_collection_key(
                            collection_id, session['user_id'], key)
                        response = await minio.download_file(database.get_collection_name(collection_id), path, True, SseCustomerKey(collection_key), session['jwt_token'], range_header=request.headers.get('Range'))
                        return response
                except Exception:
                    if request.method == 'HEAD':
                        return Response(headers={"Content-Type": "text/html; charset=utf-8", 'Content-Length': '0', 'Location': f'/{quote(path.strip('/'))}/'}, status_code=301)

            files = await minio.get_list_files(database.get_collection_name(collection_id), path, False, session['jwt_token'])
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
    session = await web_sessions.get_session(token[:32])
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        files = files.split('|')
        if access_type in access:
            await minio.delete_files(database.get_collection_name(collection_id), files, session['jwt_token'])
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
    session = await web_sessions.get_session(token)
    if session:
        if database.get_type_access(request.source_collection_id, session['user_id']) in access and database.get_type_access(request.destination_collection_id, session['user_id']) in access_dest:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            source_collection_key = database.get_collection_key(
                request.source_collection_id, session['user_id'], key)
            destination_collection_key = database.get_collection_key(
                request.destination_collection_id, session['user_id'], key)
            await minio.copy_files(database.get_collection_name(request.source_collection_id), request.source_paths, database.get_collection_name(request.destination_collection_id), request.destination_path, SseCustomerKey(source_collection_key), SseCustomerKey(destination_collection_key), session['jwt_token'])
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
    session = await web_sessions.get_session(token)
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        if access_type in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.rename_file(database.get_collection_name(collection_id), request.path, request.new_name, SseCustomerKey(collection_key), session['jwt_token'])
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
    session = await web_sessions.get_session(token)
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        if access_type in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.new_folder(database.get_collection_name(collection_id), request.name, request.path, SseCustomerKey(collection_key), session['jwt_token'])
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
    session = await web_sessions.get_session(token)
    if session:
        access_type = database.get_type_access(
            collection_id, session['user_id'])
        if access_type in access:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.upload_file(database.get_collection_name(collection_id), file, path, SseCustomerKey(collection_key), session['jwt_token'], overwrite=access_type != 4)
            database.add_log(
                'upload', 200, {'file_name': file.filename, 'path': path}, user_id=session['user_id'], collection_id=collection_id)
            await create_metadata(collection_id, database.get_collection_name(
                collection_id), jwt_token=session['jwt_token'], encryption_key=database.get_collection_key(collection_id, session['user_id'], key))
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
    username = credentials.username.strip('/')
    if username.find('/') == -1:
        org = 'default'
    else:
        username, org = credentials.username.split(
            '/')[0], credentials.username.split('/')[-1]
    if org == 'default' or org == '':
        credentials.username = username
    response = await httpx.AsyncClient(verify=not config.debug_mode).post(
        f'{config.auth_api_url}/login?org={org}',
        auth=(username, credentials.password)
    )
    if response.status_code == 200:
        jwt_token = response.json()
        user_id = database.get_user_id(credentials.username)
        if user_id is None:
            user_id = database.add_user(
                credentials.username, credentials.password)
            database.add_log(
                'new_user', 200, {'login': credentials.username}, user_id=user_id)
    else:
        database.add_log(
            'auth', 401, {'login': credentials.username}, user_id=None)
        raise HTTPException(
            status_code=401,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    key = hash_argon2_from_password(credentials.password)
    hash1, hash2 = hash_division(key)
    token = secrets.token_urlsafe(24)[:32]
    await web_sessions.add_session(
        token, hash1, user_id, jwt_token)
    hash2 = base64.urlsafe_b64encode(hash2).decode()

    await create_policy_to_user(username, database.get_collections(user_id))

    database.add_log(
        'auth', 200, {'login': credentials.username}, user_id=user_id)
    return {
        'token': token + hash2,
        'user_id': user_id,
        'username': credentials.username,
    }


@app.get('/check_session')  # safe+
async def check(token: str) -> dict[str, int | bool]:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        await create_policy_to_user(database.get_username(user_id),
                                    database.get_collections(user_id))
        return {'authenticated': True, 'user_id': user_id}
    raise HTTPException(status_code=401, detail='Token not found')


@app.get('/delete_session')  # safe+
async def check(token: str) -> bool:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        await web_sessions.delete_session(token[:32])
        return True
    else:
        return False


@app.post('/create_collection')  # safe+ logs+
async def create_collection(request: CreateCollectionRequest):
    session = await web_sessions.get_session(request.token[:32])
    if session:
        try:
            await minio.create_bucket(request.name, session['jwt_token'])
            collection_id = database.create_collection(
                request.name, session['user_id'])
            database.add_log('create_collection', 200,
                             {'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
            await create_policy_to_user(database.get_username(
                session['user_id']), database.get_collections(session['user_id']))
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
    hash1, user_id = await web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        try:
            database.give_access_user_to_collection(
                request.collection_id, user_id, request.user_id, request.access_type_id, key)
            database.add_log('give_access_user_to_collection',
                             200, {'access_type_id': request.access_type_id}, user_id=user_id, collection_id=request.collection_id)
            await create_policy_to_user(database.get_username(request.user_id),
                                        database.get_collections(request.user_id))
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
    user_id = await web_sessions.get_user_id(token)
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
    hash1, user_id = await web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        try:
            access_id = database.give_access_group_to_collection(
                request.collection_id, user_id, request.group_id, request.access_type_id, key)
            database.add_log('give_access_group_to_collection',
                             200, {'access_id': access_id}, user_id=user_id, group_id=request.group_id, collection_id=request.collection_id)
            for user in database.get_group_users(request.group_id, user_id):
                await create_policy_to_user(
                    user['username'], database.get_collections(user['id']))
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
    hash1, user_id = await web_sessions.get_hash1_and_user_id(token)
    if user_id:
        hash2 = base64.urlsafe_b64decode(hash2.encode())
        key = hash_reconstruct(hash1, hash2)
        try:
            database.add_user_to_group(
                request.group_id, user_id, request.user_id, request.role_id, key)
            database.add_log('add_user_to_group', 200,
                             {'role_id': request.role_id, 'user_id': request.user_id}, user_id=user_id, group_id=request.group_id)
            await create_policy_to_user(database.get_username(request.user_id),
                                        database.get_collections(request.user_id))
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_groups(user_id)


@app.delete('/remove_collection')  # safe+ logs+
async def remove_collection(token: str, collection_id: int):
    session = web_sessions.get_session(token[:32])
    if session:
        collection_name = database.get_collection_name(collection_id)
        try:
            await minio.remove_bucket(database.get_collection_name(collection_id), session['jwt_token'])
        except HTTPException as error:
            database.add_log('remove_collection', error.status_code, {
                             'error': error.detail, 'collection_id': collection_id, 'collection_name': collection_name}, user_id=session['user_id'])
            if error.status_code != 410:
                raise error
        database.remove_collection(collection_id, session['user_id'])
        database.add_log('remove_collection', 200, {
                         'collection_id': collection_id, 'collection_name': collection_name}, user_id=session['user_id'])
        await create_policy_to_user(database.get_username(
            session['user_id']), database.get_collections(session['user_id']))
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_other_users')  # safe+
async def get_other_users(token: str) -> list | None:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_other_users(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_access_to_collection')  # safe+
async def get_access_to_collection(token: str, collection_id: int) -> list | None:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_access_to_collection(collection_id, user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.delete('/delete_access_to_collection')  # safe+ logs+
async def delete_access_to_collection(token: str, access_id: int) -> list | None:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        try:
            access_info = database.get_access_info(access_id)
            database.delete_access_to_collection(access_id, user_id)
            database.add_log('delete_access_to_collection', 200, {
                             'access_id': access_id}, user_id=user_id)
            if access_info['user_id'] is not None:
                await create_policy_to_user(database.get_username(access_info['user_id']),
                                            database.get_collections(access_info['user_id']))
            elif access_info['group_id'] is not None:
                for user in database.get_group_users(access_info['group_id'], user_id):
                    await create_policy_to_user(
                        user['username'], database.get_collections(user['id']))
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
    req_user_id = await web_sessions.get_user_id(token[:32])
    if req_user_id:
        try:
            database.delete_user_to_group(group_id, user_id, req_user_id)
            database.add_log('delete_user_to_group', 200, {
                             'user_id': user_id}, user_id=req_user_id, group_id=group_id)
            await create_policy_to_user(database.get_username(
                user_id), database.get_collections(user_id))
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_group_users(group_id, user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_access_types')  # safe+
async def get_access_types(token: str) -> list | None:
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_access_types()
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/transfer_power_to_group')  # safe+
async def transfer_power_to_group(token: str, group_id: int, user_id: int):
    owner_user_id = await web_sessions.get_user_id(token[:32])
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        try:
            database.delete_user_to_group(group_id, user_id, user_id)
            database.add_log('exit_group', 200, {},
                             user_id=user_id, group_id=group_id)
            await create_policy_to_user(database.get_username(user_id),
                                        database.get_collections(user_id))
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
    owner_user_id = await web_sessions.get_user_id(token[:32])
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_user_info(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.post('/change_access_type')  # safe+ logs+
async def change_access_type(token: str, access_id: int, access_type_id: int):
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        try:
            database.change_access_type(access_id, user_id, access_type_id)
            database.add_log('change_access_type', 200, {'access_id': access_id, 'access_type_id': access_type_id},
                             user_id=user_id)
            access_info = database.get_access_info(access_id)
            if access_info['user_id'] is not None:
                await create_policy_to_user(database.get_username(access_info['user_id']),
                                            database.get_collections(access_info['user_id']))
            elif access_info['group_id'] is not None:
                for user in database.get_group_users(access_info['group_id'], user_id):
                    await create_policy_to_user(
                        user['username'], database.get_collections(user['id']))
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
    user_id = await web_sessions.get_user_id(request.token[:32])
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        return database.get_logs(user_id)
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/get_history_collection')  # safe+
async def get_history_collection(token: str, collection_id: int) -> list:
    user_id = await web_sessions.get_user_id(token[:32])
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        if database.get_type_access(collection_id, user_id) in access:
            try:
                await opensearch.update_document(collection_id, data)
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
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        if database.get_type_access(collection_id, user_id) in access:
            try:
                return await opensearch.get_document(collection_id)
            except Exception as error:
                database.add_log('get_collection_info', 500, {'error': str(
                    error)}, user_id=user_id, collection_id=collection_id)
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


# safe+ logs+
@app.get('/collections/{collection_id}/file_info/{token}/{path:path}')
async def get_file_info(token: str, collection_id: int, path: str):
    access = [1, 2, 3, 4]
    user_id = await web_sessions.get_user_id(token[:32])
    if user_id:
        if database.get_type_access(collection_id, user_id) in access:
            try:
                return await opensearch.get_document(f'{collection_id}/{path.strip('/')}', config.open_search_files_index)
            except Exception as error:
                database.add_log('get_file_info', 500, {'error': str(
                    error), 'path': path}, user_id=user_id, collection_id=collection_id)
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


@app.get('/search_collections')  # safe+ logs+
async def search_collection(text: str, token: str) -> list:
    if token is not None:
        session = await web_sessions.get_session(token[:32])
        # Тут специально нет проверки user_id
        try:
            collections = []
            documents = await opensearch.search_documents(text, jwt_token=session['jwt_token'])
            for document in documents:
                collection = database.get_specific_access_to_all_collections(
                    session['user_id'], [document['_id']])
                if len(collection) > 0:
                    collection[0]['index'] = document['_source']
                    collections.append(collection[0])
            return collections
        except Exception as error:
            database.add_log('search_collection_info', 500, {'error': str(
                error), 'text': text}, user_id=session['user_id'])
            raise HTTPException(
                status_code=500,
                detail=''
            )
    else:
        raise HTTPException(
            status_code=401,
            detail='Token invalid'
        )


@app.get('/search_collection_files')  # safe+ logs+
async def search_collection(text: str, token: str = None) -> list:
    if token is not None:
        user_id = await web_sessions.get_user_id(token[:32])
    else:
        user_id = None
    # Тут специально нет проверки user_id
    try:
        files = []
        documents = await opensearch.search_documents(text, index_name=config.open_search_files_index)
        for document in documents:
            files.append(document['_source'])
        return files
    except Exception as error:
        database.add_log('search_collection_files', 500, {'error': str(
            error), 'text': text}, user_id=user_id)
        raise HTTPException(
            status_code=500,
            detail=''
        )


@app.post('/change_access_to_all')  # safe+ logs+
async def change_access_to_all(token: str, collection_id: int, is_access: bool):
    token, hash2 = token[:32], token[32:]
    session = await web_sessions.get_session(token)
    if session:
        if database.get_type_access(collection_id, session['user_id']) == 1:
            hash2 = base64.urlsafe_b64decode(hash2.encode())
            key = hash_reconstruct(session['hash1'], hash2)
            try:
                database.change_access_to_all(
                    session['user_id'], collection_id, is_access, key)
                database.add_log('change_access_to_all', 200, {'is_access': is_access},
                                 user_id=session['user_id'], collection_id=collection_id)
                await create_policy_to_all(
                    database.get_absolute_access_to_all_collections())
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
