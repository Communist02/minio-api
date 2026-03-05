import base64
import httpx
import config


async def get_session(token: str) -> dict | None:
    async with httpx.AsyncClient(verify=not config.debug_mode) as client:
        response = await client.get(
            f'{config.auth_api_url}/introspect',
            headers={'Authorization': f'Beaver {token[:32]}'},
        )
    if response.status_code == 200:
        session = response.json()
        if session['active'] == True:
            session['hash1'] = base64.urlsafe_b64decode(
                session['hash1'].encode())
            session['hash2'] = base64.urlsafe_b64decode(token[32:].encode())
            session['jwt_token'] = session['jwt']
            return session


async def delete_session(token: str) -> None:
    async with httpx.AsyncClient(verify=not config.debug_mode) as client:
        response = await client.delete(
            f'{config.auth_api_url}/session',
            headers={"token": token},
        )
