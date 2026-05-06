import base64
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx
from config import config


security = HTTPBearer()


async def validate_token(token: str) -> dict | None:
    """
    Проверяет токен через сервис авторизации.
    Возвращает данные пользователя или None.
    """
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


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """
    Зависимость для получения текущего пользователя.
    Используется в защищенных маршрутах.
    """
    token = credentials.credentials

    # Проверяем формат (опционально)
    if not token or len(token) < 32:
        raise HTTPException(
            status_code=401,
            detail="Invalid token format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Валидируем токен
    user_data = await validate_token(token)

    if not user_data:
        raise HTTPException(
            status_code=401,
            detail="Token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user_data
