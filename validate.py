from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import sessions

security = HTTPBearer()


async def validate_token(token: str) -> dict | None:
    """
    Проверяет токен через сервис авторизации.
    Возвращает данные пользователя или None.
    """
    return await sessions.get_session(token)


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
