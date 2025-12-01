from datetime import datetime, timedelta
from typing import Tuple
from sqlalchemy import BINARY, update, delete, String
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import select, insert
from crypt import hash_argon2_from_password


class Base(DeclarativeBase):
    pass


class WebSession(Base):
    __tablename__ = 'web_sessions'

    token: Mapped[bytes] = mapped_column(BINARY(32), primary_key=True)
    hash1: Mapped[bytes] = mapped_column(BINARY(32), nullable=False)
    user_id: Mapped[int] = mapped_column(nullable=False)
    created: Mapped[datetime] = mapped_column(nullable=False)
    last_used: Mapped[datetime] = mapped_column(nullable=False)
    jwt_token: Mapped[str] = mapped_column(String(1024), nullable=False)


class WebSessionsBase:
    def __init__(self):
        self.engine = create_async_engine(
            'mariadb+asyncmy://root:root@localhost/web_sessions?charset=utf8mb4',
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_size=10,
            max_overflow=20,
            echo=False,
        )

    async def initialize(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def update_last_used(self, token: bytes):
        async with AsyncSession(self.engine) as session:
            query = update(WebSession).where(WebSession.token ==
                                             token).values(last_used=datetime.now())
            await session.execute(query)
            await session.commit()

    async def remove_deprecation(self):
        async with AsyncSession(self.engine) as session:
            query = delete(WebSession).where((WebSession.last_used < datetime.now(
            ) - timedelta(days=3)) | (WebSession.created < datetime.now() - timedelta(days=30)))
            await session.execute(query)
            await session.commit()

    async def get_session(self, token: str) -> dict[str, str | int]:
        token = hash_argon2_from_password(token)
        await self.remove_deprecation()
        async with AsyncSession(self.engine) as session:
            query = select(WebSession.user_id, WebSession.hash1,
                           WebSession.jwt_token).where(WebSession.token == token)
            result = (await session.execute(query)).first()
            if result is None:
                return None
            result = result.tuple()
            if result is not None:
                await self.update_last_used(token)
                return {'user_id': result[0], 'hash1': result[1], 'jwt_token': result[2]}

    async def get_user_id(self, token: str) -> int | None:
        token = hash_argon2_from_password(token)
        await self.remove_deprecation()
        async with AsyncSession(self.engine) as session:
            query = select(WebSession.user_id).where(WebSession.token == token)
            user_id = (await session.execute(query)).scalar()
            if user_id is not None:
                await self.update_last_used(token)
            return user_id

    async def get_hash1(self, token: str) -> str | None:
        token = hash_argon2_from_password(token)
        await self.remove_deprecation()
        async with AsyncSession(self.engine) as session:
            query = select(WebSession.hash1).where(WebSession.token == token)
            hash1 = (await session.execute(query)).scalar()
            if hash1 is not None:
                await self.update_last_used(token)
            return hash1

    async def get_hash1_and_user_id(self, token: str) -> Tuple[bytes | int]:
        token = hash_argon2_from_password(token)
        await self.remove_deprecation()
        async with AsyncSession(self.engine) as session:
            query = select(WebSession.hash1, WebSession.user_id).where(
                WebSession.token == token)
            return await session.execute(query).first().tuple()

    async def add_session(self, token: str, hash1: bytes, user_id: str, jwt_token: str):
        token = hash_argon2_from_password(token)
        async with AsyncSession(self.engine) as session:
            query = insert(WebSession).values(
                token=token, hash1=hash1, user_id=user_id, created=datetime.now(), last_used=datetime.now(), jwt_token=jwt_token)
            await session.execute(query)
            await session.commit()

    async def delete_session(self, token: str) -> int | None:
        token = hash_argon2_from_password(token)
        async with AsyncSession(self.engine) as session:
            query = delete(WebSession).where(WebSession.token == token)
            await session.execute(query)
            await session.commit()

    async def close(self):
        if self.engine:
            await self.engine.dispose()
