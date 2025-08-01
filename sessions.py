from datetime import datetime
from typing import Tuple
from sqlalchemy import BINARY, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy import create_engine, select, insert
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


class WebSessionsBase:
    def __init__(self):
        self.engine = create_engine(
            'mariadb+pymysql://root:root@localhost/web_sessions?charset=utf8mb4')
        self.connection = self.engine.connect()
        Base.metadata.create_all(self.engine)

    def update_last_used(self, token: bytes):
        with Session(self.engine) as session:
            query = update(WebSession).where(WebSession.token ==
                                             token).values(last_used=datetime.now())
            session.execute(query)
            session.commit()

    def get_user_id(self, token: str) -> int | None:
        token = hash_argon2_from_password(token)
        with Session(self.engine) as session:
            query = select(WebSession.user_id).where(WebSession.token == token)
            user_id = session.execute(query).scalar()
            if user_id is not None:
                self.update_last_used(token)
            return user_id

    def get_hash1(self, token: str) -> str | None:
        with Session(self.engine) as session:
            query = select(WebSession.hash1).where(WebSession.token == token)
            hash1 = session.execute(query).scalar()
            if hash1 is not None:
                self.update_last_used(token)
            return hash1

    def get_hash1_and_user_id(self, token: str) -> Tuple[bytes, int]:
        token = hash_argon2_from_password(token)
        with Session(self.engine) as session:
            query = select(WebSession.hash1, WebSession.user_id).where(
                WebSession.token == token)
            return session.execute(query).first().tuple()

    def add_session(self, token: str, hash1: bytes, user_id: str):
        token = hash_argon2_from_password(token)
        with Session(self.engine) as session:
            query = insert(WebSession).values(
                token=token, hash1=hash1, user_id=user_id, created=datetime.now(), last_used=datetime.now())
            session.execute(query)
            session.commit()
