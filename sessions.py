from datetime import datetime
from typing import Any
from sqlalchemy import VARCHAR, Column, VARBINARY, DATETIME
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import create_engine, select, insert


class Base(DeclarativeBase):
    pass


class WebSession(Base):
    __tablename__ = 'web_sessions'

    token = Column(VARCHAR(22), primary_key=True)
    hash1 = Column(VARBINARY(32), nullable=False)
    created = Column(DATETIME, nullable=False)


class WebSessionsBase:
    def __init__(self):
        self.engine = create_engine('mariadb+pymysql://root:root@localhost/web_sessions?charset=utf8mb4')
        self.connection = self.engine.connect()
        Base.metadata.create_all(self.engine)

    def check_token(self, token: str) -> str | None:
        with Session(self.engine) as session:
            query = select(WebSession.hash1).where(WebSession.token == token)
            result = session.execute(query).all()
            if len(session.execute(query).all()) > 0:
                return result[0][0]

    def add_session(self, token: str, hash1: bytes):
        with Session(self.engine) as session:
            query = insert(WebSession).values(
                token=token, hash1=hash1, created=datetime.now())
            session.execute(query)
            session.commit()
