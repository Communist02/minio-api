from sqlalchemy import DATE, VARCHAR, Column, BINARY, INT, ForeignKey, TEXT
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import create_engine, select, insert
import secrets
import crypt


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'

    id = Column(INT, primary_key=True, autoincrement=True)
    login = Column(VARCHAR(25), nullable=False)
    fio = Column(VARCHAR(140))
    email = Column(VARCHAR(50))
    job_position = Column(VARCHAR(50))
    phone = Column(VARCHAR(50))
    password_hash = Column(BINARY(32), nullable=False)
    encrypted_private_key = Column(BINARY(48), nullable=False)
    public_key = Column(BINARY(32), nullable=False)


class Project(Base):
    __tablename__ = 'projects'

    id = Column(INT, primary_key=True, autoincrement=True)
    title = Column(VARCHAR(255), nullable=False)
    description = Column(TEXT, nullable=False)
    start_date = Column(DATE)
    finish_date = Column(DATE)
    encrypted_private_key = Column(BINARY(48), nullable=False)
    public_key = Column(BINARY(32), nullable=False)


class AccessType(Base):
    __tablename__ = 'grant_types'

    id = Column(INT, primary_key=True)
    name = Column(VARCHAR(255), nullable=False)


class ResourceType(Base):
    __tablename__ = 'resource_types'

    id = Column(INT, primary_key=True, autoincrement=True)
    name = Column(VARCHAR(20), nullable=False)


class AccessCollections(Base):
    __tablename__ = 'access_collections'

    id = Column(INT, primary_key=True, autoincrement=True)
    collection_id = Column(INT, nullable=False)
    encrypted_key = Column(BINARY(92), nullable=False)
    # type_id = Column(ForeignKey(AccessType.id), nullable=False)
    user_id = Column(ForeignKey(User.id), nullable=False)
    project_id = Column(ForeignKey(Project.id), nullable=True)


class Collection(Base):
    __tablename__ = 'collections'

    id = Column(INT, primary_key=True, autoincrement=True)
    name = Column(VARCHAR(255), nullable=False)
    encrypted_key = Column(BINARY(92), nullable=False)
    user_id = Column(ForeignKey(User.id), nullable=True)
    owner_id = Column(ForeignKey(AccessCollections.id), nullable=True)
    resource_type_id = Column(ForeignKey(ResourceType.id), nullable=True)


class UserRole(Base):
    __tablename__ = 'user_roles'

    id = Column(INT, primary_key=True)
    name = Column(VARCHAR(20))


class ProjectUser(Base):
    __tablename__ = 'project_users'

    user_id = Column(ForeignKey(User.id), primary_key=True)
    project_id = Column(ForeignKey(Project.id), primary_key=True)
    role_id = Column(ForeignKey(UserRole.id), nullable=False)
    add_date = Column(DATE, nullable=False)
    exit_date = Column(DATE)
    encrypted_private_key = Column(BINARY(32), nullable=False)


class MainBase:
    def __init__(self):
        self.engine = create_engine(
            'mariadb+pymysql://root:root@localhost/main?charset=utf8mb4')
        self.connection = self.engine.connect()
        Base.metadata.create_all(self.engine)

    def add_user(self, login: str, password: str):
        private_key, public_key = crypt.random_key_pair()
        hash = crypt.hash_argon2_from_password(password)
        encrypted_private_key = crypt.sym_encrypt_key(private_key, hash)

        with Session(self.engine) as session:
            query = insert(User).values(
                login=login, encrypted_private_key=encrypted_private_key, public_key=public_key, password_hash=hash)
            session.execute(query)
            session.commit()

    def add_collection(self, name: str, user_id: int) -> int:
        collection_key = secrets.token_bytes(32)
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            public_key = session.execute(query).scalar_one()

            encrypted_key = crypt.asym_encrypt_key(collection_key, public_key)
            query = insert(Collection).values(
                name=name, user_id=user_id, encrypted_key=encrypted_key).returning(Collection.id)
            result = session.execute(query).scalar_one()
            session.commit()
            return result

    def get_collection_key(self, collection_id: int, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            query = select(User.encrypted_private_key).where(
                User.id == user_id)
            encrypted_private_key = session.execute(query).scalar_one()
            private_key = crypt.sym_decrypt_key(encrypted_private_key, key)
            query = select(Collection.encrypted_key).where(
                Collection.id == collection_id)
            encrypted_key = session.execute(query).scalar_one()
            collection_key = crypt.asym_decrypt_key(encrypted_key, private_key)
            return collection_key

    def get_user_id(self, login: str, password: str) -> int:
        with Session(self.engine) as session:
            query = select(User.id).where(User.login == login)
            user_id = session.execute(query).scalar()
            return user_id

    def get_collections(self, user_id: int) -> list:
        result = []
        with Session(self.engine) as session:
            query = select(Collection.id).where(Collection.user_id == user_id)
            collections = session.execute(query).all()
            for collection in collections:
                result.append(f'{collection[0]:03}')
            return result

    def get_access_collections(self, user_id: int) -> list:
        result = []
        with Session(self.engine) as session:
            query = select(AccessCollections.collection_id).where(AccessCollections.user_id == user_id)
            collections = session.execute(query).all()
            for collection in collections:
                result.append(f'{collection[0]:03}')
            return result

    def get_public_key(self, user_id: int) -> bytes:
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            return session.execute(query).scalar_one()

    def give_access(self, collection_id: int, owner_user_id: int, access_user_id: int, key: bytes) -> int:
        collection_key = self.get_collection_key(
            collection_id, owner_user_id, key)
        public_key = self.get_public_key(access_user_id)
        encrypted_key = crypt.asym_encrypt_key(collection_key, public_key)

        with Session(self.engine) as session:
            query = insert(AccessCollections).values(collection_id=collection_id,
                                                    user_id=access_user_id, encrypted_key=encrypted_key).returning(AccessCollections.id)
            result = session.execute(query).scalar_one()
            session.commit()
            return result
