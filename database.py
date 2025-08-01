import cryptography
from sqlalchemy import VARCHAR, Column, BINARY, INT, ForeignKey, TEXT, delete
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import create_engine, select, insert
import secrets
import crypt


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'

    id = Column(INT, primary_key=True)
    login = Column(VARCHAR(25), nullable=False)
    # fio = Column(VARCHAR(140))
    # email = Column(VARCHAR(50))
    # job_position = Column(VARCHAR(50))
    # phone = Column(VARCHAR(50))
    # password_hash = Column(BINARY(32), nullable=False)
    encrypted_private_key = Column(BINARY(48), nullable=False)
    public_key = Column(BINARY(32), nullable=False)


class Group(Base):
    __tablename__ = 'groups'

    id = Column(INT, primary_key=True, autoincrement=True)
    title = Column(VARCHAR(255), nullable=False)
    description = Column(TEXT, nullable=False)
    # start_date = Column(DATE)
    # finish_date = Column(DATE)
    # encrypted_private_key = Column(BINARY(48), nullable=False)
    public_key = Column(BINARY(32), nullable=False)


class UserRole(Base):
    __tablename__ = 'user_roles'

    id = Column(INT, primary_key=True)
    name = Column(VARCHAR(20))


class GroupUser(Base):
    __tablename__ = 'group_users'

    user_id = Column(ForeignKey(User.id), primary_key=True)
    group_id = Column(ForeignKey(Group.id), primary_key=True)
    # role_id = Column(ForeignKey(UserRole.id), nullable=False)
    # add_date = Column(DATE, nullable=False)
    # exit_date = Column(DATE)
    encrypted_private_key = Column(BINARY(48), nullable=False)


class AccessType(Base):
    __tablename__ = 'access_types'

    id = Column(INT, primary_key=True)
    name = Column(VARCHAR(255), nullable=False)


class ResourceType(Base):
    __tablename__ = 'resource_types'

    id = Column(INT, primary_key=True, autoincrement=True)
    name = Column(VARCHAR(20), nullable=False)


class AccessToCollection(Base):
    __tablename__ = 'access_to_collections'

    id = Column(INT, primary_key=True, autoincrement=True)
    collection_id = Column(INT, nullable=False)
    encrypted_key = Column(BINARY(92), nullable=False)
    # type_id = Column(ForeignKey(AccessType.id), nullable=False)
    user_id = Column(ForeignKey(User.id), nullable=True)
    group_id = Column(ForeignKey(Group.id), nullable=True)


class Collection(Base):
    __tablename__ = 'collections'

    id = Column(INT, primary_key=True, autoincrement=True)
    name = Column(VARCHAR(255), nullable=False)
    encrypted_key = Column(BINARY(92), nullable=False)
    user_id = Column(ForeignKey(User.id), nullable=True)
    owner_id = Column(ForeignKey(AccessToCollection.id), nullable=True)
    resource_type_id = Column(ForeignKey(ResourceType.id), nullable=True)


class MainBase:
    def __init__(self):
        self.engine = create_engine(
            'mariadb+pymysql://root:root@localhost/main?charset=utf8mb4')
        self.connection = self.engine.connect()
        Base.metadata.create_all(self.engine)

    def add_user(self, user_id: int, login: str, password: str):
        private_key, public_key = crypt.random_key_pair()
        hash = crypt.hash_argon2_from_password(password)
        encrypted_private_key = crypt.sym_encrypt_key(private_key, hash)

        with Session(self.engine) as session:
            query = insert(User).values(id=user_id, login=login,
                                        encrypted_private_key=encrypted_private_key, public_key=public_key, password_hash=hash)
            session.execute(query)
            session.commit()

    def create_collection(self, name: str, user_id: int) -> int:
        collection_key = secrets.token_bytes(32)
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            public_key = session.execute(query).scalar_one()

            encrypted_key = crypt.asym_encrypt_key(collection_key, public_key)
            query = insert(Collection).values(
                name=name, user_id=user_id, encrypted_key=encrypted_key).returning(Collection.id)
            collection_id = session.execute(query).scalar_one()
            session.commit()
            return collection_id

    def create_group(self, user_id: int, title: str, description: str):
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            group_private_key, group_public_key = crypt.random_key_pair()
            query = insert(Group).values(
                title=title, description=description, public_key=group_public_key).returning(Group.id)
            group_id = session.execute(query).scalar_one()

            user_public_key = session.execute(query).scalar_one()
            encrypted_private_key = crypt.asym_encrypt_key(
                group_private_key, user_public_key)
            query = insert(GroupUser).values(
                user_id=user_id, group_id=group_id, encrypted_private_key=encrypted_private_key)
            session.execute(query).scalar_one()
            session.commit()

    def get_user_private_key(self, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            query = select(User.encrypted_private_key).where(
                User.id == user_id)
            encrypted_private_key = session.execute(query).scalar_one()
            private_key = crypt.sym_decrypt_key(encrypted_private_key, key)
            return private_key

    def get_collection_key(self, collection_id: int, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            user_private_key = self.get_user_private_key(user_id, key)
            try:
                query = select(Collection.encrypted_key).where(
                    Collection.id == collection_id)
                encrypted_key = session.execute(query).scalar_one()
                collection_key = crypt.asym_decrypt_key(
                    encrypted_key, user_private_key)
            except cryptography.exceptions.InvalidTag:
                query = select(AccessToCollection.encrypted_key).where(
                    AccessToCollection.collection_id == collection_id)
                encrypted_key = session.execute(query).scalar_one()
                collection_key = crypt.asym_decrypt_key(
                    encrypted_key, user_private_key)
            return collection_key

    def get_group_private_key(self, group_id: int, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            user_private_key = self.get_user_private_key(user_id, key)
            query = select(GroupUser.encrypted_private_key).where(
                GroupUser.id == group_id)
            encrypted_private_key = session.execute(query).scalar_one()
            group_private_key = crypt.asym_decrypt_key(
                encrypted_private_key, user_private_key)
            return group_private_key

    def get_user_id(self, login: str) -> int:
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
            return result + self.get_collections_accessed(user_id)

    def get_collections_accessed(self, user_id: int) -> list:
        result = []
        with Session(self.engine) as session:
            query = select(AccessToCollection.collection_id).where(
                AccessToCollection.user_id == user_id)
            collections = session.execute(query).all()
            for collection in collections:
                result.append(f'{collection[0]:03}')
            return result

    def get_user_public_key(self, user_id: int) -> bytes:
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            return session.execute(query).scalar_one()

    def get_group_public_key(self, group_id: int) -> bytes:
        with Session(self.engine) as session:
            query = select(Group.public_key).where(Group.id == group_id)
            return session.execute(query).scalar_one()

    def give_access_user_to_collection(self, collection_id: int, owner_user_id: int, access_user_id: int, key: bytes) -> int:
        collection_key = self.get_collection_key(
            collection_id, owner_user_id, key)
        user_public_key = self.get_user_public_key(access_user_id)
        collection_encrypted_key = crypt.asym_encrypt_key(
            collection_key, user_public_key)

        with Session(self.engine) as session:
            query = insert(AccessToCollection).values(collection_id=collection_id, user_id=access_user_id,
                                                      encrypted_key=collection_encrypted_key).returning(AccessToCollection.id)
            result = session.execute(query).scalar_one()
            session.commit()
            return result

    def give_access_group_to_collection(self, collection_id: int, user_id: int, group_id: int, key: bytes) -> int:
        collection_key = self.get_collection_key(
            collection_id, user_id, key)
        group_public_key = self.get_group_public_key(user_id)
        collection_encrypted_key = crypt.asym_encrypt_key(
            collection_key, group_public_key)

        with Session(self.engine) as session:
            query = insert(AccessToCollection).values(collection_id=collection_id, group_id=group_id,
                                                      encrypted_key=collection_encrypted_key).returning(AccessToCollection.id)
            result = session.execute(query).scalar_one()
            session.commit()
            return result

    def add_user_to_group(self, group_id: int, admin_user_id: int, new_user_id: int, key: bytes):
        group_private_key = self.get_group_private_key(
            group_id, admin_user_id, key)
        user_public_key = self.get_user_public_key(new_user_id)
        encrypted_group_private_key = crypt.asym_encrypt_key(
            group_private_key, user_public_key)

        with Session(self.engine) as session:
            query = insert(GroupUser).values(
                group_id=group_id, user_id=new_user_id, encrypted_private_key=encrypted_group_private_key)
            session.execute(query)
            session.commit()

    def delete_user_to_group(self, group_id: int, user_id: int):
        with Session(self.engine) as session:
            query = delete(GroupUser).where(GroupUser.user_id ==
                                            user_id & GroupUser.group_id == group_id)
            session.execute(query)
            session.commit()

    def delete_access_user_to_collection(self, collection_id: int, user_id: int):
        with Session(self.engine) as session:
            query = delete(AccessToCollection).where(
                AccessToCollection.user_id == user_id & AccessToCollection.collection_id == collection_id)
            session.execute(query)
            session.commit()

    def delete_access_group_to_collection(self, group_id: int, user_id: int):
        with Session(self.engine) as session:
            query = delete(AccessToCollection).where(
                AccessToCollection.user_id == user_id & AccessToCollection.group_id == group_id)
            session.execute(query)
            session.commit()
