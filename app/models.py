import bcrypt
import re
import uuid

from sqlalchemy import Column, ForeignKey, Index, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import validates

from app.database import Base


class SelfCommittingObject(object):
    def __init__(self, db_session=None):
        if db_session:
            db_session.add(self)
            db_session.commit()


class User(SelfCommittingObject, Base):
    __tablename__ = 'users'

    NAME_MIN_LENGTH = 3
    NAME_MAX_LENGTH = 20
    NAME_REGEX = re.compile(r'^[a-zA-Z0-9]+$')

    PASSWORD_MIN_LENGTH = 8

    id = Column(Integer, primary_key=True)
    name = Column(String(20), unique=True, index=True, nullable=False)
    password = Column(String(60), nullable=False)

    def __init__(self, name, clear_text_password, **kwargs):
        self.name = name

        if len(clear_text_password) < self.PASSWORD_MIN_LENGTH:
            raise AssertionError

        self.password = bcrypt.hashpw(clear_text_password.encode(), bcrypt.gensalt())

        SelfCommittingObject.__init__(self, **kwargs)

    def is_valid_password(self, clear_text_password):
        return bcrypt.checkpw(clear_text_password.encode(), self.password)

    # we already check through the JSON schema, but can't hurt to validate
    # prior to saving too
    @validates('name')
    def _validate_name(self, _key, name):
        if len(name) < self.NAME_MIN_LENGTH or len(name) > self.NAME_MAX_LENGTH \
                or not self.NAME_REGEX.match(name):
            raise AssertionError

        return name


class UserToken(SelfCommittingObject, Base):
    __tablename__ = 'user_tokens'

    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    # to prevent timing attacks, a token is made of 2 UUIDs concatenated
    # that way we can query the DB for the 1st token (the prefix)
    # then do a slow comparison for the second half
    # as to making it a primary key, sqlalchemy does need a primary key to be
    # present, and we shouldn't have collisions anyway - those are UUIDs
    prefix = Column(LargeBinary(16), primary_key=True)
    suffix = Column(LargeBinary(16))

    def __init__(self, user, **kwargs):
        self.user_id = user.id
        self.prefix = uuid.uuid4().bytes
        self.suffix = uuid.uuid4().bytes

        SelfCommittingObject.__init__(self, **kwargs)

    def __str__(self):
        return UserToken._bytes_to_string(self.prefix) + UserToken._bytes_to_string(self.suffix)

    @classmethod
    def get_user_id_with_token(cls, string_token, db_session):
        '''
        Returns the user ID corresponding to the given token, or `None` if the token
        is invalid
        '''
        if not string_token or len(string_token) != 64:
            return

        try:
            prefix = uuid.UUID(string_token[:32])
            candidate = db_session.query(cls).filter(cls.prefix == prefix.bytes).first()

            if not candidate:
                return

            suffix = uuid.UUID(string_token[-32:])
            if cls._slow_compare(bytearray(suffix.bytes), bytearray(candidate.suffix)):
                return candidate.user_id
        except ValueError:
            # notably happens if the token is not the result of the
            # concatenation of two valid UUIDs
            pass

    @staticmethod
    def _slow_compare(a, b):
        result = 0

        for i in range(len(a)):
            result = (a[i] ^ b[i]) | result

        return result == 0

    @staticmethod
    def _bytes_to_string(bytes):
        return str(uuid.UUID(bytes=bytes)).replace('-', '')


class File(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(255), nullable=False)
    content_type = Column(String(255))
    data = Column(LargeBinary())

    __table_args__ = (UniqueConstraint('user_id', 'name'),
                      Index('user_id_name_idx', 'user_id', 'name'))

    def __init__(self, user_id, name, content_type, data, **kwargs):
        self.user_id = user_id
        self.name = name
        self.content_type = content_type
        self.data = data
