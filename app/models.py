import bcrypt
import re

from sqlalchemy import Column, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import validates

from database import Base


class User(Base):
    __tablename__ = 'users'

    NAME_MIN_LENGTH = 3
    NAME_MAX_LENGTH = 20
    NAME_REGEX = re.compile(r'^[a-zA-Z0-9]+$')

    PASSWORD_MIN_LENGTH = 8

    id = Column(Integer, primary_key=True)
    name = Column(String(20), unique=True, index=True, nullable=False)
    password = Column(String(60), nullable=False)

    def __init__(self, name, clear_text_password):
        self.name = name

        if len(clear_text_password) < self.PASSWORD_MIN_LENGTH:
            raise AssertionError

        self.password = bcrypt.hashpw(clear_text_password.encode(), bcrypt.gensalt())

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


class UserToken(Base):
    __tablename__ = 'user_tokens'

    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    # sqlalchemy does need a primary key to be present, and we shouldn't have
    # collisions anyway - those are UUIDs
    token = Column(String(16), primary_key=True)


class File(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(255), nullable=False)

    __table_args__ = (UniqueConstraint('user_id', 'name'),
                      Index('user_id_name_idx', 'user_id', 'name'))
