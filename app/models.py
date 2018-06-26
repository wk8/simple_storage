from sqlalchemy import Column, ForeignKey, Index, Integer, String, UniqueConstraint

from database import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(20), unique=True, index=True, nullable=False)
    password = Column(String(60), nullable=False)

    def __repr__(self):
        return '<User %r>' % (self.name)

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

    __table_args__ = (UniqueConstraint('user_id', 'name'), Index('user_id_name_idx', 'user_id', 'name'))
