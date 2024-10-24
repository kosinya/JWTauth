from database import Base

from sqlalchemy import Column, String, Integer, Boolean


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer(), primary_key=True)
    name = Column(String(), nullable=False)
    date_of_birth = Column(String())
    email = Column(String(), unique=True, nullable=False)
    password = Column(String(), nullable=False)
    is_admin = Column(Boolean(), default=False, nullable=False)
    is_active = Column(Boolean(), default=False, nullable=False)
