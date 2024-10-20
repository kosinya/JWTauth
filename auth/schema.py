from datetime import date

from pydantic import BaseModel


class UserBase(BaseModel):
    name: str
    email: str
    date_of_birth: date
    is_admin: bool
    is_active: bool


class CreateUser(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        from_attributes = True
