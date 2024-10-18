import os
from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
import jwt

from auth import schema
from auth import model

load_dotenv()
ACCESS_SECRET = os.getenv("ACCESS_TOKEN_SECRET")
ALGORITHM = os.getenv("ALGORITHM")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=10)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, ACCESS_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def create_user(session: AsyncSession, user: schema.User):
    hashed_password = get_password_hash(user.password)

    new_user = model.User(
        name=user.name,
        email=user.email,
        date_of_birth=user.date_of_birth,
        password=hashed_password,
        is_active=True,
        is_admin=False,
    )

    session.add(new_user)
    try:
        await session.commit()
        return True
    except Exception as e:
        await session.rollback()
        print(e)
        return False
