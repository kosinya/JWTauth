import os
from typing import Optional

from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta, timezone

from jwt import InvalidTokenError
from sqlalchemy import select
from fastapi import HTTPException, status, Depends
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/jwt/login")


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


def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


async def create_user(session: AsyncSession, user: schema.CreateUser):
    hashed_password = get_password_hash(user.password)

    new_user = model.User(
        name=user.name,
        email=user.email,
        date_of_birth=user.date_of_birth.strftime("%d/%m/%Y"),
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


async def get_user_by_email(session: AsyncSession, email: str) -> Optional[schema.User]:
    result = await session.execute(select(model.User).filter_by(email=email))
    return result.scalars().first()


async def get_user_by_id(session: AsyncSession, id: int) -> Optional[schema.User]:
    result = await session.execute(select(model.User).filter_by(id=id))
    return result.scalars().first()


async def authenticate_user(session: AsyncSession, email: str, password: str):
    user = await get_user_by_email(session, email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


async def login_user(session: AsyncSession, email: str, password: str) -> dict:
    user = await authenticate_user(session, email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"id": user.id}, expires_delta=None)
    return {"access_token": access_token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme), session: AsyncSession = None):
    print(f"token {token}")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, ACCESS_SECRET, algorithms=[ALGORITHM])
        print(f"token {payload}")
        id = payload.get("id")
        if id is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = await get_user_by_id(session, id)
    if user is None:
        raise credentials_exception
    return user
