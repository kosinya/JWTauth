import os
import random
from typing import Optional

from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta, timezone

from jwt import InvalidTokenError, ExpiredSignatureError
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
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))
ALGORITHM = os.getenv("ALGORITHM")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/jwt/login")


def create_token(data: dict, expires_delta: timedelta = None):
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
        date_of_birth=user.date_of_birth,
        password=hashed_password,
        is_active=False,
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


async def get_user_by_id(session: AsyncSession, user_id: int):
    result = await session.execute(select(model.User).filter_by(id=user_id))
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

    access_token = create_token(data={"id": user.id},
                                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token(data={'id': user.id},
                                 expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


async def refresh_token(r_token: str):
    try:
        payload = jwt.decode(r_token, ACCESS_SECRET, algorithms=[ALGORITHM])
        user_id = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=403, detail="Could not validate credentials")
        new_access_token = create_token(data={"id": user_id},
                                        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": new_access_token, "token_type": "bearer"}
    except (ExpiredSignatureError, InvalidTokenError):
        raise HTTPException(status_code=403, detail="Could not validate credentials")


async def get_current_user(token: str = Depends(oauth2_scheme), session: AsyncSession = None):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, ACCESS_SECRET, algorithms=[ALGORITHM])
        user_id = payload.get("id")
        if user_id is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = await get_user_by_id(session, user_id)
    if user is None:
        raise credentials_exception
    return schema.User(id=user.id,
                       name=user.name,
                       email=user.email,
                       date_of_birth=user.date_of_birth,
                       is_active=user.is_active,
                       is_admin=user.is_admin)


async def create_confirmation_code(session: AsyncSession, email: str):
    user = await get_user_by_email(session, email)
    if not user:
        raise HTTPException(status_code=404, detail=f"User with email {email} not found")

    if user.is_active:
        raise HTTPException(status_code=403, detail="User is already active")

    alphabet = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    code = ""
    for i in range(6):
        code += random.choice(alphabet)

    check = await session.execute(select(model.Activation).filter_by(user_email=email))
    if check.scalars().first():
        await session.delete(check.scalars().first())

    new_code = model.Activation(
        user_email=email,
        code=code,
        expiration_date=(datetime.now() + timedelta(minutes=10)).timestamp()
    )

    session.add(new_code)
    try:
        await session.commit()
    except Exception as e:
        await session.rollback()
        print(e)

    return code


async def user_activation(session: AsyncSession, user, code: str):
    activation = await session.execute(select(model.Activation).filter_by(user_email=user.email))
    res = activation.scalars().first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Activation code not found")

    if res.code == code:
        if res.expiration_date < str(datetime.now().timestamp()):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Activation code expired")

        user = await get_user_by_email(session, user.email)
        user.is_active = True
        session.add(user)
        try:
            await session.commit()
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Activation code invalid")

    return True
