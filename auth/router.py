from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from auth import schema
from database import get_async_session
from auth import service

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/jwt/login")


@router.post("/register", tags=["auth"])
async def register_user(user: schema.CreateUser, session: AsyncSession = Depends(get_async_session)):
    if await service.get_user_by_email(session, user.email):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User exists')

    if not await service.create_user(session, user):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    return schema.User(name=user.name,
                       email=user.email,
                       date_of_birth=user.date_of_birth,
                       is_active=user.is_active,
                       is_admin=user.is_admin)


@router.post("/login", tags=["auth"])
async def login_user(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: AsyncSession = Depends(get_async_session)):
    return await service.login_user(session, form_data.username, form_data.password)


@router.get('/get_current_user', tags=["auth"])
async def get_current_user(token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_async_session)):
    return await service.get_current_user(token, session)
