from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from auth import schema
from database import get_async_session
from auth import service

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/jwt/login")


@router.post("/register", tags=["auth"])
async def register_user(user: schema.CreateUser, session: AsyncSession = Depends(get_async_session)):
    if await service.get_user_by_email(session, user.email):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User exists')

    if not await service.create_user(session, user):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    return user


@router.post("/login", tags=["auth"])
async def login_user(email: str, password: str, session: AsyncSession = Depends(get_async_session)):
    return await service.login_user(session, email, password)


@router.get('/get_current_user', tags=["auth"])
async def get_current_user(token: str = Depends(oauth2_scheme)):
    return {'token': token}
