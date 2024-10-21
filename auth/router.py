from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from auth import schema
from database import get_async_session
from auth import service

router = APIRouter()


@router.post("/register", tags=["auth"])
async def register_user(user: schema.CreateUser, session: AsyncSession = Depends(get_async_session)):
    if await service.get_user_by_email(session, user.email):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User exists')

    if not await service.create_user(session, user):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    return user
