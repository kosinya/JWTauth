from mail import service as mail_service
from auth import service as auth_service
from database import get_async_session

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession


router = APIRouter()


@router.post('/get_activation_code', tags=['mail'])
async def send_code(token: str = Depends(auth_service.oauth2_scheme), session: AsyncSession = Depends(get_async_session)):
    user = await auth_service.get_current_user(token, session)
    return await mail_service.send_activation_email(session, user.email)



