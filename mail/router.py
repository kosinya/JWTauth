from mail import service
from mail.schema import EmailSchema

from fastapi import APIRouter

router = APIRouter()


@router.post('/send_code', tags=['mail'])
async def send_code(email: EmailSchema):
    return await service.send_email(email)
