from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse
from fastapi import status
from mail.schema import EmailSchema

from auth import service


config = ConnectionConfig(
    MAIL_USERNAME="ko.sinya@yandex.ru",
    MAIL_PASSWORD="crqjiqprgkrztxgn",
    MAIL_FROM="ko.sinya@yandex.ru",
    MAIL_PORT=465,
    MAIL_SERVER="smtp.yandex.ru",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False
)

fm = FastMail(config)


async def send_email_message(email: str, template: str):

    message = MessageSchema(
        subject="Fastapi-Mail module",
        recipients=[email],
        body=template,
        subtype="html"
    )

    try:
        await fm.send_message(message)
        return True
    except Exception as e:
        raise e


async def send_activation_email(session: AsyncSession, email: str):
    code = await service.create_confirmation_code(session, email)

    template = f"""
        <html><body>
            <p>Приветствуем, дорогой пользователь!</p>
            <p>Код для подтверждения почты и активации аккаунта: {code}</p>
        </body></html>
    """

    if await send_email_message(email, template):
        return JSONResponse(status_code=status.HTTP_200_OK, content={"success": True})
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"success": False})
