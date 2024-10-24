from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from starlette.responses import JSONResponse
from mail.schema import EmailSchema


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


async def send_email(email: EmailSchema):
    template = f"""
        <html>
            <body>
                <p>Добро пожаловать!</p>
            </body>
        </html>
    """

    message = MessageSchema(
        subject="Fastapi-Mail module",
        recipients=email.dict().get("email"),
        body=template,
        subtype="html"
    )

    try:
        await fm.send_message(message)
        return JSONResponse({"status": "success"})
    except Exception as e:
        return JSONResponse({"status": "failed", "error": str(e)})
