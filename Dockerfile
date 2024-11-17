FROM python:3.9

RUN mkdir /fastapi_app

WORKDIR /fastapi_app

COPY req.txt .

RUN pip install  --no-cache-dir --upgrade -r req.txt

COPY . .

RUN alembic upgrade head

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]

