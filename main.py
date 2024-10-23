import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth.router import router

app = FastAPI()
origins = ['*']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "Access-Control-Request-Headers", "Access-Control-Allow-Headers"],
)
app.include_router(router, prefix="/auth/jwt")


@app.get('/')
async def welcome():
    return {"message": "Welcome to JWTauth"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
