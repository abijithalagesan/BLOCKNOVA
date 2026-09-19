from fastapi import FastAPI
from api.routes import router

app = FastAPI(title="BlockNova", version="0.1.0")
app.include_router(router)
