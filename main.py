from contextlib import asynccontextmanager

from fastapi import FastAPI

import auth
from db import init_db
from routers import incidents, ops


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="ИС учета и реагирования на инциденты ИБ", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(ops.router)
