from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import auth
from app.container import container
from app.services.exceptions import ServiceError
from routers import attachments, incidents, ops, telegram


@asynccontextmanager
async def lifespan(_app: FastAPI):
    container.init_db()
    yield


app = FastAPI(title="ИС учета и реагирования на инциденты ИБ", lifespan=lifespan)


@app.exception_handler(ServiceError)
async def service_error_handler(_request: Request, exc: ServiceError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(ops.router)
app.include_router(telegram.router)
app.include_router(attachments.router)
