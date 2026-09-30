from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.db import initialize_database
from app.errors import ApiError, api_error_handler
from app.routes import auth, capabilities, vault


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


app = FastAPI(
    title="OpenLess Self-Hosted Sync Server",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_exception_handler(ApiError, api_error_handler)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _request: Request, _error: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"code": "invalid_request", "message": "request validation failed"},
    )


app.include_router(capabilities.router)
app.include_router(auth.router)
app.include_router(vault.router)
