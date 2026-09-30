from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.auth import authenticate_static_token, issue_session, require_session
from app.db import db_connection
from app.errors import ApiError
from app.models import AccountResponse, TokenResponse


router = APIRouter(prefix="/v1/auth")


@router.post("/token")
def create_session(request: Request) -> JSONResponse:
    account_id, login_name = authenticate_static_token(request)
    access_token, expires_in = issue_session(account_id)
    response = TokenResponse(
        account=AccountResponse(githubId=account_id, login=login_name),
        accessToken=access_token,
        expiresIn=expires_in,
    )
    return JSONResponse(content=response.model_dump())


@router.delete("/session", status_code=204)
def delete_session(request: Request) -> Response:
    session = require_session(request)
    with db_connection() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE access_token = ?", (session.access_token,)
        )
    return Response(status_code=204)
