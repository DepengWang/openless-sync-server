import hashlib
import sqlite3
import secrets
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Request

from app.config import SESSION_TTL_SECONDS
from app.db import db_connection, iso_utc, utc_now
from app.errors import ApiError


@dataclass(frozen=True)
class SessionContext:
    account_id: str
    access_token: str


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer_token(request: Request, failure_message: str = "session expired or invalid") -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.casefold() != "bearer" or not token.strip():
        raise ApiError(401, "unauthenticated", failure_message)
    return token.strip()


def authenticate_static_token(request: Request) -> tuple[str, str]:
    token = bearer_token(request, "invalid token")
    with db_connection() as connection:
        row = connection.execute(
            """
            SELECT account_id, login_name
            FROM accounts
            WHERE token_hash = ? AND revoked = 0
            """,
            (token_hash(token),),
        ).fetchone()
    if row is None:
        raise ApiError(401, "unauthenticated", "invalid token")
    return row["account_id"], row["login_name"]


def issue_session(account_id: str) -> tuple[str, int]:
    expires_at = iso_utc(utc_now() + timedelta(seconds=SESSION_TTL_SECONDS))
    with db_connection() as connection:
        for _ in range(3):
            access_token = secrets.token_urlsafe(32)
            try:
                connection.execute(
                    "INSERT INTO sessions (access_token, account_id, expires_at) VALUES (?, ?, ?)",
                    (access_token, account_id, expires_at),
                )
                return access_token, SESSION_TTL_SECONDS
            except sqlite3.IntegrityError as error:
                if "sessions.access_token" not in str(error):
                    raise
    raise RuntimeError("could not generate a unique session token")


def require_session(request: Request) -> SessionContext:
    access_token = bearer_token(request)
    with db_connection() as connection:
        row = connection.execute(
            """
            SELECT sessions.account_id, sessions.expires_at, accounts.revoked
            FROM sessions
            JOIN accounts ON accounts.account_id = sessions.account_id
            WHERE sessions.access_token = ?
            """,
            (access_token,),
        ).fetchone()
    if (
        row is None
        or row["revoked"]
        or row["expires_at"] <= iso_utc()
    ):
        raise ApiError(401, "unauthenticated", "session expired or invalid")
    return SessionContext(account_id=row["account_id"], access_token=access_token)
