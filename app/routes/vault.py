import base64
import binascii
import json
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from pydantic import BaseModel

from app.auth import SessionContext, require_session
from app.config import (
    IDEMPOTENCY_RETENTION_SECONDS,
    MAX_CIPHERTEXT_BYTES,
    MAX_HTTP_BODY_BYTES,
)
from app.db import db_connection, ensure_vault_metadata, iso_utc, new_etag, utc_now
from app.errors import ApiError
from app.models import OperationCommitResponse, SnapshotUpload, VaultMetadataResponse


router = APIRouter(prefix="/v1/me")


def json_response(
    model: BaseModel,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    content = model.model_dump()
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def require_json_content_type(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json")


async def read_limited_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_HTTP_BODY_BYTES:
                raise ApiError(413, "body_too_large", "request body exceeds the protocol limit")
        except ValueError:
            raise ApiError(400, "invalid_request", "invalid Content-Length") from None

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_HTTP_BODY_BYTES:
            raise ApiError(413, "body_too_large", "request body exceeds the protocol limit")
        body.extend(chunk)
    return bytes(body)


def parse_upload(raw_body: bytes) -> SnapshotUpload:
    try:
        parsed = json.loads(
            raw_body.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_object_keys,
        )
        if not isinstance(parsed, dict):
            raise ValueError("JSON root must be an object")
        return SnapshotUpload.model_validate(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError) as error:
        raise ApiError(400, "invalid_request", "snapshot body does not match the protocol") from error


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _unique_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def validate_ciphertext_size(ciphertext: str) -> None:
    try:
        encoded = ciphertext.encode("ascii")
    except UnicodeEncodeError as error:
        raise ApiError(400, "invalid_request", "ciphertext must be base64 encoded") from error
    if len(encoded) > ((MAX_CIPHERTEXT_BYTES + 2) // 3) * 4:
        raise ApiError(413, "ciphertext_too_large", "ciphertext exceeds the protocol limit")
    try:
        padded = encoded + b"=" * ((4 - len(encoded) % 4) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ApiError(400, "invalid_request", "ciphertext must be base64 encoded") from error
    if len(decoded) > MAX_CIPHERTEXT_BYTES:
        raise ApiError(413, "ciphertext_too_large", "ciphertext exceeds the protocol limit")


@router.get("/vault")
def get_vault_metadata(
    request: Request, session: SessionContext = Depends(require_session)
) -> Response:
    with db_connection() as connection:
        metadata = ensure_vault_metadata(connection, session.account_id)
    if request.headers.get("if-none-match") == metadata["etag"]:
        return Response(status_code=304, headers={"ETag": metadata["etag"]})
    body = VaultMetadataResponse(
        ownerGithubId=session.account_id,
        state=metadata["state"],
        revision=metadata["revision"],
        vaultId=metadata["vault_id"],
        lastOperationId=metadata["last_operation_id"],
    )
    return json_response(body, headers={"ETag": metadata["etag"]})


@router.get("/vault/snapshot")
def get_vault_snapshot(
    request: Request, session: SessionContext = Depends(require_session)
) -> Response:
    if_match = request.headers.get("if-match")
    with db_connection() as connection:
        metadata = ensure_vault_metadata(connection, session.account_id)
        if if_match != metadata["etag"]:
            raise ApiError(412, "precondition_failed", "vault ETag does not match")
        snapshot = connection.execute(
            "SELECT body_json FROM vault_snapshot WHERE account_id = ?",
            (session.account_id,),
        ).fetchone()
    if metadata["state"] == "empty" or snapshot is None:
        raise ApiError(404, "not_found", "vault snapshot not found")
    return Response(content=snapshot["body_json"], media_type="application/json")


@router.put("/vault/snapshot")
async def put_vault_snapshot(
    request: Request, session: SessionContext = Depends(require_session)
) -> Response:
    require_json_content_type(request)
    operation_id = request.headers.get("idempotency-key", "").strip()
    if not operation_id:
        raise ApiError(400, "invalid_request", "Idempotency-Key is required")
    if_match = request.headers.get("if-match")
    raw_body = await read_limited_body(request)

    with db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        retention_cutoff = iso_utc(
            utc_now() - timedelta(seconds=IDEMPOTENCY_RETENTION_SECONDS)
        )
        connection.execute(
            "DELETE FROM idempotency_log WHERE created_at <= ?", (retention_cutoff,)
        )
        previous = connection.execute(
            """
            SELECT response_status, response_body
            FROM idempotency_log
            WHERE account_id = ? AND operation_id = ?
            """,
            (session.account_id, operation_id),
        ).fetchone()
        if previous is not None:
            return Response(
                content=previous["response_body"],
                status_code=previous["response_status"],
                media_type="application/json",
                headers={"Idempotency-Replayed": "true"},
            )

        metadata = ensure_vault_metadata(connection, session.account_id)
        if if_match != metadata["etag"]:
            raise ApiError(412, "precondition_failed", "vault ETag does not match")

        upload = parse_upload(raw_body)
        if upload.operationId != operation_id:
            raise ApiError(400, "invalid_request", "Idempotency-Key must match operationId")
        if upload.ownerGithubId != session.account_id:
            raise ApiError(403, "forbidden", "ownerGithubId does not match the session account")
        if upload.baseRevision < 0 or upload.revision < 1:
            raise ApiError(400, "invalid_request", "revision values are out of range")
        if upload.baseRevision != metadata["revision"]:
            raise ApiError(409, "revision_conflict", "vault revision has changed")
        if upload.revision != upload.baseRevision + 1:
            raise ApiError(400, "invalid_request", "revision must equal baseRevision + 1")
        if not upload.vaultId:
            raise ApiError(400, "invalid_request", "vaultId must not be empty")
        validate_ciphertext_size(upload.ciphertext)

        new_revision = upload.baseRevision + 1
        etag = new_etag()
        now = iso_utc()
        connection.execute(
            """
            INSERT INTO vault_snapshot (account_id, body_json, revision)
            VALUES (?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                body_json = excluded.body_json,
                revision = excluded.revision
            """,
            (session.account_id, raw_body.decode("utf-8"), new_revision),
        )
        connection.execute(
            """
            UPDATE vault_metadata
            SET vault_id = ?, state = 'active', revision = ?,
                last_operation_id = ?, etag = ?, updated_at = ?
            WHERE account_id = ?
            """,
            (upload.vaultId, new_revision, operation_id, etag, now, session.account_id),
        )
        response = OperationCommitResponse(
            operationId=operation_id,
            revision=new_revision,
            status="committed",
        )
        response_body = response.model_dump_json()
        connection.execute(
            """
            INSERT INTO idempotency_log
                (account_id, operation_id, response_status, response_body, created_at)
            VALUES (?, ?, 200, ?, ?)
            """,
            (session.account_id, operation_id, response_body, now),
        )

    return Response(
        content=response_body,
        status_code=200,
        media_type="application/json",
        headers={"Idempotency-Replayed": "false"},
    )


@router.delete("/vault", status_code=204)
def delete_vault(session: SessionContext = Depends(require_session)) -> Response:
    with db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        ensure_vault_metadata(connection, session.account_id)
        connection.execute(
            "DELETE FROM vault_snapshot WHERE account_id = ?", (session.account_id,)
        )
        connection.execute(
            """
            UPDATE vault_metadata
            SET vault_id = NULL, state = 'empty', revision = 0,
                last_operation_id = NULL, etag = ?, updated_at = ?
            WHERE account_id = ?
            """,
            (new_etag(), iso_utc(), session.account_id),
        )
    return Response(status_code=204)


@router.get("/operations/{operation_id}")
def get_operation(
    operation_id: str, session: SessionContext = Depends(require_session)
) -> JSONResponse:
    with db_connection() as connection:
        row = connection.execute(
            """
            SELECT operation_id FROM idempotency_log
            WHERE account_id = ? AND operation_id = ?
            """,
            (session.account_id, operation_id),
        ).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "operation not found")
    return JSONResponse(
        content={"operationId": row["operation_id"], "status": "committed"}
    )
