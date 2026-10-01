import base64
import binascii
import hashlib
import json
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError

from app.auth import SessionContext, require_session
from app.config import (
    AEAD_NAME,
    CODEC_NAME,
    CRYPTO_PROFILE,
    IDEMPOTENCY_RETENTION_SECONDS,
    KDF_ITERATIONS,
    KDF_MEMORY_KIB,
    KDF_NAME,
    KDF_PARALLELISM,
    KDF_VERSION,
    MAX_CIPHERTEXT_BYTES,
    MAX_HTTP_BODY_BYTES,
    MIN_CIPHERTEXT_BYTES,
    PAD_BLOCK_BYTES,
    PROTOCOL_VERSION,
)
from app.db import db_connection, ensure_vault_metadata, iso_utc, new_etag, utc_now
from app.errors import ApiError
from app.models import (
    DeleteVaultRequest,
    OperationReceipt,
    SnapshotUpload,
    VaultMetadataResponse,
)


router = APIRouter(prefix="/v1/me")
REVISION_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
UUID_V4_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SQLITE_MAX_INTEGER = 9_223_372_036_854_775_807


def json_response(
    model: BaseModel,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=model.model_dump(), headers=headers)


def require_json_content_type(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json")


async def read_limited_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_HTTP_BODY_BYTES:
                raise ApiError(413, "payload_too_large", "request body exceeds the protocol limit")
        except ValueError:
            raise ApiError(400, "invalid_request", "invalid Content-Length") from None

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_HTTP_BODY_BYTES:
            raise ApiError(413, "payload_too_large", "request body exceeds the protocol limit")
        body.extend(chunk)
    return bytes(body)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _unique_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def parse_json_object(raw_body: bytes, message: str) -> dict[str, object]:
    try:
        parsed = json.loads(
            raw_body.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_object_keys,
        )
        if not isinstance(parsed, dict):
            raise ValueError("JSON root must be an object")
        return parsed
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ApiError(400, "invalid_request", message) from error


def parse_upload(raw_body: bytes) -> SnapshotUpload:
    try:
        return SnapshotUpload.model_validate(
            parse_json_object(raw_body, "snapshot body does not match the protocol")
        )
    except ValidationError as error:
        raise ApiError(400, "invalid_request", "snapshot body does not match the protocol") from error


def parse_delete(raw_body: bytes) -> DeleteVaultRequest:
    try:
        return DeleteVaultRequest.model_validate(
            parse_json_object(raw_body, "delete body does not match the protocol")
        )
    except ValidationError as error:
        raise ApiError(400, "invalid_request", "delete body does not match the protocol") from error


def parse_revision(value: str, field: str) -> int:
    if not REVISION_RE.fullmatch(value):
        raise ApiError(400, "invalid_request", f"{field} must be a canonical decimal string")
    revision = int(value)
    if revision > SQLITE_MAX_INTEGER:
        raise ApiError(400, "invalid_request", f"{field} is out of range")
    return revision


def parse_uuid_v4(value: str, field: str) -> None:
    if not UUID_V4_RE.fullmatch(value):
        raise ApiError(400, "invalid_request", f"{field} must be a canonical UUID v4")


def decode_base64url(value: str, field: str, max_bytes: int) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ApiError(400, "invalid_request", f"{field} must use canonical base64url") from error
    if not encoded or not BASE64URL_RE.fullmatch(value):
        raise ApiError(400, "invalid_request", f"{field} must use canonical base64url")
    if len(encoded) > ((max_bytes + 2) // 3) * 4:
        raise ApiError(413, "payload_too_large", f"{field} exceeds the protocol limit")
    try:
        decoded = base64.b64decode(
            encoded + b"=" * ((4 - len(encoded) % 4) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as error:
        raise ApiError(400, "invalid_request", f"{field} must use canonical base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
        raise ApiError(400, "invalid_request", f"{field} must use canonical base64url")
    if len(decoded) > max_bytes:
        raise ApiError(413, "payload_too_large", f"{field} exceeds the protocol limit")
    return decoded


def decode_ciphertext(ciphertext: str) -> bytes:
    decoded = decode_base64url(ciphertext, "ciphertext", MAX_CIPHERTEXT_BYTES)
    if len(decoded) < MIN_CIPHERTEXT_BYTES or (len(decoded) - 16) % PAD_BLOCK_BYTES != 0:
        raise ApiError(400, "invalid_crypto_header", "ciphertext framing does not match the protocol")
    return decoded


def request_fingerprint(method: str, path: str, if_match: str | None, body: bytes) -> str:
    headers = json.dumps([method, path, if_match], separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(headers + b"\0" + body).hexdigest()


def replay_or_conflict(row, fingerprint: str) -> Response | None:
    if row is None:
        return None
    if row["fingerprint"] is None or row["fingerprint"] != fingerprint:
        raise ApiError(409, "idempotency_key_reused", "operation ID was used for a different request")
    return Response(
        content=row["response_body"],
        status_code=row["response_status"],
        media_type="application/json",
        headers={"Idempotency-Replayed": "true"},
    )


def purge_expired_idempotency(connection) -> None:
    retention_cutoff = iso_utc(
        utc_now() - timedelta(seconds=IDEMPOTENCY_RETENTION_SECONDS)
    )
    connection.execute("DELETE FROM idempotency_log WHERE created_at <= ?", (retention_cutoff,))


@router.get("/vault")
def get_vault_metadata(
    request: Request, session: SessionContext = Depends(require_session)
) -> Response:
    with db_connection() as connection:
        metadata = ensure_vault_metadata(connection, session.account_id)
    if request.headers.get("if-none-match") == metadata["etag"]:
        return Response(status_code=304, headers={"ETag": metadata["etag"]})
    body = VaultMetadataResponse(
        protocolVersion=PROTOCOL_VERSION,
        state=metadata["state"],
        ownerGithubId=str(session.account_id),
        revision=str(metadata["revision"]),
        vaultId=metadata["vault_id"],
        keyId=metadata["key_id"],
        updatedAt=metadata["updated_at"],
        payloadSchemaVersion=metadata["payload_schema_version"],
        ciphertextBytes=metadata["ciphertext_bytes"],
        ciphertextSha256=metadata["ciphertext_sha256"],
        lastOperationId=metadata["last_operation_id"],
    )
    return json_response(body, headers={"ETag": metadata["etag"]})


@router.get("/vault/snapshot")
def get_vault_snapshot(
    request: Request, session: SessionContext = Depends(require_session)
) -> Response:
    if_match = request.headers.get("if-match")
    if if_match is None:
        raise ApiError(428, "precondition_required", "If-Match is required")
    with db_connection() as connection:
        metadata = ensure_vault_metadata(connection, session.account_id)
        if if_match != metadata["etag"]:
            raise ApiError(
                412,
                "revision_conflict",
                "vault ETag does not match",
                current_revision=str(metadata["revision"]),
            )
        snapshot = connection.execute(
            "SELECT body_json FROM vault_snapshot WHERE account_id = ?",
            (session.account_id,),
        ).fetchone()
    if metadata["state"] != "active" or snapshot is None:
        error_code = "vault_deleted" if metadata["state"] == "deleted" else "vault_empty"
        raise ApiError(404, error_code, "vault snapshot not found")
    return Response(
        content=snapshot["body_json"],
        media_type="application/json",
        headers={"ETag": metadata["etag"]},
    )


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
    fingerprint = request_fingerprint("PUT", "/v1/me/vault/snapshot", if_match, raw_body)

    with db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        purge_expired_idempotency(connection)
        previous = connection.execute(
            """SELECT response_status, response_body, fingerprint FROM idempotency_log
               WHERE account_id = ? AND operation_id = ?""",
            (session.account_id, operation_id),
        ).fetchone()
        replay = replay_or_conflict(previous, fingerprint)
        if replay is not None:
            return replay

        metadata = ensure_vault_metadata(connection, session.account_id)
        if if_match is None:
            raise ApiError(428, "precondition_required", "If-Match is required")
        if if_match != metadata["etag"]:
            raise ApiError(
                412,
                "revision_conflict",
                "vault ETag does not match",
                current_revision=str(metadata["revision"]),
            )

        upload = parse_upload(raw_body)
        if upload.protocolVersion != PROTOCOL_VERSION:
            raise ApiError(400, "unsupported_protocol", "unsupported protocolVersion")
        if (
            upload.payloadSchemaVersion != 1
            or upload.cryptoProfile != CRYPTO_PROFILE
            or upload.aead != AEAD_NAME
            or upload.codec != CODEC_NAME
        ):
            raise ApiError(400, "unsupported_protocol", "unsupported snapshot crypto profile")
        if (
            upload.kdf.name != KDF_NAME
            or upload.kdf.version != KDF_VERSION
            or upload.kdf.memoryKiB != KDF_MEMORY_KIB
            or upload.kdf.iterations != KDF_ITERATIONS
            or upload.kdf.parallelism != KDF_PARALLELISM
        ):
            raise ApiError(400, "unsupported_protocol", "unsupported KDF parameters")
        if upload.operationId != operation_id:
            raise ApiError(400, "invalid_request", "Idempotency-Key must match operationId")
        if upload.ownerGithubId != str(session.account_id):
            raise ApiError(403, "owner_mismatch", "ownerGithubId does not match the session account")
        parse_uuid_v4(upload.vaultId, "vaultId")
        parse_uuid_v4(upload.keyId, "keyId")
        parse_uuid_v4(upload.operationId, "operationId")
        base_revision = parse_revision(upload.baseRevision, "baseRevision")
        new_revision = parse_revision(upload.revision, "revision")
        current_revision = int(metadata["revision"])
        if base_revision != current_revision:
            raise ApiError(
                412,
                "revision_conflict",
                "vault revision has changed",
                current_revision=str(current_revision),
            )
        if new_revision != base_revision + 1:
            raise ApiError(400, "invalid_request", "revision must equal baseRevision + 1")

        salt = decode_base64url(upload.kdf.salt, "kdf.salt", 16)
        nonce = decode_base64url(upload.nonce, "nonce", 24)
        if len(salt) != 16 or len(nonce) != 24:
            raise ApiError(
                400, "invalid_crypto_header", "salt or nonce length does not match the protocol"
            )

        if upload.kind == "create":
            if metadata["state"] == "active":
                raise ApiError(409, "vault_exists", "an active vault already exists")
            if metadata["state"] == "empty" and current_revision != 0:
                raise ApiError(500, "internal_error", "empty vault has a non-zero revision")
            if metadata["vault_id"] is not None and upload.vaultId == metadata["vault_id"]:
                raise ApiError(409, "vault_exists", "a deleted vault ID cannot be reused")
        else:
            if metadata["state"] != "active" or metadata["vault_id"] is None:
                raise ApiError(409, "vault_deleted", "there is no active vault to update")
            if upload.vaultId != metadata["vault_id"]:
                raise ApiError(409, "vault_deleted", "vaultId does not match the active vault")
            if upload.operationId == metadata["last_operation_id"]:
                raise ApiError(409, "idempotency_key_reused", "operation ID must be new")
            previous_row = connection.execute(
                "SELECT body_json, revision FROM vault_snapshot WHERE account_id=?",
                (session.account_id,),
            ).fetchone()
            try:
                previous_upload = json.loads(previous_row["body_json"])
                previous_salt = previous_upload["kdf"]["salt"]
                previous_nonce = previous_upload["nonce"]
                previous_key_id = previous_upload["keyId"]
                previous_operation_id = previous_upload["operationId"]
            except (TypeError, KeyError, ValueError):
                raise ApiError(
                    409,
                    "key_epoch_changed",
                    "stored predecessor is not compatible with the current protocol",
                ) from None
            if (
                not isinstance(previous_upload, dict)
                or int(previous_row["revision"]) != current_revision
                or previous_upload.get("revision") != str(current_revision)
                or previous_upload.get("vaultId") != metadata["vault_id"]
                or previous_key_id != metadata["key_id"]
                or previous_operation_id != metadata["last_operation_id"]
                or previous_upload.get("ciphertextSha256") != metadata["ciphertext_sha256"]
            ):
                raise ApiError(
                    409,
                    "key_epoch_changed",
                    "stored predecessor does not match current metadata",
                )
            if upload.nonce == previous_nonce:
                raise ApiError(400, "invalid_crypto_header", "nonce must not be reused")
            if upload.kind == "snapshot" and upload.keyId != metadata["key_id"]:
                raise ApiError(409, "key_epoch_changed", "snapshot keyId changed unexpectedly")
            if upload.kind == "password_change" and upload.keyId == metadata["key_id"]:
                raise ApiError(409, "key_epoch_changed", "password change must use a new keyId")
            if upload.kind == "snapshot" and upload.kdf.salt != previous_salt:
                raise ApiError(409, "key_epoch_changed", "snapshot KDF salt changed unexpectedly")
            if upload.kind == "password_change" and upload.kdf.salt == previous_salt:
                raise ApiError(409, "key_epoch_changed", "password change must use a new KDF salt")

        decoded_ciphertext = decode_ciphertext(upload.ciphertext)
        ciphertext_sha256 = hashlib.sha256(decoded_ciphertext).hexdigest()
        if not SHA256_RE.fullmatch(upload.ciphertextSha256):
            raise ApiError(400, "invalid_request", "ciphertextSha256 must be lowercase SHA-256 hex")
        if upload.ciphertextSha256 != ciphertext_sha256:
            raise ApiError(400, "invalid_crypto_header", "ciphertextSha256 does not match ciphertext")
        etag = new_etag()
        committed_at = iso_utc()
        connection.execute(
            """INSERT INTO vault_snapshot (account_id, body_json, revision)
               VALUES (?, ?, ?)
               ON CONFLICT(account_id) DO UPDATE SET
                   body_json=excluded.body_json, revision=excluded.revision""",
            (session.account_id, raw_body.decode("utf-8"), new_revision),
        )
        connection.execute(
            """UPDATE vault_metadata SET vault_id=?, key_id=?, state='active', revision=?,
               payload_schema_version=?, ciphertext_bytes=?, ciphertext_sha256=?,
               last_operation_id=?, etag=?, updated_at=? WHERE account_id=?""",
            (
                upload.vaultId,
                upload.keyId,
                new_revision,
                upload.payloadSchemaVersion,
                len(decoded_ciphertext),
                ciphertext_sha256,
                operation_id,
                etag,
                committed_at,
                session.account_id,
            ),
        )
        receipt = OperationReceipt(
            operationId=operation_id,
            status="committed",
            kind=upload.kind,
            committedRevision=str(new_revision),
            committedAt=committed_at,
            vaultId=upload.vaultId,
            ciphertextSha256=ciphertext_sha256,
        )
        response_body = receipt.model_dump_json()
        connection.execute(
            """INSERT INTO idempotency_log
               (account_id, operation_id, response_status, response_body, created_at, fingerprint)
               VALUES (?, ?, 200, ?, ?, ?)""",
            (session.account_id, operation_id, response_body, committed_at, fingerprint),
        )

    return Response(
        content=response_body,
        status_code=200,
        media_type="application/json",
        headers={"Idempotency-Replayed": "false"},
    )


@router.delete("/vault")
async def delete_vault(
    request: Request, session: SessionContext = Depends(require_session)
) -> Response:
    require_json_content_type(request)
    operation_id = request.headers.get("idempotency-key", "").strip()
    if not operation_id:
        raise ApiError(400, "invalid_request", "Idempotency-Key is required")
    if_match = request.headers.get("if-match")
    raw_body = await read_limited_body(request)
    fingerprint = request_fingerprint("DELETE", "/v1/me/vault", if_match, raw_body)

    with db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        purge_expired_idempotency(connection)
        previous = connection.execute(
            """SELECT response_status, response_body, fingerprint FROM idempotency_log
               WHERE account_id = ? AND operation_id = ?""",
            (session.account_id, operation_id),
        ).fetchone()
        replay = replay_or_conflict(previous, fingerprint)
        if replay is not None:
            return replay

        metadata = ensure_vault_metadata(connection, session.account_id)
        if if_match is None:
            raise ApiError(428, "precondition_required", "If-Match is required")
        if if_match != metadata["etag"]:
            raise ApiError(
                412,
                "revision_conflict",
                "vault ETag does not match",
                current_revision=str(metadata["revision"]),
            )
        delete_request = parse_delete(raw_body)
        if delete_request.protocolVersion != PROTOCOL_VERSION:
            raise ApiError(400, "unsupported_protocol", "unsupported protocolVersion")
        if delete_request.operationId != operation_id:
            raise ApiError(400, "invalid_request", "Idempotency-Key must match operationId")
        parse_uuid_v4(delete_request.operationId, "operationId")
        parse_uuid_v4(delete_request.expectedVaultId, "expectedVaultId")
        base_revision = parse_revision(delete_request.baseRevision, "baseRevision")
        if base_revision != int(metadata["revision"]):
            raise ApiError(
                412,
                "revision_conflict",
                "vault revision has changed",
                current_revision=str(metadata["revision"]),
            )
        if metadata["state"] != "active" or metadata["vault_id"] is None:
            raise ApiError(409, "vault_deleted", "there is no active vault to delete")
        if delete_request.expectedVaultId != metadata["vault_id"]:
            raise ApiError(409, "vault_exists", "expectedVaultId does not match the current vault")

        deleted_vault_id = metadata["vault_id"]
        committed_revision = base_revision + 1
        if committed_revision > SQLITE_MAX_INTEGER:
            raise ApiError(409, "revision_exhausted", "vault revision cannot be incremented")
        committed_at = iso_utc()
        etag = new_etag()
        connection.execute(
            "DELETE FROM vault_snapshot WHERE account_id = ?", (session.account_id,)
        )
        connection.execute(
            """UPDATE vault_metadata SET key_id=NULL, state='deleted', revision=?,
               payload_schema_version=NULL, ciphertext_bytes=0, ciphertext_sha256=NULL,
               last_operation_id=?, etag=?, updated_at=? WHERE account_id=?""",
            (committed_revision, operation_id, etag, committed_at, session.account_id),
        )
        receipt = OperationReceipt(
            operationId=operation_id,
            status="committed",
            kind="delete",
            committedRevision=str(committed_revision),
            committedAt=committed_at,
            vaultId=deleted_vault_id,
            ciphertextSha256=None,
        )
        response_body = receipt.model_dump_json()
        connection.execute(
            """INSERT INTO idempotency_log
               (account_id, operation_id, response_status, response_body, created_at, fingerprint)
               VALUES (?, ?, 200, ?, ?, ?)""",
            (session.account_id, operation_id, response_body, committed_at, fingerprint),
        )

    return Response(
        content=response_body,
        status_code=200,
        media_type="application/json",
        headers={"Idempotency-Replayed": "false"},
    )


@router.get("/operations/{operation_id}")
def get_operation(
    operation_id: str, session: SessionContext = Depends(require_session)
) -> Response:
    with db_connection() as connection:
        row = connection.execute(
            """SELECT response_status, response_body FROM idempotency_log
               WHERE account_id = ? AND operation_id = ? AND created_at > ?""",
            (
                session.account_id,
                operation_id,
                iso_utc(utc_now() - timedelta(seconds=IDEMPOTENCY_RETENTION_SECONDS)),
            ),
        ).fetchone()
    if row is None:
        raise ApiError(404, "operation_not_found", "operation not found")
    return Response(content=row["response_body"], status_code=200, media_type="application/json")
