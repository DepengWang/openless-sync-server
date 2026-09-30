from fastapi import APIRouter
from fastapi.responses import Response

from app.config import (
    CRYPTO_PROFILE,
    GITHUB_CLIENT_ID,
    IDEMPOTENCY_RETENTION_SECONDS,
    MAX_BACKUP_RETENTION_DAYS,
    MAX_CIPHERTEXT_BYTES,
    MAX_HTTP_BODY_BYTES,
    MAX_PLAINTEXT_JSON_BYTES,
    PROTOCOL_VERSION,
)
from app.models import ProtocolCapabilities


router = APIRouter()


@router.get("/v1/capabilities")
def get_capabilities() -> Response:
    response = ProtocolCapabilities(
        protocolVersion=PROTOCOL_VERSION,
        cryptoProfile=CRYPTO_PROFILE,
        githubClientId=GITHUB_CLIENT_ID,
        maxHttpBodyBytes=MAX_HTTP_BODY_BYTES,
        maxCiphertextBytes=MAX_CIPHERTEXT_BYTES,
        maxPlaintextJsonBytes=MAX_PLAINTEXT_JSON_BYTES,
        idempotencyRetentionSeconds=IDEMPOTENCY_RETENTION_SECONDS,
        maxBackupRetentionDays=MAX_BACKUP_RETENTION_DAYS,
    )
    return Response(
        content=response.model_dump_json(indent=2),
        media_type="application/json",
    )
