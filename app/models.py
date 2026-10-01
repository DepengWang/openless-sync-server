from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr


class ProtocolCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    protocolVersion: StrictInt
    cryptoProfile: StrictStr
    githubClientId: StrictStr
    maxHttpBodyBytes: StrictInt
    maxCiphertextBytes: StrictInt
    maxPlaintextJsonBytes: StrictInt
    idempotencyRetentionSeconds: StrictInt
    maxBackupRetentionDays: StrictInt


class AccountResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    githubId: StrictStr
    login: StrictStr


class TokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    protocolVersion: StrictInt
    account: AccountResponse
    accessToken: StrictStr
    tokenType: Literal["Bearer"]
    expiresIn: StrictInt


class VaultMetadataResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    protocolVersion: StrictInt
    state: Literal["empty", "active", "deleted"]
    ownerGithubId: StrictStr
    revision: StrictStr
    vaultId: StrictStr | None
    keyId: StrictStr | None
    updatedAt: StrictStr | None
    payloadSchemaVersion: StrictInt | None
    ciphertextBytes: StrictInt
    ciphertextSha256: StrictStr | None
    lastOperationId: StrictStr | None


class KdfParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: StrictStr
    version: StrictInt
    memoryKiB: StrictInt
    iterations: StrictInt
    parallelism: StrictInt
    salt: StrictStr


class SnapshotUpload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    protocolVersion: StrictInt
    payloadSchemaVersion: StrictInt
    ownerGithubId: StrictStr
    vaultId: StrictStr
    keyId: StrictStr
    baseRevision: StrictStr
    revision: StrictStr
    operationId: StrictStr
    kind: Literal["create", "snapshot", "password_change"]
    cryptoProfile: StrictStr
    kdf: KdfParameters
    aead: StrictStr
    codec: StrictStr
    nonce: StrictStr
    ciphertext: StrictStr
    ciphertextSha256: StrictStr


class DeleteVaultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    protocolVersion: StrictInt
    baseRevision: StrictStr
    operationId: StrictStr
    expectedVaultId: StrictStr


class OperationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operationId: StrictStr
    status: Literal["committed"]
    kind: StrictStr
    committedRevision: StrictStr
    committedAt: StrictStr
    vaultId: StrictStr
    ciphertextSha256: StrictStr | None
