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
    githubId: str
    login: str


class TokenResponse(BaseModel):
    account: AccountResponse
    accessToken: str
    expiresIn: int


class VaultMetadataResponse(BaseModel):
    ownerGithubId: str
    state: Literal["empty", "active"]
    revision: StrictInt
    vaultId: str | None
    lastOperationId: str | None


class SnapshotUpload(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)

    ownerGithubId: StrictStr
    vaultId: StrictStr
    revision: StrictInt
    baseRevision: StrictInt
    operationId: StrictStr
    kind: Literal["create", "snapshot", "passwordChange"]
    ciphertext: StrictStr


class OperationCommitResponse(BaseModel):
    operationId: str
    revision: StrictInt
    status: Literal["committed"]
