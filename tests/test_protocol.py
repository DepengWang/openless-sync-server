import base64
import hashlib
import json
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app import config, db
from app.admin_cli import create_account
from app.main import app

VAULT_ID_1 = "be406ca5-37fa-4b26-9a9a-74c1aad48eae"
VAULT_ID_2 = "8d1c4a77-fc27-4d7e-9a21-1a76e778c130"
KEY_ID_1 = "2b1889ab-7278-48e7-8d2f-284195de2484"
KEY_ID_2 = "a9b6b69b-1854-49a6-b3e4-9e25fb476f2a"
CREATE_OP = "f1d8c32e-d209-4e56-8735-bc66b8684c71"
SNAPSHOT_OP = "0e29fa59-f117-49fa-9da1-16523a38fb82"
PASSWORD_OP = "c94cae75-f2f3-40bb-956d-6c786d96c3bc"
DELETE_OP = "e517e311-22d0-45b8-9c5d-5c16d3d04f17"
RECREATE_OP = "fbdfdd37-500f-4458-8d50-5e0528865d88"


@pytest.fixture
def api(tmp_path, monkeypatch):
    database_path = tmp_path / "sync.db"
    monkeypatch.setattr(config, "DB_PATH", database_path)
    monkeypatch.setattr(config, "STORAGE_PATH", tmp_path)
    monkeypatch.setattr(db, "DB_PATH", database_path)
    monkeypatch.setattr(db, "STORAGE_PATH", tmp_path)

    with TestClient(app) as client:
        _account_id, static_token = create_account("protocol-test")
        token_response = client.post(
            "/v1/auth/token", headers={"Authorization": f"Bearer {static_token}"}
        )
        assert token_response.status_code == 200
        token_data = token_response.json()
        assert token_data["protocolVersion"] == 1
        assert token_data["tokenType"] == "Bearer"
        assert token_data["expiresIn"] <= 900
        yield client, token_data["accessToken"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def get_metadata(client, token):
    response = client.get("/v1/me/vault", headers=auth(token))
    assert response.status_code == 200
    return response


def make_upload(
    operation_id,
    base_revision,
    revision,
    *,
    kind="snapshot",
    vault_id=VAULT_ID_1,
    key_id=KEY_ID_1,
):
    ciphertext_bytes = bytes((revision % 251,)) * (65_536 + 16)
    ciphertext = base64.urlsafe_b64encode(ciphertext_bytes).rstrip(b"=").decode("ascii")
    salt = bytes([2 if kind == "password_change" else 1]) * 16
    nonce = hashlib.sha256(operation_id.encode("ascii")).digest()[:24]
    payload = {
        "protocolVersion": 1,
        "payloadSchemaVersion": 1,
        "ownerGithubId": "1",
        "vaultId": vault_id,
        "keyId": key_id,
        "baseRevision": str(base_revision),
        "revision": str(revision),
        "operationId": operation_id,
        "kind": kind,
        "cryptoProfile": "argon2id-xchacha20poly1305-v1",
        "kdf": {
            "name": "argon2id",
            "version": 19,
            "memoryKiB": 65536,
            "iterations": 3,
            "parallelism": 4,
            "salt": base64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii"),
        },
        "aead": "xchacha20poly1305-ietf",
        "codec": "json-pad64k-v1",
        "nonce": base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii"),
        "ciphertext": ciphertext,
        "ciphertextSha256": hashlib.sha256(ciphertext_bytes).hexdigest(),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def put_snapshot(client, token, etag, body, operation_id):
    return client.put(
        "/v1/me/vault/snapshot",
        content=body,
        headers={
            **auth(token),
            "If-Match": etag,
            "Idempotency-Key": operation_id,
            "Content-Type": "application/json",
        },
    )


def test_capabilities_and_empty_metadata_contract(api):
    client, token = api
    capabilities = client.get("/v1/capabilities")
    assert capabilities.status_code == 200
    assert capabilities.json()["githubClientId"] == "Ov23liyv3nEucG7oMHNE"

    empty = get_metadata(client, token)
    assert set(empty.json()) == {
        "protocolVersion", "state", "ownerGithubId", "revision", "vaultId", "keyId",
        "updatedAt", "payloadSchemaVersion", "ciphertextBytes", "ciphertextSha256",
        "lastOperationId",
    }
    assert empty.json() == {
        "protocolVersion": 1,
        "state": "empty",
        "ownerGithubId": "1",
        "revision": "0",
        "vaultId": None,
        "keyId": None,
        "updatedAt": None,
        "payloadSchemaVersion": None,
        "ciphertextBytes": 0,
        "ciphertextSha256": None,
        "lastOperationId": None,
    }
    assert empty.headers.get("etag")
    assert empty.headers["cache-control"] == "no-store"
    assert client.get("/v1/me/vault", headers=auth(token)).status_code == 200
    not_modified = client.get(
        "/v1/me/vault", headers={**auth(token), "If-None-Match": empty.headers["etag"]}
    )
    assert not_modified.status_code == 304
    assert client.get("/v1/me/vault", headers=auth(token)).status_code == 200
    unauthorized = client.get("/v1/me/vault")
    assert unauthorized.status_code == 401
    error = unauthorized.json()["error"]
    assert set(error) == {"code", "message", "requestId"}
    assert error["code"] == "unauthenticated"
    assert error["requestId"] == unauthorized.headers["x-request-id"]
    assert UUID(error["requestId"]).version == 4


def test_put_receipt_raw_snapshot_replay_and_operation_lookup(api):
    client, token = api
    empty = get_metadata(client, token)
    operation_id = CREATE_OP
    body = make_upload(operation_id, 0, 1, kind="create")

    uploaded = put_snapshot(client, token, empty.headers["etag"], body, operation_id)
    assert uploaded.status_code == 200
    assert uploaded.headers["idempotency-replayed"] == "false"
    receipt = uploaded.json()
    assert set(receipt) == {
        "operationId", "status", "kind", "committedRevision", "committedAt", "vaultId",
        "ciphertextSha256",
    }
    assert receipt["operationId"] == operation_id
    assert receipt["status"] == "committed"
    assert receipt["kind"] == "create"
    assert receipt["committedRevision"] == "1"
    encoded_ciphertext = json.loads(body)["ciphertext"]
    decoded = base64.urlsafe_b64decode(
        encoded_ciphertext + "=" * ((4 - len(encoded_ciphertext) % 4) % 4)
    )
    assert receipt["ciphertextSha256"] == hashlib.sha256(decoded).hexdigest()

    replay = put_snapshot(client, token, empty.headers["etag"], body, operation_id)
    assert replay.status_code == 200
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.content == uploaded.content

    changed = make_upload(operation_id, 0, 1, kind="snapshot")
    assert put_snapshot(client, token, empty.headers["etag"], changed, operation_id).status_code == 409

    active = get_metadata(client, token)
    assert active.json()["revision"] == "1"
    assert active.json()["state"] == "active"
    assert active.json()["keyId"] == KEY_ID_1
    assert active.json()["payloadSchemaVersion"] == 1
    assert active.json()["ciphertextBytes"] == len(decoded)
    assert active.json()["ciphertextSha256"] == hashlib.sha256(decoded).hexdigest()
    assert active.json()["lastOperationId"] == operation_id
    assert active.json()["updatedAt"] is not None
    snapshot = client.get(
        "/v1/me/vault/snapshot",
        headers={**auth(token), "If-Match": active.headers["etag"]},
    )
    assert snapshot.status_code == 200
    assert snapshot.content == body
    assert snapshot.headers["etag"] == active.headers["etag"]
    assert client.get(
        "/v1/me/vault/snapshot", headers={**auth(token), "If-Match": empty.headers["etag"]}
    ).status_code == 412

    next_operation = PASSWORD_OP
    next_body = make_upload(next_operation, 1, 2, kind="password_change")
    next_payload = json.loads(next_body)
    next_payload["keyId"] = KEY_ID_2
    next_body = json.dumps(next_payload, separators=(",", ":")).encode()
    next_write = put_snapshot(
        client, token, active.headers["etag"], next_body, next_operation
    )
    assert next_write.status_code == 200
    assert next_write.json()["kind"] == "password_change"
    assert next_write.json()["committedRevision"] == "2"

    operation = client.get(f"/v1/me/operations/{operation_id}", headers=auth(token))
    assert operation.status_code == 200
    assert operation.content == uploaded.content
    missing = client.get(
        "/v1/me/operations/ffffffff-ffff-4fff-8fff-ffffffffffff", headers=auth(token)
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "operation_not_found"


def test_revision_conflicts_and_revision_must_be_canonical_string(api):
    client, token = api
    empty = get_metadata(client, token)
    stale = put_snapshot(
        client,
        token,
        empty.headers["etag"],
        make_upload(CREATE_OP, 0, 1, kind="create"),
        CREATE_OP,
    )
    assert stale.status_code == 200
    active = get_metadata(client, token)

    conflict = put_snapshot(
        client,
        token,
        active.headers["etag"],
        make_upload(SNAPSHOT_OP, 0, 1),
        SNAPSHOT_OP,
    )
    assert conflict.status_code == 412
    conflict_error = conflict.json()["error"]
    assert set(conflict_error) == {"code", "message", "requestId", "currentRevision"}
    assert conflict_error["code"] == "revision_conflict"
    assert conflict_error["currentRevision"] == "1"
    assert UUID(conflict_error["requestId"]).version == 4
    assert conflict_error["requestId"] == conflict.headers["x-request-id"]
    stale_etag = put_snapshot(
        client,
        token,
        empty.headers["etag"],
        make_upload(SNAPSHOT_OP, 1, 2),
        SNAPSHOT_OP,
    )
    assert stale_etag.status_code == 412

    payload = json.loads(make_upload(SNAPSHOT_OP, 1, 2))
    payload["revision"] = 2
    invalid = put_snapshot(
        client,
        token,
        active.headers["etag"],
        json.dumps(payload).encode(),
        SNAPSHOT_OP,
    )
    assert invalid.status_code == 400
    assert get_metadata(client, token).json()["revision"] == "1"


def test_delete_returns_receipt_preserves_tombstone_and_allows_new_vault(api):
    client, token = api
    empty = get_metadata(client, token)
    put_id = CREATE_OP
    put = put_snapshot(
        client, token, empty.headers["etag"], make_upload(put_id, 0, 1, kind="create"), put_id
    )
    assert put.status_code == 200
    active = get_metadata(client, token)

    snapshot_id = SNAPSHOT_OP
    snapshot_body = make_upload(snapshot_id, 1, 2, kind="snapshot")
    snapshot_write = put_snapshot(
        client, token, active.headers["etag"], snapshot_body, snapshot_id
    )
    assert snapshot_write.status_code == 200
    active = get_metadata(client, token)

    delete_id = DELETE_OP
    delete_body = json.dumps(
        {
            "protocolVersion": 1,
            "baseRevision": "2",
            "operationId": delete_id,
            "expectedVaultId": VAULT_ID_1,
        },
        separators=(",", ":"),
    ).encode()
    delete_headers = {
        **auth(token),
        "If-Match": active.headers["etag"],
        "Idempotency-Key": delete_id,
        "Content-Type": "application/json",
    }
    deleted = client.request("DELETE", "/v1/me/vault", content=delete_body, headers=delete_headers)
    assert deleted.status_code == 200
    assert deleted.headers["idempotency-replayed"] == "false"
    assert deleted.json()["kind"] == "delete"
    assert deleted.json()["committedRevision"] == "3"
    assert deleted.json()["vaultId"] == VAULT_ID_1
    assert deleted.json()["ciphertextSha256"] is None

    replay = client.request("DELETE", "/v1/me/vault", content=delete_body, headers=delete_headers)
    assert replay.status_code == 200
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.content == deleted.content

    cleared = get_metadata(client, token)
    assert cleared.json() == {
        "protocolVersion": 1,
        "state": "deleted",
        "ownerGithubId": "1",
        "revision": "3",
        "vaultId": VAULT_ID_1,
        "keyId": None,
        "updatedAt": deleted.json()["committedAt"],
        "payloadSchemaVersion": None,
        "ciphertextBytes": 0,
        "ciphertextSha256": None,
        "lastOperationId": delete_id,
    }
    assert client.get(
        "/v1/me/vault/snapshot", headers={**auth(token), "If-Match": cleared.headers["etag"]}
    ).status_code == 404

    recreate_id = RECREATE_OP
    reused_id = put_snapshot(
        client,
        token,
        cleared.headers["etag"],
        make_upload(recreate_id, 3, 4, kind="create"),
        recreate_id,
    )
    assert reused_id.status_code == 409
    assert reused_id.json()["error"]["code"] == "vault_exists"

    recreated = put_snapshot(
        client,
        token,
        cleared.headers["etag"],
        make_upload(
            recreate_id,
            3,
            4,
            kind="create",
            vault_id=VAULT_ID_2,
            key_id=KEY_ID_2,
        ),
        recreate_id,
    )
    assert recreated.status_code == 200
    assert recreated.json()["committedRevision"] == "4"

    delete_operation = client.get(f"/v1/me/operations/{delete_id}", headers=auth(token))
    assert delete_operation.status_code == 200
    assert delete_operation.content == deleted.content


def test_session_logout_invalidates_bearer_token(api):
    client, token = api
    logged_out = client.delete("/v1/auth/session", headers=auth(token))
    assert logged_out.status_code == 204
    assert client.get("/v1/me/vault", headers=auth(token)).status_code == 401
