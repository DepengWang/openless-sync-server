import pytest
from fastapi.testclient import TestClient

from app import config, db
from app.main import app


@pytest.fixture
def admin_api(tmp_path, monkeypatch):
    database_path = tmp_path / "sync.db"
    monkeypatch.setattr(config, "DB_PATH", database_path)
    monkeypatch.setattr(config, "STORAGE_PATH", tmp_path)
    monkeypatch.setattr(config, "ADMIN_TOKEN", "test-admin-token-" + "x" * 40)
    monkeypatch.setattr(db, "DB_PATH", database_path)
    monkeypatch.setattr(db, "STORAGE_PATH", tmp_path)

    with TestClient(app) as client:
        yield client, config.ADMIN_TOKEN


def admin_headers(token):
    return {"X-Admin-Token": token}


def test_admin_requires_configured_fixed_token(admin_api, monkeypatch):
    client, token = admin_api
    assert client.get("/v1/admin").status_code == 200
    assert client.get("/v1/admin/accounts").status_code == 401
    assert client.get(
        "/v1/admin/accounts", headers=admin_headers("wrong-token")
    ).status_code == 401

    monkeypatch.setattr(config, "ADMIN_TOKEN", "")
    disabled = client.get("/v1/admin/accounts", headers=admin_headers(token))
    assert disabled.status_code == 503


def test_admin_creates_accounts_and_reports_current_snapshot_bytes(admin_api):
    client, token = admin_api
    created = client.post(
        "/v1/admin/accounts",
        headers=admin_headers(token),
        json={"loginName": "depeng"},
    )
    assert created.status_code == 201
    created_data = created.json()
    assert created_data["accountId"] == "1"
    assert created_data["loginName"] == "depeng"
    assert len(created_data["staticToken"]) >= 40

    with db.db_connection() as connection:
        connection.execute(
            "UPDATE vault_metadata SET state='active', ciphertext_bytes=? WHERE account_id=?",
            (123_456, 1),
        )

    listed = client.get("/v1/admin/accounts", headers=admin_headers(token))
    assert listed.status_code == 200
    data = listed.json()
    assert data["totalSnapshotBytes"] == 123_456
    assert len(data["accounts"]) == 1
    account = data["accounts"][0]
    assert account["accountId"] == "1"
    assert account["loginName"] == "depeng"
    assert account["revoked"] is False
    assert account["vaultState"] == "active"
    assert account["revision"] == "0"
    assert account["snapshotBytes"] == 123_456
    assert account["updatedAt"] is None
    assert "staticToken" not in account
    assert "token_hash" not in account
