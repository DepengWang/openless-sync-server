import sqlite3
import json

import pytest

from app import db


def make_v2_database(path, *, active=False, recent_legacy_operation=False):
    connection = sqlite3.connect(path)
    connection.executescript(
        """CREATE TABLE accounts (
               account_id INTEGER PRIMARY KEY AUTOINCREMENT,
               login_name TEXT NOT NULL,
               token_hash TEXT NOT NULL UNIQUE,
               revoked INTEGER NOT NULL DEFAULT 0,
               created_at TEXT NOT NULL
           );
           CREATE TABLE sessions (
               access_token TEXT PRIMARY KEY,
               account_id INTEGER NOT NULL REFERENCES accounts(account_id),
               expires_at TEXT NOT NULL
           );
           CREATE TABLE vault_metadata (
               account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id),
               vault_id TEXT,
               state TEXT NOT NULL DEFAULT 'empty',
               revision INTEGER NOT NULL DEFAULT 0,
               last_operation_id TEXT,
               etag TEXT NOT NULL,
               updated_at TEXT NOT NULL
           );
           CREATE TABLE vault_snapshot (
               account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id),
               body_json TEXT NOT NULL,
               revision INTEGER NOT NULL
           );
           CREATE TABLE idempotency_log (
               account_id INTEGER NOT NULL,
               operation_id TEXT NOT NULL,
               response_status INTEGER NOT NULL,
               response_body TEXT NOT NULL,
               created_at TEXT NOT NULL,
               fingerprint TEXT,
               PRIMARY KEY (account_id, operation_id)
           );
           INSERT INTO accounts (account_id, login_name, token_hash, created_at)
           VALUES (1, 'existing', 'hash', '2026-09-01T00:00:00Z');
           INSERT INTO vault_metadata
             (account_id, vault_id, state, revision, last_operation_id, etag, updated_at)
           VALUES (1, NULL, 'empty', 0, NULL, '"legacy-etag"', '2026-09-01T00:00:00Z');
           PRAGMA user_version = 2;"""
    )
    if active:
        connection.execute(
            "UPDATE vault_metadata SET vault_id='vault-legacy', state='active', revision=1 "
            "WHERE account_id=1"
        )
        connection.execute(
            "INSERT INTO vault_snapshot (account_id, body_json, revision) VALUES (1, ?, 1)",
            ('{"revision":1,"ciphertext":"opaque"}',),
        )
    if recent_legacy_operation:
        connection.execute(
            """INSERT INTO idempotency_log
               (account_id, operation_id, response_status, response_body, created_at, fingerprint)
               VALUES (1, 'old-op', 200, '{"operationId":"old-op","status":"committed"}',
                       '2099-01-01T00:00:00Z', 'legacy-fingerprint')"""
        )
    connection.commit()
    connection.close()


def initialize_at(path, monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", path)
    monkeypatch.setattr(db, "STORAGE_PATH", tmp_path)
    db.initialize_database()


def test_empty_v2_database_migrates_and_keeps_accounts(tmp_path, monkeypatch):
    path = tmp_path / "legacy-empty.db"
    make_v2_database(path)

    initialize_at(path, monkeypatch, tmp_path)

    connection = sqlite3.connect(path)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(vault_metadata)")}
    metadata = connection.execute(
        "SELECT state, revision, key_id, updated_at, ciphertext_bytes FROM vault_metadata WHERE account_id=1"
    ).fetchone()
    assert {"key_id", "payload_schema_version", "ciphertext_bytes", "ciphertext_sha256"} <= columns
    assert metadata == ("empty", 0, None, None, 0)
    assert connection.execute("SELECT login_name FROM accounts WHERE account_id=1").fetchone()[0] == "existing"
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
    connection.close()


def test_active_v2_snapshot_fails_closed_without_rewriting_data(tmp_path, monkeypatch):
    path = tmp_path / "legacy-active.db"
    make_v2_database(path, active=True)

    with pytest.raises(RuntimeError, match="active v2 vault"):
        initialize_at(path, monkeypatch, tmp_path)

    connection = sqlite3.connect(path)
    assert connection.execute("SELECT body_json FROM vault_snapshot WHERE account_id=1").fetchone()[0] == (
        '{"revision":1,"ciphertext":"opaque"}'
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(vault_metadata)")}
    assert "key_id" not in columns
    connection.close()


def test_recent_incomplete_legacy_receipt_blocks_migration_before_schema_change(
    tmp_path, monkeypatch
):
    path = tmp_path / "legacy-operation.db"
    make_v2_database(path, recent_legacy_operation=True)

    with pytest.raises(RuntimeError, match="incomplete"):
        initialize_at(path, monkeypatch, tmp_path)

    connection = sqlite3.connect(path)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(vault_metadata)")}
    assert "key_id" not in columns
    assert connection.execute(
        "SELECT operation_id FROM idempotency_log WHERE account_id=1"
    ).fetchone()[0] == "old-op"
    connection.close()


def test_legacy_empty_nonzero_revision_recovers_delete_tombstone(tmp_path, monkeypatch):
    path = tmp_path / "legacy-deleted.db"
    make_v2_database(path)
    operation_id = "e517e311-22d0-45b8-9c5d-5c16d3d04f17"
    vault_id = "be406ca5-37fa-4b26-9a9a-74c1aad48eae"
    committed_at = db.iso_utc()
    connection = sqlite3.connect(path)
    connection.execute(
        """UPDATE vault_metadata SET revision=2, last_operation_id=?, updated_at=?
           WHERE account_id=1""",
        (operation_id, committed_at),
    )
    connection.execute(
        """INSERT INTO idempotency_log
           (account_id, operation_id, response_status, response_body, created_at, fingerprint)
           VALUES (1, ?, 200, ?, ?, 'legacy-fingerprint')""",
        (
            operation_id,
            json.dumps(
                {
                    "operationId": operation_id,
                    "status": "committed",
                    "kind": "delete",
                    "committedRevision": "2",
                    "committedAt": committed_at,
                    "vaultId": vault_id,
                    "ciphertextSha256": None,
                },
                separators=(",", ":"),
            ),
            committed_at,
        ),
    )
    connection.commit()
    connection.close()

    initialize_at(path, monkeypatch, tmp_path)

    connection = sqlite3.connect(path)
    metadata = connection.execute(
        """SELECT state, revision, vault_id, key_id, updated_at, payload_schema_version,
                  ciphertext_bytes, ciphertext_sha256, last_operation_id
           FROM vault_metadata WHERE account_id=1"""
    ).fetchone()
    assert metadata == (
        "deleted", 2, vault_id, None, committed_at, None, 0, None, operation_id
    )
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
    connection.close()
