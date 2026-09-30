import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from app.config import DB_PATH, STORAGE_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,
    login_name   TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    expires_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_metadata (
    account_id        TEXT PRIMARY KEY REFERENCES accounts(account_id),
    vault_id          TEXT,
    state             TEXT NOT NULL DEFAULT 'empty',
    revision          INTEGER NOT NULL DEFAULT 0,
    last_operation_id TEXT,
    etag              TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_snapshot (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    body_json  TEXT NOT NULL,
    revision   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_log (
    account_id      TEXT NOT NULL,
    operation_id    TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (account_id, operation_id)
);
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | None = None) -> str:
    moment = value or utc_now()
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def new_etag() -> str:
    return f'"{uuid4().hex}"'


@contextmanager
def db_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    try:
        yield connection
        if connection.in_transaction:
            connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    STORAGE_PATH.mkdir(parents=True, exist_ok=True)
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA)


def ensure_vault_metadata(connection: sqlite3.Connection, account_id: str) -> sqlite3.Row:
    now = iso_utc()
    connection.execute(
        """
        INSERT OR IGNORE INTO vault_metadata
            (account_id, vault_id, state, revision, last_operation_id, etag, updated_at)
        VALUES (?, NULL, 'empty', 0, NULL, ?, ?)
        """,
        (account_id, new_etag(), now),
    )
    row = connection.execute(
        "SELECT * FROM vault_metadata WHERE account_id = ?", (account_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError("vault metadata could not be initialized")
    return row
