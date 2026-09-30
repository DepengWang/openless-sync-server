import hashlib
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from app.config import DB_PATH, STORAGE_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    login_name   TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token TEXT PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(account_id),
    expires_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_metadata (
    account_id        INTEGER PRIMARY KEY REFERENCES accounts(account_id),
    vault_id          TEXT,
    state             TEXT NOT NULL DEFAULT 'empty',
    revision          INTEGER NOT NULL DEFAULT 0,
    last_operation_id TEXT,
    etag              TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_snapshot (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id),
    body_json  TEXT NOT NULL,
    revision   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_log (
    account_id      INTEGER NOT NULL,
    operation_id    TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    fingerprint     TEXT,
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
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA secure_delete = ON")
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
        connection.execute("PRAGMA journal_mode = DELETE")
        account_columns = connection.execute("PRAGMA table_info(accounts)").fetchall()
        account_id_type = next(
            (row["type"].upper() for row in account_columns if row["name"] == "account_id"),
            None,
        )
        if account_id_type is not None and account_id_type != "INTEGER":
            _migrate_account_ids_to_integer(connection)
        connection.executescript(SCHEMA)
        _add_column(connection, "idempotency_log", "fingerprint", "TEXT")
        _hash_legacy_sessions(connection)
        connection.execute("PRAGMA user_version = 2")


def _migrate_account_ids_to_integer(connection: sqlite3.Connection) -> None:
    """Re-key existing UUID/string accounts and all dependent rows atomically."""
    existing_tables = {
        row["name"] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    if "accounts" not in existing_tables:
        return

    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("BEGIN IMMEDIATE")
    try:
        accounts = connection.execute(
            "SELECT account_id, login_name, token_hash, revoked, created_at "
            "FROM accounts ORDER BY created_at, account_id"
        ).fetchall()
        account_map: dict[str, int] = {}
        reserved: set[int] = set()
        for row in accounts:
            old_id = str(row["account_id"])
            if re.fullmatch(r"[1-9][0-9]{0,18}", old_id):
                numeric_id = int(old_id)
                if numeric_id <= 9_223_372_036_854_775_807 and numeric_id not in reserved:
                    account_map[old_id] = numeric_id
                    reserved.add(numeric_id)
        next_id = 1
        for row in accounts:
            old_id = str(row["account_id"])
            if old_id in account_map:
                continue
            while next_id in reserved:
                next_id += 1
            if next_id > 9_223_372_036_854_775_807:
                raise RuntimeError("no SQLite account ID remains available")
            account_map[old_id] = next_id
            reserved.add(next_id)
            next_id += 1

        if "vault_metadata" in existing_tables:
            active_accounts = connection.execute(
                "SELECT account_id FROM vault_metadata WHERE state='active'"
            ).fetchall()
            incompatible = [
                str(row["account_id"])
                for row in active_accounts
                if str(account_map[str(row["account_id"])]) != str(row["account_id"])
            ]
            if incompatible:
                raise RuntimeError(
                    "cannot remap an account ID that owns an active vault: its encrypted "
                    "snapshot may bind that ID in authenticated data; migrate/re-encrypt "
                    "those vaults before changing account IDs"
                )

        connection.execute(
            "CREATE TEMP TABLE account_id_map "
            "(old_account_id TEXT PRIMARY KEY, new_account_id INTEGER NOT NULL UNIQUE)"
        )
        connection.executemany(
            "INSERT INTO account_id_map (old_account_id, new_account_id) VALUES (?, ?)",
            account_map.items(),
        )

        child_tables = ("sessions", "vault_metadata", "vault_snapshot", "idempotency_log")
        for table in child_tables:
            if table in existing_tables:
                connection.execute(f"ALTER TABLE {table} RENAME TO {table}_legacy")
        connection.execute("ALTER TABLE accounts RENAME TO accounts_legacy")
        connection.execute(
            """CREATE TABLE accounts (
                 account_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 login_name TEXT NOT NULL,
                 token_hash TEXT NOT NULL UNIQUE,
                 revoked INTEGER NOT NULL DEFAULT 0,
                 created_at TEXT NOT NULL
               )"""
        )
        connection.executemany(
            """INSERT INTO accounts (account_id, login_name, token_hash, revoked, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (account_map[str(row["account_id"])], row["login_name"], row["token_hash"],
                 row["revoked"], row["created_at"])
                for row in accounts
            ],
        )

        connection.execute(
            """CREATE TABLE sessions (
                 access_token TEXT PRIMARY KEY,
                 account_id INTEGER NOT NULL REFERENCES accounts(account_id),
                 expires_at TEXT NOT NULL
               )"""
        )
        if "sessions" in existing_tables:
            session_rows = connection.execute(
                """SELECT s.access_token, m.new_account_id, s.expires_at
                   FROM sessions_legacy AS s JOIN account_id_map AS m
                   ON CAST(s.account_id AS TEXT)=m.old_account_id"""
            ).fetchall()
            connection.executemany(
                "INSERT INTO sessions (access_token, account_id, expires_at) VALUES (?, ?, ?)",
                [
                    (_hash_if_plaintext(row["access_token"]), row["new_account_id"], row["expires_at"])
                    for row in session_rows
                ],
            )

        connection.execute(
            """CREATE TABLE vault_metadata (
                 account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id),
                 vault_id TEXT,
                 state TEXT NOT NULL DEFAULT 'empty',
                 revision INTEGER NOT NULL DEFAULT 0,
                 last_operation_id TEXT,
                 etag TEXT NOT NULL,
                 updated_at TEXT NOT NULL
               )"""
        )
        if "vault_metadata" in existing_tables:
            metadata_rows = connection.execute(
                """SELECT v.account_id, v.vault_id, v.state, v.revision,
                          v.last_operation_id, v.etag, v.updated_at, m.new_account_id
                   FROM vault_metadata_legacy AS v JOIN account_id_map AS m
                   ON CAST(v.account_id AS TEXT)=m.old_account_id"""
            ).fetchall()
            connection.executemany(
                """INSERT INTO vault_metadata
                   (account_id, vault_id, state, revision, last_operation_id, etag, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (row["new_account_id"], row["vault_id"], row["state"], row["revision"],
                     row["last_operation_id"], row["etag"], row["updated_at"])
                    for row in metadata_rows
                ],
            )

        connection.execute(
            """CREATE TABLE vault_snapshot (
                 account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id),
                 body_json TEXT NOT NULL,
                 revision INTEGER NOT NULL
               )"""
        )
        if "vault_snapshot" in existing_tables:
            snapshot_rows = connection.execute(
                """SELECT v.body_json, v.revision, m.new_account_id
                   FROM vault_snapshot_legacy AS v JOIN account_id_map AS m
                   ON CAST(v.account_id AS TEXT)=m.old_account_id"""
            ).fetchall()
            connection.executemany(
                "INSERT INTO vault_snapshot (account_id, body_json, revision) VALUES (?, ?, ?)",
                [(row["new_account_id"], row["body_json"], row["revision"]) for row in snapshot_rows],
            )

        connection.execute(
            """CREATE TABLE idempotency_log (
                 account_id INTEGER NOT NULL,
                 operation_id TEXT NOT NULL,
                 response_status INTEGER NOT NULL,
                 response_body TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 fingerprint TEXT,
                 PRIMARY KEY (account_id, operation_id)
               )"""
        )
        if "idempotency_log" in existing_tables:
            log_columns = {
                row["name"] for row in connection.execute(
                    "PRAGMA table_info(idempotency_log_legacy)"
                )
            }
            fingerprint_sql = "l.fingerprint" if "fingerprint" in log_columns else "NULL"
            log_rows = connection.execute(
                f"""SELECT l.operation_id, l.response_status, l.response_body,
                           l.created_at, {fingerprint_sql} AS fingerprint, m.new_account_id
                    FROM idempotency_log_legacy AS l JOIN account_id_map AS m
                    ON CAST(l.account_id AS TEXT)=m.old_account_id"""
            ).fetchall()
            connection.executemany(
                """INSERT INTO idempotency_log
                   (account_id, operation_id, response_status, response_body, created_at, fingerprint)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (row["new_account_id"], row["operation_id"], row["response_status"],
                     row["response_body"], row["created_at"], row["fingerprint"])
                    for row in log_rows
                ],
            )

        for table in reversed(child_tables):
            if table in existing_tables:
                connection.execute(f"DROP TABLE {table}_legacy")
        connection.execute("DROP TABLE accounts_legacy")
        connection.execute("DROP TABLE account_id_map")
        connection.execute("DROP TABLE IF EXISTS used_values")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError("account ID migration produced broken foreign keys")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


def _add_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _hash_if_plaintext(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", token):
        return token
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _hash_legacy_sessions(connection: sqlite3.Connection) -> None:
    rows = connection.execute("SELECT access_token FROM sessions").fetchall()
    for row in rows:
        token = row["access_token"]
        hashed = _hash_if_plaintext(token)
        if hashed != token:
            connection.execute(
                "UPDATE sessions SET access_token=? WHERE access_token=?", (hashed, token)
            )


def ensure_vault_metadata(connection: sqlite3.Connection, account_id: int) -> sqlite3.Row:
    now = iso_utc()
    connection.execute(
        """INSERT OR IGNORE INTO vault_metadata
           (account_id, vault_id, state, revision, last_operation_id, etag, updated_at)
           VALUES (?, NULL, 'empty', 0, NULL, ?, ?)""",
        (account_id, new_etag(), now),
    )
    row = connection.execute(
        "SELECT * FROM vault_metadata WHERE account_id=?", (account_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError("vault metadata could not be initialized")
    return row
