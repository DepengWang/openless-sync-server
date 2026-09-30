import argparse
import secrets

from app.auth import token_hash
from app.db import db_connection, ensure_vault_metadata, initialize_database, iso_utc


def create_account(login_name: str) -> tuple[str, str]:
    if not login_name.strip():
        raise ValueError("login name must not be empty")

    static_token = secrets.token_urlsafe(32)
    with db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO accounts (login_name, token_hash, revoked, created_at)
            VALUES (?, ?, 0, ?)
            """,
            (login_name.strip(), token_hash(static_token), iso_utc()),
        )
        account_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
        ensure_vault_metadata(connection, account_id)
    return str(account_id), static_token


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage local sync-server accounts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create-account")
    create_parser.add_argument("--login", required=True, help="account display name")
    args = parser.parse_args()

    initialize_database()
    if args.command == "create-account":
        account_id, static_token = create_account(args.login)
        print(f"account_id={account_id}")
        print(f"token={static_token}")


if __name__ == "__main__":
    main()
