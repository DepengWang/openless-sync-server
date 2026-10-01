# OpenLess Sync Server

[English](README.md) | [简体中文](README.zh-CN.md)

A self-hosted, Docker Compose-based sync API for OpenLess. The server stores encrypted vault snapshots as opaque data; clients are responsible for encryption and decryption.

## Configuration

The values below are non-secret examples from `.env.example`:

```dotenv
DB_PATH=/app/data/sync.db
STORAGE_PATH=/app/data
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ADMIN_TOKEN=
```

`DB_PATH` and `STORAGE_PATH` are currently set directly in `docker-compose.yml`. `PIP_INDEX_URL` can override the package index used during image builds.

To enable the private admin page, set `ADMIN_TOKEN` in your local `.env` to a long random value (at least 32 characters). Open `/v1/admin` and enter that value; the page lets you create accounts and view each account's current snapshot ciphertext size. A newly created account's static token is returned only once. If `ADMIN_TOKEN` is unset or too short, the admin APIs remain disabled. Never commit the real `.env` file, static tokens, passwords, private keys, or certificate contents. Runtime data under `data/` is excluded from Git.

## Run

```sh
docker compose up -d --build
```

The service listens on container port `8080`. In the current deployment it is bound to host loopback port `8081`; the HTTPS reverse proxy routes `/v1/` to that port.

## Protocol and authentication

The server provides the self-hosted OpenLess sync contract: account IDs are SQLite auto-increment integers exposed as decimal strings, and revisions are stored as integers but serialized as canonical decimal strings. Snapshot JSON is stored and returned unchanged; the server only decodes ciphertext bytes to enforce size limits and compute SHA-256, and never decrypts or interprets encrypted business data. PUT and DELETE use transactional compare-and-swap, full operation receipts, and idempotent replay. SQLite uses `DELETE` journaling with `synchronous=FULL` and `secure_delete=ON`; session tokens are short-lived and hashed at rest.

Authentication remains self-hosted: an administrator can create accounts and one-time static tokens through the private `/v1/admin` page or `app.admin_cli`; `POST /v1/auth/token` exchanges a user's static token for a 15-minute Bearer session and returns `protocolVersion` and `tokenType`. GitHub OAuth is not used. The `githubClientId` capability must match the Windows client's compatibility value `Ov23liyv3nEucG7oMHNE`; `githubId` and `ownerGithubId` carry this server's numeric account ID as a decimal string.

The optional `/v1/admin` page uses the fixed `ADMIN_TOKEN` environment value through an `X-Admin-Token` header. Its usage figures represent each account's current ciphertext size, not the exact physical SQLite disk-space allocation. The admin page does not store the management token in the URL or browser storage.

The startup migration preserves empty v2 accounts and sessions. It intentionally refuses to auto-upgrade a v2 database containing a stored snapshot or a still-live incomplete v2 operation receipt, because those values cannot be reconstructed losslessly in the current format.

Run the protocol tests with `uv run --with-requirements requirements-test.txt python -m pytest -q` (or install `requirements-test.txt` in a dedicated virtual environment).

## Current OpenLess sync scope (reference only)

This summarizes the OpenLess client's 2.0 E2EE cloud-sync scope for product context only; it is unrelated to this server's feature scope and is not a compatibility promise. See the upstream [encrypted cloud-sync documentation](https://github.com/Open-Less/openless/blob/v2.0.0-Beta.4-tauri/docs/encrypted-cloud-sync.md) and [document-type registry](https://github.com/Open-Less/openless/blob/v2.0.0-Beta.4-tauri/openless-all/app/crates/openless-core/src/cloud_sync_e2ee_protocol/types.rs). This server stores and returns one opaque encrypted snapshot; it does not inspect or synchronize these categories separately.

The client uses an explicit allowlist of 11 logical document types: preferences and UI preferences, channels and provider credentials, dictionary and vocabulary presets, corrections, style packs, text history, activity, and device profiles. Deletions are represented by tombstones. Provider API keys and related settings are included only inside the client-encrypted payload.

OAuth login state, sync tokens/passwords/derived keys, device private keys, remote-input PINs, operating-system permission grants, audio recordings, model weights, caches, and application binaries are excluded. Restore also preserves device-bound state and does not grant operating-system permissions.

## Implementation reference

The server-side sync implementation was informed by the original official [Open-Less/openless-cloud-sync](https://github.com/Open-Less/openless-cloud-sync) repository, whose original sign-in flow uses GitHub authentication. This project references its sync-server implementation and behavior; it does **not** adopt GitHub authentication or depend on GitHub as a sync mechanism. Authentication here is self-hosted: an administrator issues static tokens locally with `app.admin_cli`.
