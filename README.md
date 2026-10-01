# OpenLess Sync Server

A self-hosted, Docker Compose-based sync API for OpenLess. The server stores encrypted vault snapshots as opaque data; clients are responsible for encryption and decryption.

## Configuration

The values below are non-secret examples from `.env.example`:

```dotenv
DB_PATH=/app/data/sync.db
STORAGE_PATH=/app/data
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
```

`DB_PATH` and `STORAGE_PATH` are currently set directly in `docker-compose.yml`. `PIP_INDEX_URL` can override the package index used during image builds.

Use `.env.example` as a template and keep real `.env` files, static tokens, passwords, private keys, and certificate contents out of Git. Runtime data under `data/` is excluded from Git.

## Run

```sh
docker compose up -d --build
```

The service listens on container port `8080`. In the current deployment it is bound to host loopback port `8081`; the HTTPS reverse proxy routes `/v1/` to that port.

## Protocol and authentication

The server provides the self-hosted OpenLess sync contract: account IDs are SQLite auto-increment integers exposed as decimal strings, and revisions are stored as integers but serialized as canonical decimal strings. Snapshot JSON is stored and returned unchanged; the server only decodes ciphertext bytes to enforce size limits and compute SHA-256, and never decrypts or interprets encrypted business data. PUT and DELETE use transactional compare-and-swap, full operation receipts, and idempotent replay. SQLite uses `DELETE` journaling with `synchronous=FULL` and `secure_delete=ON`; session tokens are short-lived and hashed at rest.

Authentication remains self-hosted: an administrator creates an account and static token with `app.admin_cli`; `POST /v1/auth/token` exchanges that token for a 15-minute Bearer session and returns `protocolVersion` and `tokenType`. GitHub OAuth is not used. The `githubClientId` capability must match the Windows client's compatibility value `Ov23liyv3nEucG7oMHNE`; `githubId` and `ownerGithubId` carry this server's numeric account ID as a decimal string.

The startup migration preserves empty v2 accounts and sessions. It intentionally refuses to auto-upgrade a v2 database containing a stored snapshot or a still-live incomplete v2 operation receipt, because those values cannot be reconstructed losslessly in the current format.

Run the protocol tests with `uv run --with-requirements requirements-test.txt python -m pytest -q` (or install `requirements-test.txt` in a dedicated virtual environment).

## Implementation reference

The server-side sync implementation was informed by the original official [Open-Less/openless-cloud-sync](https://github.com/Open-Less/openless-cloud-sync) repository, whose original sign-in flow uses GitHub authentication. This project references its sync-server implementation and behavior; it does **not** adopt GitHub authentication or depend on GitHub as a sync mechanism. Authentication here is self-hosted: an administrator issues static tokens locally with `app.admin_cli`.
