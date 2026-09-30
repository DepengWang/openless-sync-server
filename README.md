# OpenLess Sync Server

A self-hosted, Docker Compose-based sync API for OpenLess. The server stores encrypted vault snapshots as opaque data; clients are responsible for encryption and decryption.

## Configuration

The current workspace does not contain a production `.env` file. The non-secret settings below are documented from `.env.example`:

```dotenv
DB_PATH=/app/data/sync.db
STORAGE_PATH=/app/data
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
```

`DB_PATH` and `STORAGE_PATH` are currently set directly in `docker-compose.yml`. `PIP_INDEX_URL` can override the package index used during image builds.

Never put real static tokens, passwords, private keys, or certificate contents in this README or in `.env.example`. If documenting a real `.env` elsewhere, replace secret values with `<redacted>` before sharing it. Runtime data under `data/` is excluded from Git.

## Run

```sh
docker compose up -d --build
```

The service listens on container port `8080`. In the current deployment it is bound to host loopback port `8081`; the HTTPS reverse proxy routes `/v1/` to that port.

## Protocol and authentication

The server follows the v1 self-hosted contract in [`openless_python_server_docker_v1.md`](openless_python_server_docker_v1.md): account IDs are SQLite auto-increment integers exposed as decimal strings, revisions remain integers, and uploaded encrypted JSON is stored and returned unchanged. It never decrypts or interprets encrypted business data. Implementation hardening also uses transactional compare-and-swap writes, idempotent replay, SQLite `DELETE` journaling with `synchronous=FULL` and `secure_delete=ON`, and hashed short-lived sessions.

Authentication remains self-hosted: an administrator creates an account and static token with `app.admin_cli`; `POST /v1/auth/token` exchanges that token for a 15-minute Bearer session. GitHub OAuth is not used. The `githubClientId` capability must match the Windows client's compatibility value `Ov23liyv3nEucG7oMHNE`; `githubId` and `ownerGithubId` carry this server's numeric account ID as a decimal string.

For the API contract, deployment notes, and account administration, see [`openless_python_server_docker.md`](openless_python_server_docker.md).
