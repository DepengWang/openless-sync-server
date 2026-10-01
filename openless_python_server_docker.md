# OpenLess 自建同步服务器 — Python + Docker 开发规格书

> 历史规格（早期版本）：部分协议细节已由后续实现修正。当前行为以 `README.md` 和 `app/` 中的实现为准；此文档仅保留作需求演进背景，不作为当前联调依据。

## 0. 背景（给实现者的上下文）

OpenLess 是一个开源的跨平台听写/输入法应用（Windows/macOS/Linux 桌面端 + Android），客户端代码在 `github.com/Open-Less/openless`。它自带一套**端到端加密（E2EE）多设备同步功能**，客户端 Rust 代码位于 `openless-all/app/crates/openless-core/src/cloud_sync_e2ee*`。

**现状**：这套同步机制默认依赖官方服务器 `apic.openless.top:9443`，而该服务器的登录认证走的是 **GitHub OAuth Device Flow**——客户端必须能连上 `github.com`/`api.github.com` 才能建立同步会话。在中国大陆网络环境下，这一步经常不稳定。

**本次任务目标**：实现一个**自托管的替代服务器**，具备与官方服务器完全相同的同步数据接口（客户端的加密/合并逻辑完全不用改），但认证方式换成**服务器管理员手动签发的静态 Token**，彻底不依赖 GitHub。

**重要前提**：本服务器只需要做"存储 + 认证 + 并发控制"，**不需要理解、不需要解密任何业务数据**——所有同步内容在到达服务器之前已经是客户端加密好的密文（E2EE），服务器只是一个带版本控制的密文 blob 存储 + token 校验网关。这是本项目能做得"轻量"的根本原因，请不要引入任何业务数据解析逻辑。

服务器的完整 HTTP 接口规格来自对客户端 Rust 源码（`cloud_sync_e2ee_protocol/transport.rs`、`types.rs`）的逆向整理，下面第 3 节的每一条都是从真实客户端代码里核对过的硬性要求，**不是建议，是必须**——客户端有大量 `assert`/`validate` 逻辑，字段名、字段值、HTTP 状态码但凡有一处不符，客户端会直接拒绝连接或同步失败。

---

## 1. 技术栈

| 项目 | 选型 | 理由 |
|---|---|---|
| 语言/框架 | **Python 3.12 + FastAPI** | 原生异步、Pydantic 做严格 JSON schema 校验（本协议大量字段要求 camelCase 命名 + 拒绝未知字段），单进程即可生产可用 |
| ASGI server | **uvicorn** | 与 FastAPI 官方推荐搭配，单容器单进程即可 |
| 数据库 | **SQLite**（Python 内置 `sqlite3` 模块，无需额外依赖） | 个人/小团队多设备同步场景，并发量极低，SQLite 完全够用，且免去额外容器 |
| 容器化 | **Docker + docker-compose**，单容器 | 见第 5 节 |
| HTTPS | **不在容器内处理**，交给宿主机反向代理（Caddy/Nginx）做 TLS termination，容器内只监听纯 HTTP | 简化容器逻辑；客户端强制要求 `https://` 开头的地址，但这可以由反代提供 |

---

## 2. 项目目录结构建议

```
openless-sync-server/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app 入口，挂载路由
│   ├── config.py            # 从环境变量读配置
│   ├── db.py                # SQLite 连接、建表（启动时自动建表，若不存在）
│   ├── models.py            # Pydantic 请求/响应模型（camelCase 别名）
│   ├── auth.py               # token 校验、session 签发/校验中间件
│   ├── routes/
│   │   ├── capabilities.py   # GET /v1/capabilities
│   │   ├── auth.py           # POST /v1/auth/token, DELETE /v1/auth/session
│   │   └── vault.py          # GET/PUT/DELETE /v1/me/vault*, GET /v1/me/operations/{id}
│   └── admin_cli.py           # 命令行小工具：创建账户 + 生成静态 token（不走 HTTP，本地执行）
├── data/                      # volume 挂载点：sqlite 文件 + 密文快照存这里
└── tests/
    └── test_protocol.py       # 见第 7 节验收测试，用 pytest + httpx 写
```

---

## 3. HTTP 接口详细规格（逐条硬性要求）

> 所有 JSON 字段名一律 **camelCase**。所有时间用 ISO8601 字符串。所有响应 `Content-Type: application/json`（除非另有说明）。

### 3.1 `GET /v1/capabilities`

- **认证**：无需认证，任何人可访问。
- **响应**：`200 OK`，body 必须**逐字节精确匹配**以下结构（客户端硬编码校验，任意一个数值错误都会导致客户端报 `UnsupportedProtocol` 并拒绝继续）：

```json
{
  "protocolVersion": 1,
  "cryptoProfile": "argon2id-xchacha20poly1305-v1",
  "githubClientId": "openless-selfhosted",
  "maxHttpBodyBytes": 25165824,
  "maxCiphertextBytes": 16777232,
  "maxPlaintextJsonBytes": 15728640,
  "idempotencyRetentionSeconds": 604800,
  "maxBackupRetentionDays": 30
}
```

  - `githubClientId`：任意 1-128 字节、仅由可打印 ASCII 字符组成的字符串，内容本身不校验，写死一个占位值即可（例如上面的 `"openless-selfhosted"`）。此字段名叫 github 是历史遗留，跟真实 GitHub 无关。
  - `idempotencyRetentionSeconds`：客户端要求 **≥ 604800**（即至少 7 天），写死 604800 即可。
  - `maxBackupRetentionDays`：客户端要求 **≤ 30**，写死 30 即可。
  - 其余四个数值（`protocolVersion`/`cryptoProfile`/`maxHttpBodyBytes`/`maxCiphertextBytes`/`maxPlaintextJsonBytes`）**必须与上面示例完全相等**，不可修改。

### 3.2 `POST /v1/auth/token`（新增的静态 Token 认证端点，替代官方的 `/v1/auth/github`）

- **认证**：请求头 `Authorization: Bearer <静态token>`。
- **服务器逻辑**：
  1. 从 `accounts` 表中查找与该 token 哈希匹配的账户记录。
  2. 未找到或 token 已被吊销 → `401 Unauthorized`，body：`{"code": "unauthenticated", "message": "invalid token"}`。
  3. 找到 → 在 `sessions` 表插入一条新记录：生成一个新的随机 `access_token`（建议 32 字节随机数做 base64url 编码），过期时间 = 当前时间 + 900 秒。
- **响应**（`200 OK`）：

```json
{
  "account": { "githubId": "<account_id 字符串>", "login": "<账户显示名>" },
  "accessToken": "<刚生成的随机字符串>",
  "expiresIn": 900
}
```

  - `expiresIn` 必须是 **1 到 900 之间的整数**（客户端硬性校验区间，不能超过 900）。
  - 字段名虽然叫 `account.githubId`，实际内容就是你自己账户表里的主键，跟真实 GitHub 账号无关，可以是任意字符串（建议用 UUID 或简单的用户名）。

### 3.3 `DELETE /v1/auth/session`（登出）

- **认证**：`Authorization: Bearer <access_token>`（不是静态 token，是 3.2 换回来的那个）。
- **逻辑**：从 `sessions` 表删除该 access_token 对应记录。
- **响应**：**`204 No Content`**（无 body）。客户端专门校验这个状态码，返回 200 会被当成异常。
- 若 access_token 无效/已过期 → `401`，客户端会将其当作"已经登出"处理，不视为错误。

### 3.4 认证中间件（对 3.3 之后所有 `/v1/me/*` 接口生效）

- 从 `Authorization: Bearer <access_token>` 取值，查 `sessions` 表。
- 查不到，或 `expires_at` 已过去 → 一律返回 `401 Unauthorized`，body：
  ```json
  {"code": "unauthenticated", "message": "session expired or invalid"}
  ```
  （客户端会识别 `code` 字段里的 `unauthenticated`/`session_expired` 这两个值，做出不同的重试逻辑，两个值都可以用，实现上统一用 `unauthenticated` 即可。）

### 3.5 `GET /v1/me/vault`（拉取元数据）

- **认证**：见 3.4。
- **条件请求支持**：若请求头带 `If-None-Match: <etag>` 且与当前 `vault_metadata.etag` 相等 → 返回 `304 Not Modified`，无 body。
- **否则**：返回 `200 OK`，响应头必须带 `ETag: <当前etag>`，body：

```json
{
  "ownerGithubId": "<account_id>",
  "state": "empty",
  "revision": 0,
  "vaultId": null,
  "lastOperationId": null
}
```

  - `state` 取值只能是 `"empty"` 或 `"active"`。账户第一次使用、还没上传过任何快照时是 `"empty"`。
  - `revision` 是从 0 开始的严格递增整数。
  - `etag` 的生成方式：建议直接用 `revision` 的字符串形式，或 `sha256(account_id + ":" + revision)`，只要每次 revision 变化时 etag 也跟着变、revision 不变时 etag 不变即可，客户端不关心具体算法。

### 3.6 `GET /v1/me/vault/snapshot`（拉取密文快照本体）

- **认证**：见 3.4。
- **要求请求头** `If-Match: <etag>`：若与当前 `vault_metadata.etag` 不一致 → 返回 `412 Precondition Failed`（客户端收到后会重新走 3.5 再重试）。
- **若 vault 状态是 `empty`（还没有快照）** → 返回 `404 Not Found`。
- **否则** 返回 `200 OK`，body（`ciphertext` 是 base64 编码的密文，服务器不需要、也不能解析其内容）：

```json
{
  "ownerGithubId": "<account_id>",
  "vaultId": "<vault_id>",
  "revision": 3,
  "operationId": "<上次写入时的 operation_id>",
  "kind": "snapshot",
  "baseRevision": 2,
  "ciphertext": "<base64 编码的密文 blob，原样存取，不做任何处理>"
}
```
  （具体还有哪些字段，以客户端实际发来的 upload body 结构为准——第 3.7 条服务器收到什么字段，这里原样存、原样吐出来即可，不要凭空增删字段。）

### 3.7 `PUT /v1/me/vault/snapshot`（上传新快照 —— 全部接口里最核心的一条）

- **认证**：见 3.4。
- **必须携带的请求头**：
  - `If-Match: <etag>`——必须等于当前 `vault_metadata.etag`，否则整个写入基于过期状态，需要拒绝。
  - `Idempotency-Key: <operation_id>`——同一个请求 id 的重复提交，服务器必须能识别出来。
  - `Content-Type: application/json`。
- **请求 body**：客户端发来的 JSON，至少包含 `ownerGithubId`、`vaultId`、`revision`（新版本号）、`baseRevision`（基于哪个旧版本号写的）、`operationId`、`kind`（`"create"` 或 `"snapshot"` 或 `"passwordChange"`）、`ciphertext`。服务器**原样存下整个 body**（除了要单独抽取 `revision`/`baseRevision`/`operationId` 用于并发控制判断），不需要理解每个字段的业务含义。

- **处理逻辑（严格按此顺序）**：

  1. **幂等检查**：查 `idempotency_log` 表，`(account_id, operation_id)` 是否已存在。
     - **存在** → 直接返回上次记录的响应 body 和状态码，额外加响应头 `Idempotency-Replayed: true`。**不要**重新执行任何写入逻辑。
     - **不存在** → 继续下一步。
  2. **If-Match 校验**：请求头 `If-Match` 必须等于当前 `vault_metadata.etag`，不相等 → `412 Precondition Failed`，不记入 idempotency_log（因为根本没写成功）。
  3. **乐观并发校验**：body 里的 `baseRevision` 必须等于当前 `vault_metadata.revision`；如果不相等，说明有别的设备已经抢先写过了 → 返回 **`409 Conflict`**，body：`{"code": "revision_conflict", "message": "..."}`，同样不记入 idempotency_log。
  4. **两个校验都通过**：
     - `vault_snapshot` 表整条覆盖为新的密文 body。
     - `vault_metadata.revision` = `baseRevision + 1`（也就是客户端传来的新 `revision` 值，两者应该相等，可以再做一次断言）。
     - `vault_metadata.state` 置为 `"active"`。
     - `vault_metadata.lastOperationId` = 本次 `operation_id`。
     - 生成新的 `etag`。
     - 把本次的响应结果写入 `idempotency_log`。
  5. **响应**：`200 OK`，响应头 `Idempotency-Replayed: false`，body：

  ```json
  {
    "operationId": "<本次 operation_id>",
    "revision": <新版本号>,
    "status": "committed"
  }
  ```

### 3.8 `DELETE /v1/me/vault`（删除整个 vault）

- **认证**：见 3.4。
- **逻辑**：清空该账户的 `vault_snapshot` 记录，`vault_metadata.state` 重置为 `"empty"`，`revision` 归零，生成新 `etag`。
- **响应**：`204 No Content`。

### 3.9 `GET /v1/me/operations/{operation_id}`

- **认证**：见 3.4。
- **逻辑**：查 `idempotency_log` 表是否有该 `operation_id` 的记录（跨账户查不到算未找到）。
  - 找到 → `200 OK`，`{"operationId": "...", "status": "committed"}`。
  - 没找到 → `404 Not Found`。
- 本项目 v1 版本所有写操作都是同步完成的，这个接口只是配合客户端的轮询逻辑做个简单查询，不需要真正的异步任务队列。

---

## 4. 数据库表结构（SQLite DDL，启动时若表不存在则自动创建）

```sql
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,
    login_name   TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,   -- sha256(静态token)，不存明文
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    expires_at   TEXT NOT NULL   -- ISO8601
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
    body_json  TEXT NOT NULL,   -- 原样存客户端上传的整个 JSON body（含 ciphertext 字段）
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
```

**账户/token 的管理不走 HTTP 接口**（避免暴露一个"创建账户"的公开端点带来的安全风险），而是通过 `app/admin_cli.py` 命令行工具在服务器上本地执行，例如：

```bash
docker compose exec sync-server python -m app.admin_cli create-account --login "我的账户"
# 输出：account_id=xxxx, token=<明文token，只显示这一次，自己抄下来配到客户端里>
```

---

## 5. Docker 化要求

### 5.1 `Dockerfile`

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# 非 root 用户运行
RUN useradd -m appuser
USER appuser

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### 5.2 `docker-compose.yml`

```yaml
services:
  sync-server:
    build: .
    ports:
      - "127.0.0.1:8080:8080"   # 只监听本机，对外暴露交给宿主机反代做 TLS
    volumes:
      - ./data:/app/data
    environment:
      - DB_PATH=/app/data/sync.db
      - STORAGE_PATH=/app/data
    restart: unless-stopped
```

### 5.3 `requirements.txt`

```
fastapi
uvicorn[standard]
pydantic
```

（刻意不引入 ORM/额外框架，保持依赖最小。）

### 5.4 部署验收标准

- [ ] `docker compose up -d --build` 一条命令启动成功，无需任何手动初始化步骤（建表逻辑在应用启动时自动跑）。
- [ ] 镜像体积 < 150MB（`docker images` 查看）。
- [ ] `docker compose down` 后 `docker compose up -d` 重新启动，之前创建的账户和同步数据仍然存在（验证 volume 挂载生效）。
- [ ] 容器内进程不是以 root 运行（`docker compose exec sync-server whoami` 应输出非 root 用户）。
- [ ] 容器日志中不出现明文 token、密文内容的打印（检查所有 `log`/`print` 语句，确保不泄露敏感字段）。

---

## 6. 安全要求清单

- [ ] 静态 token 在数据库中只存 `sha256` 哈希，任何日志/错误信息都不得回显明文 token。
- [ ] 所有 `/v1/me/*` 接口在未通过 3.4 认证中间件时一律 401，不允许有遗漏的未鉴权路径。
- [ ] `access_token` 严格执行 15 分钟过期，过期后的 token 即使值本身没变也必须被拒绝。
- [ ] 服务器代码里**不出现任何解密/解析 `ciphertext` 字段内容**的逻辑——这个字段对服务器来说应该完全是不透明的字节流。
- [ ] `admin_cli.py` 创建账户时生成的静态 token 用密码学安全随机数生成器（Python `secrets` 模块，不要用 `random`）。
- [ ] 所有 SQL 查询使用参数化查询，禁止字符串拼接 SQL（防注入，虽然是自用工具也要养成习惯）。

---

## 7. 验收测试清单（建议用 `pytest` + `httpx` 写成自动化测试，放在 `tests/test_protocol.py`）

1. `GET /v1/capabilities` 返回值与第 3.1 节 JSON 逐字段比对相等。
2. 用不存在的 token 调 `POST /v1/auth/token` → 401。
3. 用 `admin_cli` 建好的账户 token 调 `POST /v1/auth/token` → 200，且 `expiresIn` ≤ 900。
4. 用拿到的 `access_token` 调 `GET /v1/me/vault` → 200，`state == "empty"`，`revision == 0`，响应头有 `ETag`。
5. 带上一步拿到的 `etag` 做 `If-None-Match` 再调一次 `GET /v1/me/vault` → 304。
6. 用错误/过期的 `access_token` 调任意 `/v1/me/*` 接口 → 401。
7. 首次 `PUT /v1/me/vault/snapshot`（`baseRevision=0`）→ 200，`revision` 变成 1。
8. 用**同一个** `Idempotency-Key` 把上一步的请求原样再发一次 → 返回跟上次完全相同的 body，且响应头 `Idempotency-Replayed: true`；数据库里 `revision` 不能变成 2。
9. 换一个新的 `Idempotency-Key`，但故意把 `baseRevision` 填成过时的值（比如还是 0，而实际已经是 1）→ 409 冲突，`revision` 不变。
10. 正确递增 `baseRevision` 后再次上传 → 成功，`revision` 变成 2。
11. `GET /v1/me/vault/snapshot` 带正确 `If-Match` → 200，拿到的 `ciphertext` 与上传时完全一致（逐字节比对，验证服务器没有改动密文）。
12. `GET /v1/me/vault/snapshot` 带过时的 `If-Match` → 412。
13. `DELETE /v1/auth/session` → 204，之后用同一个 `access_token` 再请求任意接口 → 401。
14. `DELETE /v1/me/vault` → 204，之后 `GET /v1/me/vault` 的 `state` 变回 `"empty"`，`revision` 变回 0。

全部 14 条通过，即视为服务器端开发完成，可以对接客户端联调。

---

## 8. 明确不在本期范围内（不要做，避免过度设计）

- 不做多快照历史版本（v1 只保留最新一份密文，旧版本不需要留档）。
- 不做真正的异步任务队列（所有写操作都是同步完成的）。
- 不做用户自助注册/Web 管理界面（账户管理走命令行 `admin_cli.py`）。
- 不做 TLS/证书处理（交给外层反向代理）。
- 不做除本文档列出的 8 个接口之外的任何额外接口。
