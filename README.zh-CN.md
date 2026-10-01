# OpenLess 自建同步服务器

[English](README.md) | 简体中文

基于 Docker Compose 的 OpenLess 自建同步 API。服务器将加密保险库快照作为不透明数据存储；加密和解密由客户端负责。

## 配置

以下是 `.env.example` 中的非敏感示例值：

```dotenv
DB_PATH=/app/data/sync.db
STORAGE_PATH=/app/data
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
```

`DB_PATH` 和 `STORAGE_PATH` 当前直接配置在 `docker-compose.yml` 中。`PIP_INDEX_URL` 可覆盖构建镜像时使用的软件包源。

请以 `.env.example` 为模板，并勿将真实 `.env` 文件、静态 token、密码、私钥或证书内容提交到 Git。`data/` 下的运行数据已从 Git 中排除。

## 启动

```sh
docker compose up -d --build
```

服务在容器内监听 `8080` 端口。当前部署将容器端口绑定到宿主机回环地址的 `8081` 端口，再由 HTTPS 反向代理将 `/v1/` 请求转发到该端口。

## 协议与认证

服务器提供 OpenLess 自建同步协议：账户 ID 使用 SQLite 自增整数，并以十进制字符串对外返回；revision 在数据库中以整数存储，对外序列化为规范的十进制字符串。快照 JSON 原样存储和返回；服务器只解码密文字节以限制大小并计算 SHA-256，不会解密或解释加密的业务数据。PUT 和 DELETE 使用事务化比较并交换、完整操作回执和幂等重放。SQLite 使用 `DELETE` 日志模式、`synchronous=FULL` 和 `secure_delete=ON`；短期会话 token 以哈希形式存储。

认证由服务器自行管理：管理员通过 `app.admin_cli` 创建账户和静态 token；`POST /v1/auth/token` 使用静态 token 换取有效期为 15 分钟的 Bearer 会话，并返回 `protocolVersion` 和 `tokenType`。本项目不使用 GitHub OAuth。`githubClientId` capability 必须与 Windows 客户端的兼容值 `Ov23liyv3nEucG7oMHNE` 一致；`githubId` 和 `ownerGithubId` 字段承载本服务器的数字账户 ID（十进制字符串）。

启动迁移会保留空的 v2 账户和会话。如果 v2 数据库中存在已存储的快照，或仍在保留期内但不完整的 v2 操作回执，迁移会拒绝自动升级，因为无法无损地将这些数据转换为当前格式。

运行协议测试：

```sh
uv run --with-requirements requirements-test.txt python -m pytest -q
```

也可以在专用虚拟环境中安装 `requirements-test.txt` 后运行测试。

## 实现参考

服务端同步实现参考了 Open-Less 官方原始仓库 [Open-Less/openless-cloud-sync](https://github.com/Open-Less/openless-cloud-sync)，其原始登录流程使用 GitHub 认证。本项目借鉴的是同步服务端的实现与行为，**不沿用 GitHub 认证，也不依赖 GitHub 作为同步机制**；这里由管理员在本机签发静态 token，自行管理认证。
