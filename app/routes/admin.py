from secrets import compare_digest

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app import config
from app.admin_cli import create_account
from app.db import db_connection


router = APIRouter(prefix="/v1/admin", tags=["admin"])


class CreateAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    loginName: str = Field(min_length=1, max_length=80)


def require_admin_token(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> None:
    expected = config.ADMIN_TOKEN
    if not expected:
        raise HTTPException(status_code=503, detail="admin interface is not configured")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="admin token must be at least 32 characters")
    supplied_bytes = (x_admin_token or "").encode("utf-8")
    expected_bytes = expected.encode("utf-8")
    if not compare_digest(supplied_bytes, expected_bytes):
        raise HTTPException(status_code=401, detail="invalid admin token")


ADMIN_PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenLess 同步服务管理</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { max-width: 980px; margin: 2rem auto; padding: 0 1rem; }
    h1 { margin-bottom: .4rem; }
    .muted { opacity: .72; }
    .panel { border: 1px solid #8886; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
    form { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
    input, button { font: inherit; padding: .55rem .7rem; }
    input { min-width: min(22rem, 80vw); }
    button { cursor: pointer; }
    .status { min-height: 1.4rem; }
    .error { color: #c33; }
    .success { color: #287a3a; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: .65rem .5rem; border-bottom: 1px solid #8885; }
    th { white-space: nowrap; }
    code { overflow-wrap: anywhere; }
    [hidden] { display: none !important; }
  </style>
</head>
<body>
  <h1>OpenLess 同步服务管理</h1>
  <p class="muted">管理账户并查看当前加密快照大小。快照大小不等于 SQLite 文件的实际磁盘占用。</p>

  <section id="loginPanel" class="panel">
    <form id="loginForm">
      <label for="adminToken">管理令牌</label>
      <input id="adminToken" type="password" autocomplete="off" required>
      <button type="submit">验证并进入</button>
    </form>
    <p id="loginStatus" class="status" role="status"></p>
  </section>

  <main id="adminPanel" hidden>
    <section class="panel">
      <h2>创建用户</h2>
      <form id="createForm">
        <label for="loginName">用户名</label>
        <input id="loginName" maxlength="80" required>
        <button type="submit">创建账户</button>
      </form>
      <p id="createStatus" class="status" role="status"></p>
      <div id="tokenPanel" hidden>
        <p><strong>静态客户端 token（只显示本次，请立即复制保存）：</strong></p>
        <p><code id="newToken"></code> <button id="copyToken" type="button">复制</button></p>
      </div>
    </section>

    <section class="panel">
      <h2>用户与快照</h2>
      <p>账户数：<strong id="accountCount">0</strong>；快照密文合计：<strong id="totalBytes">0 B</strong></p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>用户名</th><th>账户状态</th><th>快照状态</th><th>Revision</th><th>快照大小</th><th>更新时间</th></tr></thead>
          <tbody id="accountsBody"></tbody>
        </table>
      </div>
      <p id="listStatus" class="status muted" role="status"></p>
      <button id="refreshButton" type="button">刷新</button>
      <button id="logoutButton" type="button">退出管理</button>
    </section>
  </main>

  <script>
    (() => {
      let adminToken = "";
      const byId = (id) => document.getElementById(id);
      const loginPanel = byId("loginPanel");
      const adminPanel = byId("adminPanel");

      function setMessage(element, message, isError = false) {
        element.textContent = message;
        element.classList.toggle("error", isError);
        element.classList.toggle("success", !isError && Boolean(message));
      }

      function formatBytes(value) {
        let number = Number(value);
        const units = ["B", "KiB", "MiB", "GiB"];
        let unit = 0;
        while (number >= 1024 && unit < units.length - 1) {
          number /= 1024;
          unit += 1;
        }
        return unit === 0 ? `${number.toLocaleString()} B` : `${number.toFixed(2)} ${units[unit]} (${Number(value).toLocaleString()} B)`;
      }

      async function adminRequest(path, options = {}) {
        const response = await fetch(path, {
          cache: "no-store",
          ...options,
          headers: { ...(options.headers || {}), "X-Admin-Token": adminToken },
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          const message = response.status === 401 ? "管理令牌无效" : (data.detail || `请求失败 (${response.status})`);
          throw new Error(message);
        }
        return data;
      }

      function addCell(row, value) {
        const cell = document.createElement("td");
        cell.textContent = value == null || value === "" ? "—" : String(value);
        row.appendChild(cell);
      }

      async function refreshAccounts() {
        setMessage(byId("listStatus"), "正在读取…");
        const data = await adminRequest("/v1/admin/accounts");
        const body = byId("accountsBody");
        body.replaceChildren();
        for (const account of data.accounts) {
          const row = document.createElement("tr");
          addCell(row, account.accountId);
          addCell(row, account.loginName);
          addCell(row, account.revoked ? "已撤销" : "正常");
          addCell(row, account.vaultState);
          addCell(row, account.revision);
          addCell(row, formatBytes(account.snapshotBytes));
          addCell(row, account.updatedAt);
          body.appendChild(row);
        }
        byId("accountCount").textContent = String(data.accounts.length);
        byId("totalBytes").textContent = formatBytes(data.totalSnapshotBytes);
        setMessage(byId("listStatus"), "已更新");
      }

      byId("loginForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        adminToken = byId("adminToken").value.trim();
        byId("adminToken").value = "";
        setMessage(byId("loginStatus"), "正在验证…");
        try {
          await refreshAccounts();
          loginPanel.hidden = true;
          adminPanel.hidden = false;
        } catch (error) {
          adminToken = "";
          setMessage(byId("loginStatus"), error.message, true);
        }
      });

      byId("createForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        byId("tokenPanel").hidden = true;
        setMessage(byId("createStatus"), "正在创建…");
        try {
          const result = await adminRequest("/v1/admin/accounts", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ loginName: byId("loginName").value }),
          });
          byId("loginName").value = "";
          byId("newToken").textContent = result.staticToken;
          byId("tokenPanel").hidden = false;
          setMessage(byId("createStatus"), `账户 ${result.accountId} 已创建。客户端 token 仅在此响应中返回一次。`);
          await refreshAccounts();
        } catch (error) {
          setMessage(byId("createStatus"), error.message, true);
        }
      });

      byId("copyToken").addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(byId("newToken").textContent);
          setMessage(byId("createStatus"), "Token 已复制。请妥善保存；离开页面后无法再次查看。");
        } catch (_) {
          setMessage(byId("createStatus"), "自动复制失败，请手动复制上方 token。", true);
        }
      });

      byId("refreshButton").addEventListener("click", async () => {
        try {
          await refreshAccounts();
        } catch (error) {
          setMessage(byId("listStatus"), error.message, true);
        }
      });

      byId("logoutButton").addEventListener("click", () => {
        adminToken = "";
        byId("accountsBody").replaceChildren();
        byId("newToken").textContent = "";
        byId("tokenPanel").hidden = true;
        adminPanel.hidden = true;
        loginPanel.hidden = false;
        setMessage(byId("loginStatus"), "已退出管理。");
      });
    })();
  </script>
</body>
</html>"""


@router.get("", response_class=HTMLResponse)
def admin_page() -> HTMLResponse:
    return HTMLResponse(ADMIN_PAGE)


@router.get("/accounts", dependencies=[Depends(require_admin_token)])
def list_accounts() -> JSONResponse:
    with db_connection() as connection:
        rows = connection.execute(
            """SELECT a.account_id, a.login_name, a.revoked, a.created_at,
                      v.state AS vault_state, v.revision, v.ciphertext_bytes, v.updated_at
               FROM accounts AS a
               LEFT JOIN vault_metadata AS v ON v.account_id = a.account_id
               ORDER BY a.account_id"""
        ).fetchall()

    accounts = [
        {
            "accountId": str(row["account_id"]),
            "loginName": row["login_name"],
            "revoked": bool(row["revoked"]),
            "createdAt": row["created_at"],
            "vaultState": row["vault_state"] or "empty",
            "revision": str(row["revision"] or 0),
            "snapshotBytes": int(row["ciphertext_bytes"] or 0),
            "updatedAt": row["updated_at"],
        }
        for row in rows
    ]
    return JSONResponse(
        {
            "accounts": accounts,
            "totalSnapshotBytes": sum(account["snapshotBytes"] for account in accounts),
        }
    )


@router.post("/accounts", status_code=201, dependencies=[Depends(require_admin_token)])
def create_account_from_admin(body: CreateAccountRequest) -> JSONResponse:
    account_id, static_token = create_account(body.loginName)
    return JSONResponse(
        status_code=201,
        content={
            "accountId": account_id,
            "loginName": body.loginName,
            "staticToken": static_token,
        },
    )
