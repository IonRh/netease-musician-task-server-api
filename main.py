from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    from server_api.db import db, init_db
except ModuleNotFoundError:
    from db import db, init_db

app = FastAPI(title="Netease Listen Record API")


class JoinRequest(BaseModel):
    account_md5: str = Field(..., min_length=32, max_length=32)
    daily_listen_limit: int = Field(0, ge=0, le=10000)
    monthly_listen_limit: int = Field(0, ge=0, le=300000)


class ListenRecordUpdate(BaseModel):
    account_md5: str = Field(..., min_length=32, max_length=32)
    netease_item_id: str | None = Field(None, min_length=1, max_length=128)
    daily_listen_limit: int | None = Field(None, ge=0, le=10000)
    monthly_listen_limit: int | None = Field(None, ge=0, le=300000)


class PlayFinishRequest(BaseModel):
    account_md5: str = Field(..., min_length=32, max_length=32)
    netease_item_id: str = Field(..., min_length=1, max_length=64)
    task_id: str = Field(..., min_length=16, max_length=128)
    play_token: str = Field(..., min_length=16, max_length=256)


class ClientTokenCreateRequest(BaseModel):
    label: str = Field("", max_length=100)


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int, window: int = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            values = [value for value in self._events.get(key, []) if now - value < window]
            allowed = len(values) < limit
            if allowed:
                values.append(now)
            self._events[key] = values
            return allowed


rate_limiter = SlidingWindowLimiter()
ADMIN_TOKEN = os.getenv("SERVER_API_ADMIN_TOKEN", "").strip()


def validate_account_md5(account_md5: str) -> str:
    value = account_md5.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError("account_md5 must be a 32-character hexadecimal MD5")
    return value


def parse_account_md5(account_md5: str | None) -> str:
    try:
        return validate_account_md5(account_md5 or "")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def hash_client_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_admin(request: Request) -> None:
    check_rate(request, "admin")
    if not ADMIN_TOKEN or not hmac.compare_digest(
        request.headers.get("X-Admin-Token", ""), ADMIN_TOKEN
    ):
        with db() as conn:
            record_risk(conn, None, request, "invalid_admin_token", severity=2)
        raise HTTPException(status_code=403, detail="admin authorization required")


def record_risk(
    conn: Any,
    token_id: int | None,
    request: Request,
    event_type: str,
    severity: int = 1,
    detail: str = "",
) -> None:
    conn.execute(
        "INSERT INTO risk_events(token_id,client_ip,event_type,severity,detail) VALUES (?,?,?,?,?)",
        (token_id, client_ip(request), event_type, max(1, severity), detail[:500]),
    )
    if token_id is not None:
        conn.execute(
            "UPDATE client_tokens SET risk_score=risk_score+?, risk_state=CASE WHEN risk_score+? >= 10 THEN 'quarantined' WHEN risk_score+? >= 5 THEN 'suspect' ELSE risk_state END WHERE id=?",
            (max(1, severity), max(1, severity), max(1, severity), token_id),
        )
    # 风险事件通常紧接着 HTTPException，需在异常传播前显式持久化。
    conn.commit()


def check_rate(
    request: Request,
    action: str,
    token_id: int | None = None,
    conn: Any | None = None,
) -> None:
    ip = client_ip(request)
    token_limit, ip_limit = {
        "auth": (120, 180),
        "next": (30, 60),
        "finish": (30, 60),
        "record": (60, 120),
        "join": (10, 30),
        "update": (10, 30),
        "leave": (10, 30),
        "admin": (20, 20),
    }.get(action, (20, 30))
    keys = [(f"ip:{ip}:{action}", ip_limit)]
    if token_id is not None:
        keys.append((f"token:{token_id}:{action}", token_limit))
    if not all(rate_limiter.allow(key, limit) for key, limit in keys):
        if conn is not None:
            record_risk(conn, token_id, request, "rate_limit", severity=2, detail=action)
        else:
            with db() as risk_conn:
                record_risk(risk_conn, token_id, request, "rate_limit", severity=2, detail=action)
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试", headers={"Retry-After": "60"})


def require_client(
    conn: Any,
    request: Request,
    account_md5: str | None = None,
    *,
    bind: bool = False,
) -> Any:
    raw_token = request.headers.get("X-Client-Token", "").strip()
    if len(raw_token) < 16:
        raise HTTPException(status_code=401, detail="缺少有效的客户端 Token")
    row = conn.execute(
        "SELECT * FROM client_tokens WHERE token_hash=?",
        (hash_client_token(raw_token),),
    ).fetchone()
    if row is None:
        record_risk(conn, None, request, "invalid_token", severity=2)
        raise HTTPException(status_code=401, detail="客户端 Token 无效")
    check_rate(request, "auth", int(row["id"]), conn)
    if row["enabled"] != 1 or row["risk_state"] == "quarantined":
        raise HTTPException(status_code=403, detail="客户端已被暂停或隔离")
    if account_md5 is not None:
        normalized = validate_account_md5(account_md5)
        bound = conn.execute(
            "SELECT 1 FROM client_token_accounts WHERE token_id=? AND account_md5=?",
            (row["id"], normalized),
        ).fetchone()
        if bound is None:
            if not bind:
                record_risk(conn, int(row["id"]), request, "unbound_account", severity=2, detail=normalized)
                raise HTTPException(status_code=403, detail="客户端 Token 未绑定此账号")
            binding_count = conn.execute(
                "SELECT COUNT(*) AS n FROM client_token_accounts WHERE token_id=?",
                (row["id"],),
            ).fetchone()["n"]
            if binding_count >= 20:
                record_risk(conn, int(row["id"]), request, "binding_limit", severity=3)
                raise HTTPException(status_code=409, detail="客户端 Token 已达到账号绑定上限")
            conn.execute(
                "INSERT OR IGNORE INTO client_token_accounts(token_id,account_md5) VALUES (?,?)",
                (row["id"], normalized),
            )
    conn.execute(
        "UPDATE client_tokens SET last_seen_at=datetime('now','localtime') WHERE id=?",
        (row["id"],),
    )
    return row


def token_headers(
    request: Request,
    token_id: int | None = None,
    action: str = "request",
    conn: Any | None = None,
) -> None:
    check_rate(request, action, token_id, conn)


def row_to_dict(row: Any) -> dict[str, Any]:
    result = dict(row)
    result.pop("apikey", None)
    result.pop("token_hash", None)
    result.pop("play_token_hash", None)
    return result


@app.post("/api/admin/client-tokens")
def create_client_token(request: Request, body: ClientTokenCreateRequest) -> dict[str, Any]:
    """创建独立客户端 Token；原始 Token 只在本次响应中返回。"""
    require_admin(request)
    raw_token = f"nmt_{secrets.token_urlsafe(32)}"
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO client_tokens(token_hash,label) VALUES (?,?)",
            (hash_client_token(raw_token), body.label.strip()),
        )
        token_id = cursor.lastrowid
    return {"id": token_id, "token": raw_token, "label": body.label.strip(), "warning": "Token 只显示这一次，请安全保存"}


@app.get("/api/admin/client-tokens")
def list_client_tokens(request: Request) -> list[dict[str, Any]]:
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,label,enabled,risk_score,risk_state,created_at,last_seen_at FROM client_tokens ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/client-tokens/{token_id}/revoke")
def revoke_client_token(request: Request, token_id: int) -> dict[str, Any]:
    require_admin(request)
    with db() as conn:
        cursor = conn.execute("UPDATE client_tokens SET enabled=0 WHERE id=?", (token_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="client token not found")
    return {"ok": True, "enabled": False}


@app.post("/api/admin/client-tokens/{token_id}/release")
def release_client_token(request: Request, token_id: int) -> dict[str, Any]:
    require_admin(request)
    with db() as conn:
        cursor = conn.execute(
            "UPDATE client_tokens SET enabled=1,risk_score=0,risk_state='normal' WHERE id=?",
            (token_id,),
        )
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="client token not found")
    return {"ok": True, "enabled": True, "risk_state": "normal"}


@app.get("/api/admin/risk-events")
def list_risk_events(request: Request, limit: int = 100) -> list[dict[str, Any]]:
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT r.id,r.token_id,t.label,r.client_ip,r.event_type,r.severity,r.detail,r.created_at FROM risk_events r LEFT JOIN client_tokens t ON t.id=r.token_id ORDER BY r.id DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/admin/tokens", response_class=HTMLResponse)
def token_admin_page() -> str:
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>客户端 Token 管理</title><style>
body{font-family:"Microsoft YaHei",sans-serif;margin:0;background:#f5f7fa;color:#17212b}main{max-width:900px;margin:36px auto;padding:0 20px}
.bar{display:grid;grid-template-columns:1fr 1fr auto;gap:10px}.panel{background:white;border:1px solid #dfe5ec;border-radius:8px;padding:20px;margin-bottom:18px}
input,button{font:inherit;padding:9px;border:1px solid #cbd5e1;border-radius:6px}button{cursor:pointer}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left}.warn{color:#b45309}.token{word-break:break-all;background:#f8fafc;padding:10px}
</style></head><body><main><h1>客户端 Token 管理</h1>
<p class="warn">Token 只在创建时显示一次。公共互助可能触发平台风控，请只向可信客户端分发。</p>
<section class="panel"><div class="bar"><input id="admin" type="password" placeholder="SERVER_API_ADMIN_TOKEN"><input id="label" placeholder="客户端备注"><button onclick="createToken()">生成 Token</button></div><p id="created" class="token"></p></section>
<section class="panel"><button onclick="loadTokens()">刷新列表</button><table><thead><tr><th>ID</th><th>备注</th><th>状态</th><th>风险</th><th>最后访问</th></tr></thead><tbody id="rows"></tbody></table></section>
<script>
const headers=()=>({'X-Admin-Token':document.querySelector('#admin').value,'Content-Type':'application/json'});
const esc=(value)=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
async function createToken(){const r=await fetch('/api/admin/client-tokens',{method:'POST',headers:headers(),body:JSON.stringify({label:document.querySelector('#label').value})});const d=await r.json();document.querySelector('#created').textContent=r.ok?'新 Token：'+d.token:(d.detail||'创建失败');if(r.ok)loadTokens()}
async function loadTokens(){const r=await fetch('/api/admin/client-tokens',{headers:headers()});const d=await r.json();if(!r.ok){alert(d.detail||'读取失败');return}document.querySelector('#rows').innerHTML=d.map(x=>`<tr><td>${x.id}</td><td>${esc(x.label||'-')}</td><td>${x.enabled?'启用':'停用'}</td><td>${esc(x.risk_state)} (${x.risk_score})</td><td>${esc(x.last_seen_at||'-')}</td></tr>`).join('')}
</script></main></body></html>"""


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    with db() as conn:
        stats = conn.execute(
            """
            SELECT
                COUNT(*) AS user_count,
                COALESCE(SUM(
                    CASE
                        WHEN enabled=1
                         AND count_date=date('now','localtime')
                         AND today_listen_count > 0
                        THEN 1
                        ELSE 0
                    END
                ), 0)
                    AS active_user_count,
                COALESCE(SUM(
                    CASE
                        WHEN count_date=date('now','localtime')
                        THEN today_listen_count
                        ELSE 0
                    END
                ), 0) AS today_listen_count,
                COALESCE(SUM(
                    CASE
                        WHEN count_month=strftime('%Y-%m','now','localtime')
                        THEN monthly_listen_count
                        ELSE 0
                END
                ), 0) AS monthly_listen_count,
                COALESCE(SUM(total_listen_count), 0) AS total_listen_count,
                MAX(updated_at) AS latest_data_time
            FROM listen_records
            """
        ).fetchone()

    values = {
        "user_count": int(stats["user_count"]),
        "active_user_count": int(stats["active_user_count"]),
        "today_listen_count": int(stats["today_listen_count"]),
        "monthly_listen_count": int(stats["monthly_listen_count"]),
        "total_listen_count": int(stats["total_listen_count"]),
        "latest_data_time": stats["latest_data_time"] or "暂无数据",
    }
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>音乐任务系统</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17212b;
      --muted: #64748b;
      --line: #e2e8f0;
      --paper: #f8fafc;
      --white: #ffffff;
      --accent: #2563eb;
      --accent-soft: #dbeafe;
      --green: #15803d;
      --green-soft: #dcfce7;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: var(--paper);
      color: var(--ink);
      font-family: Inter, "Microsoft YaHei", sans-serif;
    }}
    main {{ width: min(1120px, calc(100% - 40px)); margin: 0 auto; padding: 48px 0 56px; }}
    header {{ display: flex; align-items: center; justify-content: space-between; gap: 24px; margin-bottom: 28px; padding-bottom: 28px; border-bottom: 1px solid var(--line); }}
    h1 {{ margin: 0; font-size: 32px; line-height: 1.15; letter-spacing: 0; }}
    .subtitle {{ margin: 10px 0 0; color: var(--muted); font-size: 14px; }}
    .header-meta {{ display: flex; align-items: center; gap: 14px; }}
    .status {{ display: inline-flex; align-items: center; gap: 8px; color: var(--green); font-size: 13px; font-weight: 600; }}
    .status-dot {{ width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px var(--green-soft); }}
    button {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--white);
      color: var(--ink);
      padding: 10px 14px;
      font: inherit;
      cursor: pointer;
    }}
    button:hover {{ border-color: var(--accent); color: var(--accent); }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
    .stat {{
      min-height: 156px;
      padding: 22px;
      background: var(--white);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 4px 14px rgba(15, 23, 42, .04);
    }}
    .stat.primary {{ background: var(--accent); border-color: var(--accent); color: var(--white); box-shadow: 0 8px 20px rgba(37, 99, 235, .18); }}
    .stat.green {{ background: var(--green-soft); border-color: #bbf7d0; }}
    .stat.time {{ background: #fff7ed; border-color: #fed7aa; }}
    .label {{ color: var(--muted); font-size: 14px; }}
    .primary .label {{ color: var(--accent-soft); }}
    .green .label {{ color: var(--green); }}
    .time .label {{ color: #c2410c; }}
    .value {{ margin-top: 22px; font-size: 40px; line-height: 1; font-weight: 700; letter-spacing: 0; }}
    .time .value {{ margin-top: 24px; color: #9a3412; font-size: 20px; line-height: 1.35; word-break: break-word; }}
    footer {{ display: flex; justify-content: space-between; gap: 16px; margin-top: 22px; color: var(--muted); font-size: 13px; }}
    @media (max-width: 720px) {{
      main {{ width: min(100% - 24px, 520px); padding: 32px 0; }}
      header {{ align-items: flex-start; flex-direction: column; padding-bottom: 22px; }}
      .header-meta {{ width: 100%; justify-content: space-between; }}
      .grid {{ grid-template-columns: 1fr; }}
      .value {{ font-size: 36px; }}
      footer {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>音乐任务系统</h1>
        <p class="subtitle">系统运行概况</p>
      </div>
      <div class="header-meta">
        <span class="status"><span class="status-dot"></span>ONLINE</span>
        <button type="button" onclick="location.reload()">刷新数据</button>
      </div>
    </header>
    <section class="grid" aria-label="系统统计">
      <article class="stat primary">
        <div class="label">用户总数</div>
        <div class="value">{values["user_count"]:,}</div>
      </article>
      <article class="stat green">
        <div class="label">活跃用户数</div>
        <div class="value">{values["active_user_count"]:,}</div>
      </article>
      <article class="stat time">
        <div class="label">最新数据时间</div>
        <div class="value">{values["latest_data_time"]}</div>
      </article>
      <article class="stat">
        <div class="label">今日总听歌</div>
        <div class="value">{values["today_listen_count"]:,}</div>
      </article>
      <article class="stat">
        <div class="label">本月总听歌数</div>
        <div class="value">{values["monthly_listen_count"]:,}</div>
      </article>
      <article class="stat">
        <div class="label">总听歌数</div>
        <div class="value">{values["total_listen_count"]:,}</div>
      </article>
    </section>
    <footer>
      <span>数据来自当前 实时统计</span>
      <span>公益站点，请勿破坏</span>
    </footer>
  </main>
</body>
</html>"""


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}




@app.get("/api/next")
def next_music(
    request: Request,
    x_account_md5: str | None = Header(default=None, alias="X-Account-MD5"),
) -> dict[str, Any]:
    with db() as conn:
        caller_account_md5 = parse_account_md5(x_account_md5)
        token = require_client(conn, request, caller_account_md5)
        token_headers(request, int(token["id"]), "next", conn)
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute(
            "SELECT COUNT(*) AS n FROM play_leases WHERE token_id=? AND listener_account_md5=? AND status='assigned' AND expires_at > datetime('now','localtime')",
            (token["id"], caller_account_md5),
        ).fetchone()["n"]
        if active >= 2:
            raise HTTPException(status_code=409, detail="当前账号已有未完成的听歌任务")
        select_sql = """
            SELECT
                account_md5,
                netease_item_id,
                today_listen_count,
                listened_count,
                total_listen_count,
                total_listened_count,
                monthly_listen_count,
                monthly_listened_count,
                daily_listen_limit,
                monthly_listen_limit
            FROM listen_records
            WHERE enabled=1
              AND account_md5 <> ?
              AND netease_item_id <> ''
              {activity_filter}
              AND (
                  daily_listen_limit = 0
                  OR CASE
                      WHEN count_date = date('now','localtime')
                      THEN listened_count
                      ELSE 0
                  END < daily_listen_limit
              )
              AND (
                  monthly_listen_limit = 0
                  OR CASE
                      WHEN count_month = strftime('%Y-%m','localtime')
                      THEN monthly_listened_count
                      ELSE 0
                  END < monthly_listen_limit
              )
            ORDER BY
                listened_count ASC,
                CASE
                    WHEN count_date = date('now','localtime')
                    THEN today_listen_count
                    ELSE 0
                END ASC,
                updated_at ASC
            LIMIT 1
        """
        row = conn.execute(
            select_sql.format(
                activity_filter=(
                    "AND count_date = date('now','localtime') "
                    "AND today_listen_count > 0"
                )
            ),
            (caller_account_md5,),
            ).fetchone()
        if row is None:
            row = conn.execute(
                select_sql.format(activity_filter=""),
                (caller_account_md5,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="no music available")
        task_id = secrets.token_urlsafe(18)
        play_token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO play_leases(task_id,token_id,listener_account_md5,target_account_md5,netease_item_id,play_token_hash,expires_at,client_ip) VALUES (?,?,?,?,?,?,datetime('now','localtime','+30 minutes'),?)",
            (task_id, token["id"], caller_account_md5, row["account_md5"], row["netease_item_id"], hash_client_token(play_token), client_ip(request)),
        )
        return {"task_id": task_id, "play_token": play_token, "netease_item_id": row["netease_item_id"], "expires_in": 1800}


@app.post("/api/play/finish")
def play_finish(
    request: Request,
    body: PlayFinishRequest,
) -> dict[str, Any]:
    client_md5 = parse_account_md5(body.account_md5)

    with db() as conn:
        token = require_client(conn, request, client_md5)
        token_headers(request, int(token["id"]), "finish", conn)
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        lease = conn.execute(
            "SELECT * FROM play_leases WHERE task_id=? AND token_id=? AND listener_account_md5=? AND play_token_hash=?",
            (body.task_id, token["id"], client_md5, hash_client_token(body.play_token)),
        ).fetchone()
        if lease is None:
            record_risk(conn, int(token["id"]), request, "invalid_task", severity=3, detail=body.task_id)
            raise HTTPException(status_code=403, detail="任务凭证无效")
        if lease["status"] != "assigned":
            record_risk(conn, int(token["id"]), request, "replay", severity=3, detail=body.task_id)
            raise HTTPException(status_code=409, detail="任务已提交，禁止重复记账")
        if lease["expires_at"] < datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
            record_risk(conn, int(token["id"]), request, "expired_task", severity=1, detail=body.task_id)
            raise HTTPException(status_code=409, detail="任务凭证已过期")
        if lease["netease_item_id"] != body.netease_item_id:
            record_risk(conn, int(token["id"]), request, "task_item_mismatch", severity=3, detail=body.task_id)
            raise HTTPException(status_code=403, detail="任务歌曲不匹配")
        client_row = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (client_md5,),
        ).fetchone()
        if client_row is None:
            raise HTTPException(status_code=404, detail="record not found")
        if client_row["enabled"] != 1:
            raise HTTPException(status_code=404, detail="record not found")
        row = conn.execute(
            """
            SELECT *
            FROM listen_records
            WHERE account_md5=? AND netease_item_id=? AND enabled=1
            """,
            (lease["target_account_md5"], body.netease_item_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="music record not found")

        monthly_count = (
            row["monthly_listened_count"]
            if str(row["updated_at"])[:7] == datetime.now().strftime("%Y-%m")
            else 0
        )
        today_count = (
            row["listened_count"]
            if str(row["updated_at"])[:10] == datetime.now().strftime("%Y-%m-%d")
            else 0
        )
        if row["daily_listen_limit"] > 0 and today_count >= row["daily_listen_limit"]:
            raise HTTPException(status_code=409, detail="daily listen limit reached")
        if (
            row["monthly_listen_limit"] > 0
            and monthly_count >= row["monthly_listen_limit"]
        ):
            raise HTTPException(status_code=409, detail="monthly listen limit reached")

        conn.execute(
            """
            UPDATE listen_records
            SET today_listen_count=CASE
                    WHEN count_date=date('now','localtime')
                    THEN today_listen_count + 1
                    ELSE 1
                END,
                total_listen_count=total_listen_count + 1,
                monthly_listen_count=CASE
                    WHEN count_month=strftime('%Y-%m','now','localtime')
                    THEN monthly_listen_count + 1
                    ELSE 1
                END,
                count_date=date('now','localtime'),
                count_month=strftime('%Y-%m','now','localtime'),
                updated_at=datetime('now','localtime')
            WHERE account_md5=?
            """,
            (client_md5,),
        )
        conn.execute(
            """
            UPDATE listen_records
            SET listened_count=CASE
                    WHEN substr(updated_at, 1, 10)=date('now','localtime')
                    THEN listened_count + 1
                    ELSE 1
                END,
                total_listened_count=total_listened_count + 1,
                monthly_listened_count=CASE
                    WHEN substr(updated_at, 1, 7)=strftime('%Y-%m','now','localtime')
                    THEN monthly_listened_count + 1
                    ELSE 1
                END,
                updated_at=datetime('now','localtime')
            WHERE account_md5=? AND netease_item_id=? AND enabled=1
            """,
            (row["account_md5"], body.netease_item_id),
        )
        conn.execute(
            "UPDATE play_leases SET status='finished', completed_at=datetime('now','localtime') WHERE task_id=? AND status='assigned'",
            (body.task_id,),
        )
        result = conn.execute(
            """
            SELECT account_md5, today_listen_count,
                   total_listen_count, monthly_listen_count
            FROM listen_records
            WHERE account_md5=?
            """,
            (client_md5,),
        ).fetchone()
    return row_to_dict(result)


@app.post("/api/join")
def join(request: Request, body: JoinRequest) -> dict[str, Any]:
    try:
        account_md5 = validate_account_md5(body.account_md5)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    with db() as conn:
        token = require_client(conn, request, account_md5, bind=True)
        token_headers(request, int(token["id"]), "join", conn)
        # apikey 保留在旧表中仅为兼容旧数据库，不再作为认证凭据。
        legacy_key = secrets.token_hex(32)
        existing = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (account_md5,),
        ).fetchone()
        if existing is not None:
            conn.execute(
                """
                UPDATE listen_records
                SET enabled=1,
                    daily_listen_limit=?,
                    monthly_listen_limit=?,
                    updated_at=datetime('now','localtime')
                WHERE account_md5=?
                """,
                (
                    body.daily_listen_limit,
                    body.monthly_listen_limit,
                    account_md5,
                ),
            )
            row = conn.execute(
                "SELECT * FROM listen_records WHERE account_md5=?",
                (account_md5,),
            ).fetchone()
            return row_to_dict(row)

        try:
            conn.execute(
                """
                INSERT INTO listen_records(
                    account_md5,
                    apikey,
                    enabled,
                    netease_item_id,
                    daily_listen_limit,
                    monthly_listen_limit
                )
                VALUES (?, ?, 1, '', ?, ?)
                """,
                (
                    account_md5,
                    legacy_key,
                    body.daily_listen_limit,
                    body.monthly_listen_limit,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="account_md5 already exists",
            ) from exc
        row = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (account_md5,),
        ).fetchone()
    return row_to_dict(row)


@app.get("/api/listen-records/{account_md5}")
def get_listen_record(
    request: Request,
    account_md5: str,
) -> dict[str, Any]:
    with db() as conn:
        normalized = parse_account_md5(account_md5)
        token = require_client(conn, request, normalized)
        token_headers(request, int(token["id"]), "record", conn)
        row = conn.execute("SELECT * FROM listen_records WHERE account_md5=?", (normalized,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="record not found")
    if row["enabled"] != 1:
        raise HTTPException(status_code=404, detail="record not found")
    return row_to_dict(row)


@app.post("/api/update")
def update_listen_record(
    request: Request,
    body: ListenRecordUpdate,
) -> dict[str, Any]:
    try:
        account_md5 = validate_account_md5(body.account_md5)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    fields = body.model_dump(exclude_unset=True, exclude={"account_md5"})
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")

    sets = [f"{key}=?" for key in fields]
    values = list(fields.values())
    values.append(account_md5)

    with db() as conn:
        token = require_client(conn, request, account_md5)
        token_headers(request, int(token["id"]), "update", conn)
        if "enabled" in fields:
            raise HTTPException(status_code=400, detail="enabled cannot be changed by client")
        conn.execute(
            f"""
            UPDATE listen_records
            SET {', '.join(sets)}, updated_at=datetime('now','localtime')
            WHERE account_md5=?
            """,
            values,
        )
        row = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (account_md5,),
        ).fetchone()
    return row_to_dict(row)


@app.delete("/api/listen-records/{account_md5}")
def delete_listen_record(
    request: Request,
    account_md5: str,
) -> dict[str, bool]:
    with db() as conn:
        normalized = parse_account_md5(account_md5)
        token = require_client(conn, request, normalized)
        token_headers(request, int(token["id"]), "leave", conn)
        cur = conn.execute(
            """
            UPDATE listen_records
            SET enabled=0, updated_at=datetime('now','localtime')
            WHERE account_md5=?
            """,
            (normalized,),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="record not found")
    return {"ok": True, "enabled": False}
