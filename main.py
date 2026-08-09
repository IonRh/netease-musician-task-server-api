from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    from server_api.db import db, init_db
except ModuleNotFoundError:
    from db import db, init_db

app = FastAPI(title="Netease Listen Record API")


class JoinRequest(BaseModel):
    account_md5: str = Field(..., min_length=32, max_length=32)
    apikey: str = Field(..., min_length=1)
    daily_listen_limit: int = Field(0, ge=0)
    monthly_listen_limit: int = Field(0, ge=0)


class ListenRecordUpdate(BaseModel):
    account_md5: str = Field(..., min_length=32, max_length=32)
    netease_item_id: str | None = Field(None, min_length=1)
    daily_listen_limit: int | None = Field(None, ge=0)
    monthly_listen_limit: int | None = Field(None, ge=0)


class PlayFinishRequest(BaseModel):
    account_md5: str = Field(..., min_length=32, max_length=32)
    netease_item_id: str = Field(..., min_length=1, max_length=64)


def validate_account_md5(account_md5: str) -> str:
    value = account_md5.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError("account_md5 must be a 32-character hexadecimal MD5")
    return value


def validate_apikey(apikey: str) -> str:
    value = apikey.strip()
    if not value:
        raise ValueError("X-API-Key must not be empty")
    return value


def generate_apikey(account_md5: str, now: datetime | None = None) -> str:
    """Generate the hourly API key from the account MD5."""
    current = now or datetime.now()
    time_part = current.strftime("%Y%m%d%H")
    source = f"{account_md5}{time_part}"
    return hashlib.md5(source.encode("utf-8")).hexdigest()


def validate_generated_apikey(account_md5: str, apikey: str) -> str:
    normalized_md5 = validate_account_md5(account_md5)
    normalized_apikey = validate_apikey(apikey)
    expected = generate_apikey(normalized_md5)
    if not hmac.compare_digest(normalized_apikey, expected):
        raise ValueError("apikey does not match account_md5 and current hour")
    return normalized_apikey


def require_record_access(conn: Any, account_md5: str, apikey: str | None) -> Any:
    try:
        normalized_md5 = validate_account_md5(account_md5)
        normalized_apikey = validate_generated_apikey(normalized_md5, apikey or "")
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    row = conn.execute(
        """
        SELECT *
        FROM listen_records
        WHERE account_md5=?
        """,
        (normalized_md5,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="record not found")
    if row["apikey"] != normalized_apikey:
        conn.execute(
            """
            UPDATE listen_records
            SET apikey=?, updated_at=datetime('now','localtime')
            WHERE account_md5=?
            """,
            (normalized_apikey, normalized_md5),
        )
        row = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (normalized_md5,),
        ).fetchone()
    return row


def require_any_apikey(conn: Any, apikey: str | None) -> None:
    try:
        normalized_apikey = validate_apikey(apikey or "")
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    row = conn.execute(
        "SELECT 1 FROM listen_records WHERE apikey=? LIMIT 1",
        (normalized_apikey,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="invalid API key")


def require_caller_account(conn: Any, apikey: str | None) -> str:
    try:
        normalized_apikey = validate_apikey(apikey or "")
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    rows = conn.execute(
        """
        SELECT account_md5, apikey
        FROM listen_records
        WHERE enabled=1
        """
    ).fetchall()
    for row in rows:
        current_apikey = generate_apikey(row["account_md5"])
        if normalized_apikey == row["apikey"] or hmac.compare_digest(
            normalized_apikey,
            current_apikey,
        ):
            return row["account_md5"]
    raise HTTPException(status_code=401, detail="API key is not linked to an account")


def row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row)


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
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    with db() as conn:
        caller_account_md5 = require_caller_account(conn, x_api_key)
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
    return {"netease_item_id": row["netease_item_id"]}


@app.post("/api/play/finish")
def play_finish(
    body: PlayFinishRequest,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    client_md5 = validate_account_md5(body.account_md5)

    with db() as conn:
        client_row = require_record_access(conn, client_md5, x_api_key)
        if client_row["enabled"] != 1:
            raise HTTPException(status_code=404, detail="record not found")
        row = conn.execute(
            """
            SELECT *
            FROM listen_records
            WHERE netease_item_id=? AND account_md5<>? AND enabled=1
            ORDER BY listened_count ASC, updated_at ASC
            LIMIT 1
            """,
            (body.netease_item_id, client_md5),
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
def join(body: JoinRequest) -> dict[str, Any]:
    try:
        account_md5 = validate_account_md5(body.account_md5)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        apikey = validate_generated_apikey(account_md5, body.apikey)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    with db() as conn:
        existing = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (account_md5,),
        ).fetchone()
        if existing is not None:
            if existing["enabled"] == 1:
                raise HTTPException(
                    status_code=409,
                    detail="account_md5 already exists and is enabled",
                )
            conn.execute(
                """
                UPDATE listen_records
                SET apikey=?,
                    enabled=1,
                    daily_listen_limit=?,
                    monthly_listen_limit=?,
                    updated_at=datetime('now','localtime')
                WHERE account_md5=?
                """,
                (
                    apikey,
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
                    apikey,
                    body.daily_listen_limit,
                    body.monthly_listen_limit,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="account_md5 or apikey already exists",
            ) from exc
        row = conn.execute(
            "SELECT * FROM listen_records WHERE account_md5=?",
            (account_md5,),
        ).fetchone()
    return row_to_dict(row)


@app.get("/api/listen-records/{account_md5}")
def get_listen_record(
    account_md5: str,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    with db() as conn:
        row = require_record_access(conn, account_md5, x_api_key)
    if row["enabled"] != 1:
        raise HTTPException(status_code=404, detail="record not found")
    return row_to_dict(row)


@app.post("/api/update")
def update_listen_record(
    body: ListenRecordUpdate,
    x_api_key: str | None = Header(default=None),
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
        require_record_access(conn, account_md5, x_api_key)
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
    account_md5: str,
    x_api_key: str | None = Header(default=None),
) -> dict[str, bool]:
    with db() as conn:
        require_record_access(conn, account_md5, x_api_key)
        cur = conn.execute(
            """
            UPDATE listen_records
            SET enabled=0, updated_at=datetime('now','localtime')
            WHERE account_md5=?
            """,
            (account_md5,),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="record not found")
    return {"ok": True, "enabled": False}
