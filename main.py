from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException
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
    netease_item_id: str = Field(..., min_length=1)


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


def row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}




@app.get("/api/next")
def next_music(
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    with db() as conn:
        require_any_apikey(conn, x_api_key)
        row = conn.execute(
            """
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
              AND netease_item_id <> ''
              AND count_date = date('now','localtime')
              AND today_listen_count > 0
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
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no music available")
    return row_to_dict(row)


@app.post("/api/play/finish")
def play_finish(
    body: PlayFinishRequest,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    try:
        account_md5 = validate_account_md5(body.account_md5)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    with db() as conn:
        require_any_apikey(conn, x_api_key)
        row = conn.execute(
            """
            SELECT *
            FROM listen_records
            WHERE account_md5=? AND netease_item_id=? AND enabled=1
            """,
            (account_md5, body.netease_item_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="music record not found")

        monthly_count = (
            row["monthly_listened_count"]
            if row["count_month"] == datetime.now().strftime("%Y-%m")
            else 0
        )
        today_count = (
            row["listened_count"]
            if row["count_date"] == datetime.now().strftime("%Y-%m-%d")
            else 0
        )
        if row["daily_listen_limit"] > 0 and today_count >= row["daily_listen_limit"]:
            raise HTTPException(status_code=409, detail="daily listen limit reached")
        if (
            row["monthly_listen_limit"] > 0
            and monthly_count >= row["monthly_listen_limit"]
        ):
            raise HTTPException(status_code=409, detail="monthly listen limit reached")

        cur = conn.execute(
            """
            UPDATE listen_records
            SET today_listen_count=CASE
                    WHEN count_date=date('now','localtime')
                    THEN today_listen_count + 1
                    ELSE 1
                END,
                listened_count=CASE
                    WHEN count_date=date('now','localtime')
                    THEN listened_count + 1
                    ELSE 1
                END,
                total_listen_count=total_listen_count + 1,
                total_listened_count=total_listened_count + 1,
                monthly_listen_count=CASE
                    WHEN count_month=strftime('%Y-%m','now','localtime')
                    THEN monthly_listen_count + 1
                    ELSE 1
                END,
                monthly_listened_count=CASE
                    WHEN count_month=strftime('%Y-%m','localtime')
                    THEN monthly_listened_count + 1
                    ELSE 1
                END,
                count_date=date('now','localtime'),
                count_month=strftime('%Y-%m','now','localtime'),
                updated_at=datetime('now','localtime')
            WHERE account_md5=? AND netease_item_id=?
            """,
            (account_md5, body.netease_item_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="music record not found")
        row = conn.execute(
            """
            SELECT account_md5, netease_item_id,
                   today_listen_count, listened_count,
                   total_listen_count, total_listened_count,
                   monthly_listen_count, monthly_listened_count,
                   daily_listen_limit, monthly_listen_limit
            FROM listen_records
            WHERE account_md5=? AND netease_item_id=?
            """,
            (account_md5, body.netease_item_id),
        ).fetchone()
    return row_to_dict(row)


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
