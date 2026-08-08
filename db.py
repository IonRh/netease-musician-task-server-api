from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("SERVER_API_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.getenv("SERVER_API_DB_PATH", DATA_DIR / "server_api.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS listen_records (
    account_md5         TEXT PRIMARY KEY,
    apikey              TEXT NOT NULL UNIQUE,
    enabled             INTEGER NOT NULL DEFAULT 1,
    netease_item_id     TEXT NOT NULL DEFAULT '',
    today_listen_count  INTEGER NOT NULL DEFAULT 0,
    listened_count      INTEGER NOT NULL DEFAULT 0,
    total_listen_count  INTEGER NOT NULL DEFAULT 0,
    total_listened_count INTEGER NOT NULL DEFAULT 0,
    monthly_listen_count INTEGER NOT NULL DEFAULT 0,
    monthly_listened_count INTEGER NOT NULL DEFAULT 0,
    daily_listen_limit  INTEGER NOT NULL DEFAULT 0,
    monthly_listen_limit INTEGER NOT NULL DEFAULT 0,
    count_date          TEXT NOT NULL DEFAULT (date('now','localtime')),
    count_month         TEXT NOT NULL DEFAULT (strftime('%Y-%m','now','localtime')),
    created_at          TEXT DEFAULT (datetime('now','localtime')),
    updated_at          TEXT DEFAULT (datetime('now','localtime'))
);
"""


def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(listen_records)")
        }
        if "apikey" not in columns:
            conn.execute("ALTER TABLE listen_records ADD COLUMN apikey TEXT")
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_listen_records_apikey
                ON listen_records(apikey)
                WHERE apikey IS NOT NULL AND apikey <> ''
                """
            )
        migrations = {
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "total_listen_count": "INTEGER NOT NULL DEFAULT 0",
            "total_listened_count": "INTEGER NOT NULL DEFAULT 0",
            "monthly_listen_count": "INTEGER NOT NULL DEFAULT 0",
            "monthly_listened_count": "INTEGER NOT NULL DEFAULT 0",
            "daily_listen_limit": "INTEGER NOT NULL DEFAULT 0",
            "monthly_listen_limit": "INTEGER NOT NULL DEFAULT 0",
            "count_date": "TEXT",
            "count_month": "TEXT",
        }
        for name, definition in migrations.items():
            if name not in columns:
                conn.execute(
                    f"ALTER TABLE listen_records ADD COLUMN {name} {definition}"
                )
        conn.execute(
            """
            UPDATE listen_records
            SET total_listen_count=COALESCE(total_listen_count, today_listen_count),
                total_listened_count=COALESCE(total_listened_count, listened_count),
                monthly_listen_count=COALESCE(monthly_listen_count, today_listen_count),
                monthly_listened_count=COALESCE(monthly_listened_count, listened_count),
                count_date=COALESCE(count_date, date('now','localtime')),
                count_month=COALESCE(count_month, strftime('%Y-%m','localtime'))
            """
        )
