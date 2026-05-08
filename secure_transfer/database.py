from __future__ import annotations

import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = "secure_transfer.db"


class Database:
    """Small SQLite wrapper with idempotent schema creation and light migrations."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = str(db_path)
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    recipient TEXT,
                    file_name TEXT,
                    file_hash TEXT,
                    package_hash TEXT,
                    status TEXT NOT NULL,
                    details_json TEXT,
                    prev_hash TEXT,
                    record_hash TEXT
                );

                CREATE TABLE IF NOT EXISTS shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    package_path TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    package_hash TEXT,
                    revoked INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp_utc DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type);
                CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);
                CREATE INDEX IF NOT EXISTS idx_shares_token ON shares(token);
                CREATE INDEX IF NOT EXISTS idx_shares_expiry ON shares(expires_at_utc);
                """
            )
            self._ensure_columns(conn, "audit_logs", {"prev_hash": "TEXT", "record_hash": "TEXT"})

    @staticmethod
    def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
