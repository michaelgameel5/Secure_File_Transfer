from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .audit_logger import AuditLogger
from .database import Database
from .utils import b64url_json, sha256_file, unb64url_json


class ShareManager:
    def __init__(self, db_path: str | Path = "secure_transfer.db"):
        self.db = Database(db_path)
        self.audit = AuditLogger(db_path)

    def create_share_link(
        self,
        package_path: str | Path,
        recipient_email: str,
        expires_at_utc: str,
        package_hash: str | None = None,
        base_url: str | None = None,
    ) -> str:
        package_path = str(Path(package_path).resolve())
        package_hash = package_hash or sha256_file(package_path)
        random_id = secrets.token_urlsafe(18)
        token = b64url_json(
            {
                "v": 1,
                "id": random_id,
                "recipient": recipient_email,
                "expires_at_utc": expires_at_utc,
                "package_hash": package_hash,
            }
        )
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO shares
                (token, package_path, recipient, expires_at_utc, created_at_utc, package_hash, revoked)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    token,
                    package_path,
                    recipient_email,
                    expires_at_utc,
                    datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                    package_hash,
                ),
            )
        self.audit.log(
            event_type="SHARE_LINK_CREATED",
            status="success",
            recipient=recipient_email,
            package_hash=package_hash,
            details={"expires_at_utc": expires_at_utc},
        )
        if base_url:
            return f"{base_url.rstrip('/')}/share/{token}"
        return f"sftdlp://share/{token}"

    def resolve_link(self, share_link: str) -> dict[str, Any]:
        token = share_link.rsplit("/", 1)[-1]
        decoded = unb64url_json(token)
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM shares WHERE token = ?", (token,)).fetchone()
        if not row:
            raise ValueError("Share link is unknown on this local machine.")
        row_data = dict(row)
        if row_data["revoked"]:
            raise ValueError("Share link has been revoked.")
        expires = datetime.fromisoformat(row_data["expires_at_utc"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            raise ValueError("Share link has expired.")
        if decoded.get("package_hash") != row_data.get("package_hash"):
            raise ValueError("Share link integrity check failed.")
        return row_data

    def list_shares(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT id, package_path, recipient, expires_at_utc, created_at_utc, package_hash, revoked FROM shares ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_link(self, share_link: str) -> None:
        token = share_link.rsplit("/", 1)[-1]
        with self.db.connect() as conn:
            conn.execute("UPDATE shares SET revoked = 1 WHERE token = ?", (token,))
        self.audit.log(event_type="SHARE_LINK_REVOKED", status="success", details={"token_prefix": token[:12]})


def expires_after_hours(hours: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(microsecond=0).isoformat()
