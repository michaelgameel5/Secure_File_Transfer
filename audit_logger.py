from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from .database import Database
from .models import utc_now_iso

GENESIS_HASH = "0" * 64


class AuditLogger:
    """Append-only local audit trail with a SHA-256 hash chain.

    The hash chain is a classroom-friendly tamper-evidence mechanism: every row stores
    the previous row hash and a hash of its own canonical payload. If any historic row
    is changed, chain verification fails.
    """

    def __init__(self, db_path: str | Path = "secure_transfer.db"):
        self.db = Database(db_path)

    def log(
        self,
        event_type: str,
        status: str,
        actor: str = "local-user",
        recipient: str | None = None,
        file_name: str | None = None,
        file_hash: str | None = None,
        package_hash: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        timestamp = utc_now_iso()
        details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT record_hash FROM audit_logs WHERE record_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["record_hash"] if row else GENESIS_HASH
            payload = self._canonical_payload(
                timestamp_utc=timestamp,
                event_type=event_type,
                actor=actor,
                recipient=recipient,
                file_name=file_name,
                file_hash=file_hash,
                package_hash=package_hash,
                status=status,
                details_json=details_json,
                prev_hash=prev_hash,
            )
            record_hash = self._hash(payload)
            conn.execute(
                """
                INSERT INTO audit_logs
                (timestamp_utc, event_type, actor, recipient, file_name, file_hash, package_hash, status, details_json, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    event_type,
                    actor,
                    recipient,
                    file_name,
                    file_hash,
                    package_hash,
                    status,
                    details_json,
                    prev_hash,
                    record_hash,
                ),
            )

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self.db.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'blocked'").fetchone()[0]
            success = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'success'").fetchone()[0]
            encrypted = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'FILE_ENCRYPTED'").fetchone()[0]
            latest = conn.execute("SELECT timestamp_utc FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
            events = conn.execute(
                "SELECT event_type, COUNT(*) AS count FROM audit_logs GROUP BY event_type ORDER BY count DESC"
            ).fetchall()
        return {
            "total_events": int(total),
            "blocked_actions": int(blocked),
            "successful_actions": int(success),
            "encrypted_packages": int(encrypted),
            "latest_event_utc": latest[0] if latest else "None",
            "event_breakdown": {row["event_type"]: row["count"] for row in events},
            "hash_chain_valid": self.verify_chain()["valid"],
        }

    def verify_chain(self) -> dict[str, Any]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
        expected_prev = GENESIS_HASH
        legacy_rows = 0
        for row in rows:
            data = dict(row)
            if not data.get("record_hash") or not data.get("prev_hash"):
                legacy_rows += 1
                continue
            if data["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "legacy_rows": legacy_rows,
                    "failed_at_id": data.get("id"),
                    "reason": "Previous hash does not match the prior audit record.",
                }
            payload = self._canonical_payload(
                timestamp_utc=data.get("timestamp_utc"),
                event_type=data.get("event_type"),
                actor=data.get("actor"),
                recipient=data.get("recipient"),
                file_name=data.get("file_name"),
                file_hash=data.get("file_hash"),
                package_hash=data.get("package_hash"),
                status=data.get("status"),
                details_json=data.get("details_json") or "{}",
                prev_hash=data.get("prev_hash"),
            )
            calculated = self._hash(payload)
            if calculated != data["record_hash"]:
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "legacy_rows": legacy_rows,
                    "failed_at_id": data.get("id"),
                    "reason": "Audit record hash does not match stored payload.",
                }
            expected_prev = data["record_hash"]
        return {
            "valid": True,
            "checked_rows": len(rows),
            "legacy_rows": legacy_rows,
            "failed_at_id": None,
            "reason": "Audit hash chain is valid.",
        }

    def export_json(self, output_path: str | Path, limit: int = 500) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "exported_at_utc": utc_now_iso(),
            "integrity": self.verify_chain(),
            "stats": self.stats(),
            "logs": self.recent(limit),
        }
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return output_path

    def export_csv(self, output_path: str | Path, limit: int = 500) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rows = self.recent(limit)
        headers = [
            "id",
            "timestamp_utc",
            "event_type",
            "status",
            "actor",
            "recipient",
            "file_name",
            "file_hash",
            "package_hash",
            "prev_hash",
            "record_hash",
            "details_json",
        ]
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key, "") for key in headers})
        return output_path

    @staticmethod
    def _canonical_payload(**kwargs: Any) -> str:
        return json.dumps(kwargs, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _hash(payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
