from __future__ import annotations

import sqlite3

from secure_transfer.audit_logger import AuditLogger


def test_audit_hash_chain_detects_tampering(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLogger(db)
    audit.log("DLP_SCAN", "success", details={"severity": "clean"})
    audit.log("FILE_ENCRYPTED", "success", package_hash="abc")

    assert audit.verify_chain()["valid"] is True

    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_logs SET status = 'blocked' WHERE id = 1")

    result = audit.verify_chain()
    assert result["valid"] is False
    assert result["failed_at_id"] == 1


def test_audit_exports_json_and_csv(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLogger(db)
    audit.log("DLP_SCAN", "success")

    json_path = audit.export_json(tmp_path / "audit.json")
    csv_path = audit.export_csv(tmp_path / "audit.csv")

    assert json_path.exists()
    assert csv_path.exists()
    assert "hash_chain_valid" in json_path.read_text(encoding="utf-8")
    assert "record_hash" in csv_path.read_text(encoding="utf-8")
