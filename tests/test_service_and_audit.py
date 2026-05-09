from pathlib import Path

from secure_transfer.audit_logger import AuditLogger
from secure_transfer.service import SecureTransferService


def test_service_creates_package_and_audit_logs(tmp_path: Path):
    db = tmp_path / "audit.db"
    sample = tmp_path / "safe.txt"
    sample.write_text("safe content", encoding="utf-8")
    service = SecureTransferService(db)

    result = service.encrypt_and_share(
        file_path=sample,
        recipient_email="trusted@example.com",
        recipient_role="trusted",
        passphrase="StrongPass123!",
        output_dir=tmp_path / "packages",
        expires_hours=1,
    )

    assert result["status"] == "success"
    assert Path(result["package_path"]).exists()
    logs = AuditLogger(db).recent(10)
    assert any(log["event_type"] == "DLP_SCAN" for log in logs)
    assert any(log["event_type"] == "FILE_ENCRYPTED" for log in logs)
