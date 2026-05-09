from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure_transfer.crypto_engine import CryptoEngine


def test_encrypt_decrypt_roundtrip(tmp_path: Path):
    source = tmp_path / "report.txt"
    source.write_text("confidential but allowed content", encoding="utf-8")
    engine = CryptoEngine()
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()

    package = engine.encrypt_file(
        file_path=source,
        passphrase="StrongPass123!",
        output_dir=tmp_path / "packages",
        recipient_email="analyst@example.com",
        expires_at_utc=expires,
    )
    restored = engine.decrypt_package(package.package_path, "StrongPass123!", tmp_path / "out")

    assert restored.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
