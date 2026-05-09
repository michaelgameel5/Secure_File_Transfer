from pathlib import Path

from secure_transfer.dlp_engine import DLPEngine


def test_dlp_blocks_external_high_risk_content(tmp_path: Path):
    sample = tmp_path / "customers.txt"
    sample.write_text("Email: user@example.com\nCard: 4111 1111 1111 1111", encoding="utf-8")

    result = DLPEngine().scan(sample, "external@example.com", "external")

    assert result.blocked is True
    assert result.severity == "high"
    assert any(f.rule_id == "PII.CREDIT_CARD" for f in result.findings)


def test_dlp_allows_clean_external_file(tmp_path: Path):
    sample = tmp_path / "public.txt"
    sample.write_text("Normal product announcement without sensitive data.", encoding="utf-8")

    result = DLPEngine().scan(sample, "external@example.com", "external")

    assert result.blocked is False
    assert result.severity == "clean"


def test_credit_card_is_not_duplicated_as_phone(tmp_path: Path):
    sample = tmp_path / "card.txt"
    sample.write_text("Card: 4111 1111 1111 1111", encoding="utf-8")

    result = DLPEngine().scan(sample, "external@example.com", "external")
    rule_ids = [finding.rule_id for finding in result.findings]

    assert "PII.CREDIT_CARD" in rule_ids
    assert "PII.PHONE" not in rule_ids


def test_real_phone_still_detected(tmp_path: Path):
    sample = tmp_path / "phone.txt"
    sample.write_text("Customer phone: +20 100 123 4567", encoding="utf-8")

    result = DLPEngine().scan(sample, "trusted@example.com", "trusted")

    assert any(f.rule_id == "PII.PHONE" for f in result.findings)
    assert result.risk_score > 0
