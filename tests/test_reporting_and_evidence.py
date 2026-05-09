from __future__ import annotations

import json

from secure_transfer.evidence_verifier import EvidenceVerifier
from secure_transfer.reporting import HTMLReportGenerator


def test_html_report_generator_creates_blocked_report(tmp_path):
    operation = {
        "status": "blocked",
        "file_path": str(tmp_path / "customers.txt"),
        "file_hash": "a" * 64,
        "dlp": {
            "blocked": True,
            "severity": "high",
            "risk_score": 85,
            "decision": "block",
            "confidence": "high",
            "recipient_email": "external@example.com",
            "recipient_role": "external",
            "blocked_reasons": ["High/critical sensitive content cannot be shared externally."],
            "findings": [{"rule_id": "PII.CREDIT_CARD", "label": "Credit card number", "severity": "high", "count": 1, "evidence": "411...111"}],
        },
    }
    path = HTMLReportGenerator(tmp_path).generate_transfer_report(operation)
    html = path.read_text(encoding="utf-8")
    assert "Transfer Decision Report" in html
    assert "85/100" in html
    assert "PII.CREDIT_CARD" in html


def test_evidence_manifest_verifies_hash(tmp_path):
    evidence = tmp_path / "audit_export.json"
    evidence.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    verifier = EvidenceVerifier(tmp_path / "keys")
    manifest = verifier.create_manifest(evidence)
    assert verifier.verify_manifest(manifest)["valid"] is True
    evidence.write_text("tampered", encoding="utf-8")
    assert verifier.verify_manifest(manifest)["valid"] is False
