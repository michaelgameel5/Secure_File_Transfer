from __future__ import annotations

from pathlib import Path

from main import run_selftest
from secure_transfer.methodology import methodology_dict, write_methodology


def test_methodology_exports_markdown_and_json(tmp_path: Path):
    data = methodology_dict()
    assert data["methodology_version"] == "2.0"
    assert len(data["stages"]) >= 6

    md = write_methodology(tmp_path / "methodology.md")
    js = write_methodology(tmp_path / "methodology.json")
    assert "Intake & Classification" in md.read_text(encoding="utf-8")
    assert "decision_model" in js.read_text(encoding="utf-8")


def test_selftest_runs_end_to_end(tmp_path: Path):
    result = run_selftest(str(tmp_path), keep=True)
    assert result["status"] == "pass"
    assert result["checks"]["allowed_success"] is True
    assert result["checks"]["blocked_success"] is True
    assert result["checks"]["audit_chain_valid"] is True
    assert result["checks"]["report_hash_sidecars_created"] is True
