from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class DLPFinding:
    rule_id: str
    label: str
    severity: str
    evidence: str
    count: int = 1


@dataclass
class DLPResult:
    file_path: str
    recipient_email: str
    recipient_role: str
    blocked: bool
    severity: str
    findings: list[DLPFinding] = field(default_factory=list)
    blocked_reasons: list[str] = field(default_factory=list)
    risk_score: int = 0
    decision: str = "allow"
    confidence: str = "low"
    recommended_action: str = "Transfer is allowed by the current policy."

    def summary(self) -> str:
        if not self.findings and not self.blocked_reasons:
            return f"Clean: no DLP rule matched. Risk score {self.risk_score}/100."
        parts = []
        for finding in self.findings:
            parts.append(f"{finding.label} ({finding.severity}, x{finding.count})")
        parts.extend(self.blocked_reasons)
        parts.append(f"Risk score {self.risk_score}/100; decision: {self.decision.upper()}")
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "recipient_email": self.recipient_email,
            "recipient_role": self.recipient_role,
            "blocked": self.blocked,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
            "findings": [finding.__dict__ for finding in self.findings],
            "blocked_reasons": self.blocked_reasons,
            "summary": self.summary(),
        }
