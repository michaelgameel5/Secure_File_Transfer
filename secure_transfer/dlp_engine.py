from __future__ import annotations

import mimetypes
import re
from pathlib import Path

from .models import DLPFinding, DLPResult
from .policy_config import PolicyConfig


class DLPEngine:
    """Local DLP engine with content, file-type, recipient, and risk-score policies."""

    PATTERNS = [
        {
            "rule_id": "PII.EMAIL",
            "label": "Email address",
            "severity": "medium",
            "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        },
        {
            "rule_id": "SECRET.AWS_ACCESS_KEY",
            "label": "AWS access key format",
            "severity": "high",
            "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        },
        {
            "rule_id": "SECRET.API_KEY",
            "label": "Possible API key/token",
            "severity": "high",
            "regex": re.compile(r"(?i)\b(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-.]{20,}"),
        },
        {
            "rule_id": "SECRET.PRIVATE_KEY",
            "label": "Private key block",
            "severity": "critical",
            "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        },
        {
            "rule_id": "PII.CREDIT_CARD",
            "label": "Credit card number",
            "severity": "high",
            "regex": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
            "validator": "luhn",
        },
        {
            "rule_id": "PII.EGYPT_NATIONAL_ID",
            "label": "Possible Egyptian national ID",
            "severity": "high",
            "regex": re.compile(r"(?<!\d)[23]\d{13}(?!\d)"),
        },
        {
            "rule_id": "PII.IBAN",
            "label": "Possible IBAN / bank account",
            "severity": "high",
            "regex": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        },
        {
            "rule_id": "SECRET.HIGH_ENTROPY_TOKEN",
            "label": "High-entropy secret-like token",
            "severity": "medium",
            "regex": re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-/+=]{32,}(?![A-Za-z0-9_\-])"),
            "validator": "entropy",
        },
        {
            "rule_id": "PII.PHONE",
            "label": "Possible phone number",
            "severity": "low",
            "regex": re.compile(r"(?<!\d)(?:\+?\d[\s\-().]*){10,15}(?!\d)"),
            "validator": "phone",
        },
    ]

    SEVERITY_ORDER = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, policy_path: str | Path | None = None) -> None:
        self.policy = PolicyConfig.load(policy_path)

    def reload_policy(self, policy_path: str | Path | None = None) -> None:
        self.policy = PolicyConfig.load(policy_path)

    def scan(self, file_path: str | Path, recipient_email: str, recipient_role: str) -> DLPResult:
        path = Path(file_path)
        findings: list[DLPFinding] = []
        blocked_reasons: list[str] = []
        recipient_role = recipient_role.lower().strip() or "external"
        extension = path.suffix.lower()

        if recipient_role == "external" and extension in self.policy.blocked_external_extensions:
            blocked_reasons.append(f"File type {extension} cannot be shared with external recipients.")

        content = self._read_text_for_scan(path)
        occupied_sensitive_spans: list[tuple[int, int]] = []

        for rule in self.PATTERNS:
            raw_matches = list(rule["regex"].finditer(content))
            matches: list[str] = []
            validated_spans: list[tuple[int, int]] = []

            for match in raw_matches:
                value = match.group(0)
                validator = rule.get("validator")
                if validator == "luhn" and not self._valid_luhn(value):
                    continue
                if validator == "entropy" and self._shannon_entropy(value) < 4.0:
                    continue
                if validator == "phone":
                    # Avoid duplicate/noisy phone findings when the match overlaps a validated card,
                    # IBAN, national ID, or another stronger sensitive identifier.
                    if self._overlaps(match.span(), occupied_sensitive_spans):
                        continue
                    if not self._is_likely_phone(value):
                        continue
                matches.append(value)
                validated_spans.append(match.span())

            if not matches:
                continue

            if rule["rule_id"] != "PII.PHONE":
                occupied_sensitive_spans.extend(validated_spans)

            findings.append(
                DLPFinding(
                    rule_id=rule["rule_id"],
                    label=rule["label"],
                    severity=rule["severity"],
                    evidence=self._mask(matches[0]),
                    count=len(matches),
                )
            )

        max_sev = "clean"
        for finding in findings:
            if self.SEVERITY_ORDER[finding.severity] > self.SEVERITY_ORDER[max_sev]:
                max_sev = finding.severity

        if recipient_role == "external":
            if any(f.severity in self.policy.external_block_severities for f in findings):
                blocked_reasons.append("High/critical sensitive content cannot be shared externally.")
            elif extension in self.policy.high_risk_extensions and any(f.severity == "medium" for f in findings):
                blocked_reasons.append("High-risk document with PII requires internal/trusted recipient.")

        blocked = bool(blocked_reasons)
        risk_score = self._risk_score(findings, recipient_role, extension, blocked)
        decision = "block" if blocked else ("warn" if risk_score >= 25 else "allow")
        confidence = self._confidence(findings, blocked, content)
        recommended_action = self._recommended_action(decision, recipient_role, blocked_reasons)

        return DLPResult(
            file_path=str(path),
            recipient_email=recipient_email,
            recipient_role=recipient_role,
            blocked=blocked,
            severity=max_sev,
            findings=findings,
            blocked_reasons=blocked_reasons,
            risk_score=risk_score,
            decision=decision,
            confidence=confidence,
            recommended_action=recommended_action,
        )

    def _read_text_for_scan(self, path: Path) -> str:
        mime, _ = mimetypes.guess_type(path.name)
        # Read a bounded prefix to avoid loading huge files in a classroom/demo project.
        data = path.read_bytes()[:2 * 1024 * 1024]
        if mime and not mime.startswith("text") and path.suffix.lower() not in {".csv", ".json", ".xml", ".env", ".log"}:
            # Best-effort string extraction from binary/document files.
            return data.decode("utf-8", errors="ignore")
        return data.decode("utf-8", errors="ignore")

    def _risk_score(self, findings: list[DLPFinding], recipient_role: str, extension: str, blocked: bool) -> int:
        weights = self.policy.risk_weights
        score = 0
        for finding in findings:
            score += weights.get(finding.severity, 0)
            if finding.count > 1:
                score += min(20, (finding.count - 1) * 5)
        if recipient_role == "external":
            score += weights.get("external_recipient", 10)
        if extension in self.policy.high_risk_extensions:
            score += weights.get("high_risk_extension", 10)
        if extension in self.policy.blocked_external_extensions:
            score += weights.get("blocked_file_type", 45)
        if blocked:
            score = max(score, 70)
        return max(0, min(100, score))

    @staticmethod
    def _recommended_action(decision: str, recipient_role: str, blocked_reasons: list[str]) -> str:
        if decision == "block":
            reason = " ".join(blocked_reasons) if blocked_reasons else "Policy block triggered."
            return f"Do not transfer as-is. {reason} Remove sensitive data, use an internal/trusted recipient, or document an approved override."
        if decision == "warn":
            return "Transfer is allowed, but review the findings and confirm business need before sharing."
        if recipient_role == "external":
            return "Transfer is allowed by current rules; keep the package expiration short for external recipients."
        return "Transfer is allowed by the current policy."

    @staticmethod
    def _confidence(findings: list[DLPFinding], blocked: bool, content: str) -> str:
        if blocked or any(f.severity in {"high", "critical"} for f in findings):
            return "high"
        if findings:
            return "medium"
        return "medium" if content else "low"

    @staticmethod
    def _valid_luhn(value: str) -> bool:
        digits = [int(ch) for ch in value if ch.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    @staticmethod
    def _is_likely_phone(value: str) -> bool:
        digits = "".join(ch for ch in value if ch.isdigit())
        compact = re.sub(r"\D", "", value)
        if len(digits) < 10 or len(digits) > 15:
            return False
        # Card / financial formatting: 4-4-4-4 groups or long plain financial number.
        if re.fullmatch(r"\d{4}[ -]\d{4}[ -]\d{4}([ -]\d{1,4})?", value.strip()):
            return False
        if len(digits) >= 13 and not value.strip().startswith("+"):
            return False
        # Accept common phone-like forms: explicit plus, parentheses, or regional mobile prefixes.
        if value.strip().startswith("+") or any(ch in value for ch in "()-"):
            return True
        return compact.startswith(("010", "011", "012", "015", "01", "20"))

    @staticmethod
    def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
        start, end = span
        return any(start < other_end and end > other_start for other_start, other_end in spans)

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        from math import log2

        counts = {char: value.count(char) for char in set(value)}
        length = len(value)
        return -sum((count / length) * log2(count / length) for count in counts.values())

    @staticmethod
    def _mask(value: str) -> str:
        value = value.strip()
        if len(value) <= 8:
            return "*" * len(value)
        return value[:3] + "..." + value[-3:]
