from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit_logger import AuditLogger
from .crypto_engine import CryptoEngine
from .dlp_engine import DLPEngine
from .email_sender import send_package
from .reporting import HTMLReportGenerator
from .sharing import ShareManager, expires_after_hours
from .utils import sha256_file


class SecureTransferService:
    def __init__(self, db_path: str | Path = "secure_transfer.db", policy_path: str | Path | None = "policies.dlp.json"):
        self.db_path = db_path
        self.audit = AuditLogger(db_path)
        self.dlp = DLPEngine(policy_path if Path(str(policy_path)).exists() else None)
        self.crypto = CryptoEngine()
        self.shares = ShareManager(db_path)

    def encrypt_and_share(
        self,
        file_path: str | Path,
        recipient_email: str,
        recipient_role: str,
        passphrase: str,
        output_dir: str | Path = "secure_packages",
        expires_hours: int = 24,
        actor: str = "local-user",
        override_dlp_block: bool = False,
        report_dir: str | Path = "reports",
        # Email delivery (all optional – omit to skip sending)
        send_email: bool = False,
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_use_ssl: bool = False,
        sender_email: str = "",
        sender_password: str = "",
        sender_display_name: str = "",
        # Public base URL for share link (ngrok or local)
        base_url: str | None = None,
    ) -> dict[str, Any]:
        file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not recipient_email or "@" not in recipient_email:
            raise ValueError("Recipient email must be a valid email-like value.")

        file_hash = sha256_file(file_path)
        dlp_result = self.dlp.scan(file_path, recipient_email, recipient_role)
        self.audit.log(
            event_type="DLP_SCAN",
            actor=actor,
            recipient=recipient_email,
            file_name=file_path.name,
            file_hash=file_hash,
            status="blocked" if dlp_result.blocked else "success",
            details=dlp_result.to_dict(),
        )

        if dlp_result.blocked and not override_dlp_block:
            self.audit.log(
                event_type="TRANSFER_BLOCKED",
                actor=actor,
                recipient=recipient_email,
                file_name=file_path.name,
                file_hash=file_hash,
                status="blocked",
                details={"reason": dlp_result.summary(), "severity": dlp_result.severity, "risk_score": dlp_result.risk_score},
            )
            result = {
                "status": "blocked",
                "file_path": str(file_path),
                "file_hash": file_hash,
                "recipient_email": recipient_email,
                "recipient_role": recipient_role,
                "dlp": dlp_result.to_dict(),
                "policy": {
                    "policy_name": self.dlp.policy.data.get("policy_name"),
                    "policy_version": self.dlp.policy.data.get("version"),
                },
                "message": dlp_result.summary(),
                "next_action": dlp_result.recommended_action,
            }
            result["report_path"] = str(HTMLReportGenerator(report_dir).generate_transfer_report(result))
            self.audit.log(
                event_type="HTML_REPORT_GENERATED",
                actor=actor,
                recipient=recipient_email,
                file_name=file_path.name,
                file_hash=file_hash,
                status="success",
                details={"report_path": result["report_path"], "transfer_status": "blocked"},
            )
            return result

        expires_at = expires_after_hours(expires_hours)
        package = self.crypto.encrypt_file(
            file_path=file_path,
            passphrase=passphrase,
            output_dir=output_dir,
            recipient_email=recipient_email,
            expires_at_utc=expires_at,
            dlp_summary=dlp_result.to_dict(),
        )
        share_link = self.shares.create_share_link(
            package_path=package.package_path,
            recipient_email=recipient_email,
            expires_at_utc=expires_at,
            package_hash=package.package_hash,
            base_url=base_url,
        )
        self.audit.log(
            event_type="FILE_ENCRYPTED",
            actor=actor,
            recipient=recipient_email,
            file_name=file_path.name,
            file_hash=package.original_file_hash,
            package_hash=package.package_hash,
            status="success",
            details={
                "package_path": package.package_path,
                "expires_at_utc": expires_at,
                "algorithm": "AES-256-GCM",
                "backend": self.crypto.backend,
                "risk_score": dlp_result.risk_score,
                "decision": dlp_result.decision,
                "zero_knowledge_note": "Passphrase is never stored in the SQLite database or package metadata.",
            },
        )
        result = {
            "status": "success",
            "file_path": str(file_path),
            "file_hash": file_hash,
            "recipient_email": recipient_email,
            "recipient_role": recipient_role,
            "package_path": package.package_path,
            "package_hash": package.package_hash,
            "share_link": share_link,
            "expires_at_utc": expires_at,
            "dlp": dlp_result.to_dict(),
            "policy": {
                "policy_name": self.dlp.policy.data.get("policy_name"),
                "policy_version": self.dlp.policy.data.get("version"),
            },
        }
        result["report_path"] = str(HTMLReportGenerator(report_dir).generate_transfer_report(result))
        self.audit.log(
            event_type="HTML_REPORT_GENERATED",
            actor=actor,
            recipient=recipient_email,
            file_name=file_path.name,
            file_hash=file_hash,
            package_hash=package.package_hash,
            status="success",
            details={"report_path": result["report_path"]},
        )

        # ── Optional email delivery ───────────────────────────────────────
        if send_email and sender_email and sender_password and smtp_host:
            try:
                send_package(
                    smtp_host=smtp_host,
                    smtp_port=smtp_port,
                    use_ssl=smtp_use_ssl,
                    sender_email=sender_email,
                    sender_password=sender_password,
                    sender_display_name=sender_display_name,
                    recipient_email=recipient_email,
                    package_path=package.package_path,
                    share_link=share_link,
                    expires_at_utc=expires_at,
                    original_filename=file_path.name,
                )
                result["email_sent"] = True
                self.audit.log(
                    event_type="EMAIL_SENT",
                    actor=actor,
                    recipient=recipient_email,
                    file_name=file_path.name,
                    package_hash=package.package_hash,
                    status="success",
                    details={"smtp_host": smtp_host, "smtp_port": smtp_port},
                )
            except Exception as exc:
                result["email_sent"] = False
                result["email_error"] = str(exc)
                self.audit.log(
                    event_type="EMAIL_FAILED",
                    actor=actor,
                    recipient=recipient_email,
                    file_name=file_path.name,
                    package_hash=package.package_hash,
                    status="error",
                    details={"error": str(exc)},
                )

        return result

    def decrypt_package(
        self,
        package_path: str | Path,
        passphrase: str,
        output_dir: str | Path = "restored_files",
        actor: str = "local-user",
    ) -> dict[str, Any]:
        package_path = Path(package_path)
        if not package_path.exists():
            raise FileNotFoundError(f"Package not found: {package_path}")
        package_hash = sha256_file(package_path)
        info = self.crypto.inspect_package(package_path)
        output_path = self.crypto.decrypt_package(package_path, passphrase, output_dir)
        self.audit.log(
            event_type="FILE_DECRYPTED",
            actor=actor,
            recipient=info.get("recipient_email"),
            file_name=info.get("original_filename"),
            file_hash=sha256_file(output_path),
            package_hash=package_hash,
            status="success",
            details={"output_path": str(output_path)},
        )
        return {"status": "success", "output_path": str(output_path), "package": info}

    def inspect_package(self, package_path: str | Path) -> dict[str, Any]:
        return self.crypto.inspect_package(package_path)

    def resolve_share_link(self, share_link: str) -> dict[str, Any]:
        data = self.shares.resolve_link(share_link)
        self.audit.log(
            event_type="SHARE_LINK_RESOLVED",
            status="success",
            recipient=data.get("recipient"),
            package_hash=data.get("package_hash"),
            details={"package_path": data.get("package_path"), "expires_at_utc": data.get("expires_at_utc")},
        )
        return data

    def revoke_share_link(self, share_link: str) -> dict[str, str]:
        self.shares.revoke_link(share_link)
        return {"status": "success", "message": "Share link revoked."}
