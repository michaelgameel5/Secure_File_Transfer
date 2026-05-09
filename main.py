from __future__ import annotations

import argparse
import getpass
import json
import sys
import tempfile
from pathlib import Path

from secure_transfer.audit_logger import AuditLogger
from secure_transfer.evidence_verifier import EvidenceVerifier
from secure_transfer.methodology import methodology_json, methodology_markdown, write_methodology
from secure_transfer.policy_config import PolicyConfig
from secure_transfer.service import SecureTransferService
from secure_transfer.sharing import ShareManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure File Transfer & DLP System - local AES-256-GCM encrypted sharing demo"
    )
    sub = parser.add_subparsers(dest="command")

    encrypt = sub.add_parser("encrypt", help="Run DLP scan, encrypt file, and create local share link")
    encrypt.add_argument("file", help="File to protect")
    encrypt.add_argument("--recipient", required=True, help="Recipient email")
    encrypt.add_argument(
        "--role",
        choices=["internal", "trusted", "external"],
        default="external",
        help="Recipient trust level used by the DLP policy engine",
    )
    encrypt.add_argument("--expires-hours", type=int, default=24, help="Expiration window in hours")
    encrypt.add_argument("--output-dir", default="secure_packages", help="Where .sftpkg files are saved")
    encrypt.add_argument("--report-dir", default="reports", help="Where HTML transfer reports are saved")
    encrypt.add_argument("--db", default="secure_transfer.db", help="SQLite database path")
    encrypt.add_argument("--passphrase", help="Demo passphrase. Omit to type it securely.")
    encrypt.add_argument(
        "--override-dlp-block",
        action="store_true",
        help="For instructor/demo only: encrypt even if DLP blocks the transfer",
    )

    decrypt = sub.add_parser("decrypt", help="Decrypt a .sftpkg package")
    decrypt.add_argument("package", help="Encrypted package path")
    decrypt.add_argument("--output-dir", default="restored_files", help="Where decrypted files are saved")
    decrypt.add_argument("--db", default="secure_transfer.db", help="SQLite database path")
    decrypt.add_argument("--passphrase", help="Demo passphrase. Omit to type it securely.")

    inspect = sub.add_parser("inspect", help="Show safe public metadata from a .sftpkg package")
    inspect.add_argument("package", help="Encrypted package path")

    audit = sub.add_parser("audit", help="Show recent audit logs")
    audit.add_argument("--db", default="secure_transfer.db", help="SQLite database path")
    audit.add_argument("--limit", type=int, default=20)
    audit.add_argument("--format", choices=["json", "table"], default="table")

    stats = sub.add_parser("stats", help="Show audit summary and hash-chain integrity")
    stats.add_argument("--db", default="secure_transfer.db", help="SQLite database path")

    export = sub.add_parser("export-audit", help="Export audit evidence as JSON or CSV")
    export.add_argument("output", help="Output file path (.json or .csv)")
    export.add_argument("--db", default="secure_transfer.db", help="SQLite database path")
    export.add_argument("--limit", type=int, default=500)

    shares = sub.add_parser("shares", help="List local share records")
    shares.add_argument("--db", default="secure_transfer.db", help="SQLite database path")
    shares.add_argument("--limit", type=int, default=20)

    resolve = sub.add_parser("resolve", help="Resolve a local sftdlp:// share link")
    resolve.add_argument("link", help="sftdlp://share/... link")
    resolve.add_argument("--db", default="secure_transfer.db", help="SQLite database path")

    revoke = sub.add_parser("revoke", help="Revoke a local share link")
    revoke.add_argument("link", help="sftdlp://share/... link")
    revoke.add_argument("--db", default="secure_transfer.db", help="SQLite database path")


    sign = sub.add_parser("sign-evidence", help="Sign an exported audit JSON/CSV with local OpenSSL keys")
    sign.add_argument("evidence_file", help="Audit export file to sign")
    sign.add_argument("--key-dir", default="keys", help="Directory for generated OpenSSL audit keys")

    verify_sig = sub.add_parser("verify-signature", help="Verify an OpenSSL evidence signature")
    verify_sig.add_argument("evidence_file")
    verify_sig.add_argument("signature_file")
    verify_sig.add_argument("--public-key", default=None)
    verify_sig.add_argument("--key-dir", default="keys")

    verify_manifest = sub.add_parser("verify-manifest", help="Verify evidence file SHA-256 using a manifest JSON")
    verify_manifest.add_argument("manifest_file")

    policy = sub.add_parser("policy", help="Show or initialize the editable DLP policy JSON")
    policy.add_argument("action", choices=["show", "init"], nargs="?", default="show")
    policy.add_argument("--path", default="policies.dlp.json")

    methodology = sub.add_parser("methodology", help="Show or export the project security methodology")
    methodology.add_argument("--format", choices=["markdown", "json"], default="markdown")
    methodology.add_argument("--output", help="Optional output file path")

    selftest = sub.add_parser("selftest", help="Run a full safe demo: allow, block, decrypt, audit, report, manifest")
    selftest.add_argument("--work-dir", default=None, help="Optional work directory. Defaults to a temporary folder.")
    selftest.add_argument("--keep", action="store_true", help="Keep temporary self-test files instead of deleting them")

    gui = sub.add_parser("gui", help="Launch PyQt5 desktop interface")
    gui.add_argument("--db", default="secure_transfer.db", help="SQLite database path")

    return parser


def ask_passphrase(current: str | None, confirm: bool = False) -> str:
    if current:
        return current
    first = getpass.getpass("Passphrase: ")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise SystemExit("Passphrases do not match.")
    return first


def print_table(rows: list[dict[str, object]]) -> None:
    if not rows:
        print("No records found.")
        return
    headers = ["timestamp_utc", "event_type", "status", "file_name", "recipient"]
    widths = {h: max(len(h), *(len(str(row.get(h, "") or "")) for row in rows[:20])) for h in headers}
    print(" | ".join(h.ljust(widths[h]) for h in headers))
    print("-+-".join("-" * widths[h] for h in headers))
    for row in rows:
        print(" | ".join(str(row.get(h, "") or "").ljust(widths[h]) for h in headers))



def run_selftest(work_dir: str | None = None, keep: bool = False) -> dict[str, object]:
    """Run an end-to-end non-destructive demo used before packaging releases."""
    temp_ctx = None
    if work_dir:
        root = Path(work_dir)
        root.mkdir(parents=True, exist_ok=True)
    else:
        temp_ctx = tempfile.TemporaryDirectory(prefix="sftdlp_selftest_")
        root = Path(temp_ctx.name)

    try:
        safe = root / "safe_notes.txt"
        risky = root / "customer_cards.txt"
        restored = root / "restored"
        packages = root / "packages"
        reports = root / "reports"
        db = root / "secure_transfer.db"
        safe.write_text("Public demo note for trusted transfer. No secrets inside.\n", encoding="utf-8")
        risky.write_text("Customer: demo@example.com\nCard: 4111 1111 1111 1111\nToken: api_key='abcdefghijklmnopqrstuvwxyz123456'\n", encoding="utf-8")

        service = SecureTransferService(db)
        allowed = service.encrypt_and_share(
            file_path=safe,
            recipient_email="trusted@example.com",
            recipient_role="trusted",
            passphrase="StrongPass123!",
            output_dir=packages,
            report_dir=reports,
            expires_hours=4,
        )
        blocked = service.encrypt_and_share(
            file_path=risky,
            recipient_email="external@example.com",
            recipient_role="external",
            passphrase="StrongPass123!",
            output_dir=packages,
            report_dir=reports,
            expires_hours=4,
        )
        decrypted = service.decrypt_package(allowed["package_path"], "StrongPass123!", restored)
        audit = AuditLogger(db)
        audit_export = audit.export_json(root / "audit_export.json")
        manifest = EvidenceVerifier(root / "keys").create_manifest(audit_export)
        manifest_result = EvidenceVerifier(root / "keys").verify_manifest(manifest)
        checks = {
            "allowed_success": allowed.get("status") == "success" and Path(str(allowed.get("package_path"))).exists(),
            "blocked_success": blocked.get("status") == "blocked" and blocked.get("dlp", {}).get("decision") == "block",
            "decrypted_matches": Path(str(decrypted["output_path"])).read_text(encoding="utf-8") == safe.read_text(encoding="utf-8"),
            "audit_chain_valid": audit.verify_chain()["valid"],
            "html_reports_created": len(list(reports.glob("*.html"))) >= 2,
            "report_hash_sidecars_created": len(list(reports.glob("*.html.sha256"))) >= 2,
            "manifest_valid": bool(manifest_result.get("valid")),
        }
        status = "pass" if all(checks.values()) else "fail"
        return {
            "status": status,
            "work_dir": str(root),
            "checks": checks,
            "allowed_report": allowed.get("report_path"),
            "blocked_report": blocked.get("report_path"),
            "audit_export": str(audit_export),
            "manifest": str(manifest),
            "manifest_valid": manifest_result,
            "kept_files": bool(work_dir or keep),
        }
    finally:
        if temp_ctx is not None and not keep:
            temp_ctx.cleanup()

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        build_parser().print_help()
        return 0

    try:
        if args.command == "encrypt":
            service = SecureTransferService(args.db)
            result = service.encrypt_and_share(
                file_path=args.file,
                recipient_email=args.recipient,
                recipient_role=args.role,
                passphrase=ask_passphrase(args.passphrase, confirm=True),
                output_dir=args.output_dir,
                expires_hours=args.expires_hours,
                override_dlp_block=args.override_dlp_block,
                report_dir=args.report_dir,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "success" else 2

        if args.command == "decrypt":
            service = SecureTransferService(args.db)
            result = service.decrypt_package(
                package_path=args.package,
                passphrase=ask_passphrase(args.passphrase),
                output_dir=args.output_dir,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.command == "inspect":
            print(json.dumps(SecureTransferService().inspect_package(args.package), indent=2, sort_keys=True))
            return 0

        if args.command == "audit":
            logs = AuditLogger(args.db).recent(args.limit)
            if args.format == "json":
                print(json.dumps(logs, indent=2, sort_keys=True))
            else:
                print_table(logs)
            return 0

        if args.command == "stats":
            audit = AuditLogger(args.db)
            print(json.dumps({"stats": audit.stats(), "integrity": audit.verify_chain()}, indent=2, sort_keys=True))
            return 0

        if args.command == "export-audit":
            audit = AuditLogger(args.db)
            output = Path(args.output)
            if output.suffix.lower() == ".csv":
                path = audit.export_csv(output, args.limit)
            else:
                path = audit.export_json(output, args.limit)
            print(f"Exported audit evidence to {path}")
            return 0


        if args.command == "sign-evidence":
            result = EvidenceVerifier(args.key_dir).sign_file(args.evidence_file)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.command == "verify-signature":
            result = EvidenceVerifier(args.key_dir).verify_signature(args.evidence_file, args.signature_file, args.public_key)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["valid"] else 2

        if args.command == "verify-manifest":
            result = EvidenceVerifier().verify_manifest(args.manifest_file)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["valid"] else 2


        if args.command == "methodology":
            content = methodology_json() if args.format == "json" else methodology_markdown()
            if args.output:
                path = write_methodology(args.output)
                print(f"Methodology exported to {path}")
            else:
                print(content)
            return 0

        if args.command == "selftest":
            result = run_selftest(args.work_dir, keep=args.keep)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "pass" else 2

        if args.command == "policy":
            config = PolicyConfig.load(args.path)
            if args.action == "init":
                path = config.save(args.path)
                print(f"Policy initialized at {path}")
            else:
                print(config.to_json())
            return 0

        if args.command == "shares":
            print(json.dumps(ShareManager(args.db).list_shares(args.limit), indent=2, sort_keys=True))
            return 0

        if args.command == "resolve":
            print(json.dumps(SecureTransferService(args.db).resolve_share_link(args.link), indent=2, sort_keys=True))
            return 0

        if args.command == "revoke":
            print(json.dumps(SecureTransferService(args.db).revoke_share_link(args.link), indent=2, sort_keys=True))
            return 0

        if args.command == "gui":
            from secure_transfer.gui import run_gui

            run_gui(args.db)
            return 0

        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
