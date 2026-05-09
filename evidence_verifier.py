from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import utc_now_iso


class EvidenceSigningError(RuntimeError):
    pass


class EvidenceVerifier:
    """Creates and verifies audit evidence packages.

    Signing uses the local OpenSSL executable when available. This keeps the project aligned
    with the brief while staying offline and dependency-light.
    """

    def __init__(self, key_dir: str | Path = "keys") -> None:
        self.key_dir = Path(key_dir)
        self.private_key = self.key_dir / "audit_private_key.pem"
        self.public_key = self.key_dir / "audit_public_key.pem"

    def sha256(self, path: str | Path) -> str:
        h = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def create_manifest(self, evidence_file: str | Path, output_path: str | Path | None = None) -> Path:
        evidence_file = Path(evidence_file)
        if not evidence_file.exists():
            raise FileNotFoundError(f"Evidence file not found: {evidence_file}")
        output_path = Path(output_path or evidence_file.with_suffix(evidence_file.suffix + ".manifest.json"))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        manifest = {
            "generated_at_utc": utc_now_iso(),
            "evidence_file": str(evidence_file),
            "evidence_file_name": evidence_file.name,
            "sha256": self.sha256(evidence_file),
            "signature_file": str(evidence_file.with_suffix(evidence_file.suffix + ".sig")),
            "public_key_file": str(self.public_key),
            "verification_command": f"openssl dgst -sha256 -verify {self.public_key} -signature {evidence_file.with_suffix(evidence_file.suffix + '.sig')} {evidence_file}",
        }
        output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return output_path

    def sign_file(self, evidence_file: str | Path) -> dict[str, Any]:
        evidence_file = Path(evidence_file)
        if not evidence_file.exists():
            raise FileNotFoundError(f"Evidence file not found: {evidence_file}")
        openssl = shutil.which("openssl")
        if not openssl:
            raise EvidenceSigningError("OpenSSL executable was not found. Install OpenSSL or use manifest verification only.")

        self.key_dir.mkdir(parents=True, exist_ok=True)
        if not self.private_key.exists() or not self.public_key.exists():
            subprocess.run([openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.private_key)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run([openssl, "rsa", "-pubout", "-in", str(self.private_key), "-out", str(self.public_key)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        signature = evidence_file.with_suffix(evidence_file.suffix + ".sig")
        subprocess.run([openssl, "dgst", "-sha256", "-sign", str(self.private_key), "-out", str(signature), str(evidence_file)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        manifest = self.create_manifest(evidence_file)
        return {
            "status": "signed",
            "evidence_file": str(evidence_file),
            "sha256": self.sha256(evidence_file),
            "signature_file": str(signature),
            "public_key_file": str(self.public_key),
            "manifest_file": str(manifest),
            "verify_command": f"openssl dgst -sha256 -verify {self.public_key} -signature {signature} {evidence_file}",
        }

    def verify_signature(self, evidence_file: str | Path, signature_file: str | Path, public_key_file: str | Path | None = None) -> dict[str, Any]:
        openssl = shutil.which("openssl")
        if not openssl:
            raise EvidenceSigningError("OpenSSL executable was not found. Cannot verify RSA signature.")
        evidence_file = Path(evidence_file)
        signature_file = Path(signature_file)
        public_key_file = Path(public_key_file or self.public_key)
        for path in (evidence_file, signature_file, public_key_file):
            if not path.exists():
                raise FileNotFoundError(f"Missing verification input: {path}")
        proc = subprocess.run([openssl, "dgst", "-sha256", "-verify", str(public_key_file), "-signature", str(signature_file), str(evidence_file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {
            "valid": proc.returncode == 0,
            "openssl_output": (proc.stdout or proc.stderr).strip(),
            "evidence_file": str(evidence_file),
            "signature_file": str(signature_file),
            "public_key_file": str(public_key_file),
            "sha256": self.sha256(evidence_file),
        }

    def verify_manifest(self, manifest_file: str | Path) -> dict[str, Any]:
        manifest_file = Path(manifest_file)
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        evidence = Path(manifest["evidence_file"])
        if not evidence.exists():
            sibling = manifest_file.parent / manifest.get("evidence_file_name", "")
            evidence = sibling if sibling.exists() else evidence
        if not evidence.exists():
            return {"valid": False, "reason": "Evidence file referenced by manifest was not found.", "manifest_file": str(manifest_file)}
        actual = self.sha256(evidence)
        expected = manifest.get("sha256")
        return {
            "valid": actual == expected,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "evidence_file": str(evidence),
            "manifest_file": str(manifest_file),
        }
