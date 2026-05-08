from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import utc_now_iso
from .utils import atomic_write, b64d, b64e, safe_filename, sha256_file

MAGIC = "SFTDLP-PACKAGE"
VERSION = "1.0"
KDF_ITERATIONS = 200_000


class CryptoBackendError(RuntimeError):
    pass


class PackageExpiredError(RuntimeError):
    pass


@dataclass
class EncryptedPackage:
    package_path: str
    package_hash: str
    original_file_hash: str
    expires_at_utc: str
    metadata: dict[str, Any]


class CryptoEngine:
    """AES-256-GCM file encryption engine.

    It prefers PyCryptodome, as required by the project brief. A cryptography fallback is
    included only so tests can run in environments where PyCryptodome is not installed.
    """

    def __init__(self) -> None:
        self.backend = self._detect_backend()

    def encrypt_file(
        self,
        file_path: str | Path,
        passphrase: str,
        output_dir: str | Path,
        recipient_email: str,
        expires_at_utc: str,
        dlp_summary: dict[str, Any] | None = None,
    ) -> EncryptedPackage:
        if not passphrase or len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters for the demo project.")

        source = Path(file_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        data = source.read_bytes()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(passphrase, salt)
        ciphertext, tag = self._aes_gcm_encrypt(key, nonce, data, aad=source.name.encode("utf-8"))

        metadata = {
            "magic": MAGIC,
            "version": VERSION,
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": KDF_ITERATIONS,
            "backend": self.backend,
            "original_filename": source.name,
            "original_size": source.stat().st_size,
            "original_sha256": sha256_file(source),
            "recipient_email": recipient_email,
            "created_at_utc": utc_now_iso(),
            "expires_at_utc": expires_at_utc,
            "dlp_summary": dlp_summary or {},
            "salt_b64": b64e(salt),
            "nonce_b64": b64e(nonce),
            "tag_b64": b64e(tag),
            "ciphertext_b64": b64e(ciphertext),
        }

        package_name = f"{safe_filename(source.stem)}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.sftpkg"
        package_path = output_dir / package_name
        payload = json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8")
        atomic_write(package_path, payload)
        return EncryptedPackage(
            package_path=str(package_path),
            package_hash=sha256_file(package_path),
            original_file_hash=metadata["original_sha256"],
            expires_at_utc=expires_at_utc,
            metadata=metadata,
        )

    def decrypt_package(
        self,
        package_path: str | Path,
        passphrase: str,
        output_dir: str | Path,
        ignore_expiration: bool = False,
    ) -> Path:
        package = json.loads(Path(package_path).read_text(encoding="utf-8"))
        if package.get("magic") != MAGIC:
            raise ValueError("Invalid secure transfer package.")

        expires_at = datetime.fromisoformat(package["expires_at_utc"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if not ignore_expiration and datetime.now(timezone.utc) > expires_at:
            raise PackageExpiredError("This encrypted package has expired.")

        salt = b64d(package["salt_b64"])
        nonce = b64d(package["nonce_b64"])
        tag = b64d(package["tag_b64"])
        ciphertext = b64d(package["ciphertext_b64"])
        key = self._derive_key(passphrase, salt, int(package.get("iterations", KDF_ITERATIONS)))
        plaintext = self._aes_gcm_decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            aad=package["original_filename"].encode("utf-8"),
        )

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / package["original_filename"]
        atomic_write(output_path, plaintext)

        if sha256_file(output_path) != package["original_sha256"]:
            output_path.unlink(missing_ok=True)
            raise ValueError("Integrity check failed after decryption.")
        return output_path

    def inspect_package(self, package_path: str | Path) -> dict[str, Any]:
        package = json.loads(Path(package_path).read_text(encoding="utf-8"))
        public_keys = [
            "magic",
            "version",
            "algorithm",
            "kdf",
            "iterations",
            "backend",
            "original_filename",
            "original_size",
            "original_sha256",
            "recipient_email",
            "created_at_utc",
            "expires_at_utc",
            "dlp_summary",
        ]
        return {key: package.get(key) for key in public_keys}

    def _derive_key(self, passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
        try:
            from Crypto.Protocol.KDF import PBKDF2  # type: ignore
            from Crypto.Hash import SHA256  # type: ignore

            return PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
        except Exception:
            try:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                )
                return kdf.derive(passphrase.encode("utf-8"))
            except Exception as exc:  # pragma: no cover
                raise CryptoBackendError(
                    "Install pycryptodome with: pip install pycryptodome"
                ) from exc

    def _aes_gcm_encrypt(self, key: bytes, nonce: bytes, data: bytes, aad: bytes) -> tuple[bytes, bytes]:
        try:
            from Crypto.Cipher import AES  # type: ignore

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return ciphertext, tag
        except Exception:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                encrypted = AESGCM(key).encrypt(nonce, data, aad)
                return encrypted[:-16], encrypted[-16:]
            except Exception as exc:  # pragma: no cover
                raise CryptoBackendError(
                    "Install pycryptodome with: pip install pycryptodome"
                ) from exc

    def _aes_gcm_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        try:
            from Crypto.Cipher import AES  # type: ignore

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
            except Exception as exc:
                raise ValueError("Decryption failed. Wrong passphrase or tampered package.") from exc

    @staticmethod
    def _detect_backend() -> str:
        try:
            import Crypto  # type: ignore  # noqa: F401

            return "pycryptodome"
        except Exception:
            try:
                import cryptography  # type: ignore  # noqa: F401

                return "cryptography-fallback"
            except Exception:
                return "missing"
