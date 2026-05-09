# Secure File Transfer & DLP System

A premium local-first cybersecurity desktop application for encrypted file transfer, Data Leakage Prevention, expiring secure packages, HTML evidence reports, and tamper-evident audit logging.

This is not just an encryption script. It is a complete security workflow: **classify → inspect → decide → encrypt → share → preserve evidence**.

---

## What Makes It Strong

| Area | Implementation |
|---|---|
| Encryption | AES-256-GCM authenticated encryption with random salt and nonce per package |
| Key Derivation | PBKDF2-HMAC-SHA256; passphrase and derived key are never stored |
| DLP | PII, secrets, tokens, private keys, credit cards, IBAN-like values, Egyptian national ID patterns, phone numbers |
| False Positive Control | Luhn validation and overlap suppression prevent credit-card numbers from being duplicated as phone numbers |
| Risk Engine | 0–100 risk score, confidence, recommended action, and Allow / Warn / Block decision |
| Policy Editor | Editable JSON policy from CLI and GUI |
| Sharing | `.sftpkg` encrypted package with expiration metadata and local `sftdlp://` share pointer |
| Reports | Standalone premium HTML transfer report for every allowed or blocked attempt |
| Evidence Integrity | HTML report `.sha256` sidecars, audit manifests, and OpenSSL RSA signatures |
| Audit Trail | SQLite audit log with SHA-256 hash-chain verification |
| Interface | Premium dark PyQt5 dashboard, methodology page, decision rail, risk bar, audit trail, and policy editor |
| Testing | End-to-end self-test plus automated tests for crypto, DLP, audit, reporting, methodology, and evidence verification |

---

## Architecture

```text
main.py
  ├── secure_transfer/service.py            # Main workflow: DLP → encrypt/share → report → audit
  ├── secure_transfer/crypto_engine.py      # AES-256-GCM package encryption/decryption
  ├── secure_transfer/dlp_engine.py         # DLP rules, false-positive reduction, risk scoring
  ├── secure_transfer/policy_config.py      # Editable DLP policy JSON loader/saver
  ├── secure_transfer/methodology.py        # Six-stage security methodology
  ├── secure_transfer/reporting.py          # Premium HTML transfer reports + report hashes
  ├── secure_transfer/evidence_verifier.py  # Audit manifests + OpenSSL signatures
  ├── secure_transfer/audit_logger.py       # SQLite audit trail + SHA-256 hash chain
  ├── secure_transfer/sharing.py            # Expiring local share links
  ├── secure_transfer/database.py           # SQLite schema and migrations
  ├── secure_transfer/models.py             # Data models
  └── secure_transfer/gui.py                # PyQt5 desktop interface
```

---

## Installation

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional for signed evidence exports:

```bash
openssl version
```

---

## Run the Desktop App

```bash
python main.py gui
```

Main GUI pages:

1. **Dashboard** — product overview, audit metrics, workflow summary, and premium cards.
2. **Methodology** — the six-stage security workflow and evidence model.
3. **Protect & Share** — choose file, recipient role, expiry, passphrase, then run DLP and encryption.
4. **Open Package** — inspect and decrypt `.sftpkg` packages.
5. **Audit Trail** — review events, verify the hash chain, and export evidence.
6. **Policy Editor** — edit the local JSON DLP policy directly from the GUI.

---

## Fast Release Self-Test

Run this before submission:

```bash
python -m compileall -q .
python -m pytest -q
python main.py selftest --keep --work-dir demo_selftest
```

Expected result:

```json
{
  "status": "pass",
  "checks": {
    "allowed_success": true,
    "blocked_success": true,
    "decrypted_matches": true,
    "audit_chain_valid": true,
    "html_reports_created": true,
    "report_hash_sidecars_created": true,
    "manifest_valid": true
  }
}
```

---

## CLI Demo Flow

### 1. Encrypt a safe file

```bash
python main.py encrypt sample_data/safe_notes.txt \
  --recipient analyst@example.com \
  --role trusted \
  --expires-hours 24 \
  --passphrase StrongPass123!
```

Expected:

- `status: success`
- `.sftpkg` package created
- HTML report generated in `reports/`
- `.html.sha256` integrity sidecar generated
- Audit events written to SQLite

### 2. Try a blocked external transfer

```bash
python main.py encrypt sample_data/sensitive_customer_data.txt \
  --recipient outsider@example.com \
  --role external \
  --passphrase StrongPass123!
```

Expected:

- `status: blocked`
- `decision: block`
- high risk score
- credit card detected once, not duplicated as phone
- no encrypted package created
- blocked decision HTML report generated

### 3. Show methodology

```bash
python main.py methodology
python main.py methodology --format json
python main.py methodology --output docs/METHODOLOGY.md
```

### 4. Export and verify audit evidence

```bash
python main.py stats
python main.py export-audit audit_export.json
python main.py sign-evidence audit_export.json --key-dir keys
python main.py verify-manifest audit_export.json.manifest.json
python main.py verify-signature audit_export.json audit_export.json.sig --public-key keys/audit_public_key.pem
```

Expected signature verification:

```text
Verified OK
```

---

## DLP Rules Included

- Email address detection.
- Credit card detection with Luhn validation.
- API key / token detection.
- AWS access key format detection.
- Private key block detection.
- High-entropy token detection.
- Egyptian national ID style pattern detection.
- IBAN / bank-account style pattern detection.
- Phone number detection with card-overlap suppression.
- External-recipient blocking for sensitive extensions:
  - `.env`, `.key`, `.pem`, `.p12`, `.pfx`, `.sqlite`, `.db`, `.kdbx`
- High-risk documents with PII require trusted or internal recipients.

---

## Six-Stage Methodology

| Stage | Goal |
|---|---|
| 1. Intake & Classification | Identify file, recipient, role, expiry, and business context |
| 2. DLP Content Inspection | Detect sensitive content locally before encryption |
| 3. Policy Decision | Convert findings into Allow / Warn / Block |
| 4. Zero-Knowledge Packaging | Encrypt approved files without storing passphrases |
| 5. Expiring Local Share Record | Create a local share pointer with expiry and revocation support |
| 6. Evidence & Audit Readiness | Generate reports, hash chains, manifests, and optional signatures |

Full methodology: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)

---

## Screenshots

Suggested screenshot order for submission:

| Slide / Document Section | Screenshot |
|---|---|
| Product Dashboard | `docs/screenshots/dashboard.png` |
| Methodology Page | `docs/screenshots/methodology.png` |
| Protect & Share Form | `docs/screenshots/protect-share.png` |
| Blocked DLP Decision | `docs/screenshots/dlp-blocked.png` |
| HTML Evidence Report | `docs/screenshots/html-report.png` |
| Audit Trail + Verify Chain | `docs/screenshots/audit-trail.png` |
| Policy Editor | `docs/screenshots/policy-editor.png` |

Placeholder SVGs are included in `docs/screenshots/` so the documentation layout is ready before real screenshots are added.

---

## Testing Status

Verified commands:

```bash
python -m compileall -q .
python -m pytest -q
python main.py selftest --keep --work-dir demo_selftest
```

Current verified result:

```text
12 passed
selftest: pass
OpenSSL signature verification: Verified OK
```

---

## Project Mapping to Requirements

| Requirement | Status |
|---|---|
| File Encryption Engine: AES-256-GCM | Implemented |
| DLP Policy Engine: pattern matching + file type rules | Implemented |
| Secure File Sharing: encrypted packages + expiration | Implemented |
| Complete Audit Logging: timestamped local SQLite logs | Implemented |
| P0: phone/card false-positive fix | Implemented |
| P0: HTML report generator | Implemented with `.sha256` sidecar |
| P0: README, demo guide, sample outputs, limitations | Implemented |
| P1: policy editor | Implemented |
| P1: risk score | Implemented |
| P1: evidence verifier | Implemented |
| P1: audit export signing | Implemented with OpenSSL |
| P1/P2: improved GUI dashboard and premium cards | Implemented |
| P2: methodology dashboard, timeline, screenshot placeholders, docs | Implemented |

---

## Current Limitations

This project is intentionally honest about scope while still presenting strong engineering work:

- The app is a local-first academic prototype, not a production enterprise gateway.
- `sftdlp://` links resolve through local SQLite metadata; they are not internet-hosted download URLs.
- The DLP engine is best-effort pattern analysis. It reduces common false positives but cannot guarantee perfect detection.
- PDF/DOCX scanning uses best-effort text extraction from bytes; production deployments should add dedicated parsers.
- OpenSSL evidence signing depends on a local OpenSSL installation.
- Enterprise production features such as SSO, central policy management, hardware-backed keys, endpoint deployment, and remote revocation are future extensions.

---

## Recommended Live Demo

1. Open the GUI with `python main.py gui`.
2. Show **Dashboard** and explain the local-first architecture.
3. Show **Methodology** and explain the six-stage security workflow.
4. Run **Safe Demo** with a trusted recipient.
5. Open the generated HTML report and `.sha256` sidecar.
6. Run **Risky Demo** with an external recipient.
7. Show the DLP block decision, risk bar, and recommended action.
8. Open **Audit Trail** and verify the hash chain.
9. Export and sign audit evidence.
10. Open **Policy Editor** and show how the rules can be changed.
