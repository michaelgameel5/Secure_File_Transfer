from __future__ import annotations

import json
from pathlib import Path

from .audit_logger import AuditLogger
from .email_sender import PROVIDER_PRESETS
from .methodology import METHODOLOGY_STAGES, methodology_markdown
from .policy_config import PolicyConfig
from .service import SecureTransferService
from . import share_server, tunnel


class MissingPyQt5Error(RuntimeError):
    pass


def run_gui(db_path: str = "secure_transfer.db") -> None:
    try:
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QColor, QFont
        from PyQt5.QtWidgets import (
            QApplication,
            QAbstractItemView,
            QCheckBox,
            QComboBox,
            QFileDialog,
            QFrame,
            QGridLayout,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QSizePolicy,
            QSpinBox,
            QProgressBar,
            QScrollArea,
            QStackedWidget,
            QTableWidget,
            QTableWidgetItem,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except Exception as exc:  # pragma: no cover
        raise MissingPyQt5Error("Install PyQt5 with: pip install PyQt5") from exc

    import sys

    APP_ROOT = Path(__file__).resolve().parents[1]

    class App(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.policy_path = APP_ROOT / "policies.dlp.json"
            self.service = SecureTransferService(db_path, self.policy_path)
            self.audit = AuditLogger(db_path)
            self.setWindowTitle("Secure File Transfer & DLP — Professional Edition")
            self.resize(1280, 780)
            self.setMinimumSize(1080, 680)
            self.nav_buttons: list[QPushButton] = []

            # Start share server + ngrok tunnel in background
            share_server.start(db_path)
            tunnel.start(share_server.PORT)
            self._public_url: str | None = tunnel.get_public_url()

            root = QWidget()
            root_layout = QHBoxLayout(root)
            root_layout.setContentsMargins(0, 0, 0, 0)
            root_layout.setSpacing(0)

            self.sidebar = self._build_sidebar()
            self.stack = QStackedWidget()
            self.stack.addWidget(self._build_dashboard_page())
            self.stack.addWidget(self._build_methodology_page())
            self.stack.addWidget(self._build_encrypt_page())
            self.stack.addWidget(self._build_decrypt_page())
            self.stack.addWidget(self._build_audit_page())
            self.stack.addWidget(self._build_policy_page())

            root_layout.addWidget(self.sidebar)
            root_layout.addWidget(self.stack, 1)
            self.setCentralWidget(root)

            self._apply_style()
            self._activate_nav(0)
            self.refresh_all()

        # ---------- UI builders ----------
        def _build_sidebar(self) -> QFrame:
            side = QFrame()
            side.setObjectName("Sidebar")
            side.setFixedWidth(260)
            layout = QVBoxLayout(side)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(12)

            logo = QLabel("SFT DLP")
            logo.setObjectName("Logo")
            tagline = QLabel("Zero-knowledge local protection")
            tagline.setObjectName("Muted")
            layout.addWidget(logo)
            layout.addWidget(tagline)
            layout.addSpacing(16)

            items = [
                ("Dashboard", 0),
                ("Methodology", 1),
                ("Protect & Share", 2),
                ("Open Package", 3),
                ("Audit Trail", 4),
                ("Policy Editor", 5),
            ]
            for text, index in items:
                btn = QPushButton(text)
                btn.setObjectName("NavButton")
                btn.setCursor(Qt.PointingHandCursor)
                btn.clicked.connect(lambda _=False, i=index: self._activate_nav(i))
                self.nav_buttons.append(btn)
                layout.addWidget(btn)

            layout.addStretch(1)
            status = QLabel("AES-256-GCM • SQLite • PyQt5\nLocal-first. No cloud dependency.")
            status.setObjectName("SidebarFooter")
            status.setWordWrap(True)
            layout.addWidget(status)
            return side

        def _build_dashboard_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(26, 24, 26, 24)
            layout.setSpacing(18)

            hero = self._card()
            hero_layout = QVBoxLayout(hero)
            hero_layout.setContentsMargins(24, 22, 24, 22)
            title = QLabel("Secure File Transfer & Data Leakage Prevention")
            title.setObjectName("HeroTitle")
            subtitle = QLabel(
                "Encrypt files locally, enforce recipient-aware DLP decisions, create expiring share packages, and keep a tamper-evident audit trail."
            )
            subtitle.setObjectName("HeroSubtitle")
            subtitle.setWordWrap(True)
            hero_layout.addWidget(title)
            hero_layout.addWidget(subtitle)
            layout.addWidget(hero)

            metrics = QGridLayout()
            metrics.setSpacing(14)
            self.metric_total = self._metric_card("Audit Events", "0", "All recorded operations")
            self.metric_blocked = self._metric_card("Blocked", "0", "DLP prevented risky transfer")
            self.metric_encrypted = self._metric_card("Encrypted", "0", "Secure packages created")
            self.metric_chain = self._metric_card("Audit Integrity", "Valid", "SHA-256 hash-chain status")
            metrics.addWidget(self.metric_total, 0, 0)
            metrics.addWidget(self.metric_blocked, 0, 1)
            metrics.addWidget(self.metric_encrypted, 0, 2)
            metrics.addWidget(self.metric_chain, 0, 3)
            layout.addLayout(metrics)

            lower = QGridLayout()
            lower.setSpacing(14)
            workflow = self._info_card(
                "System Workflow",
                "1. Select a local file\n2. Run DLP content + type rules\n3. Block risky external sharing\n4. Encrypt with AES-256-GCM\n5. Generate expiring local share link\n6. Write hash-chained audit evidence",
            )
            policy = self._info_card(
                "DLP Coverage",
                "• Emails and phone numbers\n• Credit-card numbers with Luhn validation\n• API keys, secrets, tokens\n• Private key blocks\n• External recipient blocking for .env, .pem, .db, .kdbx\n• High-risk docs with PII require trusted/internal role",
            )
            lower.addWidget(workflow, 0, 0)
            lower.addWidget(policy, 0, 1)
            layout.addLayout(lower)
            layout.addStretch(1)
            return page

        def _build_methodology_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(26, 24, 26, 24)
            layout.setSpacing(18)
            layout.addWidget(self._page_header(
                "Security Methodology",
                "A defensible six-stage workflow: classify, inspect, decide, encrypt, share, and preserve evidence.",
            ))

            intro = self._card()
            intro_layout = QVBoxLayout(intro)
            intro_layout.setContentsMargins(22, 20, 22, 20)
            title = QLabel("Local-first DLP methodology built for a professional product demo")
            title.setObjectName("SectionTitle")
            body = QLabel(
                "The system scans before encryption, applies recipient-aware policy, scores the risk, creates an expiring local package, and records every step in a tamper-evident audit chain."
            )
            body.setObjectName("InfoText")
            body.setWordWrap(True)
            intro_layout.addWidget(title)
            intro_layout.addWidget(body)
            layout.addWidget(intro)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setObjectName("MethodScroll")
            content = QWidget()
            grid = QGridLayout(content)
            grid.setContentsMargins(0, 0, 0, 0)
            grid.setSpacing(14)
            for idx, stage in enumerate(METHODOLOGY_STAGES):
                card = self._card()
                c = QVBoxLayout(card)
                c.setContentsMargins(18, 16, 18, 16)
                number = QLabel(f"0{idx + 1}")
                number.setObjectName("Pill")
                heading = QLabel(stage.stage)
                heading.setObjectName("SectionTitle")
                objective = QLabel(stage.objective)
                objective.setObjectName("InfoText")
                objective.setWordWrap(True)
                controls = QLabel("Controls:\n" + "\n".join(f"• {item}" for item in stage.controls[:4]))
                controls.setObjectName("InfoText")
                controls.setWordWrap(True)
                evidence = QLabel("Evidence: " + ", ".join(stage.evidence))
                evidence.setObjectName("Muted")
                evidence.setWordWrap(True)
                c.addWidget(number)
                c.addWidget(heading)
                c.addWidget(objective)
                c.addWidget(controls)
                c.addWidget(evidence)
                grid.addWidget(card, idx // 2, idx % 2)
            scroll.setWidget(content)
            layout.addWidget(scroll, 1)
            return page

        def _build_encrypt_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(26, 24, 26, 24)
            layout.setSpacing(18)

            header = self._page_header(
                "Protect & Share",
                "Run DLP first. If policy allows the transfer, the file is encrypted locally and packaged for secure sharing.",
            )
            layout.addWidget(header)

            body = QGridLayout()
            body.setSpacing(18)
            form_card = self._card()
            form = QGridLayout(form_card)
            form.setContentsMargins(22, 22, 22, 22)
            form.setHorizontalSpacing(12)
            form.setVerticalSpacing(12)

            self.file_input = QLineEdit()
            self.file_input.setPlaceholderText("Choose a file to protect")
            browse = QPushButton("Browse")
            browse.clicked.connect(self.browse_file)
            safe_demo = QPushButton("Safe Demo")
            safe_demo.clicked.connect(lambda: self._set_demo_file("safe_notes.txt"))
            risky_demo = QPushButton("Risky Demo")
            risky_demo.clicked.connect(lambda: self._set_demo_file("sensitive_customer_data.txt"))

            form.addWidget(self._field_label("File"), 0, 0)
            form.addWidget(self.file_input, 0, 1, 1, 3)
            form.addWidget(browse, 0, 4)
            form.addWidget(safe_demo, 1, 1)
            form.addWidget(risky_demo, 1, 2)

            self.recipient_input = QLineEdit("analyst@example.com")
            self.recipient_input.setPlaceholderText("recipient@company.com")
            self.role_input = QComboBox()
            self.role_input.addItems(["external", "trusted", "internal"])
            self.expiry_input = QSpinBox()
            self.expiry_input.setRange(1, 24 * 30)
            self.expiry_input.setValue(24)
            self.expiry_input.setSuffix(" hours")
            self.pass_input = QLineEdit()
            self.pass_input.setEchoMode(QLineEdit.Password)
            self.pass_input.setPlaceholderText("minimum 8 characters")
            self.pass_input.textChanged.connect(self._update_pass_strength)
            self.pass_strength = QLabel("Passphrase strength: waiting")
            self.pass_strength.setObjectName("Muted")
            self.override_box = QCheckBox("Instructor demo override for blocked transfers")
            self.override_box.setObjectName("CheckBox")

            form.addWidget(self._field_label("Recipient"), 2, 0)
            form.addWidget(self.recipient_input, 2, 1, 1, 4)
            form.addWidget(self._field_label("Recipient role"), 3, 0)
            form.addWidget(self.role_input, 3, 1, 1, 2)
            form.addWidget(self._field_label("Expires after"), 4, 0)
            form.addWidget(self.expiry_input, 4, 1, 1, 2)
            form.addWidget(self._field_label("Passphrase"), 5, 0)
            form.addWidget(self.pass_input, 5, 1, 1, 4)
            form.addWidget(self.pass_strength, 6, 1, 1, 3)
            form.addWidget(self.override_box, 7, 1, 1, 4)

            # ── Email delivery section ────────────────────────────────────
            email_sep = QFrame()
            email_sep.setFrameShape(QFrame.HLine)
            email_sep.setObjectName("Separator")
            form.addWidget(email_sep, 8, 0, 1, 5)

            email_header = QLabel("Email Delivery (optional)")
            email_header.setObjectName("SectionTitle")
            form.addWidget(email_header, 9, 0, 1, 5)

            self.send_email_box = QCheckBox("Send package to recipient via email after encryption")
            self.send_email_box.setObjectName("CheckBox")
            self.send_email_box.toggled.connect(self._toggle_email_fields)
            form.addWidget(self.send_email_box, 10, 1, 1, 4)

            self.smtp_provider = QComboBox()
            self.smtp_provider.addItems(list(PROVIDER_PRESETS.keys()))
            self.smtp_provider.currentTextChanged.connect(self._apply_smtp_preset)
            form.addWidget(self._field_label("Provider"), 11, 0)
            form.addWidget(self.smtp_provider, 11, 1, 1, 4)

            self.smtp_host_input = QLineEdit()
            self.smtp_host_input.setPlaceholderText("smtp.example.com")
            self.smtp_port_input = QLineEdit("587")
            self.smtp_port_input.setFixedWidth(70)
            self.smtp_ssl_box = QCheckBox("SSL (port 465)")
            self.smtp_ssl_box.setObjectName("CheckBox")
            form.addWidget(self._field_label("SMTP host"), 12, 0)
            form.addWidget(self.smtp_host_input, 12, 1, 1, 2)
            form.addWidget(self.smtp_port_input, 12, 3)
            form.addWidget(self.smtp_ssl_box, 12, 4)

            self.sender_email_input = QLineEdit()
            self.sender_email_input.setPlaceholderText("your@email.com")
            form.addWidget(self._field_label("Your email"), 13, 0)
            form.addWidget(self.sender_email_input, 13, 1, 1, 4)

            self.sender_pass_input = QLineEdit()
            self.sender_pass_input.setEchoMode(QLineEdit.Password)
            self.sender_pass_input.setPlaceholderText("App Password / SMTP password")
            form.addWidget(self._field_label("SMTP password"), 14, 0)
            form.addWidget(self.sender_pass_input, 14, 1, 1, 4)

            self.smtp_help_label = QLabel("")
            self.smtp_help_label.setObjectName("Muted")
            self.smtp_help_label.setWordWrap(True)
            form.addWidget(self.smtp_help_label, 15, 1, 1, 4)

            # Start with email fields hidden
            self._email_widgets = [
                self.smtp_provider, self.smtp_host_input, self.smtp_port_input,
                self.smtp_ssl_box, self.sender_email_input, self.sender_pass_input,
                self.smtp_help_label,
            ]
            self._toggle_email_fields(False)
            self._apply_smtp_preset(self.smtp_provider.currentText())

            run_btn = QPushButton("Run DLP → Encrypt → Create Share Link")
            run_btn.setObjectName("PrimaryButton")
            run_btn.clicked.connect(self.run_encrypt)
            form.addWidget(run_btn, 16, 0, 1, 5)

            result_card = self._card()
            result_layout = QVBoxLayout(result_card)
            result_layout.setContentsMargins(18, 18, 18, 18)
            result_title = QLabel("Decision Rail")
            result_title.setObjectName("SectionTitle")
            self.result_decision = QLabel("Waiting for DLP scan")
            self.result_decision.setObjectName("DecisionBadge")
            self.result_risk = QLabel("Risk score: --/100")
            self.result_risk.setObjectName("InfoText")
            self.risk_bar = QProgressBar()
            self.risk_bar.setRange(0, 100)
            self.risk_bar.setValue(0)
            self.risk_bar.setTextVisible(True)
            self.encrypt_output = QTextEdit()
            self.encrypt_output.setReadOnly(True)
            self.encrypt_output.setObjectName("Terminal")
            self.encrypt_output.setPlainText("Run a demo to see DLP verdict, encrypted package path, expiration, report path, and share token.")
            result_layout.addWidget(result_title)
            result_layout.addWidget(self.result_decision)
            result_layout.addWidget(self.result_risk)
            result_layout.addWidget(self.risk_bar)
            result_layout.addWidget(self.encrypt_output, 1)

            body.addWidget(form_card, 0, 0)
            body.addWidget(result_card, 0, 1)
            body.setColumnStretch(0, 3)
            body.setColumnStretch(1, 2)
            layout.addLayout(body, 1)
            return page

        def _build_decrypt_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(26, 24, 26, 24)
            layout.setSpacing(18)
            layout.addWidget(self._page_header("Open Package", "Inspect and decrypt .sftpkg files after validating expiration and integrity."))

            # ── Download-by-link card ─────────────────────────────────────
            link_card = self._card()
            link_form = QGridLayout(link_card)
            link_form.setContentsMargins(22, 22, 22, 22)
            link_form.setSpacing(12)
            link_form.addWidget(QLabel("Got a share link? Paste it below to download the encrypted package."), 0, 0, 1, 3)
            self.share_link_input = QLineEdit()
            self.share_link_input.setPlaceholderText("https://xxxx.ngrok-free.app/share/...")
            download_btn = QPushButton("Download Package")
            download_btn.setObjectName("PrimaryButton")
            download_btn.clicked.connect(self.download_from_link)
            link_form.addWidget(self._field_label("Share link"), 1, 0)
            link_form.addWidget(self.share_link_input, 1, 1)
            link_form.addWidget(download_btn, 1, 2)
            self.download_status = QLabel("")
            self.download_status.setObjectName("Muted")
            self.download_status.setWordWrap(True)
            link_form.addWidget(self.download_status, 2, 1, 1, 2)
            link_form.setColumnStretch(1, 1)
            layout.addWidget(link_card)

            # ── Decrypt card ──────────────────────────────────────────────
            card = self._card()
            form = QGridLayout(card)
            form.setContentsMargins(22, 22, 22, 22)
            form.setSpacing(12)

            self.package_input = QLineEdit()
            self.package_input.setPlaceholderText("Choose .sftpkg package")
            browse = QPushButton("Browse")
            browse.clicked.connect(self.browse_package)
            self.decrypt_pass = QLineEdit()
            self.decrypt_pass.setEchoMode(QLineEdit.Password)
            self.decrypt_pass.setPlaceholderText("Package passphrase")
            inspect_btn = QPushButton("Inspect Metadata")
            inspect_btn.clicked.connect(self.inspect_package)
            decrypt_btn = QPushButton("Decrypt Package")
            decrypt_btn.setObjectName("PrimaryButton")
            decrypt_btn.clicked.connect(self.run_decrypt)

            form.addWidget(self._field_label("Package"), 0, 0)
            form.addWidget(self.package_input, 0, 1)
            form.addWidget(browse, 0, 2)
            form.addWidget(self._field_label("Passphrase"), 1, 0)
            form.addWidget(self.decrypt_pass, 1, 1, 1, 2)
            form.addWidget(inspect_btn, 2, 1)
            form.addWidget(decrypt_btn, 2, 2)
            self.decrypt_output = QTextEdit()
            self.decrypt_output.setReadOnly(True)
            self.decrypt_output.setObjectName("Terminal")
            form.addWidget(self.decrypt_output, 3, 0, 1, 3)
            form.setColumnStretch(1, 1)
            layout.addWidget(card, 1)
            return page

        def _build_audit_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(26, 24, 26, 24)
            layout.setSpacing(18)

            top = QHBoxLayout()
            top.addWidget(self._page_header("Audit Trail", "Every DLP scan, block, encryption, share action, and decryption is timestamped locally."), 1)
            refresh = QPushButton("Refresh")
            refresh.clicked.connect(self.refresh_all)
            verify = QPushButton("Verify Chain")
            verify.clicked.connect(self.verify_chain)
            export = QPushButton("Export JSON")
            export.clicked.connect(self.export_audit_json)
            top.addWidget(verify)
            top.addWidget(export)
            top.addWidget(refresh)
            layout.addLayout(top)

            card = self._card()
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 16, 16, 16)
            self.audit_table = QTableWidget(0, 8)
            self.audit_table.setHorizontalHeaderLabels([
                "Time UTC", "Event", "Status", "File", "Recipient", "Package Hash", "Record Hash", "Details"
            ])
            self.audit_table.setAlternatingRowColors(True)
            self.audit_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.audit_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.audit_table.verticalHeader().setVisible(False)
            header = self.audit_table.horizontalHeader()
            header.setStretchLastSection(True)
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
            card_layout.addWidget(self.audit_table)
            layout.addWidget(card, 1)
            return page


        def _build_policy_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(26, 24, 26, 24)
            layout.setSpacing(18)
            top = QHBoxLayout()
            top.addWidget(self._page_header("Policy Editor", "Edit the local DLP policy used for blocked extensions, high-risk file types, and risk scoring."), 1)
            load_btn = QPushButton("Reload")
            load_btn.clicked.connect(self.load_policy_editor)
            save_btn = QPushButton("Save Policy")
            save_btn.setObjectName("PrimaryButton")
            save_btn.clicked.connect(self.save_policy_editor)
            top.addWidget(load_btn)
            top.addWidget(save_btn)
            layout.addLayout(top)

            card = self._card()
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(18, 18, 18, 18)
            note = QLabel("The policy is stored as JSON and loaded by the DLP engine. Keep it simple for the demo: blocked external extensions, high-risk extensions, and risk weights.")
            note.setObjectName("InfoText")
            note.setWordWrap(True)
            self.policy_editor = QTextEdit()
            self.policy_editor.setObjectName("Terminal")
            self.policy_editor.setPlainText(PolicyConfig.load(self.policy_path).to_json())
            card_layout.addWidget(note)
            card_layout.addWidget(self.policy_editor, 1)
            layout.addWidget(card, 1)
            return page

        # ---------- Actions ----------
        def _activate_nav(self, index: int) -> None:
            self.stack.setCurrentIndex(index)
            for idx, button in enumerate(self.nav_buttons):
                button.setProperty("active", idx == index)
                button.style().unpolish(button)
                button.style().polish(button)

        def browse_file(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Choose file")
            if path:
                self.file_input.setText(path)

        def browse_package(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Choose package", filter="Secure Package (*.sftpkg)")
            if path:
                self.package_input.setText(path)

        def _set_demo_file(self, name: str) -> None:
            path = APP_ROOT / "sample_data" / name
            self.file_input.setText(str(path))

        def _toggle_email_fields(self, enabled: bool) -> None:
            for w in self._email_widgets:
                w.setVisible(enabled)

        def _apply_smtp_preset(self, provider: str) -> None:
            preset = PROVIDER_PRESETS.get(provider, {})
            self.smtp_host_input.setText(preset.get("smtp_host", ""))
            self.smtp_port_input.setText(str(preset.get("smtp_port", 587)))
            self.smtp_ssl_box.setChecked(bool(preset.get("use_ssl", False)))
            self.smtp_help_label.setText(preset.get("help", ""))

        def run_encrypt(self) -> None:
            try:
                send_email = self.send_email_box.isChecked()
                result = self.service.encrypt_and_share(
                    file_path=self.file_input.text().strip(),
                    recipient_email=self.recipient_input.text().strip(),
                    recipient_role=self.role_input.currentText(),
                    passphrase=self.pass_input.text(),
                    expires_hours=int(self.expiry_input.value()),
                    override_dlp_block=self.override_box.isChecked(),
                    send_email=send_email,
                    smtp_host=self.smtp_host_input.text().strip() if send_email else "",
                    smtp_port=int(self.smtp_port_input.text().strip() or "587") if send_email else 587,
                    smtp_use_ssl=self.smtp_ssl_box.isChecked() if send_email else False,
                    sender_email=self.sender_email_input.text().strip() if send_email else "",
                    sender_password=self.sender_pass_input.text() if send_email else "",
                    base_url=self._public_url,
                )
                self.encrypt_output.setPlainText(json.dumps(result, indent=2, sort_keys=True))
                dlp = result.get("dlp", {})
                score = int(dlp.get("risk_score", 0) or 0)
                decision = str(dlp.get("decision", result.get("status", "unknown"))).upper()
                self.result_decision.setText(f"Decision: {decision}")
                self.result_risk.setText(f"Risk score: {score}/100 • Confidence: {str(dlp.get('confidence', 'low')).upper()}")
                self.risk_bar.setValue(max(0, min(100, score)))
                self.refresh_all()
                if result["status"] == "blocked":
                    QMessageBox.warning(self, "DLP Blocked", result["message"])
                else:
                    email_note = ""
                    if result.get("email_sent"):
                        email_note = f"\n\n✅ Package emailed to {self.recipient_input.text().strip()}"
                    elif result.get("email_error"):
                        email_note = f"\n\n⚠️ Email failed: {result['email_error']}"
                    QMessageBox.information(
                        self,
                        "Secure Package Created",
                        f"DLP allowed the transfer and the encrypted package was created.{email_note}",
                    )
            except Exception as exc:
                QMessageBox.critical(self, "Error", str(exc))

        def download_from_link(self) -> None:
            import urllib.request
            link = self.share_link_input.text().strip()
            if not link.startswith("http"):
                self.download_status.setText("⚠️ Link must start with https://")
                return
            try:
                save_dir = APP_ROOT / "downloaded_packages"
                save_dir.mkdir(parents=True, exist_ok=True)
                # Derive filename from URL or use default
                filename = link.rsplit("/share/", 1)[-1][:20] + ".sftpkg"
                save_path = save_dir / filename
                self.download_status.setText("Downloading…")
                QApplication.processEvents()
                req = urllib.request.Request(link, headers={"User-Agent": "SFT-DLP-App/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    # Use Content-Disposition filename if available
                    cd = resp.headers.get("Content-Disposition", "")
                    if 'filename="' in cd:
                        filename = cd.split('filename="')[1].rstrip('"')
                        save_path = save_dir / filename
                    data = resp.read()
                save_path.write_bytes(data)
                self.package_input.setText(str(save_path))
                self.download_status.setText(f"✅ Saved to: {save_path}")
            except Exception as exc:
                self.download_status.setText(f"❌ Download failed: {exc}")

        def inspect_package(self) -> None:
            try:
                result = self.service.inspect_package(self.package_input.text().strip())
                self.decrypt_output.setPlainText(json.dumps(result, indent=2, sort_keys=True))
            except Exception as exc:
                QMessageBox.critical(self, "Error", str(exc))

        def run_decrypt(self) -> None:
            try:
                result = self.service.decrypt_package(self.package_input.text().strip(), self.decrypt_pass.text())
                self.decrypt_output.setPlainText(json.dumps(result, indent=2, sort_keys=True))
                self.refresh_all()
                QMessageBox.information(self, "Success", f"Restored to {result['output_path']}")
            except Exception as exc:
                QMessageBox.critical(self, "Error", str(exc))


        def load_policy_editor(self) -> None:
            try:
                self.policy_editor.setPlainText(PolicyConfig.load(self.policy_path).to_json())
                QMessageBox.information(self, "Policy Loaded", "DLP policy reloaded from disk.")
            except Exception as exc:
                QMessageBox.critical(self, "Policy Error", str(exc))

        def save_policy_editor(self) -> None:
            try:
                data = json.loads(self.policy_editor.toPlainText())
                PolicyConfig(data).save(self.policy_path)
                self.service.dlp.reload_policy(self.policy_path)
                QMessageBox.information(self, "Policy Saved", f"Policy saved to {self.policy_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Policy Error", str(exc))

        def refresh_all(self) -> None:
            self.refresh_audit()
            self.refresh_metrics()

        def refresh_metrics(self) -> None:
            stats = self.audit.stats()
            self.metric_total.findChild(QLabel, "MetricValue").setText(str(stats["total_events"]))
            self.metric_blocked.findChild(QLabel, "MetricValue").setText(str(stats["blocked_actions"]))
            self.metric_encrypted.findChild(QLabel, "MetricValue").setText(str(stats["encrypted_packages"]))
            self.metric_chain.findChild(QLabel, "MetricValue").setText("Valid" if stats["hash_chain_valid"] else "Broken")

        def refresh_audit(self) -> None:
            logs = self.audit.recent(200)
            self.audit_table.setRowCount(len(logs))
            for row, log in enumerate(logs):
                values = [
                    log.get("timestamp_utc", ""),
                    log.get("event_type", ""),
                    log.get("status", ""),
                    log.get("file_name", "") or "",
                    log.get("recipient", "") or "",
                    self._short_hash(log.get("package_hash")),
                    self._short_hash(log.get("record_hash")),
                    (log.get("details_json", "") or "")[:180],
                ]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if col == 2:
                        status = str(value).lower()
                        if status == "blocked":
                            item.setForeground(QColor("#ffb4a8"))
                        elif status == "success":
                            item.setForeground(QColor("#9ff2c5"))
                    self.audit_table.setItem(row, col, item)

        def verify_chain(self) -> None:
            result = self.audit.verify_chain()
            title = "Audit Chain Valid" if result["valid"] else "Audit Chain Broken"
            QMessageBox.information(self, title, json.dumps(result, indent=2))
            self.refresh_metrics()

        def export_audit_json(self) -> None:
            default = str(Path.cwd() / "audit_export.json")
            path, _ = QFileDialog.getSaveFileName(self, "Export audit JSON", default, "JSON Files (*.json)")
            if not path:
                return
            exported = self.audit.export_json(path)
            QMessageBox.information(self, "Export Complete", f"Audit evidence exported to:\n{exported}")

        def _update_pass_strength(self, text: str) -> None:
            score = 0
            score += len(text) >= 8
            score += len(text) >= 12
            score += any(ch.islower() for ch in text) and any(ch.isupper() for ch in text)
            score += any(ch.isdigit() for ch in text)
            score += any(not ch.isalnum() for ch in text)
            levels = {0: "waiting", 1: "weak", 2: "medium", 3: "good", 4: "strong", 5: "excellent"}
            self.pass_strength.setText(f"Passphrase strength: {levels.get(score, 'excellent')}")

        # ---------- Small UI helpers ----------
        def _page_header(self, title: str, subtitle: str) -> QFrame:
            frame = QFrame()
            frame.setObjectName("Header")
            layout = QVBoxLayout(frame)
            layout.setContentsMargins(0, 0, 0, 0)
            h = QLabel(title)
            h.setObjectName("PageTitle")
            s = QLabel(subtitle)
            s.setObjectName("PageSubtitle")
            s.setWordWrap(True)
            layout.addWidget(h)
            layout.addWidget(s)
            return frame

        def _card(self) -> QFrame:
            frame = QFrame()
            frame.setObjectName("Card")
            frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            return frame

        def _metric_card(self, title: str, value: str, caption: str) -> QFrame:
            card = self._card()
            layout = QVBoxLayout(card)
            layout.setContentsMargins(18, 16, 18, 16)
            t = QLabel(title)
            t.setObjectName("MetricTitle")
            v = QLabel(value)
            v.setObjectName("MetricValue")
            v.setFont(QFont("Segoe UI", 22, QFont.Bold))
            c = QLabel(caption)
            c.setObjectName("Muted")
            c.setWordWrap(True)
            layout.addWidget(t)
            layout.addWidget(v)
            layout.addWidget(c)
            return card

        def _info_card(self, title: str, body: str) -> QFrame:
            card = self._card()
            layout = QVBoxLayout(card)
            layout.setContentsMargins(20, 18, 20, 18)
            t = QLabel(title)
            t.setObjectName("SectionTitle")
            b = QLabel(body)
            b.setObjectName("InfoText")
            b.setWordWrap(True)
            layout.addWidget(t)
            layout.addWidget(b)
            return card

        def _field_label(self, text: str) -> QLabel:
            label = QLabel(text)
            label.setObjectName("FieldLabel")
            return label

        @staticmethod
        def _short_hash(value: str | None) -> str:
            if not value:
                return ""
            return value[:10] + "…" + value[-6:] if len(value) > 20 else value

        def _apply_style(self) -> None:
            self.setStyleSheet(
                """
                QMainWindow, QWidget {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #050814, stop:0.45 #071326, stop:1 #0b1020);
                    color: #eaf2ff;
                    font-family: Segoe UI, Arial;
                    font-size: 13px;
                }
                QFrame#Sidebar {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #071326, stop:1 #050814);
                    border-right: 1px solid #1f3357;
                }
                QLabel#Logo { font-size: 28px; font-weight: 900; color: #ffffff; letter-spacing: 1px; }
                QLabel#SidebarFooter {
                    color: #9fb5d8; background: rgba(22, 42, 80, 0.45); border: 1px solid #263d66;
                    border-radius: 16px; padding: 14px; line-height: 1.4;
                }
                QPushButton#NavButton {
                    background: transparent; color: #b8c7e4; border: 1px solid transparent;
                    text-align: left; padding: 13px 14px; border-radius: 13px; font-weight: 700;
                }
                QPushButton#NavButton:hover { background: #101e36; color: #ffffff; border: 1px solid #233a61; }
                QPushButton#NavButton[active="true"] {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #7c3aed);
                    color: white; border: 1px solid #5b7fff;
                }
                QFrame#Card {
                    background: rgba(14, 25, 46, 0.88); border: 1px solid #24395f;
                    border-radius: 18px;
                }
                QLabel#HeroTitle { font-size: 32px; font-weight: 900; color: white; }
                QLabel#HeroSubtitle, QLabel#PageSubtitle { color: #a9bad6; font-size: 14px; }
                QLabel#PageTitle { font-size: 27px; font-weight: 900; color: white; }
                QLabel#SectionTitle { font-size: 18px; font-weight: 850; color: white; }
                QLabel#MetricTitle { color: #97aacf; font-weight: 750; }
                QLabel#MetricValue { color: #ffffff; }
                QLabel#Muted { color: #8fa5c9; }
                QLabel#InfoText { color: #cbd8ef; line-height: 1.5; }
                QLabel#FieldLabel { color: #dce8fb; font-weight: 750; }
                QLineEdit, QSpinBox, QComboBox, QTextEdit {
                    background: #081225; color: #eef6ff; border: 1px solid #2a416b;
                    border-radius: 11px; padding: 10px; selection-background-color: #2563eb;
                }
                QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus { border: 1px solid #60a5fa; }
                QTextEdit#Terminal {
                    background: #050b16; color: #d7e6ff; border: 1px solid #263e68;
                    font-family: Consolas, Cascadia Mono, monospace; font-size: 12px;
                }
                QPushButton {
                    background: #142341; color: #eaf2ff; border: 1px solid #2b4774;
                    border-radius: 11px; padding: 10px 14px; font-weight: 800;
                }
                QPushButton:hover { background: #1c3158; border: 1px solid #4b79bd; }
                QPushButton#PrimaryButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #7c3aed);
                    color: white; border: 1px solid #7295ff; padding: 13px 16px;
                }
                QCheckBox#CheckBox { color: #b9c8e4; padding: 6px; }
                QTableWidget {
                    background: #081225; alternate-background-color: #0d1930; color: #eaf2ff;
                    border: 1px solid #24395f; border-radius: 12px; gridline-color: #1d3152;
                }
                QHeaderView::section {
                    background: #12264a; color: #ffffff; border: 0; border-right: 1px solid #2f4a78;
                    padding: 9px; font-weight: 850;
                }
                QTableWidget::item { padding: 8px; }
                QScrollBar:vertical { background: #081225; width: 12px; margin: 0; }
                QScrollBar::handle:vertical { background: #2a416b; border-radius: 6px; min-height: 30px; }

                QLabel#DecisionBadge {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #12305c, stop:1 #24164f);
                    border: 1px solid #365f99; border-radius: 14px; padding: 12px;
                    color: #ffffff; font-size: 18px; font-weight: 900;
                }
                QLabel#Pill {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #7c3aed);
                    color: white; border-radius: 12px; padding: 8px 12px; max-width: 42px; font-weight: 900;
                }
                QProgressBar {
                    background: #061226; color: #eaf2ff; border: 1px solid #2a416b; border-radius: 10px;
                    text-align: center; height: 22px; font-weight: 800;
                }
                QProgressBar::chunk {
                    border-radius: 9px;
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #38bdf8, stop:0.55 #7c3aed, stop:1 #ef4444);
                }
                QScrollArea#MethodScroll { background: transparent; border: 0; }
                """
            )

    app = QApplication(sys.argv)
    window = App()
    window.show()
    app.exec_()
