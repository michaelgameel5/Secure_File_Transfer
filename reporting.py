from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .methodology import METHODOLOGY_STAGES
from .models import utc_now_iso


class HTMLReportGenerator:
    """Generates polished standalone HTML evidence reports for each transfer attempt.

    Every report also receives a `.sha256` sidecar file so the reviewer can prove the
    HTML report was not changed after generation.
    """

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_transfer_report(self, operation: dict[str, Any]) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        status = str(operation.get("status", "unknown")).lower()
        file_name = Path(str(operation.get("file_path", "transfer"))).stem or "transfer"
        safe_stem = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in file_name)[:50]
        path = self.output_dir / f"transfer_report_{safe_stem}_{status}_{timestamp}.html"
        path.write_text(self._render(operation), encoding="utf-8")
        digest = self.sha256(path)
        path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
        return path

    @staticmethod
    def sha256(path: str | Path) -> str:
        h = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _render(self, operation: dict[str, Any]) -> str:
        dlp = operation.get("dlp", {}) or {}
        findings = dlp.get("findings", []) or []
        blocked = bool(dlp.get("blocked"))
        status = "BLOCKED" if blocked or operation.get("status") == "blocked" else "APPROVED"
        status_class = "blocked" if status == "BLOCKED" else "approved"
        risk_score = max(0, min(100, int(dlp.get("risk_score", 0) or 0)))
        decision = str(dlp.get("decision", status.lower())).upper()
        package_hash = operation.get("package_hash") or "Not created"
        package_path = operation.get("package_path") or "Not created"
        share_link = operation.get("share_link") or "Not created"
        next_action = operation.get("next_action") or dlp.get("recommended_action") or "Review the transfer decision and retain generated evidence."
        report_hash_note = "A .sha256 sidecar is generated beside this HTML file for report-integrity verification."

        findings_rows = "".join(
            f"""
            <tr>
              <td>{html.escape(str(item.get('rule_id', '')))}</td>
              <td>{html.escape(str(item.get('label', '')))}</td>
              <td><span class=\"sev {html.escape(str(item.get('severity', '')).lower())}\">{html.escape(str(item.get('severity', '')).upper())}</span></td>
              <td>{html.escape(str(item.get('count', '')))}</td>
              <td><code>{html.escape(str(item.get('evidence', '')))}</code></td>
            </tr>
            """
            for item in findings
        ) or "<tr><td colspan='5'>No DLP findings detected.</td></tr>"

        blocked_reasons = dlp.get("blocked_reasons", []) or []
        reasons_html = "".join(f"<li>{html.escape(str(reason))}</li>" for reason in blocked_reasons) or "<li>No block reason. Transfer allowed by current policy.</li>"
        methodology_html = "".join(
            f"""
            <div class=\"method-card\">
              <div class=\"method-index\">{idx:02d}</div>
              <div>
                <h3>{html.escape(stage.stage)}</h3>
                <p>{html.escape(stage.objective)}</p>
              </div>
            </div>
            """
            for idx, stage in enumerate(METHODOLOGY_STAGES, start=1)
        )
        operation_json = html.escape(json.dumps(operation, indent=2, sort_keys=True))
        risk_band = "Critical" if risk_score >= 70 else ("Review" if risk_score >= 25 else "Low")

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Transfer Evidence Report</title>
  <style>
    :root {{
      --bg:#030712; --panel:#071326; --panel2:#0c1b33; --line:#244064; --text:#edf5ff;
      --muted:#a4b8d8; --blue:#38bdf8; --indigo:#2563eb; --purple:#8b5cf6; --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Segoe UI, Inter, Arial, sans-serif; background:radial-gradient(circle at 18% -10%, rgba(56,189,248,.25), transparent 32%), radial-gradient(circle at 95% 8%, rgba(139,92,246,.24), transparent 34%), linear-gradient(135deg,#030712 0%,#071326 50%,#070a18 100%); color:var(--text); }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:38px 24px 60px; }}
    .hero {{ position:relative; overflow:hidden; border:1px solid rgba(148,163,184,.24); background:linear-gradient(135deg,rgba(12,27,51,.96),rgba(5,12,28,.88)); border-radius:32px; padding:34px; box-shadow:0 34px 90px rgba(0,0,0,.42); }}
    .hero:after {{ content:""; position:absolute; inset:-40% -15% auto auto; width:360px; height:360px; background:radial-gradient(circle,rgba(56,189,248,.16),transparent 68%); filter:blur(4px); }}
    .eyebrow {{ color:#93c5fd; text-transform:uppercase; letter-spacing:.18em; font-weight:900; font-size:12px; }}
    h1 {{ margin:10px 0 10px; font-size:46px; line-height:1.02; letter-spacing:-.04em; }}
    .subtitle {{ color:var(--muted); max-width:860px; line-height:1.65; font-size:15px; }}
    .topline {{ display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start; }}
    .badge {{ display:inline-flex; align-items:center; gap:8px; padding:11px 15px; border-radius:999px; font-weight:950; border:1px solid; box-shadow:0 0 26px rgba(59,130,246,.16); }}
    .badge.approved {{ background:rgba(34,197,94,.12); color:#bbf7d0; border-color:rgba(34,197,94,.45); }}
    .badge.blocked {{ background:rgba(239,68,68,.14); color:#fecaca; border-color:rgba(239,68,68,.5); }}
    .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:22px; }}
    .card {{ border:1px solid rgba(148,163,184,.22); background:rgba(7,19,38,.82); border-radius:24px; padding:21px; box-shadow:inset 0 1px 0 rgba(255,255,255,.04); }}
    .metric {{ font-size:34px; font-weight:950; margin-top:8px; letter-spacing:-.03em; }}
    .label {{ color:var(--muted); font-size:13px; font-weight:750; }}
    .two {{ display:grid; grid-template-columns:1.08fr .92fr; gap:16px; margin-top:16px; }}
    h2 {{ margin:0 0 14px; font-size:22px; letter-spacing:-.02em; }}
    h3 {{ margin:0 0 5px; font-size:15px; }}
    table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:16px; }}
    th,td {{ border-bottom:1px solid rgba(38,59,98,.75); padding:12px; text-align:left; vertical-align:top; }}
    th {{ background:#102447; color:#fff; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    code, pre {{ font-family:Cascadia Mono, Consolas, monospace; }}
    pre {{ white-space:pre-wrap; background:#030915; border:1px solid rgba(148,163,184,.23); border-radius:18px; padding:16px; color:#dbeafe; max-height:440px; overflow:auto; }}
    .sev {{ padding:5px 9px; border-radius:999px; font-size:12px; font-weight:950; }}
    .sev.low {{ background:rgba(59,130,246,.14); color:#bfdbfe; }}
    .sev.medium {{ background:rgba(245,158,11,.14); color:#fde68a; }}
    .sev.high,.sev.critical {{ background:rgba(239,68,68,.15); color:#fecaca; }}
    .risk-shell {{ margin-top:14px; height:13px; border-radius:999px; background:#111c33; border:1px solid rgba(148,163,184,.18); overflow:hidden; }}
    .risk-fill {{ width:{risk_score}%; height:100%; background:linear-gradient(90deg,var(--blue),var(--purple),var(--amber),var(--red)); }}
    .timeline {{ list-style:none; padding:0; margin:0; }}
    .timeline li {{ position:relative; padding:0 0 18px 30px; color:#dbeafe; }}
    .timeline li:before {{ content:""; position:absolute; left:4px; top:4px; width:12px; height:12px; border-radius:50%; background:linear-gradient(135deg,var(--blue),var(--purple)); box-shadow:0 0 20px rgba(56,189,248,.55); }}
    .timeline li:after {{ content:""; position:absolute; left:9px; top:19px; width:2px; height:calc(100% - 18px); background:#263b62; }}
    .timeline li:last-child:after {{ display:none; }}
    .method-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }}
    .method-card {{ display:flex; gap:12px; border:1px solid rgba(148,163,184,.18); background:rgba(12,27,51,.62); border-radius:18px; padding:14px; }}
    .method-index {{ min-width:36px; height:36px; display:grid; place-items:center; border-radius:12px; background:linear-gradient(135deg,var(--indigo),var(--purple)); font-weight:950; }}
    .method-card p {{ margin:0; color:var(--muted); line-height:1.45; font-size:13px; }}
    .callout {{ border:1px solid rgba(56,189,248,.28); background:linear-gradient(135deg,rgba(56,189,248,.12),rgba(139,92,246,.09)); border-radius:22px; padding:18px; color:#dbeafe; }}
    .foot {{ color:var(--muted); font-size:12px; margin-top:18px; }}
    @media(max-width:960px) {{ .grid,.two,.method-grid {{ grid-template-columns:1fr; }} h1 {{ font-size:34px; }} }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <div class="topline">
        <div>
          <div class="eyebrow">Secure File Transfer & DLP Evidence</div>
          <h1>Transfer Decision Report</h1>
          <p class="subtitle">Local-first evidence report showing DLP verdict, risk scoring, package details, expiration, and audit-ready technical metadata.</p>
        </div>
        <span class="badge {status_class}">{status}</span>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Risk Score</div><div class="metric">{risk_score}/100</div><div class="risk-shell"><div class="risk-fill"></div></div></div>
        <div class="card"><div class="label">Risk Band</div><div class="metric">{html.escape(risk_band)}</div></div>
        <div class="card"><div class="label">Decision</div><div class="metric">{html.escape(decision)}</div></div>
        <div class="card"><div class="label">Confidence</div><div class="metric">{html.escape(str(dlp.get('confidence','low')).upper())}</div></div>
      </div>
    </section>

    <section class="two">
      <div class="card">
        <h2>Transfer Metadata</h2>
        <table>
          <tr><th>Field</th><th>Value</th></tr>
          <tr><td>Generated At UTC</td><td>{html.escape(utc_now_iso())}</td></tr>
          <tr><td>File</td><td>{html.escape(str(operation.get('file_path','')))}</td></tr>
          <tr><td>File SHA-256</td><td><code>{html.escape(str(operation.get('file_hash','')))}</code></td></tr>
          <tr><td>Recipient</td><td>{html.escape(str(dlp.get('recipient_email', operation.get('recipient_email',''))))}</td></tr>
          <tr><td>Recipient Role</td><td>{html.escape(str(dlp.get('recipient_role', operation.get('recipient_role',''))))}</td></tr>
          <tr><td>Package Path</td><td>{html.escape(str(package_path))}</td></tr>
          <tr><td>Package SHA-256</td><td><code>{html.escape(str(package_hash))}</code></td></tr>
          <tr><td>Share Link</td><td><code>{html.escape(str(share_link))}</code></td></tr>
          <tr><td>Expires At UTC</td><td>{html.escape(str(operation.get('expires_at_utc','Not created')))}</td></tr>
        </table>
      </div>
      <div class="card">
        <h2>Decision Timeline</h2>
        <ul class="timeline">
          <li>File selected and SHA-256 fingerprint calculated.</li>
          <li>DLP rules scanned content and file type locally.</li>
          <li>Recipient trust policy and risk score were evaluated.</li>
          <li>{'Transfer was blocked before encryption.' if status == 'BLOCKED' else 'AES-256-GCM package and expiring local share link were created.'}</li>
          <li>Audit event was written to the local SQLite hash chain.</li>
        </ul>
        <h2>Policy Reasons</h2>
        <ul>{reasons_html}</ul>
      </div>
    </section>

    <section class="card" style="margin-top:16px">
      <h2>DLP Findings</h2>
      <table>
        <thead><tr><th>Rule</th><th>Label</th><th>Severity</th><th>Count</th><th>Masked Evidence</th></tr></thead>
        <tbody>{findings_rows}</tbody>
      </table>
    </section>

    <section class="card" style="margin-top:16px">
      <h2>Methodology Trace</h2>
      <div class="method-grid">{methodology_html}</div>
    </section>

    <section class="callout" style="margin-top:16px">
      <h2>Recommended Action</h2>
      <p>{html.escape(str(next_action))}</p>
    </section>

    <section class="card" style="margin-top:16px">
      <h2>Raw Evidence JSON</h2>
      <pre>{operation_json}</pre>
      <p class="foot">{html.escape(report_hash_note)}</p>
    </section>
  </main>
</body>
</html>"""


def transfer_operation_hash(operation: dict[str, Any]) -> str:
    payload = json.dumps(operation, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
