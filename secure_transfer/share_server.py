"""
share_server.py – Local HTTP server that serves .sftpkg packages by share token.

The recipient pastes the public link into the app. The app calls this server
(via the ngrok tunnel) which validates the token, checks expiry/revocation,
and streams the file back.

Runs in a daemon thread so it doesn't block the GUI.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

# Flask is a new dependency — imported lazily so the rest of the app still
# works if it isn't installed yet.


PORT = 8765
_server_thread: threading.Thread | None = None
_flask_app: Any = None  # Flask app instance


def _make_flask_app(db_path: str) -> Any:
    try:
        from flask import Flask, abort, send_file
    except ImportError as exc:
        raise ImportError(
            "Flask is required for share server. Run: pip install flask"
        ) from exc

    from .database import Database
    from .utils import unb64url_json
    from datetime import datetime, timezone

    app = Flask(__name__)
    app.config["db_path"] = db_path

    # Suppress Flask startup banner
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    @app.route("/share/<token>", methods=["GET"])
    def serve_package(token: str):
        try:
            decoded = unb64url_json(token)
        except Exception:
            abort(400, "Invalid token")

        db = Database(app.config["db_path"])
        with db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM shares WHERE token = ?", (token,)
            ).fetchone()

        if not row:
            abort(404, "Share link not found")

        row_data = dict(row)

        if row_data.get("revoked"):
            abort(410, "Share link has been revoked")

        expires = datetime.fromisoformat(row_data["expires_at_utc"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            abort(410, "Share link has expired")

        if decoded.get("package_hash") != row_data.get("package_hash"):
            abort(403, "Token integrity check failed")

        package_path = Path(row_data["package_path"])
        if not package_path.exists():
            abort(404, "Package file not found on server")

        return send_file(
            package_path,
            as_attachment=True,
            download_name=package_path.name,
            mimetype="application/octet-stream",
        )

    @app.route("/ping", methods=["GET"])
    def ping():
        return {"status": "ok"}

    return app


def start(db_path: str) -> None:
    """Start the share server in a background daemon thread."""
    global _server_thread, _flask_app

    if _server_thread and _server_thread.is_alive():
        return  # Already running

    _flask_app = _make_flask_app(db_path)

    def _run() -> None:
        _flask_app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True)

    _server_thread = threading.Thread(target=_run, daemon=True)
    _server_thread.start()


def is_running() -> bool:
    return _server_thread is not None and _server_thread.is_alive()
