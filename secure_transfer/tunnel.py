"""
tunnel.py – Creates a public ngrok HTTPS tunnel to the local share server.

ngrok gives the sender a public URL like https://abc123.ngrok-free.app
that works from any network. The recipient pastes this URL into the app.

Free ngrok accounts work fine. No account needed for basic use, but
authenticated accounts get a stable subdomain and no browser warning page.
"""
from __future__ import annotations

import threading

_public_url: str | None = None
_tunnel_thread: threading.Thread | None = None
_error: str | None = None


def start(port: int, ngrok_auth_token: str | None = None) -> None:
    """Start ngrok tunnel in a background thread."""
    global _tunnel_thread

    if _tunnel_thread and _tunnel_thread.is_alive():
        return

    def _run() -> None:
        global _public_url, _error
        try:
            from pyngrok import ngrok, conf
        except ImportError:
            _error = "pyngrok not installed. Run: pip install pyngrok"
            return

        try:
            if ngrok_auth_token:
                conf.get_default().auth_token = ngrok_auth_token

            tunnel = ngrok.connect(port, "http")
            _public_url = tunnel.public_url.replace("http://", "https://")
        except Exception as exc:
            _error = str(exc)

    _tunnel_thread = threading.Thread(target=_run, daemon=True)
    _tunnel_thread.start()
    _tunnel_thread.join(timeout=15)  # Wait up to 15s for tunnel to come up


def get_public_url() -> str | None:
    return _public_url


def get_error() -> str | None:
    return _error


def is_active() -> bool:
    return _public_url is not None
