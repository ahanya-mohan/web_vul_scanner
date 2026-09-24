"""The bundled vulnerable target application.

Intentionally insecure — see the package docstring. Slice 0 provides only a
landing page and a health endpoint; the injectable routes arrive in later
slices alongside the checks that detect them.
"""

from __future__ import annotations

from flask import Flask

_INDEX_HTML = """<!doctype html>
<title>Vulnerable Practice Target</title>
<h1>Vulnerable Practice Target</h1>
<p>This app is intentionally insecure and exists only as a scanning target
for web_vul_scanner. Do not deploy it.</p>
"""


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return _INDEX_HTML

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    return app


if __name__ == "__main__":  # pragma: no cover
    # Bind to loopback only: this app must never be reachable off-box.
    create_app().run(host="127.0.0.1", port=5000)
