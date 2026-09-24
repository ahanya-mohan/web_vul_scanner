"""The bundled vulnerable target application.

Intentionally insecure — see the package docstring. Each vulnerable route is
paired with a safe equivalent so the scanner's checks can demonstrate both a
true positive (vulnerable route) and no false positive (safe route).
"""

from __future__ import annotations

import sqlite3

from flask import Flask, request

from targets.vulnerable_app.db import Database

_INDEX_HTML = """<!doctype html>
<title>Vulnerable Practice Target</title>
<h1>Vulnerable Practice Target</h1>
<p>This app is intentionally insecure and exists only as a scanning target
for web_vul_scanner. Do not deploy it.</p>
<ul>
  <li><a href="/search?q=phone">Product search</a></li>
</ul>
"""


def create_app() -> Flask:
    app = Flask(__name__)
    db = Database()

    @app.get("/")
    def index() -> str:
        return _INDEX_HTML

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    # -- SQL injection: vulnerable vs. safe -------------------------------------

    @app.get("/search")
    def search() -> tuple[str, int] | str:
        q = request.args.get("q", "")
        # VULNERABLE: user input concatenated straight into the SQL string.
        sql = f"SELECT name, price FROM products WHERE name LIKE '%{q}%'"
        try:
            rows = db.execute(sql)
        except sqlite3.Error as exc:
            # VULNERABLE: echoing the DB error enables error-based detection.
            return f"Database error: {exc}", 500
        items = "".join(f"<li>{name} - ${price}</li>" for name, price in rows)
        return f"<h1>Search results</h1><ul>{items}</ul>"

    @app.get("/search-safe")
    def search_safe() -> str:
        q = request.args.get("q", "")
        # SAFE: parameterized query; the value can never change the SQL.
        rows = db.execute("SELECT name, price FROM products WHERE name LIKE ?", (f"%{q}%",))
        items = "".join(f"<li>{name} - ${price}</li>" for name, price in rows)
        return f"<h1>Search results</h1><ul>{items}</ul>"

    return app


if __name__ == "__main__":  # pragma: no cover
    # Bind to loopback only: this app must never be reachable off-box.
    create_app().run(host="127.0.0.1", port=5000)
