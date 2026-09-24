"""Shared fixtures. The bundled vulnerable app runs in a background thread so
tests (and CI) can scan a real HTTP target without any external setup.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from targets.vulnerable_app import create_app


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def target_url() -> Iterator[str]:
    """Start the vulnerable target on a loopback port; yield its base URL."""
    port = _free_port()
    server = make_server("127.0.0.1", port, create_app(), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
