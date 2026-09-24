"""The Django UI is a thin wrapper over the scanner library."""

from __future__ import annotations


def test_form_page_renders(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert b"Target URL" in response.content


def test_scan_renders_findings(client, target_url: str) -> None:
    response = client.post("/", {"url": target_url, "allow_hosts": ""})
    assert response.status_code == 200
    assert b"Target reachable" in response.content
    assert b"SQL injection" in response.content


def test_unauthorized_host_shows_error(client) -> None:
    response = client.post("/", {"url": "http://example.com", "allow_hosts": ""})
    assert response.status_code == 200
    assert b"not authorized" in response.content
