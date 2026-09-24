"""The reflected-XSS check must flag the unescaped route and clear the safe one."""

from __future__ import annotations

from web_vul_scanner.core.authorization import Authorization
from web_vul_scanner.report.models import Severity
from web_vul_scanner.scanner import Scanner


def _scan(url: str):
    with Scanner(Authorization()) as scanner:
        return scanner.scan(url)


def test_vulnerable_greet_is_flagged(target_url: str) -> None:
    result = _scan(f"{target_url}/greet?name=friend")

    xss = [f for f in result.findings if f.check_id == "reflected_xss"]
    assert len(xss) == 1
    assert xss[0].severity is Severity.HIGH
    assert "name" in xss[0].name


def test_safe_greet_is_not_flagged(target_url: str) -> None:
    result = _scan(f"{target_url}/greet-safe?name=friend")

    assert [f for f in result.findings if f.check_id == "reflected_xss"] == []


def test_sql_route_is_not_reported_as_xss(target_url: str) -> None:
    # /search does not reflect its input, so it must not trip the XSS check.
    result = _scan(f"{target_url}/search?q=phone")

    assert [f for f in result.findings if f.check_id == "reflected_xss"] == []
