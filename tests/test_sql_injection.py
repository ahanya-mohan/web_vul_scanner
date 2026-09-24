"""The SQL injection check must flag the vulnerable route and clear the safe one."""

from __future__ import annotations

from web_vul_scanner.core.authorization import Authorization
from web_vul_scanner.report.models import Severity
from web_vul_scanner.scanner import Scanner


def _scan(url: str):
    with Scanner(Authorization()) as scanner:
        return scanner.scan(url)


def test_vulnerable_search_is_flagged(target_url: str) -> None:
    result = _scan(f"{target_url}/search?q=phone")

    sqli = [f for f in result.findings if f.check_id == "sql_injection"]
    assert len(sqli) == 1
    assert sqli[0].severity is Severity.HIGH
    assert "q" in sqli[0].name
    assert sqli[0].remediation


def test_safe_search_is_not_flagged(target_url: str) -> None:
    result = _scan(f"{target_url}/search-safe?q=phone")

    assert [f for f in result.findings if f.check_id == "sql_injection"] == []


def test_endpoint_without_inputs_has_no_sqli_finding(target_url: str) -> None:
    result = _scan(f"{target_url}/healthz")

    assert [f for f in result.findings if f.check_id == "sql_injection"] == []


def test_login_form_is_discovered_and_flagged(target_url: str) -> None:
    # From the base URL the crawler finds the POST login form and the check
    # detects the injectable username/password fields.
    result = _scan(target_url)

    sqli = [f for f in result.findings if f.check_id == "sql_injection"]
    assert any("username" in f.name for f in sqli)
