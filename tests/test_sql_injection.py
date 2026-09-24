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


def test_no_params_means_no_sqli_finding(target_url: str) -> None:
    result = _scan(target_url)

    assert [f for f in result.findings if f.check_id == "sql_injection"] == []
