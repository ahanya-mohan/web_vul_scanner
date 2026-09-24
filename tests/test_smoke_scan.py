"""End-to-end smoke test: the whole pipeline runs against the bundled target."""

from __future__ import annotations

from web_vul_scanner.core.authorization import Authorization
from web_vul_scanner.report.models import Severity
from web_vul_scanner.scanner import Scanner


def test_scan_reports_target_reachable(target_url: str) -> None:
    with Scanner(Authorization()) as scanner:
        result = scanner.scan(target_url)

    assert result.target == target_url
    assert result.finished_at is not None

    reachability = [f for f in result.findings if f.check_id == "reachability"]
    assert len(reachability) == 1
    assert reachability[0].name == "Target reachable"
    assert reachability[0].severity is Severity.INFO
    assert "HTTP 200" in reachability[0].evidence


def test_scan_result_serializes_to_json(target_url: str) -> None:
    with Scanner(Authorization()) as scanner:
        result = scanner.scan(target_url)

    data = result.to_dict()
    assert data["target"] == target_url
    assert data["summary"]["total"] == len(result.findings)
    assert "\"findings\"" in result.to_json()
