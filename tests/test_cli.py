"""The CLI wires argument parsing, the gate and reporting together."""

from __future__ import annotations

import json

from web_vul_scanner.cli import main


def test_scan_command_json_output_on_plain_endpoint(target_url: str, capsys) -> None:
    # /healthz has no inputs, so only the reachability (Info) finding appears.
    exit_code = main(["scan", f"{target_url}/healthz", "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    report = json.loads(out)
    assert report["summary"]["highest_severity"] == "Info"


def test_scan_command_text_output_reports_findings(target_url: str, capsys) -> None:
    exit_code = main(["scan", target_url])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Target reachable" in out
    assert "SQL injection" in out  # discovered by crawling from the base URL


def test_scan_refuses_unauthorized_host(capsys) -> None:
    exit_code = main(["scan", "http://example.com"])
    err = capsys.readouterr().err

    assert exit_code == 2
    assert "not authorized" in err


def test_fail_on_does_not_trip_when_only_info(target_url: str) -> None:
    assert main(["scan", f"{target_url}/healthz", "--fail-on", "high"]) == 0


def test_fail_on_trips_on_vulnerable_target(target_url: str) -> None:
    # The base target exposes HIGH-severity findings, so --fail-on high exits 1.
    assert main(["scan", target_url, "--fail-on", "high"]) == 1
