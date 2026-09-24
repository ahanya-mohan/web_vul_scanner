"""The CLI wires argument parsing, the gate and reporting together."""

from __future__ import annotations

import json

from web_vul_scanner.cli import main


def test_scan_command_json_output(target_url: str, capsys) -> None:
    exit_code = main(["scan", target_url, "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    report = json.loads(out)
    assert report["target"] == target_url
    assert report["summary"]["highest_severity"] == "Info"


def test_scan_command_text_output(target_url: str, capsys) -> None:
    exit_code = main(["scan", target_url])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Target reachable" in out


def test_scan_refuses_unauthorized_host(capsys) -> None:
    exit_code = main(["scan", "http://example.com"])
    err = capsys.readouterr().err

    assert exit_code == 2
    assert "not authorized" in err


def test_fail_on_threshold_below_findings_still_passes(target_url: str) -> None:
    # Only INFO findings exist so far, so --fail-on high must not trip.
    assert main(["scan", target_url, "--fail-on", "high"]) == 0
