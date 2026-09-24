"""Text and HTML rendering of scan results."""

from __future__ import annotations

from web_vul_scanner.core.authorization import Authorization
from web_vul_scanner.report.render import render_html
from web_vul_scanner.scanner import Scanner


def _scan(url: str):
    with Scanner(Authorization()) as scanner:
        return scanner.scan(url)


def test_render_html_is_a_self_contained_document(target_url: str) -> None:
    html = render_html(_scan(target_url))

    assert html.startswith("<!doctype html>")
    assert "<style>" in html  # inline CSS, no external assets
    assert target_url in html
    assert "SQL injection" in html
    assert "sev-high" in html


def test_cli_writes_html_report(target_url: str, tmp_path, capsys) -> None:
    from web_vul_scanner.cli import main

    out = tmp_path / "report.html"
    exit_code = main(["scan", target_url, "--format", "html", "--output", str(out)])

    assert exit_code == 0
    assert f"Wrote html report to {out}" in capsys.readouterr().out
    contents = out.read_text(encoding="utf-8")
    assert contents.startswith("<!doctype html>")
    assert "SQL injection" in contents
