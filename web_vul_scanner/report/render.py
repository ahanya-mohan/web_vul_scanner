"""Render a :class:`~web_vul_scanner.report.models.ScanResult` as text or HTML."""

from __future__ import annotations

from html import escape

from web_vul_scanner.report.models import ScanResult, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def render_text(result: ScanResult) -> str:
    """A compact, human-readable summary of a scan."""
    lines = [
        f"Scan of {result.target}",
        f"  findings: {len(result.findings)}  "
        f"highest: {result.highest_severity.label}",
        "",
    ]
    if not result.findings:
        lines.append("  No findings.")
        return "\n".join(lines)

    for severity in _SEVERITY_ORDER:
        group = [f for f in result.findings if f.severity is severity]
        for finding in group:
            lines.append(f"[{severity.label.upper()}] {finding.name}")
            lines.append(f"    url:      {finding.url}")
            if finding.evidence:
                lines.append(f"    evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"    fix:      {finding.remediation}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_HTML_STYLE = """
  body { margin:0; font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; }
  .wrap { max-width: 900px; margin: 0 auto; padding: 2rem 1.25rem; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  h1 span { color:#38bdf8; }
  .meta { color:#94a3b8; font-size:.9rem; margin-bottom:1.5rem; }
  table { width:100%; border-collapse:collapse; background:#1e293b;
          border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:.6rem .7rem;
           border-bottom:1px solid #334155; vertical-align:top; }
  th { color:#94a3b8; font-size:.75rem; text-transform:uppercase; letter-spacing:.04em; }
  code { background:#0b1220; padding:.05rem .3rem; border-radius:4px; }
  .muted { color:#94a3b8; font-size:.85rem; }
  .badge { display:inline-block; padding:.1rem .55rem; border-radius:999px;
           font-size:.75rem; font-weight:700; }
  .sev-critical { background:#7f1d1d; color:#fecaca; }
  .sev-high { background:#9a3412; color:#fed7aa; }
  .sev-medium { background:#854d0e; color:#fde68a; }
  .sev-low { background:#155e75; color:#a5f3fc; }
  .sev-info { background:#334155; color:#cbd5e1; }
"""


def _badge(severity: Severity) -> str:
    return f'<span class="badge sev-{severity.label.lower()}">{severity.label}</span>'


def render_html(result: ScanResult) -> str:
    """A standalone, self-contained HTML report for a scan."""
    rows = []
    for finding in result.findings:
        remediation = (
            f'<div class="muted">Fix: {escape(finding.remediation)}</div>'
            if finding.remediation
            else ""
        )
        evidence = (
            f'<div class="muted">{escape(finding.evidence)}</div>' if finding.evidence else ""
        )
        rows.append(
            f"<tr><td>{_badge(finding.severity)}</td>"
            f"<td><strong>{escape(finding.name)}</strong>{remediation}</td>"
            f"<td><code>{escape(finding.url)}</code>{evidence}</td></tr>"
        )

    body = (
        f"<table><thead><tr><th>Severity</th><th>Finding</th><th>Where / evidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else "<p>No findings.</p>"
    )
    finished = result.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC") if result.finished_at else ""

    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Scan report — {escape(result.target)}</title>\n<style>{_HTML_STYLE}</style>\n"
        '</head>\n<body>\n<div class="wrap">\n'
        "<h1>web<span>_</span>vul<span>_</span>scanner report</h1>\n"
        f'<p class="meta">Target <code>{escape(result.target)}</code> &middot; {finished} &middot; '
        f"{len(result.findings)} finding(s) &middot; "
        f"highest severity {_badge(result.highest_severity)}</p>\n"
        f"{body}\n</div>\n</body>\n</html>\n"
    )

