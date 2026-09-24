"""Render a :class:`~web_vul_scanner.report.models.ScanResult` for the terminal."""

from __future__ import annotations

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
