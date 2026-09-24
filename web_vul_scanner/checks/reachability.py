"""A trivial baseline check: is the target reachable over HTTP?

This is the simplest possible check. It sends no attack payloads; it just
confirms the scanner can reach the target and reports the status code and
server banner. It exercises the whole pipeline end to end (authorization,
HTTP client, findings, reporting) and gives real checks a template to follow.
"""

from __future__ import annotations

from collections.abc import Iterable

import requests

from web_vul_scanner.checks.base import Check, CheckContext, register
from web_vul_scanner.report.models import Finding, Severity


@register
class ReachabilityCheck(Check):
    id = "reachability"
    name = "Target reachable"

    def run(self, context: CheckContext) -> Iterable[Finding]:
        try:
            response = context.http.get(context.target)
        except requests.RequestException as exc:
            yield Finding(
                check_id=self.id,
                name="Target unreachable",
                severity=Severity.INFO,
                url=context.target,
                evidence=f"Request failed: {exc}",
                remediation="Confirm the target URL is correct and the host is up.",
            )
            return

        server = response.headers.get("Server", "unknown")
        yield Finding(
            check_id=self.id,
            name=self.name,
            severity=Severity.INFO,
            url=context.target,
            evidence=f"HTTP {response.status_code}, Server: {server}",
            remediation="",
        )
