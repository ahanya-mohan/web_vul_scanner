"""Reflected cross-site scripting (XSS) check.

For each injectable parameter, the check submits a uniquely tagged HTML marker
and looks for it, unescaped, in the response. Because the marker carries a
random token and real angle brackets, finding it verbatim means the input is
reflected into the page without HTML-encoding — the core of reflected XSS. A
safe endpoint that escapes output turns the marker into ``&lt;...&gt;``, which
does not match.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable

import requests

from web_vul_scanner.checks.base import Check, CheckContext, register
from web_vul_scanner.core.injection import InjectionPoint
from web_vul_scanner.report.models import Finding, Severity

_REMEDIATION = (
    "Contextually encode user input on output (HTML-escape it), rely on a "
    "template engine with auto-escaping, and add a Content-Security-Policy "
    "as defense in depth."
)


@register
class XssInjectionCheck(Check):
    id = "reflected_xss"
    name = "Reflected XSS"

    def run(self, context: CheckContext) -> Iterable[Finding]:
        for point in context.injection_points:
            finding = self._test_point(context, point)
            if finding is not None:
                yield finding

    def _test_point(self, context: CheckContext, point: InjectionPoint) -> Finding | None:
        token = secrets.token_hex(6)
        marker = f"<wvs{token}>"
        try:
            response = point.send(context.http, marker)
        except requests.RequestException:
            return None

        if marker not in response.text:
            return None  # not reflected, or reflected but escaped

        return Finding(
            check_id=self.id,
            name=f"Reflected XSS in parameter '{point.param}'",
            severity=Severity.HIGH,
            url=point.describe(),
            evidence=(
                f"The HTML marker {marker!r} submitted in '{point.param}' was "
                f"reflected unescaped in the response."
            ),
            remediation=_REMEDIATION,
        )
