"""Error-based SQL injection check.

For each injectable parameter, the check sends a single quote and looks for a
database error in the response that was not there for the benign value. A SQL
error appearing only after injecting a quote is strong evidence that the input
reaches a query unescaped.

This is a deliberately conservative detector: it requires the error signature
to be absent from the baseline response, which avoids flagging pages that
already show database errors for unrelated reasons.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import requests

from web_vul_scanner.checks.base import Check, CheckContext, register
from web_vul_scanner.core.injection import InjectionPoint
from web_vul_scanner.report.models import Finding, Severity

_REMEDIATION = (
    "Use parameterized queries (prepared statements) so user input is always "
    "treated as data, never as SQL. Never build queries by string concatenation, "
    "and do not echo database errors back to the client."
)

# Signatures of database errors across common engines.
_SQL_ERROR_SIGNATURES = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"you have an error in your sql syntax",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"unterminated quoted string",
        r"unterminated string",
        r"unrecognized token",
        r'near ".+": syntax error',
        r"sqlite3?\.(operationalerror|warning|databaseerror)",
        r"sqlite error",
        r"psycopg2\.",
        r"pg::\w+error",
        r"syntax error at or near",
        r"ora-\d{5}",
        r"odbc sql server driver",
    )
]


def _matched_signature(text: str) -> str | None:
    for signature in _SQL_ERROR_SIGNATURES:
        if signature.search(text):
            return signature.pattern
    return None


@register
class SqlInjectionCheck(Check):
    id = "sql_injection"
    name = "SQL injection"

    def run(self, context: CheckContext) -> Iterable[Finding]:
        for point in context.injection_points:
            finding = self._test_point(context, point)
            if finding is not None:
                yield finding

    def _test_point(self, context: CheckContext, point: InjectionPoint) -> Finding | None:
        try:
            baseline = point.send(context.http, point.base_value)
            probe = point.send(context.http, point.base_value + "'")
        except requests.RequestException:
            return None

        if _matched_signature(baseline.text):
            return None  # page already errors; can't attribute it to our input

        signature = _matched_signature(probe.text)
        if signature is None:
            return None

        return Finding(
            check_id=self.id,
            name=f"SQL injection in parameter '{point.param}'",
            severity=Severity.HIGH,
            url=point.describe(),
            evidence=(
                f"Injecting a single quote into '{point.param}' produced a database "
                f"error (matched /{signature}/) absent from the baseline response."
            ),
            remediation=_REMEDIATION,
        )
