"""The scan engine: run every registered check against one target."""

from __future__ import annotations

from web_vul_scanner.checks import all_checks
from web_vul_scanner.checks.base import CheckContext
from web_vul_scanner.core.authorization import Authorization
from web_vul_scanner.core.crawler import discover
from web_vul_scanner.core.http_client import HttpClient
from web_vul_scanner.report.models import ScanResult


class Scanner:
    """Runs the registered checks against a target and collects the findings."""

    def __init__(self, authorization: Authorization, *, http: HttpClient | None = None) -> None:
        self._auth = authorization
        self._http = http or HttpClient(authorization)

    def scan(self, target: str) -> ScanResult:
        # Fail fast, before any check runs, if the target is not authorized.
        self._auth.ensure_allowed(target)

        injection_points = discover(self._http, target)

        result = ScanResult(target=target)
        context = CheckContext(target=target, http=self._http, injection_points=injection_points)
        for check in all_checks():
            for finding in check.run(context):
                result.add(finding)
        result.complete()
        return result

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
