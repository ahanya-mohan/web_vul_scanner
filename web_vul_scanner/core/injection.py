"""Injection points: a single place in a request where user input reaches the
target, and the machinery to resend that request with a chosen payload.

Checks (SQL injection, XSS, ...) are written against :class:`InjectionPoint`,
so they don't care whether the point came from a URL query parameter or a form
field discovered by the crawler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import requests

from web_vul_scanner.core.http_client import HttpClient


@dataclass(slots=True)
class InjectionPoint:
    """One injectable parameter and the request needed to reach it."""

    method: str  # "GET" or "POST"
    action_url: str  # URL to send to, without the injected query string
    param: str  # the parameter being tested
    base_value: str  # its original, benign value
    location: str  # "query" or "form"
    others: dict[str, str] = field(default_factory=dict)  # sibling params, held constant

    def send(self, http: HttpClient, payload: str) -> requests.Response:
        """Resend the request with ``payload`` in this point's parameter."""
        values = dict(self.others)
        values[self.param] = payload
        if self.method == "POST":
            return http.post(self.action_url, data=values)
        return http.get(self.action_url, params=values)

    def describe(self) -> str:
        return f"{self.method} {self.action_url} ({self.location} parameter '{self.param}')"

    def key(self) -> tuple:
        """Identity for de-duplication across discovery."""
        return (self.method, self.action_url, self.param, self.location, tuple(sorted(self.others)))


def query_injection_points(url: str) -> list[InjectionPoint]:
    """Every query-string parameter in ``url`` as a GET injection point."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    action = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    points: list[InjectionPoint] = []
    for index, (name, value) in enumerate(pairs):
        others = {n: v for i, (n, v) in enumerate(pairs) if i != index}
        points.append(InjectionPoint("GET", action, name, value, "query", others))
    return points
