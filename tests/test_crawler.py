"""The crawler discovers query and form injection points from a base URL."""

from __future__ import annotations

from web_vul_scanner.core.authorization import Authorization
from web_vul_scanner.core.crawler import discover
from web_vul_scanner.core.http_client import HttpClient


def test_discovers_query_and_form_points(target_url: str) -> None:
    with HttpClient(Authorization()) as http:
        points = discover(http, target_url)

    found = {(p.location, p.method, p.param) for p in points}
    assert ("query", "GET", "q") in found  # linked /search?q=...
    assert ("query", "GET", "name") in found  # linked /greet?name=...
    assert ("form", "POST", "username") in found  # /login form
    assert ("form", "POST", "password") in found


def test_stays_on_the_same_origin(target_url: str) -> None:
    with HttpClient(Authorization()) as http:
        points = discover(http, target_url)

    netloc = target_url.split("//", 1)[1]
    assert all(netloc in p.action_url for p in points)
