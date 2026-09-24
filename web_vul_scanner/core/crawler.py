"""A small same-origin crawler that discovers injection points.

Given a starting URL, it follows same-origin links a few pages deep and parses
each page for query-string parameters and HTML forms, turning every input it
finds into an :class:`~web_vul_scanner.core.injection.InjectionPoint`. The
checks then run against those points, so a user only has to supply a base URL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests

from web_vul_scanner.core.http_client import HttpClient
from web_vul_scanner.core.injection import InjectionPoint, query_injection_points

_NON_INPUT_TYPES = {"submit", "button", "image", "reset"}


@dataclass
class _Form:
    method: str = "GET"
    action: str = ""
    fields: dict[str, str] = field(default_factory=dict)


class _PageParser(HTMLParser):
    """Collects same-page links and forms from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[_Form] = []
        self._current: _Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, dict(attrs))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, dict(attrs))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def _handle(self, tag: str, attrs: dict[str, str | None]) -> None:
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "form":
            self._current = _Form(
                method=(attrs.get("method") or "GET").upper(),
                action=attrs.get("action") or "",
            )
        elif tag in {"input", "textarea", "select"} and self._current is not None:
            name = attrs.get("name")
            if name and (attrs.get("type") or "").lower() not in _NON_INPUT_TYPES:
                self._current.fields[name] = attrs.get("value") or ""


def _form_injection_points(form: _Form, page_url: str) -> list[InjectionPoint]:
    action_url = urljoin(page_url, form.action) if form.action else page_url
    points: list[InjectionPoint] = []
    for name, value in form.fields.items():
        others = {n: v for n, v in form.fields.items() if n != name}
        points.append(
            InjectionPoint(form.method, action_url, name, value or "test", "form", others)
        )
    return points


def discover(http: HttpClient, base_url: str, *, max_pages: int = 15) -> list[InjectionPoint]:
    """Crawl from ``base_url`` and return the injection points found."""
    base_netloc = urlsplit(base_url).netloc
    seen: set[str] = set()
    queue: list[str] = [base_url]
    points: list[InjectionPoint] = []
    keys: set[tuple] = set()

    def add(point: InjectionPoint) -> None:
        key = point.key()
        if key not in keys:
            keys.add(key)
            points.append(point)

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        try:
            response = http.get(url)
        except requests.RequestException:
            continue

        for point in query_injection_points(url):
            add(point)

        if "html" not in response.headers.get("Content-Type", "").lower():
            continue

        parser = _PageParser()
        parser.feed(response.text)

        for form in parser.forms:
            for point in _form_injection_points(form, url):
                add(point)

        for href in parser.links:
            absolute = urljoin(url, href).split("#")[0]
            if urlsplit(absolute).netloc == base_netloc and absolute not in seen:
                queue.append(absolute)

    return points
