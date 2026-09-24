"""A small, deliberately polite HTTP client.

Every request the scanner makes goes through here, which gives one place to
enforce the things a scanner must get right: the authorization gate, a request
timeout, a delay between requests so a target is never flooded, and a clear
User-Agent so the traffic is identifiable in the target's logs.
"""

from __future__ import annotations

import time

import requests

from web_vul_scanner.core.authorization import Authorization

DEFAULT_USER_AGENT = "web_vul_scanner/0.1 (educational scanner; +authorized-use-only)"


class HttpClient:
    """An authorized, throttled wrapper around a :class:`requests.Session`."""

    def __init__(
        self,
        authorization: Authorization,
        *,
        timeout: float = 10.0,
        delay: float = 0.2,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self._auth = authorization
        self._timeout = timeout
        self._delay = delay
        self._session = requests.Session()
        self._session.headers["User-Agent"] = user_agent
        self._last_request_at = 0.0

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an authorized, throttled request.

        Raises :class:`~web_vul_scanner.core.authorization.UnauthorizedTargetError`
        before any traffic is sent if the target host is not allowed.
        """
        self._auth.ensure_allowed(url)
        self._throttle()
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("allow_redirects", True)
        return self._session.request(method, url, **kwargs)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _throttle(self) -> None:
        if self._delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_request_at = time.monotonic()
