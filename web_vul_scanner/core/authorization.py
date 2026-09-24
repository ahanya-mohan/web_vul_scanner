"""The authorization gate.

Active scanning sends crafted requests to a target, so the scanner must only
ever be pointed at systems the operator is allowed to test. Every request the
scanner makes goes through :meth:`Authorization.ensure_allowed`, which refuses
any host that is not on an explicit allowlist.

The allowlist is empty by default: a caller must opt a host in, either through
the ``--allow`` CLI flag or by using the bundled demo target, whose loopback
host the demo command adds for you.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

_LOOPBACK_NAMES = {"localhost"}


class UnauthorizedTargetError(Exception):
    """Raised when a scan is attempted against a host that was not allowed."""


class Authorization:
    """An allowlist of hosts (``host`` or ``host:port``) the scanner may probe.

    Loopback targets (``localhost``, ``127.0.0.0/8``, ``::1``) are the operator's
    own machine, so they are permitted by default; pass ``allow_loopback=False``
    to require them to be listed explicitly like any other host.
    """

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        *,
        allow_loopback: bool = True,
    ) -> None:
        self._allowed: set[str] = set()
        self._allow_loopback = allow_loopback
        for host in allowed_hosts or []:
            self.allow(host)

    def allow(self, host: str) -> None:
        """Add a host to the allowlist.

        Accepts a bare host (``example.test``), a ``host:port`` pair, or a full
        URL, from which the network location is taken.
        """
        self._allowed.add(self._normalize(host))

    @property
    def allowed_hosts(self) -> set[str]:
        return set(self._allowed)

    def is_allowed(self, url: str) -> bool:
        netloc = urlsplit(url).netloc.lower()
        host_only = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc
        if self._allow_loopback and self._is_loopback(host_only):
            return True
        return netloc in self._allowed or host_only in self._allowed

    @staticmethod
    def _is_loopback(host: str) -> bool:
        host = host.strip("[]")  # IPv6 URLs wrap the address in brackets
        if host in _LOOPBACK_NAMES:
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def ensure_allowed(self, url: str) -> None:
        """Raise :class:`UnauthorizedTargetError` unless ``url``'s host is allowed."""
        if not self.is_allowed(url):
            allowed = ", ".join(sorted(self._allowed)) or "(none)"
            raise UnauthorizedTargetError(
                f"Refusing to scan {url!r}: its host is not authorized. "
                f"Allowed hosts: {allowed}. Add one with Authorization.allow() "
                f"or the --allow flag, and only for systems you may test."
            )

    @staticmethod
    def _normalize(host: str) -> str:
        # Treat a full URL and a bare host the same way.
        candidate = host if "//" in host else f"//{host}"
        netloc = urlsplit(candidate).netloc.lower()
        return netloc or host.lower()
