"""The check interface and a registry of available checks.

Adding a new capability to the scanner means adding one module here with a
:class:`Check` subclass decorated with :func:`register`. The scanner runs every
registered check, so nothing else has to change.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from web_vul_scanner.core.http_client import HttpClient
from web_vul_scanner.core.injection import InjectionPoint
from web_vul_scanner.report.models import Finding


@dataclass(slots=True)
class CheckContext:
    """Everything a check needs to inspect a target.

    ``injection_points`` are the parameters discovered by the crawler; checks
    that probe inputs iterate over them.
    """

    target: str
    http: HttpClient
    injection_points: list[InjectionPoint] = field(default_factory=list)


class Check(abc.ABC):
    """Base class for all checks.

    Subclasses set a unique ``id`` and a human ``name`` and implement
    :meth:`run`, yielding a finding for anything noteworthy.
    """

    id: str = ""
    name: str = ""

    @abc.abstractmethod
    def run(self, context: CheckContext) -> Iterable[Finding]:
        """Inspect ``context.target`` and yield findings."""
        raise NotImplementedError


_REGISTRY: list[type[Check]] = []


def register(check_cls: type[Check]) -> type[Check]:
    """Class decorator that adds a check to the global registry."""
    if not check_cls.id:
        raise ValueError(f"{check_cls.__name__} must define a non-empty id")
    if any(existing.id == check_cls.id for existing in _REGISTRY):
        raise ValueError(f"Duplicate check id: {check_cls.id!r}")
    _REGISTRY.append(check_cls)
    return check_cls


def all_checks() -> Iterator[Check]:
    """Instantiate every registered check, in registration order."""
    for check_cls in _REGISTRY:
        yield check_cls()
