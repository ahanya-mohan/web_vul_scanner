"""The scan result data model.

Every check produces zero or more :class:`Finding` objects. A whole scan is a
:class:`ScanResult`, which knows how to serialize itself to a plain dict / JSON
so the CLI, the web UI and the tests all share one representation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    """How serious a finding is. Ordered, so results can be sorted or filtered."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass(frozen=True, slots=True)
class Finding:
    """A single thing the scanner observed about a target.

    ``check_id`` ties the finding back to the check that produced it, ``evidence``
    is a short human-readable justification, and ``remediation`` is the advice
    shown to the user.
    """

    check_id: str
    name: str
    severity: Severity
    url: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "severity": self.severity.label,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(slots=True)
class ScanResult:
    """The outcome of scanning one target: its findings and timing."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def complete(self) -> None:
        """Mark the scan as finished and sort findings by descending severity."""
        self.finished_at = datetime.now(timezone.utc)
        self.findings.sort(key=lambda f: f.severity, reverse=True)

    @property
    def highest_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.label] = counts.get(finding.severity.label, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "highest_severity": self.highest_severity.label,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
