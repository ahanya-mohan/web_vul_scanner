"""Vulnerability checks.

A check is a self-contained probe that inspects a target and yields
:class:`~web_vul_scanner.report.models.Finding` objects. New checks subclass
:class:`~web_vul_scanner.checks.base.Check` and register themselves so the
scanner discovers them automatically.
"""

from web_vul_scanner.checks.base import Check, CheckContext, all_checks, register
from web_vul_scanner.checks.reachability import ReachabilityCheck

__all__ = ["Check", "CheckContext", "ReachabilityCheck", "all_checks", "register"]
