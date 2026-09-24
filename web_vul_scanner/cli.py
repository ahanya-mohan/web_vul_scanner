"""Command-line entry point.

Examples::

    web_vul_scanner scan http://127.0.0.1:5000 --allow 127.0.0.1:5000
    web_vul_scanner scan http://127.0.0.1:5000 --json

The scanner refuses any target whose host is not passed with ``--allow``. Only
authorize hosts you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from web_vul_scanner import __version__
from web_vul_scanner.core.authorization import Authorization, UnauthorizedTargetError
from web_vul_scanner.report.models import Severity
from web_vul_scanner.report.render import render_text
from web_vul_scanner.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web_vul_scanner",
        description="Educational web vulnerability scanner (authorized use only).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a target URL")
    scan.add_argument("url", help="target URL, e.g. http://127.0.0.1:5000")
    scan.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="HOST",
        help="authorize a non-loopback host (repeatable); loopback is allowed by default.",
    )
    scan.add_argument("--json", action="store_true", help="print the report as JSON")
    scan.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity],
        default=None,
        help="exit non-zero if a finding of this severity or higher is present",
    )
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    # Loopback (the operator's own machine) is allowed by default; any other
    # host must be authorized explicitly with --allow.
    authorization = Authorization(args.allow)

    try:
        with Scanner(authorization) as scanner:
            result = scanner.scan(args.url)
    except UnauthorizedTargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(result.to_json() if args.json else render_text(result), end="" if args.json else "\n")

    if args.fail_on is not None:
        threshold = Severity[args.fail_on.upper()]
        if result.highest_severity >= threshold and result.findings:
            return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    return 0  # pragma: no cover - argparse enforces a valid command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
