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
from pathlib import Path

from web_vul_scanner import __version__
from web_vul_scanner.classifier.dataset import DEFAULT_MODEL
from web_vul_scanner.classifier.features import feature_vector
from web_vul_scanner.classifier.model import GaussianNaiveBayes
from web_vul_scanner.core.authorization import Authorization, UnauthorizedTargetError
from web_vul_scanner.report.models import Severity
from web_vul_scanner.report.render import render_html, render_text
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
    scan.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="report format (default: text)",
    )
    scan.add_argument("--json", action="store_true", help="shortcut for --format json")
    scan.add_argument(
        "--output",
        type=Path,
        metavar="PATH",
        help="write the report to a file instead of stdout",
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity],
        default=None,
        help="exit non-zero if a finding of this severity or higher is present",
    )

    classify = sub.add_parser(
        "classify",
        help="predict whether a URL looks like phishing (offline; sends no requests)",
    )
    classify.add_argument("url", help="the URL to classify")
    classify.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL,
        help="path to a trained model.json (default: the bundled model)",
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

    fmt = "json" if args.json else args.format
    report = {"json": result.to_json, "html": lambda: render_html(result)}.get(
        fmt, lambda: render_text(result)
    )()

    if args.output is not None:
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote {fmt} report to {args.output}")
    else:
        print(report, end="\n" if fmt == "text" else "")

    if args.fail_on is not None:
        threshold = Severity[args.fail_on.upper()]
        if result.highest_severity >= threshold and result.findings:
            return 1
    return 0


def _run_classify(args: argparse.Namespace) -> int:
    if not args.model.exists():
        print(
            f"error: no model at {args.model}. Train one with "
            f"`python -m web_vul_scanner.classifier.train`.",
            file=sys.stderr,
        )
        return 2

    model = GaussianNaiveBayes.load(args.model)
    probabilities = model.predict_proba(feature_vector(args.url))
    phishing_prob = probabilities.get(1, 0.0)
    verdict = "PHISHING" if model.predict(feature_vector(args.url)) == 1 else "legitimate"

    print(f"{verdict}  (phishing probability {phishing_prob:.1%})")
    print(f"  {args.url}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "classify":
        return _run_classify(args)
    return 0  # pragma: no cover - argparse enforces a valid command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
