"""The `chokr-spec` command: run the conformance vectors with the reference checker."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from chokr_spec import __version__
from chokr_spec.runner import LEVELS, run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chokr-spec", description="CHOKR protocol data and reference checker")
    parser.add_argument("--version", action="version", version=f"chokr-spec {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="run the conformance vectors; exit 0 only when every vector passes")
    check.add_argument("--level", choices=LEVELS, default=LEVELS[-1], help="the highest level to run")
    check.add_argument("--vectors", type=Path, help="a vector folder (default: the packaged vectors)")
    check.add_argument("--report", type=Path, help="write the JSON report here")
    check.add_argument("--json", action="store_true", help="print the JSON report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the exit code: 0 when every vector passes, 1 otherwise."""
    args = _parser().parse_args(argv)
    report = run(args.level, vectors=args.vectors)
    if args.report is not None:
        args.report.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        for result in report.results:
            if result.status != "pass":
                print(f"{result.status.upper()} {result.id}: {result.detail}")
        print(f"{report.passed} passed, {report.failed} failed")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
