"""sigma-pipeline command-line entrypoint.

Subcommands:
    sigma lint      validate Sigma YAML files
    sigma test      run rules against fixture logs and assert match/no-match
    sigma diff      compare two rule sets, report rule and coverage deltas
    sigma stats     summarize rule counts by severity, tactic, and logsource
    sigma deploy    push validated rules to Splunk via the REST API
    sigma coverage  emit ATT&CK coverage as markdown or Navigator JSON layer
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma_pipeline import coverage, deploy, diff, lint, stats, test


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sigma", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lint = sub.add_parser("lint", help="validate Sigma YAML files")
    p_lint.add_argument("rules_dir", type=Path, help="directory of Sigma .yml rules")
    p_lint.add_argument(
        "--strict",
        action="store_true",
        help="also run pySigma's validator suite (requires `pip install -e .[strict]`)",
    )

    p_test = sub.add_parser("test", help="evaluate rules against fixture logs")
    p_test.add_argument("rules_dir", type=Path, help="directory of Sigma .yml rules")
    p_test.add_argument(
        "--fixtures",
        type=Path,
        default=Path("tests/fixtures"),
        help="fixture root (default: tests/fixtures)",
    )

    p_deploy = sub.add_parser("deploy", help="push rules to Splunk via REST API")
    p_deploy.add_argument("rules_dir", type=Path, help="directory of Sigma .yml rules")
    p_deploy.add_argument("--host", default="localhost")
    p_deploy.add_argument("--port", type=int, default=8089)
    p_deploy.add_argument("--app", default="splunk-sigma", help="target Splunk app")
    p_deploy.add_argument(
        "--target-index",
        default="main",
        help="index the deployed saved searches will run against",
    )
    p_deploy.add_argument(
        "--dry-run", action="store_true", help="print plan, do not write to Splunk"
    )
    p_deploy.add_argument(
        "--with-dashboard",
        type=Path,
        default=None,
        metavar="DIR",
        help="also push every .xml under DIR as a Splunk dashboard view",
    )

    p_diff = sub.add_parser("diff", help="diff two rule sets and report coverage deltas")
    p_diff.add_argument("rules_dir", type=Path, help="new (current) rules directory")
    p_diff.add_argument("baseline_dir", type=Path, help="old (baseline) rules directory")
    p_diff.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="output format (default: text)",
    )
    p_diff.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write to file instead of stdout",
    )

    p_stats = sub.add_parser("stats", help="summarize rule counts by severity/tactic/logsource")
    p_stats.add_argument("rules_dir", type=Path, help="directory of Sigma .yml rules")

    p_cov = sub.add_parser("coverage", help="emit ATT&CK coverage report")
    p_cov.add_argument("rules_dir", type=Path, help="directory of Sigma .yml rules")
    p_cov.add_argument(
        "--format",
        choices=["markdown", "navigator"],
        default="markdown",
        help="output format (default: markdown)",
    )
    p_cov.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write to file instead of stdout",
    )

    args = parser.parse_args(argv)
    if args.cmd == "lint":
        return lint.run(args.rules_dir, strict=args.strict)
    if args.cmd == "test":
        return test.run(args.rules_dir, args.fixtures)
    if args.cmd == "diff":
        return diff.run(args.rules_dir, args.baseline_dir, args.format, args.output)
    if args.cmd == "stats":
        return stats.run(args.rules_dir)
    if args.cmd == "deploy":
        return deploy.run(
            rules_dir=args.rules_dir,
            host=args.host,
            port=args.port,
            app=args.app,
            target_index=args.target_index,
            dry_run=args.dry_run,
            dashboards_dir=args.with_dashboard,
        )
    if args.cmd == "coverage":
        return coverage.run(args.rules_dir, args.format, args.output)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
