"""sigma-pipeline command-line entrypoint.

Subcommands:
    sigma lint    validate Sigma YAML files
    sigma test    run rules against fixture logs and assert match/no-match
    sigma deploy  push validated rules to Splunk via the REST API
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma_pipeline import deploy, lint, test


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sigma", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lint = sub.add_parser("lint", help="validate Sigma YAML files")
    p_lint.add_argument("rules_dir", type=Path, help="directory of Sigma .yml rules")

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

    args = parser.parse_args(argv)
    if args.cmd == "lint":
        return lint.run(args.rules_dir)
    if args.cmd == "test":
        return test.run(args.rules_dir, args.fixtures)
    if args.cmd == "deploy":
        return deploy.run(
            rules_dir=args.rules_dir,
            host=args.host,
            port=args.port,
            app=args.app,
            target_index=args.target_index,
            dry_run=args.dry_run,
        )
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
