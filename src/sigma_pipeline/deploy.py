"""Sigma rule deployer.

Pushes validated Sigma rules to a target Splunk instance via its REST API.

For each rule, we register or update a saved search whose SPL is:

    search index=<target_index> | sigma rules="id:<rule_id>"

The saved search description carries the rule's ATT&CK techniques and
severity so it surfaces in Splunk Web alongside the SPL. The mapping is
idempotent: existing saved searches are updated in place rather than
duplicated.

Auth: SPLUNK_USERNAME / SPLUNK_PASSWORD environment variables, matching
the convention used by splunk-sigma's `sigma_watch` service.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from sigma_engine import load_rules_from_dir
from sigma_engine.rules import Rule

SAVED_SEARCH_PREFIX = "sigma_"


def _saved_search_name(rule: Rule) -> str:
    return f"{SAVED_SEARCH_PREFIX}{rule.id}"


def _saved_search_spl(rule: Rule, target_index: str) -> str:
    return f'search index={target_index} | sigma rules="id:{rule.id}"'


def _saved_search_description(rule: Rule) -> str:
    attack = ", ".join(rule.attack) if rule.attack else "(none)"
    return (
        f"[sigma-pipeline] {rule.title}\n"
        f"Severity: {rule.level}\n"
        f"ATT&CK: {attack}\n\n"
        f"{rule.description}"
    )


def _plan(rules: list[Rule], target_index: str) -> list[tuple[str, str, str]]:
    return [
        (_saved_search_name(r), _saved_search_spl(r, target_index), _saved_search_description(r))
        for r in rules
    ]


def run(
    rules_dir: Path,
    host: str,
    port: int,
    app: str,
    target_index: str,
    dry_run: bool,
) -> int:
    if not rules_dir.is_dir():
        print(f"error: {rules_dir} is not a directory")
        return 2
    rules = load_rules_from_dir(str(rules_dir))
    if not rules:
        print(f"error: no rules loaded from {rules_dir}")
        return 2

    plan = _plan(rules, target_index)
    print(
        f"deploy: {len(plan)} rule(s) -> {host}:{port} app={app} index={target_index}"
        f"{' (dry-run)' if dry_run else ''}"
    )
    for name, spl, _desc in plan:
        print(f"  - {name}")
        print(f"      {spl}")
    if dry_run:
        return 0

    user = os.environ.get("SPLUNK_USERNAME")
    pw = os.environ.get("SPLUNK_PASSWORD")
    if not user or not pw:
        print("error: SPLUNK_USERNAME / SPLUNK_PASSWORD must be set", file=sys.stderr)
        return 2

    try:
        import splunklib.client as splunk_client
    except ImportError:
        print(
            "error: splunklib not installed. `pip install splunk-sdk`",
            file=sys.stderr,
        )
        return 2

    service = splunk_client.connect(
        host=host, port=port, username=user, password=pw, app=app
    )
    saved = service.saved_searches

    created = updated = 0
    for name, spl, desc in plan:
        if name in saved:
            saved[name].update(search=spl, description=desc)
            updated += 1
        else:
            saved.create(name, spl, description=desc)
            created += 1
        print(f"  ok: {name}")

    print(f"\ndeploy: {created} created, {updated} updated")
    return 0
