"""Sigma rule fixture tester.

Each rule is associated with two folders under <fixtures>/<rule_id>/:

    positive/   .json files the rule MUST match
    negative/   .json files the rule MUST NOT match

A fixture file may contain a single event (object) or a list of events.

Pass criteria:
  - For every positive file: at least one event in it triggers the rule.
  - For every negative file: no event in it triggers the rule.

A rule with no fixtures is reported as a warning (untested coverage),
not a failure — so that the pipeline can be adopted incrementally.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigma_engine import Evaluator, load_rules_from_dir


@dataclass
class CaseResult:
    rule_id: str
    polarity: str  # "positive" | "negative"
    fixture: Path
    passed: bool
    detail: str

    def fmt(self) -> str:
        flag = "PASS" if self.passed else "FAIL"
        return f"  [{flag}] {self.polarity:<8} {self.fixture.name}  {self.detail}"


def _load_events(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text())
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    raise ValueError(f"{path}: fixture must be an object or array")


def _evaluate_one(evaluator: Evaluator, rule_id: str, events: list[dict[str, Any]]) -> int:
    """Return the number of events in this fixture that triggered the named rule."""
    hits = 0
    for ev in events:
        for match in evaluator.match(ev):
            if match.rule.id == rule_id:
                hits += 1
                break  # only count once per event
    return hits


def _test_rule(
    evaluator: Evaluator, rule_id: str, fixtures_root: Path
) -> tuple[list[CaseResult], bool]:
    """Returns (results, had_any_fixtures)."""
    rule_root = fixtures_root / rule_id
    results: list[CaseResult] = []
    pos_dir = rule_root / "positive"
    neg_dir = rule_root / "negative"

    if not rule_root.is_dir():
        return results, False

    for path in sorted(pos_dir.glob("*.json")) if pos_dir.is_dir() else []:
        events = _load_events(path)
        hits = _evaluate_one(evaluator, rule_id, events)
        passed = hits > 0
        detail = f"{hits}/{len(events)} events matched"
        results.append(CaseResult(rule_id, "positive", path, passed, detail))

    for path in sorted(neg_dir.glob("*.json")) if neg_dir.is_dir() else []:
        events = _load_events(path)
        hits = _evaluate_one(evaluator, rule_id, events)
        passed = hits == 0
        detail = f"{hits}/{len(events)} events matched (expected 0)"
        results.append(CaseResult(rule_id, "negative", path, passed, detail))

    return results, bool(results)


def run(rules_dir: Path, fixtures_root: Path) -> int:
    if not rules_dir.is_dir():
        print(f"error: {rules_dir} is not a directory")
        return 2
    rules = load_rules_from_dir(str(rules_dir))
    if not rules:
        print(f"error: no rules loaded from {rules_dir}")
        return 2

    evaluator = Evaluator(rules)
    total_cases = total_failed = 0
    untested: list[str] = []

    for rule in rules:
        results, had_fixtures = _test_rule(evaluator, rule.id, fixtures_root)
        if not had_fixtures:
            untested.append(rule.id)
            continue
        failed = sum(1 for r in results if not r.passed)
        total_cases += len(results)
        total_failed += failed
        header = f"\n{rule.id}  ({rule.title})"
        print(header)
        for r in results:
            print(r.fmt())
        if failed:
            print(f"  -> {failed}/{len(results)} case(s) failed")

    print(
        f"\ntest: {len(rules)} rule(s), "
        f"{total_cases} case(s), {total_failed} failure(s), "
        f"{len(untested)} rule(s) without fixtures"
    )
    if untested:
        print("  untested: " + ", ".join(untested))
    return 0 if total_failed == 0 else 1
