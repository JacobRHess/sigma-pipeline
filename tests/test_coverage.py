"""Unit tests for the coverage reporter."""

from __future__ import annotations

import json
from pathlib import Path

from sigma_engine.rules import Rule, Selection

from sigma_pipeline.coverage import _gather, _markdown, _navigator, _technique_ids


def _rule(rid: str, level: str, attack: list[str]) -> Rule:
    return Rule(
        id=rid,
        title=f"Test {rid}",
        description="x",
        level=level,
        attack=attack,
        logsource={"category": "process_creation"},
        selections={"sel": Selection(name="sel", matchers=[])},
        condition="sel",
    )


def test_technique_ids_filters_tactics():
    r = _rule("r1", "high", ["EXECUTION", "T1059.001"])
    assert _technique_ids(r) == ["T1059.001"]


def test_gather_collapses_by_technique():
    rules = [
        _rule("r1", "high", ["T1059"]),
        _rule("r2", "critical", ["T1059"]),
        _rule("r3", "low", ["T1003.001"]),
    ]
    by_tech = _gather(rules)
    assert set(by_tech) == {"T1059", "T1003.001"}
    assert len(by_tech["T1059"]) == 2


def test_navigator_uses_max_severity_per_technique():
    rules = [
        _rule("r1", "low", ["T1059"]),
        _rule("r2", "critical", ["T1059"]),
    ]
    layer = _navigator(_gather(rules))
    techs = {t["techniqueID"]: t for t in layer["techniques"]}
    assert techs["T1059"]["score"] == 5  # critical wins over low


def test_navigator_layer_is_valid_json(tmp_path: Path):
    rules = [_rule("r1", "high", ["T1059.001"])]
    payload = _navigator(_gather(rules))
    raw = json.dumps(payload)
    assert json.loads(raw) == payload  # round-trip


def test_markdown_lists_each_rule():
    rules = [
        _rule("r1", "high", ["T1059"]),
        _rule("r2", "critical", ["T1003.001"]),
    ]
    md = _markdown(_gather(rules), rules)
    assert "T1059" in md
    assert "T1003.001" in md
    assert "high" in md
    assert "critical" in md
