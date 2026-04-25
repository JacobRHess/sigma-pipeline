"""Unit tests for the stats command."""
from __future__ import annotations

from sigma_engine.rules import FieldMatcher, Rule, Selection

from sigma_pipeline.stats import _format, _technique_count


def _rule(rid: str, level: str = "high", tags=None, attack=None, logsource=None) -> Rule:
    return Rule(
        id=rid,
        title=f"Test {rid}",
        description="x",
        level=level,
        attack=attack or [],
        logsource=logsource or {"category": "process_creation", "product": "windows"},
        selections={
            "sel": Selection(
                name="sel",
                matchers=[FieldMatcher(field_name="X", operator="equals", patterns=["y"])],
            )
        },
        condition="sel",
        tags=tags or [],
    )


def test_technique_count_dedupes():
    rules = [
        _rule("a", attack=["T1059"]),
        _rule("b", attack=["T1059", "T1059.001"]),
    ]
    assert _technique_count(rules) == 2


def test_format_lists_severity_in_low_to_high_order():
    rules = [
        _rule("a", level="critical"),
        _rule("b", level="low"),
        _rule("c", level="high"),
    ]
    out = _format(rules)
    low_pos = out.index("low ")
    high_pos = out.index("high ")
    crit_pos = out.index("critical ")
    assert low_pos < high_pos < crit_pos


def test_format_groups_tactics_from_tags():
    rules = [
        _rule("a", tags=["attack.execution", "attack.t1059"]),
        _rule("b", tags=["attack.persistence", "attack.t1547"]),
        _rule("c", tags=["attack.execution", "attack.t1059.001"]),
    ]
    out = _format(rules)
    assert "execution" in out
    assert "persistence" in out
    # "execution" appears in two rules, persistence in one — verify counts.
    for line in out.splitlines():
        if line.strip().startswith("execution"):
            assert line.strip().endswith("2")
        if line.strip().startswith("persistence"):
            assert line.strip().endswith("1")


def test_format_groups_logsources():
    rules = [
        _rule("a", logsource={"category": "process_creation", "product": "windows"}),
        _rule("b", logsource={"category": "network_connection", "product": "windows"}),
        _rule("c", logsource={"category": "process_creation", "product": "windows"}),
    ]
    out = _format(rules)
    assert "process_creation/windows" in out
    assert "network_connection/windows" in out
