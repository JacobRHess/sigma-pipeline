"""Unit tests for the diff command."""
from __future__ import annotations

from sigma_engine.rules import FieldMatcher, Rule, Selection

from sigma_pipeline.diff import _diff_coverage, _diff_rules, _format_markdown, _format_text


def _rule(rid: str, level: str = "high", attack=None, image: str = "\\evil.exe") -> Rule:
    return Rule(
        id=rid,
        title=f"Test {rid}",
        description="x",
        level=level,
        attack=attack or [],
        logsource={"category": "process_creation"},
        selections={
            "sel": Selection(
                name="sel",
                matchers=[
                    FieldMatcher(field_name="Image", operator="endswith", patterns=[image])
                ],
            )
        },
        condition="sel",
    )


def test_diff_detects_added_and_removed():
    old = [_rule("a"), _rule("b")]
    new = [_rule("a"), _rule("c")]
    rd = _diff_rules(old, new)
    assert [r.id for r in rd.added] == ["c"]
    assert [r.id for r in rd.removed] == ["b"]
    assert rd.modified == []


def test_diff_detects_severity_change():
    old = [_rule("a", level="high")]
    new = [_rule("a", level="critical")]
    rd = _diff_rules(old, new)
    assert len(rd.modified) == 1
    _, _, changes = rd.modified[0]
    assert any("severity: high → critical" in c for c in changes)


def test_diff_detects_detection_logic_change():
    old = [_rule("a", image="\\evil.exe")]
    new = [_rule("a", image="\\different.exe")]
    rd = _diff_rules(old, new)
    assert len(rd.modified) == 1
    _, _, changes = rd.modified[0]
    assert "detection logic changed" in changes


def test_diff_ignores_description_only_change():
    old = [_rule("a")]
    new_rule = _rule("a")
    new_rule.description = "completely different prose"
    rd = _diff_rules(old, [new_rule])
    assert rd.modified == []


def test_coverage_diff_added_and_removed_techniques():
    old = [_rule("a", attack=["T1059"])]
    new = [_rule("a", attack=["T1059"]), _rule("b", attack=["T1003.001"])]
    cd = _diff_coverage(old, new)
    assert cd.added_techniques == ["T1003.001"]
    assert cd.removed_techniques == []


def test_coverage_diff_score_change():
    # Same technique, but new rule set bumps severity from low to critical.
    old = [_rule("a", level="low", attack=["T1059"])]
    new = [_rule("a", level="critical", attack=["T1059"])]
    cd = _diff_coverage(old, new)
    assert cd.score_changes == [("T1059", 2, 5)]


def test_format_text_no_changes():
    rd = _diff_rules([_rule("a")], [_rule("a")])
    cd = _diff_coverage([_rule("a")], [_rule("a")])
    out = _format_text(rd, cd)
    assert "(no rule changes)" in out
    assert "(no coverage changes)" in out


def test_format_markdown_renders_changes():
    old = [_rule("a", level="low", attack=["T1059"])]
    new = [_rule("a", level="critical", attack=["T1059"]), _rule("b", attack=["T1003"])]
    rd = _diff_rules(old, new)
    cd = _diff_coverage(old, new)
    md = _format_markdown(rd, cd)
    assert "**added** `b`" in md
    assert "severity: low → critical" in md
    assert "**+ T1003**" in md
    assert "T1059 severity score 2 → 5" in md
