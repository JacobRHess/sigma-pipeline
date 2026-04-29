"""Unit tests for deploy plan + dashboard discovery (no Splunk contact)."""

from __future__ import annotations

from pathlib import Path

from sigma_engine.rules import Rule, Selection

from sigma_pipeline.deploy import (
    _dashboard_files,
    _plan,
    _saved_search_description,
    _saved_search_name,
    _saved_search_spl,
)


def _rule(rid: str, level: str = "high", attack=("attack.t1059.001",)) -> Rule:
    return Rule(
        id=rid,
        title=f"Rule {rid}",
        description="d",
        level=level,
        attack=list(attack),
        logsource={"category": "process_creation", "product": "windows"},
        selections={"selection": Selection(name="selection", matchers=[])},
        condition="selection",
    )


def test_saved_search_name_prefixed():
    assert _saved_search_name(_rule("t1003_001_lsass_dump")) == "sigma_t1003_001_lsass_dump"


def test_saved_search_spl_includes_target_index():
    spl = _saved_search_spl(_rule("rid_x"), target_index="my_idx")
    assert spl == 'search index=my_idx | sigma rules="id:rid_x"'


def test_saved_search_description_includes_attack_and_severity():
    desc = _saved_search_description(_rule("rid_y", level="critical"))
    assert "Severity: critical" in desc
    assert "attack.t1059.001" in desc
    assert "[sigma-pipeline]" in desc


def test_plan_returns_one_entry_per_rule():
    plan = _plan([_rule("a"), _rule("b")], target_index="main")
    assert [name for name, _, _ in plan] == ["sigma_a", "sigma_b"]


def test_dashboard_files_returns_empty_for_none():
    assert _dashboard_files(None) == []


def test_dashboard_files_returns_empty_for_missing_dir(tmp_path: Path):
    assert _dashboard_files(tmp_path / "no_such") == []


def test_dashboard_files_lists_xml_only(tmp_path: Path):
    (tmp_path / "a.xml").write_text("<dashboard/>")
    (tmp_path / "b.xml").write_text("<dashboard/>")
    (tmp_path / "readme.md").write_text("ignore me")
    out = _dashboard_files(tmp_path)
    assert [p.name for p in out] == ["a.xml", "b.xml"]
