"""Unit tests for the linter — covers the basic schema, enum, and tag checks
so a regression in those small functions trips CI even before fixture-level
behavior is exercised.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sigma_pipeline.lint import _is_valid_attack_tag, lint_rule


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


GOOD_RULE = """\
title: Good rule
id: t9999_test_good
status: stable
description: A well-formed rule for unit-test purposes.
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\evil.exe'
  condition: selection
tags:
  - attack.execution
  - attack.t9999
"""


def test_attack_tag_validator():
    assert _is_valid_attack_tag("attack.t1059")
    assert _is_valid_attack_tag("attack.t1059.001")
    assert _is_valid_attack_tag("attack.execution")
    assert _is_valid_attack_tag("attack.credential_access")
    assert not _is_valid_attack_tag("attack.")
    assert not _is_valid_attack_tag("attack.T1059.0001")  # 4 sub-digits, malformed
    assert not _is_valid_attack_tag("attack.123")        # tactic must start with letter


def test_lint_rule_clean(tmp_path: Path):
    path = _write(tmp_path, "good.yml", GOOD_RULE)
    findings, rid = lint_rule(path)
    errors = [f for f in findings if f.severity == "error"]
    assert errors == [], errors
    assert rid == "t9999_test_good"


def test_lint_rule_missing_required_field(tmp_path: Path):
    body = GOOD_RULE.replace("level: medium\n", "")
    path = _write(tmp_path, "no_level.yml", body)
    findings, _ = lint_rule(path)
    msgs = [f.message for f in findings if f.severity == "error"]
    assert any("level" in m for m in msgs)


def test_lint_rule_bad_level(tmp_path: Path):
    body = GOOD_RULE.replace("level: medium", "level: extreme")
    path = _write(tmp_path, "bad_level.yml", body)
    findings, _ = lint_rule(path)
    assert any("level 'extreme'" in f.message for f in findings)


def test_lint_rule_malformed_tag(tmp_path: Path):
    body = GOOD_RULE.replace("attack.t9999", "attack.t99999")
    path = _write(tmp_path, "bad_tag.yml", body)
    findings, _ = lint_rule(path)
    assert any("malformed ATT&CK tag" in f.message for f in findings)


@pytest.mark.parametrize(
    "broken_condition",
    [
        "selection and",        # dangling operator
        "(selection or",        # unbalanced parens
        "selection unknown_op", # bare unknown trailing token
    ],
)
def test_lint_rule_bad_condition(tmp_path: Path, broken_condition: str):
    body = GOOD_RULE.replace("condition: selection", f"condition: {broken_condition}")
    path = _write(tmp_path, "bad_cond.yml", body)
    findings, _ = lint_rule(path)
    assert any(
        "condition does not parse" in f.message or "engine rejected rule" in f.message
        for f in findings
    ), [f.fmt() for f in findings]
