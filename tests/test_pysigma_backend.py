"""Unit tests for the optional pySigma --strict backend.

The backend is meant to degrade gracefully:
  - returns a single 'install pysigma' warning when the import fails
  - never raises on a malformed rule (all parse errors become warnings)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sigma_pipeline import pysigma_backend


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "rule.yml"
    p.write_text(body)
    return p


GOOD_RULE = """\
title: Strict-mode rule
id: 11111111-2222-3333-4444-555555555555
status: stable
description: A rule with a real UUID, accepted by pySigma.
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
  - attack.t1059
"""

NON_UUID_RULE = GOOD_RULE.replace(
    "id: 11111111-2222-3333-4444-555555555555",
    "id: t9999_test_slug",
)


def test_handles_missing_pysigma(monkeypatch, tmp_path):
    monkeypatch.setattr(pysigma_backend, "_try_import", lambda: False)
    findings = pysigma_backend.validate_rule(_write(tmp_path, GOOD_RULE))
    assert len(findings) == 1
    assert "pySigma not installed" in findings[0].message


def test_non_uuid_rule_reported_as_warning(tmp_path: Path):
    pytest.importorskip("sigma.collection")
    findings = pysigma_backend.validate_rule(_write(tmp_path, NON_UUID_RULE))
    assert any("UUID" in f.message for f in findings)
    # Crucially, it surfaces as a warning, not an error — strict mode is advisory
    # and must not break a working pipeline.
    assert all(f.severity == "warning" for f in findings)


def test_uuid_rule_passes_cleanly_or_only_advisory(tmp_path: Path):
    pytest.importorskip("sigma.collection")
    findings = pysigma_backend.validate_rule(_write(tmp_path, GOOD_RULE))
    # pySigma may still emit best-practice advisories (e.g. tag format),
    # but never errors.
    assert all(f.severity == "warning" for f in findings)


def test_malformed_yaml_returns_warning_not_raise(tmp_path: Path):
    pytest.importorskip("sigma.collection")
    findings = pysigma_backend.validate_rule(_write(tmp_path, "not: [valid yaml"))
    assert findings  # backend reported something
    assert all(f.severity == "warning" for f in findings)
