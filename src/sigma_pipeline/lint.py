"""Sigma rule linter.

Checks (per rule file):
  - YAML parses
  - Required fields present: id, title, description, status, level,
    logsource, detection, condition
  - level is one of: informational | low | medium | high | critical
  - status is one of: stable | test | experimental | deprecated | unsupported
  - Each ATT&CK tag matches "attack.t<digits>(.<digits>)?"
  - The detection condition string parses through the sigma_engine

Cross-rule checks:
  - Rule IDs are unique across the corpus

Exit code: 0 on clean, 1 on any failure.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma_engine import load_rule_from_file
from sigma_engine.evaluator import _evaluate_condition

REQUIRED_FIELDS = ["id", "title", "description", "status", "level", "logsource", "detection"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
# Accepts ATT&CK technique tags (attack.t1059, attack.t1059.001) and
# tactic tags (attack.execution, attack.credential_access, ...).
ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"^attack\.[a-z][a-z_]*$", re.IGNORECASE)


def _is_valid_attack_tag(tag: str) -> bool:
    """A tag starting with `attack.t<digit>...` is clearly a technique attempt;
    require it to match the strict technique regex. Otherwise allow the
    tactic shape (alpha + underscores, e.g. attack.credential_access).
    """
    if re.match(r"^attack\.t\d", tag, re.IGNORECASE):
        return bool(ATTACK_TECHNIQUE_RE.match(tag))
    return bool(ATTACK_TACTIC_RE.match(tag))


@dataclass
class Finding:
    path: Path
    severity: str  # "error" | "warning"
    message: str

    def fmt(self) -> str:
        return f"[{self.severity.upper()}] {self.path}: {self.message}"


def _check_required(doc: dict[str, Any], path: Path) -> list[Finding]:
    findings = []
    for field in REQUIRED_FIELDS:
        if field not in doc:
            findings.append(Finding(path, "error", f"missing required field '{field}'"))
    detection = doc.get("detection") or {}
    if isinstance(detection, dict) and "condition" not in detection:
        findings.append(Finding(path, "error", "detection.condition is missing"))
    return findings


def _check_enums(doc: dict[str, Any], path: Path) -> list[Finding]:
    findings = []
    level = doc.get("level")
    if level is not None and level not in VALID_LEVELS:
        findings.append(
            Finding(path, "error", f"level '{level}' not in {sorted(VALID_LEVELS)}")
        )
    status = doc.get("status")
    if status is not None and status not in VALID_STATUS:
        findings.append(
            Finding(path, "error", f"status '{status}' not in {sorted(VALID_STATUS)}")
        )
    return findings


def _check_attack_tags(doc: dict[str, Any], path: Path) -> list[Finding]:
    findings = []
    tags = doc.get("tags") or []
    if not isinstance(tags, list):
        findings.append(Finding(path, "error", "tags must be a list"))
        return findings
    has_technique = False
    for tag in tags:
        if not isinstance(tag, str):
            findings.append(Finding(path, "error", f"non-string tag: {tag!r}"))
            continue
        if not tag.lower().startswith("attack."):
            continue
        if not _is_valid_attack_tag(tag):
            findings.append(
                Finding(
                    path,
                    "error",
                    f"malformed ATT&CK tag '{tag}' "
                    "(expected attack.tNNNN[.NNN] or attack.<tactic>)",
                )
            )
        if ATTACK_TECHNIQUE_RE.match(tag):
            has_technique = True
    if not has_technique:
        findings.append(
            Finding(path, "warning", "no ATT&CK technique tag (attack.tNNNN[.NNN])")
        )
    return findings


def _check_engine_loadable(path: Path) -> list[Finding]:
    """Round-trip through the engine: load the rule, then parse its condition.

    Loading catches structural issues (missing selections, malformed
    detection blocks). The condition pass catches dangling operators,
    unknown selection refs, and trailing tokens.
    """
    try:
        rule = load_rule_from_file(str(path))
    except Exception as exc:  # noqa: BLE001
        return [Finding(path, "error", f"engine rejected rule: {exc}")]
    sel_results = {name: False for name in rule.selections}
    try:
        _evaluate_condition(rule.condition, sel_results)
    except Exception as exc:  # noqa: BLE001
        return [Finding(path, "error", f"condition does not parse: {exc}")]
    return []


def _check_unique_ids(seen_ids: dict[str, list[Path]]) -> list[Finding]:
    findings = []
    for rid, paths in seen_ids.items():
        if len(paths) > 1:
            joined = ", ".join(str(p) for p in paths)
            findings.append(
                Finding(paths[0], "error", f"duplicate rule id '{rid}' also at: {joined}")
            )
    return findings


def lint_rule(path: Path, strict: bool = False) -> tuple[list[Finding], str | None]:
    """Lint one rule file. Returns (findings, rule_id_or_None)."""
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return [Finding(path, "error", f"YAML parse error: {exc}")], None
    if not isinstance(doc, dict):
        return [Finding(path, "error", "top-level YAML is not a mapping")], None

    findings: list[Finding] = []
    findings += _check_required(doc, path)
    findings += _check_enums(doc, path)
    findings += _check_attack_tags(doc, path)
    findings += _check_engine_loadable(path)
    if strict:
        from sigma_pipeline import pysigma_backend
        findings += pysigma_backend.validate_rule(path)
    return findings, doc.get("id")


def run(rules_dir: Path, strict: bool = False) -> int:
    if not rules_dir.is_dir():
        print(f"error: {rules_dir} is not a directory")
        return 2

    rule_files = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))
    if not rule_files:
        print(f"error: no .yml/.yaml rules under {rules_dir}")
        return 2

    all_findings: list[Finding] = []
    seen_ids: dict[str, list[Path]] = defaultdict(list)

    for path in rule_files:
        findings, rid = lint_rule(path, strict=strict)
        all_findings.extend(findings)
        if rid:
            seen_ids[rid].append(path)
    all_findings.extend(_check_unique_ids(seen_ids))

    errors = [f for f in all_findings if f.severity == "error"]
    warnings = [f for f in all_findings if f.severity == "warning"]
    for f in all_findings:
        print(f.fmt())

    summary = (
        f"\nlint: {len(rule_files)} rule(s), "
        f"{len(errors)} error(s), {len(warnings)} warning(s)"
    )
    print(summary)
    return 0 if not errors else 1
