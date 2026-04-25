"""ATT&CK coverage reporter.

Two output formats:

  --format markdown   Human-readable Markdown table of rules grouped by
                      ATT&CK technique. Drop straight into a README.

  --format navigator  ATT&CK Navigator JSON layer. Upload to
                      https://mitre-attack.github.io/attack-navigator/
                      to render a heatmap colored by rule severity.

Severity → coverage score mapping:
    informational=1, low=2, medium=3, high=4, critical=5
A technique covered by multiple rules takes the maximum severity score.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from sigma_engine import load_rules_from_dir
from sigma_engine.rules import Rule

SEVERITY_SCORE = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
NAVIGATOR_COLOR = {
    1: "#a8c9ff",
    2: "#7faaff",
    3: "#558bff",
    4: "#2c6cff",
    5: "#0046d1",
}
# `rule.attack` is already stripped to bare technique IDs by the engine
# loader (e.g. "T1059.001"); we just normalize and filter to the ones
# matching the technique shape so tactic-only entries don't slip in.
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _technique_ids(rule: Rule) -> list[str]:
    return [t.upper() for t in rule.attack if TECHNIQUE_ID_RE.match(t)]


def _gather(rules: list[Rule]) -> dict[str, list[Rule]]:
    """technique_id -> [rule, ...]"""
    by_tech: dict[str, list[Rule]] = defaultdict(list)
    for r in rules:
        for tid in _technique_ids(r):
            by_tech[tid].append(r)
    return dict(sorted(by_tech.items()))


def _markdown(by_tech: dict[str, list[Rule]], rules: list[Rule]) -> str:
    lines = []
    lines.append(f"# ATT&CK coverage ({len(rules)} rule(s), {len(by_tech)} technique(s))\n")
    lines.append("| Technique | Rule | Severity |")
    lines.append("|-----------|------|----------|")
    for tid, tech_rules in by_tech.items():
        for r in tech_rules:
            lines.append(f"| {tid} | {r.title} | {r.level} |")
    return "\n".join(lines) + "\n"


def _navigator(by_tech: dict[str, list[Rule]]) -> dict:
    techniques = []
    for tid, tech_rules in by_tech.items():
        score = max(SEVERITY_SCORE.get(r.level, 0) for r in tech_rules)
        comment = "; ".join(f"{r.title} ({r.level})" for r in tech_rules)
        techniques.append(
            {
                "techniqueID": tid,
                "score": score,
                "color": NAVIGATOR_COLOR.get(score, "#cccccc"),
                "comment": comment,
                "enabled": True,
            }
        )
    return {
        "name": "sigma-pipeline coverage",
        "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Detection coverage from sigma-pipeline rules, colored by severity.",
        "gradient": {
            "colors": ["#a8c9ff", "#0046d1"],
            "minValue": 1,
            "maxValue": 5,
        },
        "techniques": techniques,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#f0f0f0",
    }


def run(rules_dir: Path, fmt: str, output: Path | None) -> int:
    if not rules_dir.is_dir():
        print(f"error: {rules_dir} is not a directory", file=sys.stderr)
        return 2
    rules = load_rules_from_dir(str(rules_dir))
    if not rules:
        print(f"error: no rules loaded from {rules_dir}", file=sys.stderr)
        return 2
    by_tech = _gather(rules)

    if fmt == "markdown":
        body = _markdown(by_tech, rules)
    elif fmt == "navigator":
        body = json.dumps(_navigator(by_tech), indent=2)
    else:
        print(f"error: unknown format '{fmt}' (expected: markdown|navigator)", file=sys.stderr)
        return 2

    if output:
        output.write_text(body)
        print(f"wrote {output}  ({len(by_tech)} technique(s), {len(rules)} rule(s))")
    else:
        print(body)
    return 0
