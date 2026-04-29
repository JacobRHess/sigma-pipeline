"""Quick rule-pulse summary.

Counts rules by severity, ATT&CK tactic, and logsource. Useful as a
single-glance "where does our coverage stand?" snapshot for PR comments
or release notes.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from sigma_engine import load_rules_from_dir
from sigma_engine.rules import Rule

# Sigma's recognized ATT&CK tactic tags. Anything in attack.* that isn't
# a technique (T-prefixed) and matches one of these is counted as a tactic.
KNOWN_TACTICS = {
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}


def _tactics(rule: Rule) -> list[str]:
    out = []
    for tag in rule.tags:
        if not tag.lower().startswith("attack."):
            continue
        rest = tag.split(".", 1)[1].lower()
        if rest in KNOWN_TACTICS:
            out.append(rest)
    return out


def _logsource_key(rule: Rule) -> str:
    cat = rule.logsource.get("category", "?")
    prod = rule.logsource.get("product", "?")
    return f"{cat}/{prod}"


def _technique_count(rules: list[Rule]) -> int:
    seen: set[str] = set()
    for r in rules:
        for tid in r.attack:
            if tid.upper().startswith("T") and tid[1:2].isdigit():
                seen.add(tid.upper())
    return len(seen)


def _format(rules: list[Rule]) -> str:
    sev = Counter(r.level for r in rules)
    tactics = Counter(t for r in rules for t in _tactics(r))
    sources = Counter(_logsource_key(r) for r in rules)

    lines = [
        f"Rules:       {len(rules)}",
        f"Techniques:  {_technique_count(rules)}",
        "",
        "Severity:",
    ]
    # Order severities low-to-critical so the visual reads as expected.
    severity_order = ["informational", "low", "medium", "high", "critical"]
    for level in severity_order:
        if sev[level]:
            lines.append(f"  {level:<14} {sev[level]}")
    other = sorted(set(sev) - set(severity_order))
    for level in other:
        lines.append(f"  {level:<14} {sev[level]}")

    lines.append("")
    lines.append("By tactic:")
    for tactic, n in sorted(tactics.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {tactic:<22} {n}")

    lines.append("")
    lines.append("By logsource:")
    for src, n in sorted(sources.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {src:<32} {n}")
    return "\n".join(lines) + "\n"


def run(rules_dir: Path) -> int:
    if not rules_dir.is_dir():
        print(f"error: {rules_dir} is not a directory", file=sys.stderr)
        return 2
    rules = load_rules_from_dir(str(rules_dir))
    if not rules:
        print(f"error: no rules loaded from {rules_dir}", file=sys.stderr)
        return 2
    print(_format(rules), end="")
    return 0
