"""Rule-set diff.

Compares two directories of Sigma rules and reports:

  - Rules added, removed, modified (id matches but content differs)
  - ATT&CK techniques newly covered, no longer covered
  - Severity-score deltas per technique (max-severity model from coverage.py)

Output formats:
    text      Plain text grouped under Rules:/Coverage: headings (default)
    markdown  Same content as a markdown bullet list, suitable for PR comments
"""
from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sigma_engine import load_rules_from_dir
from sigma_engine.rules import Rule

from sigma_pipeline.coverage import SEVERITY_SCORE, _technique_ids


@dataclass
class RuleDiff:
    added: list[Rule] = field(default_factory=list)
    removed: list[Rule] = field(default_factory=list)
    modified: list[tuple[Rule, Rule, list[str]]] = field(default_factory=list)


@dataclass
class CoverageDiff:
    added_techniques: list[str] = field(default_factory=list)
    removed_techniques: list[str] = field(default_factory=list)
    score_changes: list[tuple[str, int, int]] = field(default_factory=list)


def _index_rules(rules: list[Rule]) -> dict[str, Rule]:
    out: dict[str, Rule] = {}
    for r in rules:
        out[r.id] = r
    return out


def _rule_signature(r: Rule) -> tuple:
    """Stable comparison key. Two rules with the same id but a different
    signature are 'modified'. We compare the parts that affect what the rule
    does, not bookkeeping fields like description text."""
    selections = tuple(
        (name, tuple((m.field_name, m.operator, tuple(m.patterns)) for m in sel.matchers))
        for name, sel in sorted(r.selections.items())
    )
    return (
        r.title,
        r.level,
        tuple(sorted(r.attack)),
        tuple(sorted(r.logsource.items())),
        selections,
        r.condition.strip(),
    )


def _what_changed(old: Rule, new: Rule) -> list[str]:
    changes = []
    if old.level != new.level:
        changes.append(f"severity: {old.level} → {new.level}")
    if old.title != new.title:
        changes.append(f"title: {old.title!r} → {new.title!r}")
    if sorted(old.attack) != sorted(new.attack):
        added = sorted(set(new.attack) - set(old.attack))
        removed = sorted(set(old.attack) - set(new.attack))
        if added:
            changes.append(f"attack +{added}")
        if removed:
            changes.append(f"attack -{removed}")
    if old.condition.strip() != new.condition.strip():
        changes.append("condition changed")
    if _selections_changed(old, new):
        changes.append("detection logic changed")
    return changes or ["unspecified change"]


def _selections_changed(old: Rule, new: Rule) -> bool:
    if set(old.selections) != set(new.selections):
        return True
    for name, sel in old.selections.items():
        new_sel = new.selections[name]
        old_m = [(m.field_name, m.operator, tuple(m.patterns)) for m in sel.matchers]
        new_m = [(m.field_name, m.operator, tuple(m.patterns)) for m in new_sel.matchers]
        if sorted(old_m) != sorted(new_m):
            return True
    return False


def _diff_rules(old: list[Rule], new: list[Rule]) -> RuleDiff:
    old_idx = _index_rules(old)
    new_idx = _index_rules(new)
    out = RuleDiff()
    for rid in sorted(set(new_idx) - set(old_idx)):
        out.added.append(new_idx[rid])
    for rid in sorted(set(old_idx) - set(new_idx)):
        out.removed.append(old_idx[rid])
    for rid in sorted(set(old_idx) & set(new_idx)):
        old_r, new_r = old_idx[rid], new_idx[rid]
        if _rule_signature(old_r) != _rule_signature(new_r):
            out.modified.append((old_r, new_r, _what_changed(old_r, new_r)))
    return out


def _technique_scores(rules: list[Rule]) -> dict[str, int]:
    by_tech: dict[str, list[Rule]] = defaultdict(list)
    for r in rules:
        for tid in _technique_ids(r):
            by_tech[tid].append(r)
    return {
        tid: max(SEVERITY_SCORE.get(r.level, 0) for r in tech_rules)
        for tid, tech_rules in by_tech.items()
    }


def _diff_coverage(old: list[Rule], new: list[Rule]) -> CoverageDiff:
    old_scores = _technique_scores(old)
    new_scores = _technique_scores(new)
    out = CoverageDiff()
    out.added_techniques = sorted(set(new_scores) - set(old_scores))
    out.removed_techniques = sorted(set(old_scores) - set(new_scores))
    for tid in sorted(set(old_scores) & set(new_scores)):
        if old_scores[tid] != new_scores[tid]:
            out.score_changes.append((tid, old_scores[tid], new_scores[tid]))
    return out


def _format_text(rd: RuleDiff, cd: CoverageDiff) -> str:
    lines = ["Rules:"]
    if not (rd.added or rd.removed or rd.modified):
        lines.append("  (no rule changes)")
    for r in rd.added:
        lines.append(f"  + {r.id}  ({r.title})")
    for r in rd.removed:
        lines.append(f"  - {r.id}  ({r.title})")
    for _old, new, changes in rd.modified:
        lines.append(f"  ~ {new.id}  ({'; '.join(changes)})")

    lines.append("")
    lines.append("Coverage:")
    if not (cd.added_techniques or cd.removed_techniques or cd.score_changes):
        lines.append("  (no coverage changes)")
    for tid in cd.added_techniques:
        lines.append(f"  + {tid}")
    for tid in cd.removed_techniques:
        lines.append(f"  - {tid}  (no longer covered)")
    for tid, old_score, new_score in cd.score_changes:
        arrow = "↑" if new_score > old_score else "↓"
        lines.append(f"    score: {tid}  {old_score} → {new_score} {arrow}")
    return "\n".join(lines) + "\n"


def _format_markdown(rd: RuleDiff, cd: CoverageDiff) -> str:
    lines = ["## Rule changes", ""]
    if not (rd.added or rd.removed or rd.modified):
        lines.append("_No rule changes._")
    else:
        for r in rd.added:
            lines.append(f"- **added** `{r.id}` — {r.title}")
        for r in rd.removed:
            lines.append(f"- **removed** `{r.id}` — {r.title}")
        for _old, new, changes in rd.modified:
            lines.append(f"- **modified** `{new.id}` — {'; '.join(changes)}")
    lines.append("")
    lines.append("## Coverage changes")
    lines.append("")
    if not (cd.added_techniques or cd.removed_techniques or cd.score_changes):
        lines.append("_No coverage changes._")
    else:
        for tid in cd.added_techniques:
            lines.append(f"- **+ {tid}** newly covered")
        for tid in cd.removed_techniques:
            lines.append(f"- **− {tid}** no longer covered")
        for tid, old_score, new_score in cd.score_changes:
            arrow = "↑" if new_score > old_score else "↓"
            lines.append(f"- {tid} severity score {old_score} → {new_score} {arrow}")
    return "\n".join(lines) + "\n"


def run(new_dir: Path, old_dir: Path, fmt: str, output: Path | None) -> int:
    for label, d in (("new", new_dir), ("old", old_dir)):
        if not d.is_dir():
            print(f"error: {label} rules dir {d} is not a directory", file=sys.stderr)
            return 2
    new_rules = load_rules_from_dir(str(new_dir))
    old_rules = load_rules_from_dir(str(old_dir))
    rd = _diff_rules(old_rules, new_rules)
    cd = _diff_coverage(old_rules, new_rules)

    if fmt == "text":
        body = _format_text(rd, cd)
    elif fmt == "markdown":
        body = _format_markdown(rd, cd)
    else:
        print(f"error: unknown format '{fmt}' (expected: text|markdown)", file=sys.stderr)
        return 2

    if output:
        output.write_text(body)
        print(f"wrote {output}")
    else:
        print(body, end="")
    return 0
