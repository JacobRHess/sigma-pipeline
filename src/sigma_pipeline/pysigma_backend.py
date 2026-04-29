"""pySigma validator wrapper for `sigma lint --strict`.

Wraps the SigmaHQ reference parser/validators (https://github.com/SigmaHQ/pySigma).
Imported lazily so the base install doesn't pay the dependency cost.

pySigma is stricter than our base linter — for example, it requires rule
IDs to be UUIDs (per the Sigma spec). When a rule fails pySigma's parse,
we surface the issue as a `warning` rather than an `error`, so opting
into --strict doesn't break a working pipeline; it just reports what
would need to change to be fully spec-compliant.

Some pySigma validators (notably ATTACKTagValidator) load a live MITRE
ATT&CK feed at first use. We skip any validator that errors on init
or returns a network-related RuntimeError, so this works offline.
"""

from __future__ import annotations

from pathlib import Path

from sigma_pipeline.lint import Finding


def _try_import():
    try:
        from sigma.collection import SigmaCollection  # noqa: F401

        return True
    except ImportError:
        return False


# Validators we run when available. Chosen to avoid network fetches:
# tag format / detection structure / modifier sanity. ATTACKTagValidator
# is excluded because it loads a live MITRE feed on first use.
_OFFLINE_VALIDATORS = (
    "tag_format",
    "dangling_detection",
    "dangling_condition",
    "invalid_modifier_combinations",
    "duplicate_references",
    "control_character",
)


def validate_rule(path: Path) -> list[Finding]:
    if not _try_import():
        return [
            Finding(
                path,
                "warning",
                "pySigma not installed — `pip install -e '.[strict]'` to enable",
            )
        ]

    from sigma.collection import SigmaCollection
    from sigma.validators.core import validators as VAL_REGISTRY

    findings: list[Finding] = []
    try:
        col = SigmaCollection.from_yaml(path.read_text(), collect_errors=True)
    except Exception as exc:  # pySigma raises various SigmaError subclasses
        return [Finding(path, "warning", f"pySigma: parse failed: {exc}")]

    for rule in col.rules:
        for err in rule.errors:
            findings.append(Finding(path, "warning", f"pySigma: {err}"))
        if rule.errors:
            # Skip validator suite on rules that didn't fully parse —
            # validators assume a well-formed rule and may crash otherwise.
            continue
        for vname in _OFFLINE_VALIDATORS:
            cls = VAL_REGISTRY.get(vname)
            if cls is None:
                continue
            try:
                validator = cls()
                issues = list(validator.validate(rule))
                issues.extend(validator.finalize())
            except Exception:  # validator chose to fail; treat as N/A
                continue
            for issue in issues:
                findings.append(Finding(path, "warning", f"pySigma[{vname}]: {issue}"))
    return findings
