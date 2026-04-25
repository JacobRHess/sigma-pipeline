# sigma-pipeline

Fixture-driven testing for [Sigma](https://github.com/SigmaHQ/sigma) detection rules. Each rule ships with example events it should and should not match — a regression breaks the build the same way a unit-test failure does.

```bash
sigma lint     rules/
sigma test     rules/ --fixtures tests/fixtures
sigma diff     rules/ ../old-rules/        # what changed in our coverage?
sigma coverage rules/ --format navigator --output coverage.json
sigma deploy   rules/ --host splunk.example.com --target-index main
```

Built on top of [splunk-sigma](https://github.com/JacobRHess/splunk-sigma) (the rule-evaluation engine) and optionally [`pySigma`](https://github.com/SigmaHQ/pySigma) (additional validators in `--strict` mode).

---

## Why this exists

Detection rules don't have unit tests.

Most teams treat Sigma rules as configuration: someone writes the YAML, it gets deployed, and the next time anyone finds out it's broken is when a real incident slips past it. The Sigma ecosystem has good tools for *validating* rule structure ([pySigma](https://github.com/SigmaHQ/pySigma), [sigma-cli](https://github.com/SigmaHQ/sigma-cli)) and for *converting* rules into vendor query languages — but nothing standard for asking the question that matters most:

> When we tweak this rule, does it still fire on the attack it's supposed to catch, and does it still stay quiet on the benign activity that looks like the attack?

`sigma-pipeline` answers that question. Each rule has a folder of positive fixtures (events the rule must match) and negative fixtures (events it must not match). `sigma test` walks them and fails the build on any miss. The lint, coverage, diff, and deploy stages exist to make that test loop actually usable in a real workflow — they're the scaffolding, not the centerpiece.

| Stage    | What it does                                                                      |
|----------|-----------------------------------------------------------------------------------|
| lint     | YAML schema, required fields, ATT&CK tag format, unique IDs, condition parses. `--strict` adds pySigma's validator suite. |
| test     | each rule fires on its positive fixtures and stays silent on its negative ones    |
| diff     | compare two rule sets, report added/removed/modified rules and coverage deltas    |
| stats    | rule counts by severity / ATT&CK tactic / logsource — single-glance pulse         |
| coverage | emits markdown table + ATT&CK Navigator JSON layer for the heatmap visual         |
| deploy   | validated rules become saved searches in Splunk, idempotently, on merge to main   |

If someone tweaks a regex in a rule, the test stage catches the case where coverage silently breaks. That's the loop most detection teams don't have today.

## Quickstart

```bash
git clone https://github.com/JacobRHess/sigma-pipeline
cd sigma-pipeline
pip install -e .[dev]

sigma lint rules/
sigma test rules/ --fixtures tests/fixtures
sigma deploy rules/ --dry-run    # prints the deploy plan, makes no changes
```

## Repository layout

```
sigma-pipeline/
├── src/sigma_pipeline/
│   ├── cli.py              argparse entrypoint, registers subcommands
│   ├── lint.py             rule-file linter (+ optional pySigma backend)
│   ├── pysigma_backend.py  pySigma validator wrapper, used by `lint --strict`
│   ├── test.py             fixture-driven tester
│   ├── diff.py             rule-set / coverage diff
│   ├── stats.py            rule-corpus summary (severity / tactic / logsource)
│   ├── coverage.py         ATT&CK coverage reporter
│   └── deploy.py           Splunk REST-API deploy
├── rules/                  .yml Sigma rules (the detection content)
├── tests/fixtures/
│   └── <rule_id>/
│       ├── positive/       *.json events the rule MUST match
│       └── negative/       *.json events the rule MUST NOT match
└── .github/workflows/ci.yml
```

## How tests work

Each rule has its own folder under `tests/fixtures/<rule_id>/`. Inside, `positive/` holds JSON event files the rule must match (true positives), and `negative/` holds events it must not match (benign noise that resembles the threat).

A fixture file may be a single JSON object or an array of objects.

```
tests/fixtures/t1059_001_pwsh_encoded/
├── positive/
│   ├── encoded_command.json
│   └── encoded_pwsh7.json
└── negative/
    └── normal_powershell.json
```

```text
$ sigma test rules/ --fixtures tests/fixtures

t1059_001_pwsh_encoded  (PowerShell Encoded Command Execution)
  [PASS] positive encoded_command.json  1/1 events matched
  [PASS] positive encoded_pwsh7.json    1/1 events matched
  [PASS] negative normal_powershell.json 0/2 events matched (expected 0)

test: 3 rule(s), 8 case(s), 0 failure(s), 0 rule(s) without fixtures
```

A failure looks like:

```text
[FAIL] positive encoded_command.json  0/1 events matched
  -> 1/3 case(s) failed
```

Rules without fixtures are reported as untested but do not fail the run, so the pipeline can be adopted incrementally.

## Strict lint (pySigma)

`sigma lint --strict` runs the [pySigma](https://github.com/SigmaHQ/pySigma) validator suite in addition to the built-in checks. pySigma is the upstream reference implementation maintained by SigmaHQ; it knows about modifier semantics, deprecated fields, title conventions, and dozens of other rule-quality issues that the built-in linter doesn't bother re-implementing.

```bash
pip install -e .[strict]
sigma lint rules/ --strict
```

Strict mode is opt-in so the base install stays light — pySigma pulls in a non-trivial dependency tree.

## Coverage diffs

`sigma diff` compares two rule sets and reports what changed:

```bash
sigma diff rules/ ../old-rules/
```

```text
Rules:
  + t1546_008_accessibility_features
  - t1059_001_pwsh_encoded_legacy
  ~ t1003_001_lsass_dump  (severity: high → critical)

Coverage:
  + T1546.008  (accessibility features)
  - T1059.001  (powershell, no longer covered)
    score:  T1003.001  4 → 5
```

Useful as a PR comment ("here's what this branch changes about our detection coverage") and as a release-notes generator. Markdown output via `--format markdown`.

**Automated in CI:** `.github/workflows/pr-coverage-diff.yml` runs `sigma diff` on every PR that touches `rules/` and posts the result as a sticky PR comment. Reviewers see coverage impact at a glance instead of reading raw YAML diffs. The comment is updated in place on each new commit.

## Rule pulse

`sigma stats` summarizes the rule corpus at a glance — useful for release notes or quick health checks:

```text
$ sigma stats rules/

Rules:       6
Techniques:  6

Severity:
  high           4
  critical       2

By tactic:
  command_and_control    1
  credential_access      1
  defense_evasion        1
  execution              1
  impact                 1
  persistence            1

By logsource:
  process_creation/windows         6
```

## ATT&CK coverage

`sigma coverage` walks the rules and emits coverage in two formats:

```bash
# Markdown table — drop into a README or PR comment.
sigma coverage rules/ --format markdown --output docs/COVERAGE.md

# ATT&CK Navigator JSON layer — upload to
# https://mitre-attack.github.io/attack-navigator/ for the heatmap view.
sigma coverage rules/ --format navigator --output coverage.json
```

Severity is mapped to a 1–5 score (informational → critical) and Navigator
colors techniques accordingly. Techniques covered by multiple rules take
the maximum score.

A pre-rendered markdown report is checked in at [`docs/COVERAGE.md`](docs/COVERAGE.md).

## How deploy works

`sigma deploy` registers each rule as a Splunk saved search whose SPL is:

```
search index=<target_index> | sigma rules="id:<rule_id>"
```

The `splunk-sigma` app does the actual evaluation at search time; the saved search is a thin handle so analysts can find, schedule, and alert on each rule from Splunk Web. Deploys are idempotent (existing saved searches are updated in place; new ones are created).

Authentication uses `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` environment variables. The `--dry-run` flag prints the plan without writing.

```bash
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD='<pw>'
sigma deploy rules/ --host splunk.example.com --target-index main
```

## CI workflow

`.github/workflows/ci.yml` runs lint and test on every push and pull request. On merges to `main`, it additionally runs deploy against a Splunk instance configured via repo secrets (`SPLUNK_HOST`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`). Deploy is gated on the `splunk-prod` GitHub Environment, which lets you require manual approval before production rules change.

## Adding a rule

1. Drop the YAML into `rules/`, following the Sigma spec.
2. Create `tests/fixtures/<rule_id>/positive/*.json` with at least one event the rule should match.
3. Create `tests/fixtures/<rule_id>/negative/*.json` with at least one event it should not match (a near-miss that exercises the boundary is more valuable than a totally unrelated event).
4. Run `sigma lint rules/` and `sigma test rules/ --fixtures tests/fixtures` locally.
5. Open a PR. CI runs the same checks before merge.

## Dependencies

- [`splunk-sigma`](https://github.com/JacobRHess/splunk-sigma) — provides the rule-evaluation engine (`sigma_engine` package).
- [`splunk-sdk`](https://pypi.org/project/splunk-sdk/) — Splunk REST API client used by the deploy stage.
- [`pySigma`](https://github.com/SigmaHQ/pySigma) — optional, used by `lint --strict` for the upstream validator suite.
- `pyyaml` — rule-file parsing.

## License

MIT — see [`LICENSE`](LICENSE).
