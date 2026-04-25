# sigma-pipeline

Detection-as-code CI/CD for [Sigma](https://github.com/SigmaHQ/sigma) rules. Lints, tests against fixture logs, and deploys to Splunk via the REST API.

```bash
sigma lint     rules/
sigma test     rules/ --fixtures tests/fixtures
sigma coverage rules/ --format navigator --output coverage.json
sigma deploy   rules/ --host splunk.example.com --target-index main
```

Built on top of [splunk-sigma](https://github.com/JacobRHess/splunk-sigma), which provides the rule-evaluation engine.

---

## Why this exists

Standard CI/CD checks code quality. Detection content needs its own checks: does the rule actually catch what it claims to, and does it stay quiet on benign activity? `sigma-pipeline` adds three Sigma-specific stages to a normal pipeline:

| Stage    | What it does                                                                      |
|----------|-----------------------------------------------------------------------------------|
| lint     | YAML schema, required fields, ATT&CK tag format, unique IDs, condition parses     |
| test     | each rule fires on its positive fixtures and stays silent on its negative ones    |
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
│   ├── cli.py          argparse entrypoint, registers subcommands
│   ├── lint.py         rule-file linter
│   ├── test.py         fixture-driven tester
│   └── deploy.py       Splunk REST-API deploy
├── rules/              .yml Sigma rules (the detection content)
├── tests/fixtures/
│   └── <rule_id>/
│       ├── positive/   *.json events the rule MUST match
│       └── negative/   *.json events the rule MUST NOT match
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
- `pyyaml` — rule-file parsing.

## License

MIT — see [`LICENSE`](LICENSE).
