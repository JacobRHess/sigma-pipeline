"""Seed Splunk with synthetic Sigma rule fires for the demo dashboard.

For each rule in rules/, walks tests/fixtures/<rule_id>/positive/*.json
and posts each fixture event to index=main with sourcetype=sigma:fire.
Each event is enriched with the rule's metadata (severity, technique,
tactic, title) and timestamps are spread across the last 24h so the
timeline panel has texture.

Install (the seeder needs `requests`, declared under the [demo] extra):
    pip install -e .[demo]

Usage (basic auth):
    SPLUNK_USERNAME=admin SPLUNK_PASSWORD=... python scripts/seed_splunk_demo.py

Usage (session key from ~/.splunk/authToken_*):
    SPLUNK_SESSION_KEY=<key> python scripts/seed_splunk_demo.py

Optional:
    --host (default localhost) --port (default 8089) --index (default main)
    --fires-per-fixture (default 6) --hours (default 24)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


def _technique_from_tags(tags: list[str]) -> str | None:
    for t in tags:
        if t.lower().startswith("attack.t") and any(c.isdigit() for c in t):
            return t.split(".", 1)[1].upper()
    return None


def _tactic_from_tags(tags: list[str]) -> str | None:
    for t in tags:
        low = t.lower()
        if low.startswith("attack.") and not low.startswith("attack.t"):
            return low.split(".", 1)[1]
    return None


def _load_rule_meta(rule_path: Path) -> dict:
    doc = yaml.safe_load(rule_path.read_text())
    tags = doc.get("tags") or []
    return {
        "rule_id": doc["id"],
        "title": doc["title"],
        "severity": doc["level"],
        "technique": _technique_from_tags(tags) or "unknown",
        "tactic": _tactic_from_tags(tags) or "unknown",
    }


def _build_event(fixture: dict, meta: dict, when: float) -> dict:
    enriched = dict(fixture)
    enriched["_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))
    enriched["sigma_rule_id"] = meta["rule_id"]
    enriched["sigma_title"] = meta["title"]
    enriched["sigma_severity"] = meta["severity"]
    enriched["sigma_technique"] = meta["technique"]
    enriched["sigma_tactic"] = meta["tactic"]
    return enriched


def _post(session, url: str, auth, headers, params: dict, body: str) -> None:
    r = session.post(
        url, params=params, data=body, auth=auth, headers=headers, verify=False, timeout=10
    )
    r.raise_for_status()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--index", default="main")
    ap.add_argument("--fires-per-fixture", type=int, default=6)
    ap.add_argument("--hours", type=int, default=24)
    args = ap.parse_args()

    user = os.environ.get("SPLUNK_USERNAME")
    pw = os.environ.get("SPLUNK_PASSWORD")
    session_key = os.environ.get("SPLUNK_SESSION_KEY")
    if not session_key and not (user and pw):
        print(
            "error: set SPLUNK_SESSION_KEY, or SPLUNK_USERNAME and SPLUNK_PASSWORD",
            file=sys.stderr,
        )
        return 2

    try:
        import requests
    except ImportError:
        print("error: pip install requests", file=sys.stderr)
        return 2

    session = requests.Session()
    auth = None
    headers: dict[str, str] = {}
    if session_key:
        headers["Authorization"] = f"Splunk {session_key}"
    else:
        auth = (user, pw)
    url = f"https://{args.host}:{args.port}/services/receivers/simple"

    rules = sorted(RULES_DIR.glob("*.yml"))
    if not rules:
        print(f"error: no rules under {RULES_DIR}", file=sys.stderr)
        return 2

    now = time.time()
    earliest = now - args.hours * 3600
    total = 0

    for rule_path in rules:
        meta = _load_rule_meta(rule_path)
        pos_dir = FIXTURES_DIR / meta["rule_id"] / "positive"
        if not pos_dir.is_dir():
            print(f"  skip {meta['rule_id']}: no positive fixtures")
            continue
        fixtures = sorted(pos_dir.glob("*.json"))
        rule_total = 0
        for fx in fixtures:
            try:
                payload = json.loads(fx.read_text())
            except json.JSONDecodeError as exc:
                print(f"  warn {fx}: {exc}")
                continue
            payloads = payload if isinstance(payload, list) else [payload]
            for one in payloads:
                if not isinstance(one, dict):
                    print(f"  warn {fx}: skipping non-object element")
                    continue
                for _ in range(args.fires_per_fixture):
                    when = random.uniform(earliest, now)
                    event = _build_event(one, meta, when)
                    params = {
                        "index": args.index,
                        "sourcetype": "sigma:fire",
                        "source": f"sigma-pipeline:{meta['rule_id']}",
                        "host": "demo-host",
                    }
                    _post(session, url, auth, headers, params, json.dumps(event))
                    total += 1
                    rule_total += 1
        print(f"  ok   {meta['rule_id']:40s} +{rule_total}")

    print(f"\nseeded {total} events into index={args.index} (sourcetype=sigma:fire)")
    print("dashboard: http(s)://<splunk-web>/en-US/app/search/sigma_overview")
    return 0


if __name__ == "__main__":
    sys.exit(main())
