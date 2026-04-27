#!/usr/bin/env bash
# Convenience wrapper: prompts silently for Splunk password, then runs the
# seed_splunk_demo.py script. Works under both bash and zsh because the
# shebang forces bash interpretation.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

: "${SPLUNK_USERNAME:=Jhess}"

if [[ -z "${SPLUNK_PASSWORD:-}" ]]; then
  read -sp "Splunk password for ${SPLUNK_USERNAME}: " SPLUNK_PASSWORD
  echo
fi

export SPLUNK_USERNAME SPLUNK_PASSWORD
python3 scripts/seed_splunk_demo.py "$@"
unset SPLUNK_PASSWORD
