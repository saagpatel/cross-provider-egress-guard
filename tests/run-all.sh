#!/usr/bin/env bash
# One-command demo + CI gate: runs every deterministic, offline test harness
# against the in-repo hook copies and the in-repo fixture policies. No live
# ~/.claude install, no network, no Codex required. Exits non-zero if any suite fails.
#
#   bash tests/run-all.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CCH="$ROOT/claude-code/hooks"
FIX="$ROOT/tests/fixtures"

fails=0
run() {
  local name="$1"; shift
  printf '\n══ %s ══\n' "$name"
  if "$@"; then printf '   → PASS\n'; else printf '   → FAIL\n'; fails=$((fails+1)); fi
}

run "mcp-guard egress (Modes 1-4)" \
  env HOOK="$CCH/mcp-guard.sh" MCP_GATE_POLICY="$FIX/policy-r6r7.json" \
  bash "$ROOT/tests/run-egress-tests.sh"

run "bash egress (curl/wget/ssh)" \
  env HOOK="$CCH/bash-egress-guard.sh" MCP_GATE_POLICY="$FIX/policy-r6r7.json" \
  bash "$ROOT/tests/run-bash-egress-tests.sh"

run "git/gh shell write owner+host scope" \
  env HOOK="$CCH/bash-egress-guard.sh" \
  bash "$ROOT/tests/run-git-gh-egress-tests.sh"

run "connector owner-scope + host pinning" \
  env HOOK="$CCH/mcp-guard.sh" \
  bash "$ROOT/tests/run-r6r7-tests.sh"

run "sensitive-read guard" \
  bash "$ROOT/tests/run-sensitive-read-tests.sh"

run "deny-helper hardening" \
  bash "$ROOT/tests/run-deny-helper-tests.sh"

run "cross-provider parity (CC ⇄ Codex)" \
  env MCP_GATE_POLICY="$FIX/policy-r6r7.json" \
  bash "$ROOT/tests/parity-check.sh"

printf '\n────────────────────────────\n'
if [ "$fails" -eq 0 ]; then
  printf 'ALL SUITES PASS\n'
else
  printf 'SUITES FAILED: %d\n' "$fails"
fi
exit "$fails"
