#!/bin/bash
# Regression coverage for claude-code/hooks/lib/deny.sh.
# Proves the hooks do not trust PATH for jq, and fail closed when no usable jq
# can be resolved.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MCP_HOOK="${MCP_HOOK:-$ROOT/claude-code/hooks/mcp-guard.sh}"
BASH_HOOK="${BASH_HOOK:-$ROOT/claude-code/hooks/bash-egress-guard.sh}"
POLICY="${MCP_GATE_POLICY:-$ROOT/tests/fixtures/policy-r6r7.json}"

TMPDIR=$(mktemp -d)
TOKDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR" "$TOKDIR"' EXIT

pass=0
fail=0

FAKEBIN="$TMPDIR/fakebin"
mkdir -p "$FAKEBIN"
{
  printf '%s\n' '#!/bin/sh'
  printf '%s\n' 'echo "path jq should not run" >&2'
  printf '%s\n' 'exit 42'
} > "$FAKEBIN/jq"
chmod +x "$FAKEBIN/jq"

is_deny() {
  printf '%s' "$1" | grep -q '"permissionDecision":[[:space:]]*"deny"'
}

assert_deny() {
  local name="$1" out="$2" reason_expect="${3:-}"
  if is_deny "$out" && { [ -z "$reason_expect" ] || printf '%s' "$out" | grep -qF "$reason_expect"; }; then
    printf 'ok   %-42s [deny]\n' "$name"
    pass=$((pass+1))
  else
    printf 'FAIL %-42s expected=deny\n' "$name"
    [ -n "$reason_expect" ] && printf '       expected reason to contain: %s\n' "$reason_expect"
    [ -n "$out" ] && printf '       output: %s\n' "$out"
    fail=$((fail+1))
  fi
}

run_mcp() {
  local json="$1"
  PATH="$FAKEBIN:$PATH" \
    MCP_GATE_POLICY="$POLICY" \
    CLAUDE_TOKEN_DIR="$TOKDIR" \
    bash "$MCP_HOOK" <<< "$json" 2>/dev/null
}

run_bash() {
  local json="$1"
  PATH="$FAKEBIN:$PATH" \
    MCP_GATE_POLICY="$POLICY" \
    bash "$BASH_HOOK" <<< "$json" 2>/dev/null
}

run_mcp_no_jq() {
  local json="$1"
  CPEG_DENY_TESTING=1 \
    CPEG_DENY_JQ_CANDIDATES="$TMPDIR/not-here" \
    MCP_GATE_POLICY="$POLICY" \
    CLAUDE_TOKEN_DIR="$TOKDIR" \
    bash "$MCP_HOOK" <<< "$json" 2>/dev/null
}

run_bash_no_jq() {
  local json="$1"
  CPEG_DENY_TESTING=1 \
    CPEG_DENY_JQ_CANDIDATES="$TMPDIR/not-here" \
    MCP_GATE_POLICY="$POLICY" \
    bash "$BASH_HOOK" <<< "$json" 2>/dev/null
}

MCP_DENY='{"tool_name":"mcp__claude_ai_X__browser_navigate","tool_input":{"url":"https://evil.tld/x"}}'
BASH_DENY='{"tool_name":"Bash","tool_input":{"command":"curl https://evil.tld/x"}}'

assert_deny "mcp hook ignores PATH-poisoned jq" "$(run_mcp "$MCP_DENY")"
assert_deny "bash hook ignores PATH-poisoned jq" "$(run_bash "$BASH_DENY")"
assert_deny "mcp hook denies when jq unavailable" "$(run_mcp_no_jq "$MCP_DENY")" "jq is unavailable"
assert_deny "bash hook denies when jq unavailable" "$(run_bash_no_jq "$BASH_DENY")" "jq is unavailable"

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
