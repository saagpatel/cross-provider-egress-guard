#!/bin/bash
# R6 (connector owner-scope) + R7 (no attacker-provisionable wildcard hosts) harness
# for mcp-guard.sh, run against the post-change fixture policy. R7 is policy-only
# (hook logic unchanged → passes as soon as the fixture drops the wildcards); R6
# needs the connector_owner_scope enforcement in mcp-guard.sh.
#
# Usage:  HOOK=claude-code/hooks/mcp-guard.sh bash tests/run-r6r7-tests.sh
set -uo pipefail

HOOK="${HOOK:-$HOME/.claude/hooks/mcp-guard.sh}"
HERE="$(cd "$(dirname "$0")" && pwd)"
export MCP_GATE_POLICY="${MCP_GATE_POLICY:-$HERE/fixtures/policy-r6r7.json}"
TOKDIR=$(mktemp -d); export CLAUDE_TOKEN_DIR="$TOKDIR"; trap 'rm -rf "$TOKDIR"' EXIT

pass=0; fail=0
run_case() {
  local name="$1" expect="$2" json="$3" out got
  out=$(printf '%s' "$json" | bash "$HOOK" 2>/dev/null)
  if printf '%s' "$out" | grep -q '"permissionDecision":[[:space:]]*"deny"'; then got=deny; else got=allow; fi
  if [ "$got" = "$expect" ]; then printf 'ok   %-44s [%s]\n' "$name" "$got"; pass=$((pass+1))
  else printf 'FAIL %-44s expected=%s got=%s\n' "$name" "$expect" "$got"; fail=$((fail+1))
    [ -n "$out" ] && printf '       reason: %s\n' "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason' 2>/dev/null)"
  fi
}

NAV='mcp__claude_ai_X__browser_navigate'
# ── R7: attacker-provisionable wildcards removed ─────────────────────────────
run_case "R7 deny evil.vercel.app"           deny  "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://evil.vercel.app/x\"}}"
run_case "R7 deny evil.atlassian.net"        deny  "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://evil.atlassian.net/x\"}}"
run_case "R7 deny made-up githubusercontent" deny  "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://evil.githubusercontent.com/x\"}}"
run_case "R7 deny made-up box subdomain"     deny  "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://evil.box.com/x\"}}"
# ── R7: legitimate narrowed subdomains still allowed ─────────────────────────
run_case "R7 allow raw.githubusercontent"    allow "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://raw.githubusercontent.com/a/b.txt\"}}"
run_case "R7 allow objects.githubusercontent" allow "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://objects.githubusercontent.com/x\"}}"
run_case "R7 allow api.box.com"              allow "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://api.box.com/2.0/files\"}}"
run_case "R7 allow api.vercel.com"           allow "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://api.vercel.com/v6\"}}"
run_case "R7 allow exact github.com"         allow "{\"tool_name\":\"$NAV\",\"tool_input\":{\"url\":\"https://github.com/cli/cli\"}}"

# ── R6: connector owner-scope (github → example-owner only) ──────────────────────
GH='mcp__codex_apps__github__list_pull_requests'
run_case "R6 deny github owner=evil (field)" deny  "{\"tool_name\":\"$GH\",\"tool_input\":{\"owner\":\"evil\",\"repo\":\"x\"}}"
run_case "R6 deny github owner=evil (url)"    deny  "{\"tool_name\":\"$GH\",\"tool_input\":{\"url\":\"https://github.com/evil/x/pull/1\"}}"
run_case "R6 deny github owner obj.login"     deny  "{\"tool_name\":\"$GH\",\"tool_input\":{\"owner\":{\"login\":\"evil\"}}}"
run_case "R6 deny github full_name evil/x"    deny  "{\"tool_name\":\"$GH\",\"tool_input\":{\"full_name\":\"evil/x\"}}"
run_case "R6 deny github repository_full_name" deny  "{\"tool_name\":\"$GH\",\"tool_input\":{\"repository_full_name\":\"notmine/cross-provider-egress-guard\"}}"
run_case "R6 allow github owner=example-owner"    allow "{\"tool_name\":\"$GH\",\"tool_input\":{\"owner\":\"example-owner\",\"repo\":\"x\"}}"
run_case "R6 allow github url example-owner"      allow "{\"tool_name\":\"$GH\",\"tool_input\":{\"url\":\"https://github.com/example-owner/x\"}}"
run_case "R6 allow github repo_full_name mine" allow "{\"tool_name\":\"$GH\",\"tool_input\":{\"repository_full_name\":\"example-owner/x\"}}"
run_case "R6 allow github no owner (gap)"     allow "{\"tool_name\":\"$GH\",\"tool_input\":{\"state\":\"open\"}}"
# mixed owners — ANY disallowed owner in the payload denies (example-owner + evil via URL)
run_case "R6 deny mixed owners (one evil)"    deny  "{\"tool_name\":\"$GH\",\"tool_input\":{\"owner\":\"example-owner\",\"url\":\"https://github.com/evil/y\"}}"
run_case "R6 allow owner case-insensitive"    allow "{\"tool_name\":\"$GH\",\"tool_input\":{\"owner\":\"EXAMPLE-OWNER\"}}"
# scope applies ONLY to github connectors — a non-github connector is unaffected
run_case "R6 allow non-github connector"      allow '{"tool_name":"mcp__claude_ai_Vercel__list_projects","tool_input":{"owner":"evil"}}'

echo "---"; echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
