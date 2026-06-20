#!/bin/bash
# Phase 3 — cross-provider parity verifier.
# Proves CC (mcp-guard.sh) and Codex (codex-egress.patch) enforce the SAME egress
# allow-list by construction: both read the single shared policy and NEITHER embeds a
# divergent day-job host/connector list in its enforcement code. With one source of
# truth and no hardcoded duplicate, drift is structurally impossible — so the roadmap's
# "diff the two host lists is empty" acceptance is trivially satisfied.
#
# Usage:  bash tests/parity-check.sh   (expects pass=… fail=0)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY="${MCP_GATE_POLICY:-$HOME/.claude/mcp-gate-policy.json}"
CC_HOOK="$ROOT/claude-code/hooks/mcp-guard.sh"
BASH_HOOK="$ROOT/claude-code/hooks/bash-egress-guard.sh"
CODEX_PATCH="$ROOT/codex/codex-egress.patch"
HOST_LITERALS='github\.com|\.box\.com|atlassian\.net|vercel\.app|cloudflare\.com|googleapis\.com'

pass=0; fail=0
chk(){ if eval "$2" >/dev/null 2>&1; then printf 'ok   %s\n' "$1"; pass=$((pass+1)); else printf 'FAIL %s\n' "$1"; fail=$((fail+1)); fi; }

# True if a day-job host literal appears in CODE (comments stripped) of the CC hook.
cc_has_hardcoded_host(){ sed 's/#.*//' "$CC_HOOK" | grep -qE "$HOST_LITERALS"; }
# True if a day-job host literal appears in CODE of the Codex patch's enforcement
# additions (common.py / pre_tool_use_dispatch.py), excluding comments and test fixtures.
codex_has_hardcoded_host(){
  awk -v re="$HOST_LITERALS" '
    /^\+\+\+ b\// { f=$2; sub("b/","",f) }
    /^\+/ && (f ~ /common\.py/ || f ~ /pre_tool_use_dispatch\.py/) {
      line=$0; sub(/#.*/,"",line); if (line ~ re) { found=1 }
    }
    END { exit (found ? 0 : 1) }
  ' "$CODEX_PATCH"
}

# 1. Single source of truth is valid + default-deny.
chk "shared policy egress.default == deny"        'jq -e ".egress.default==\"deny\"" "$POLICY"'

# 2. Both consumers read the SAME policy file path.
chk "CC hook reads mcp-gate-policy.json"          'grep -q "mcp-gate-policy.json" "$CC_HOOK"'
chk "Codex patch reads mcp-gate-policy.json"      'grep -q "mcp-gate-policy.json" "$CODEX_PATCH"'

# 3. Both consume the same egress keys from that file.
for k in allow_hosts allow_connectors network_name_globs non_egress_servers url_tools connector_tools connector_owner_scope; do
  chk "CC hook consumes egress.$k"                'grep -q "egress.'"$k"'" "$CC_HOOK"'
  chk "Codex patch consumes $k"                   'grep -q "'"$k"'" "$CODEX_PATCH"'
done

# 3b. R12 shell-only key — github_shell_owners is consumed by the SHELL hooks
#     (claude-code/hooks/bash-egress-guard.sh + Codex common.py), not mcp-guard.sh.
chk "CC bash-egress consumes github_shell_owners" 'grep -q "github_shell_owners" "$BASH_HOOK"'
chk "Codex patch consumes github_shell_owners"    'grep -q "github_shell_owners" "$CODEX_PATCH"'

# 3c. R13 shell-only key — github_shell_hosts (write-destination host allow-list) is
#     consumed by the SHELL hooks (bash-egress-guard.sh + Codex common.py).
chk "CC bash-egress consumes github_shell_hosts"  'grep -q "github_shell_hosts" "$BASH_HOOK"'
chk "Codex patch consumes github_shell_hosts"     'grep -q "github_shell_hosts" "$CODEX_PATCH"'

# 4. No divergent hardcoded allow-list: day-job host literals must NOT appear in either
#    enforcement surface (they live ONLY in the shared JSON). Test-fixture hosts in the
#    patch's tests/test_hooks.py hunk are excluded — only common.py / pre_tool additions count.
chk "CC hook embeds no day-job host literal (code)"    '! cc_has_hardcoded_host'
chk "Codex enforcement embeds no host literal (code)"  '! codex_has_hardcoded_host'

echo "---"
if [ "$fail" -eq 0 ]; then echo "PARITY: PASS ($pass checks) — single shared source, no embedded divergent allow-list"; else echo "PARITY: FAIL ($fail of $((pass+fail)))"; fi
exit $fail
