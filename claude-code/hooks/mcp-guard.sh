#!/bin/bash
# PreToolUse hook — matcher "mcp__.*" — the first BLOCK-capable gate for MCP
# tool calls. Closes red-team 2026-06-07 CRITICAL: MCP calls bypass the entire
# Bash guard stack; the only prior mcp hooks are PostToolUse loggers.
#
# Layers (in order):
#   1.  policy.deny      → hard block (operator opt-in)
#   2.  content sentinel → block payloads that reference a credential path, carry
#       a known secret token, or contain a curl/wget @file exfil shape.
#   2a. control-plane sentinel → block payloads that reference hook, agent,
#       settings, policy, token, or skill-definition paths under the harness
#       control surface.
#   2.5 egress control   → destination-aware gate for network/send-class tools
#       (Cross-Provider Egress Guard). Additive: only tools matching a network
#       mode are gated; everything else falls through unchanged. Fail-closed.
#   3.  policy.require_token → demand a fresh (<60s) claude-confirm token; consume
#       it single-use (atomic mv). Scoped token filenames (<hex>.<toolclass>) are
#       preferred; bare <hex> tokens remain a legacy fallback.
#   default → allow (PostToolUse loggers still record it).
#
# Env overrides (for tests; production uses the defaults):
#   MCP_GATE_POLICY   default ~/.claude/mcp-gate-policy.json
#   CLAUDE_TOKEN_DIR  default ~/.claude/.tokens
#
# Register in settings.json hooks.PreToolUse:
#   { "matcher": "mcp__.*",
#     "hooks": [{ "type": "command", "command": "bash ~/.claude/hooks/mcp-guard.sh", "timeout": 5 }] }
set -uo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=claude-code/hooks/lib/deny.sh
. "$HOOK_DIR/lib/deny.sh"
require_jq_or_deny "Blocked (mcp-guard): jq is unavailable; refusing to evaluate MCP hook input fail-closed."

POLICY="${MCP_GATE_POLICY:-$HOME/.claude/mcp-gate-policy.json}"
TOKEN_DIR="${CLAUDE_TOKEN_DIR:-$HOME/.claude/.tokens}"

# Secret patterns (best-effort source; fall back to a minimal set).
if ! source "$HOME/.claude/hooks/lib/secret-patterns.sh" 2>/dev/null; then
  SECRET_MEGA_REGEX='AKIA[0-9A-Z]{16}|sk-ant-api[0-9]+-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|xox[bpsar]-[A-Za-z0-9-]+'
fi

INPUT=$(cat)
TOOL=$(printf '%s' "$INPUT" | "$CPEG_JQ" -r '.tool_name // empty')
[ -z "$TOOL" ] && exit 0
case "$TOOL" in mcp__*) ;; *) exit 0 ;; esac
INPUT_BLOB=$(printf '%s' "$INPUT" | "$CPEG_JQ" -rc '.tool_input // {}')

# Glob-match $1 against a newline-separated list of patterns ($2).
match_any() {
  local tool="$1" list="$2" p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    # Policy arrays may include readability pseudo-entries.
    case "$p" in _comment*) continue ;; esac
    # shellcheck disable=SC2254
    case "$tool" in $p) return 0 ;; esac
  done <<< "$list"
  return 1
}

# R6 — emit candidate resource owners from a connector payload ($INPUT_BLOB),
# lowercased + deduped. Reads owner/org/organization/repoOwner (string or
# {login}), the owner part of "owner/repo" in repository / full_name /
# repository_full_name (the field the live GitHub connector actually sends —
# ground-truthed against the live connector schema), and any github.com/<owner> URL.
# Each "owner/repo" field is evaluated independently (no // short-circuit), so a
# field that arrives as an object can't shadow a sibling that carries the string.
# A call with no detectable owner emits nothing → passes (the remaining R6
# surface, same class as R3, documented in LIMITATIONS.md).
owners_in_payload() {
  {
    "$CPEG_JQ" -r '
      [ (.owner | if type=="object" then .login else . end),
        .org, .organization, .repoOwner, .repo_owner,
        ((.repository           // "") | if type=="string" and test("/") then split("/")[0] else empty end),
        ((.full_name            // "") | if type=="string" and test("/") then split("/")[0] else empty end),
        ((.repository_full_name // "") | if type=="string" and test("/") then split("/")[0] else empty end)
      ] | map(select(type=="string" and . != "")) | .[]' <<< "$INPUT_BLOB" 2>/dev/null
    printf '%s' "$INPUT_BLOB" | grep -oiE 'github\.com[/:]+[A-Za-z0-9_.-]+' | sed -E 's#.*[/:]##'
  } | tr '[:upper:]' '[:lower:]' | sed '/^$/d' | sort -u
}

# R6 — if $TOOL matches a connector_owner_scope glob, every owner positively
# identified in the payload must be on that glob's allow-list (else deny).
enforce_owner_scope() {
  local g allowed owner
  while IFS= read -r g; do
    [ -z "$g" ] && continue
    # shellcheck disable=SC2254
    case "$TOOL" in $g) ;; *) continue ;; esac
    allowed=$(printf '%s' "$OWNER_SCOPE" | "$CPEG_JQ" -r --arg k "$g" '.[$k][]? // empty' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    while IFS= read -r owner; do
      [ -z "$owner" ] && continue
      if ! printf '%s\n' "$allowed" | grep -qxF "$owner"; then
        deny "Blocked (mcp-guard egress R6): connector $TOOL targets owner '$owner', not on the connector_owner_scope allow-list for '$g'. Scope it to an allowed owner or widen the policy."
      fi
    done <<< "$(owners_in_payload)"
  done <<< "$(printf '%s' "$OWNER_SCOPE" | "$CPEG_JQ" -r 'keys[]?' 2>/dev/null)"
}

DENY_LIST=""; TOKEN_LIST=""
POLICY_OK=false
if [ -f "$POLICY" ] && "$CPEG_JQ" empty "$POLICY" 2>/dev/null; then
  POLICY_OK=true
  DENY_LIST=$("$CPEG_JQ" -r '.deny[]? // empty' "$POLICY" 2>/dev/null)
  TOKEN_LIST=$("$CPEG_JQ" -r '.require_token[]? // empty' "$POLICY" 2>/dev/null)
else
  # Fail closed if the policy cannot be read. Keep token-gated classes and
  # network-name MCP tools denied until the shared policy is restored.
  echo "mcp-guard: policy $POLICY missing/invalid — FAILING CLOSED on built-in token + egress defaults" >&2
  TOKEN_LIST='mcp__*Supabase*__execute_sql
mcp__*Supabase*__apply_migration
mcp__*__browser_run_code_unsafe
mcp__*github*__*merge*
mcp__*github*__*push*
mcp__asc-mcp__*submit*
mcp__asc-mcp__*release*
mcp__*Vercel*__*deploy*
mcp__*loudflare*__*
mcp__*ctx_execute*
mcp__*ctx_execute_file*
mcp__serena__replace_symbol_body
mcp__serena__rename_symbol
mcp__serena__safe_delete_symbol
mcp__engraph__delete
mcp__engraph__rewrite
mcp__engraph__move_note'
fi

# ── Layer 1: policy deny ────────────────────────────────────────────────────
if [ -n "$DENY_LIST" ] && match_any "$TOOL" "$DENY_LIST"; then
  deny "Blocked (mcp-guard): $TOOL is on the policy deny list."
fi

# ── Layer 2: always-on content sentinel for ALL MCP tools ───────────────────
# These scans run before egress/token gates so novel or renamed MCP tools cannot
# move local credentials through a payload just because their tool name is new.
HOME_ESC="${HOME//\//\\/}"
SENSITIVE='(\$HOME|~|'"$HOME_ESC"')/(\.ssh|\.aws|\.gnupg|\.config/op|\.config/gcloud|\.docker/config\.json|\.kube/config|\.netrc|\.pypirc|\.git-credentials|\.anthropic|\.claude/\.tokens)'
  if printf '%s' "$INPUT_BLOB" | grep -qE "$SENSITIVE"; then
    deny "Blocked (mcp-guard): $TOOL payload references a protected credential path. MCP code-exec may not touch ~/.ssh, ~/.aws, etc."
  fi
  if printf '%s' "$INPUT_BLOB" | grep -qE '(curl|wget)[^"]*([[:space:]=]@[~/.]|-T[[:space:]]+[~/.])'; then
    deny "Blocked (mcp-guard): $TOOL payload contains a curl/wget local-file upload (exfil signature)."
  fi
# Any MCP tool shipping a recognizable secret token outward.
if printf '%s' "$INPUT_BLOB" | grep -qE "$SECRET_MEGA_REGEX"; then
  deny "Blocked (mcp-guard): $TOOL input contains a string matching a known secret/token pattern. Refusing to pass a credential to an MCP tool."
fi

# ── Layer 2a: control-plane sentinel ────────────────────────────────────────
# Literal references to hook, agent, settings, policy, token, or skill-definition
# paths under the harness control surface are denied for every MCP tool.
DOT_RE='\.'
CONTROL_HOME="${DOT_RE}claude"
HOOKS_SEG='hooks'
POLICY_BASE='mcp-gate-policy'
CONTROL_PLANE_RE="(${CONTROL_HOME}/${HOOKS_SEG}|${CONTROL_HOME}/agents|${CONTROL_HOME}/settings(${DOT_RE}local)?${DOT_RE}json|${CONTROL_HOME}/${POLICY_BASE}${DOT_RE}json|${CONTROL_HOME}${DOT_RE}json|${CONTROL_HOME}/${DOT_RE}tokens|${CONTROL_HOME}/skills/[^/\"]*/SKILL${DOT_RE}md)"
if printf '%s' "$INPUT_BLOB" | grep -qE "$CONTROL_PLANE_RE"; then
  deny "Blocked (mcp-guard control-plane): $TOOL payload references a protected harness path. MCP tools may not target hooks, agents, settings, policy, tokens, or skill definitions."
fi

# ── Layer 2.5: destination-aware egress control ─────────────────────────────
# Additive + fail-closed. Egress params come from policy when valid, otherwise
# from built-in fail-closed defaults.
# Classification order (first match wins):
#   Mode 1  url_tools          → host(s) extracted from payload must all be allow-listed
#   (skip)  non_egress_servers → localhost/fs-local servers bypass the gate
#   Mode 2  connector_tools    → allow iff full tool name matches an allow_connectors glob
#   Mode 3  network_name_globs → generic network/send name → fail-closed deny
#   Mode 4  unknown + URL      → unknown non-local tool carrying a URL → deny
if $POLICY_OK; then
  EGRESS_DEFAULT=$("$CPEG_JQ" -r '.egress.default // empty' "$POLICY" 2>/dev/null)
  URL_TOOLS=$("$CPEG_JQ" -r '.egress.url_tools[]? // empty' "$POLICY" 2>/dev/null)
  ALLOW_HOSTS=$("$CPEG_JQ" -r '.egress.allow_hosts[]? // empty' "$POLICY" 2>/dev/null)
  CONNECTOR_TOOLS=$("$CPEG_JQ" -r '.egress.connector_tools[]? // empty' "$POLICY" 2>/dev/null)
  ALLOW_CONNECTORS=$("$CPEG_JQ" -r '.egress.allow_connectors[]? // empty' "$POLICY" 2>/dev/null)
  NET_GLOBS=$("$CPEG_JQ" -r '.egress.network_name_globs[]? // empty' "$POLICY" 2>/dev/null)
  OWNER_SCOPE=$("$CPEG_JQ" -rc '.egress.connector_owner_scope // {}' "$POLICY" 2>/dev/null)
  MAXBYTES=$("$CPEG_JQ" -r '.egress.max_payload_bytes_to_novel_host // 512' "$POLICY" 2>/dev/null)
  NON_EGRESS=$("$CPEG_JQ" -r '.egress.non_egress_servers[]? // empty' "$POLICY" 2>/dev/null)
else
  EGRESS_DEFAULT=deny
  URL_TOOLS=''
  ALLOW_HOSTS=''
  CONNECTOR_TOOLS=''
  ALLOW_CONNECTORS=''
  NET_GLOBS=$'mcp__*fetch*\nmcp__*http*\nmcp__*send*\nmcp__*upload*\nmcp__*webhook*'
  OWNER_SCOPE='{}'
  MAXBYTES=512
  NON_EGRESS=$'bridge-db\nserena\nengraph\ncost-tracker\nportfolio-health\npersonal_ops\nplugin_context-mode_context-mode'
fi

if [ "$EGRESS_DEFAULT" = "deny" ]; then
  # non_egress_servers match the EXACT server segment of mcp__<server>__<tool>,
  # not a prefix glob — so "bridge-db" can never shadow "bridge-db-hosted", and a
  # glob metacharacter in a policy entry is a harmless literal (string compare).
  # Treat hyphen/underscore as spelling aliases for server ids because MCP server
  # names appear in both forms across config and tool names (personal-ops vs
  # personal_ops). This preserves exact segment matching after normalization.
  SERVER="${TOOL#mcp__}"; SERVER="${SERVER%%__*}"
  SERVER_ALIAS="${SERVER//-/_}"
  is_non_egress=false
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    if [ "$SERVER" = "$s" ] || [ "$SERVER_ALIAS" = "${s//-/_}" ]; then is_non_egress=true; break; fi
  done <<< "$NON_EGRESS"

  if match_any "$TOOL" "$URL_TOOLS"; then
    # Mode 1 — extract every host from the payload; all must be allow-listed.
    # Match ANY scheme://authority (not just http/https) so a mixed payload with
    # ws://, ftp://, gopher:// etc. still surfaces its host.
    HOSTS=$(printf '%s' "$INPUT_BLOB" | grep -oiE '[a-z][a-z0-9+.-]*://[^/?#"'"'"' ]+' \
            | sed -E 's#^[a-z][a-z0-9+.-]*://##; s#^.*@##; s#:.*$##; s#\.$##' \
            | tr '[:upper:]' '[:lower:]' | sort -u)
    if [ -z "$HOSTS" ]; then
      deny "Blocked (mcp-guard egress): $TOOL is a URL-class tool but no destination host could be extracted from its input. Fail-closed."
    fi
    PAYLOAD_BYTES=${#INPUT_BLOB}
    while IFS= read -r h; do
      [ -z "$h" ] && continue
      host="${h%%:*}"   # strip :port
      if ! match_any "$host" "$ALLOW_HOSTS"; then
        if [ "$PAYLOAD_BYTES" -gt "$MAXBYTES" ]; then
          deny "Blocked (mcp-guard egress): $TOOL targets non-allowlisted host '$host' with an oversized payload (${PAYLOAD_BYTES}B > ${MAXBYTES}B). Fail-closed."
        fi
        deny "Blocked (mcp-guard egress): $TOOL targets non-allowlisted host '$host'. Add it to egress.allow_hosts or use an allowed destination."
      fi
    done <<< "$HOSTS"
    # all hosts allow-listed → fall through (allow)
  elif $is_non_egress; then
    : # local / non-egress server — no destination control
  elif match_any "$TOOL" "$CONNECTOR_TOOLS"; then
    # Mode 2 — fixed-backend connector; must be on the allow_connectors list.
    if ! match_any "$TOOL" "$ALLOW_CONNECTORS"; then
      deny "Blocked (mcp-guard egress): connector $TOOL is not on the egress allow_connectors list (unknown/renamed connector). Fail-closed."
    fi
    enforce_owner_scope   # R6 — connector resource (owner) scoping
  elif match_any "$TOOL" "$NET_GLOBS"; then
    # Mode 3 — generic network/send name from a non-local, non-connector server.
    deny "Blocked (mcp-guard egress): $TOOL matches a network/send-class name but its destination cannot be verified (Mode 3 fail-closed catch-all)."
  elif printf '%s' "$INPUT_BLOB" | grep -qiE '[a-z][a-z0-9+.-]*://[a-z0-9._-]+'; then
    # Mode 4 — unknown, non-local, non-connector tool carrying a URL.
    deny "Blocked (mcp-guard egress): $TOOL is an unrecognized non-local tool carrying a URL destination in its payload (Mode 4 fail-closed). If this is a legitimate local tool, add its server to egress.non_egress_servers; if a known connector, add it to connector_tools/allow_connectors."
  fi
fi

# ── Layer 3: require a fresh confirm token for high-risk tools ───────────────
tool_class() {
  local t="$1"
  case "$t" in
    *ctx_execute_file*) echo "ctx_execute" ;;
    *ctx_execute*) echo "ctx_execute" ;;
    *replace_symbol_body*|*rename_symbol*|*safe_delete_symbol*) echo "serena_write" ;;
    *engraph__delete*|*engraph__rewrite*|*engraph__move_note*) echo "engraph_write" ;;
    *Supabase*execute_sql*|*Supabase*apply_migration*|*Supabase**delete*|*Supabase**drop*) echo "supabase_write" ;;
    *github**merge*|*github**push*|*github**delete*) echo "github_write" ;;
    *Vercel**deploy*) echo "vercel_deploy" ;;
    *loudflare*) echo "cloudflare_write" ;;
    *browser_run_code_unsafe*) echo "browser_exec" ;;
    *asc-mcp**submit*|*asc-mcp**release*) echo "asc_release" ;;
    *bridge-db__clear_handoff*|*bridge-db__mark_shipped_processed*) echo "bridge_write" ;;
    *) echo "generic" ;;
  esac
}

if [ -n "$TOKEN_LIST" ] && match_any "$TOOL" "$TOKEN_LIST"; then
  CLASS=$(tool_class "$TOOL")
  FRESH=""
  if [ -d "$TOKEN_DIR" ]; then
    FRESH=$(find "$TOKEN_DIR" -maxdepth 1 -type f \
              -name "[0-9a-f]*.$CLASS" ! -name '.consumed-*' -mmin -1 2>/dev/null \
            | head -1 || true)
    if [ -z "$FRESH" ]; then
      FRESH=$(find "$TOKEN_DIR" -maxdepth 1 -type f \
                -name '[0-9a-f]*' ! -name '[0-9a-f]*.*' ! -name '.consumed-*' -mmin -1 2>/dev/null \
              | head -1 || true)
    fi
  fi
  if [ -z "$FRESH" ]; then
    deny "Blocked (mcp-guard): $TOOL is high-risk (class: $CLASS) and requires operator confirmation. Operator: run \`claude-confirm\` or \`claude-confirm $CLASS\` within 60s, then retry."
  fi
  # Single-use atomic consume (TOCTOU-safe).
  mv "$FRESH" "$TOKEN_DIR/.consumed-$(basename "$FRESH")" 2>/dev/null \
    || deny "Blocked (mcp-guard): confirmation token was already consumed (concurrent use). Generate a new one with \`claude-confirm\`."
fi

exit 0
