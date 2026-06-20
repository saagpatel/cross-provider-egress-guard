#!/bin/bash
# Canonical PreToolUse deny emitter and jq resolver for egress guard hooks.
# Source this before the hook's first jq use.

_CPEG_JQ=""

_cpeg_resolve_jq() {
  local candidate candidates

  if [ "${CPEG_DENY_TESTING:-}" = "1" ] && [ -n "${CPEG_DENY_JQ_CANDIDATES+x}" ]; then
    candidates="$CPEG_DENY_JQ_CANDIDATES"
  else
    candidates="/opt/homebrew/bin/jq:/usr/local/bin/jq:/usr/bin/jq:/bin/jq:/opt/local/bin/jq:/nix/var/nix/profiles/default/bin/jq"
  fi

  IFS=':' read -r -a _cpeg_jq_candidates <<< "$candidates"
  for candidate in "${_cpeg_jq_candidates[@]}"; do
    [ -n "$candidate" ] || continue
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if [ "${CPEG_DENY_TESTING:-}" != "1" ]; then
    candidate=$(command -v jq 2>/dev/null || true)
    if [ -n "$candidate" ] && [[ "$candidate" == /* ]] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  return 1
}

_CPEG_JQ="$(_cpeg_resolve_jq || true)"
CPEG_JQ="$_CPEG_JQ"

deny() {
  local reason="$1" escaped_reason

  if [ -n "$CPEG_JQ" ] && [ -x "$CPEG_JQ" ]; then
    # shellcheck disable=SC2016 # jq program; $reason is passed via --arg.
    "$CPEG_JQ" -n --arg reason "$reason" '{
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: $reason
      }
    }'
  else
    escaped_reason=$(printf '%s' "$reason" \
      | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' 2>/dev/null \
      || printf '%s' "$reason")
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' \
      "$escaped_reason"
  fi

  exit 0
}

require_jq_or_deny() {
  local reason="${1:-Blocked: jq is unavailable; refusing to evaluate hook input fail-closed.}"
  if [ -z "$CPEG_JQ" ] || [ ! -x "$CPEG_JQ" ]; then
    deny "$reason"
  fi
}
