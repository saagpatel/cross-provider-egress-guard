#!/bin/bash
# shellcheck disable=SC2016
# PreToolUse hook - matcher "Bash" - deny Bash reads/staging of sensitive files.
#
# Repo-owned R1 source-side mitigation for the read -> exfil chain. Conservative
# by design: protect credential-shaped paths and common obfuscations before data
# can be copied, archived, or read into a later send.
set -uo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=claude-code/hooks/lib/deny.sh
# shellcheck disable=SC1091
. "$HOOK_DIR/lib/deny.sh"
require_jq_or_deny "Blocked (protect-sensitive-reads): jq is unavailable; refusing to evaluate Bash hook input fail-closed."

INPUT=$(cat)
INPUT_LEN=${#INPUT}
if [ "$INPUT_LEN" -gt 131072 ]; then
  deny "Blocked (protect-sensitive-reads): command input exceeds maximum allowed size (128 KB)."
fi

TOOL=$(printf '%s' "$INPUT" | "$CPEG_JQ" -r '.tool_name // empty')
[ "$TOOL" = "Bash" ] || exit 0
CMD=$(printf '%s' "$INPUT" | "$CPEG_JQ" -r '.tool_input.command // empty')
[ -n "$CMD" ] || exit 0

READ_CMDS='(cat|bat|head|tail|less|more|view|file|hexdump|xxd|od|strings|nl|tac|column|dd|paste|tr|cut|rev|fold|expand|unexpand|base64|base32|split|csplit|fmt|pr|join|comm|sort|uniq|cmp|zcat|gzip|gunzip|bzcat|xzcat)'
LIST_CMDS='(ls|find|tree|stat|du|wc|md5|md5sum|shasum|sha1sum|sha256sum)'
TEXT_CMDS='(grep|egrep|fgrep|rg|ag|awk|sed|perl|python|python3|ruby|node|php|sh|bash|zsh|fish|jq)'
COPY_CMDS='(cp|install|rsync|tar|zip|cpio|pax|ditto|gpg|scp|openssl)'
CMD_POS='(^|[;&|]|&&|\|\|)[[:space:]]*'

POLICY="${CODEX_EGRESS_POLICY:-$HOME/.claude/mcp-gate-policy.json}"
HOME_SEGS=""
DIR_SEGS=""
PROJ_SEGS=""

_segments_to_ere() {
  sed -E 's/[.[\*^$()+?{}|]/\\&/g' | paste -sd'|' -
}

if [ -r "$POLICY" ]; then
  HOME_SEGS=$("$CPEG_JQ" -r '.sensitive_paths.home[]? // empty' "$POLICY" 2>/dev/null | _segments_to_ere)
  DIR_SEGS=$("$CPEG_JQ" -r '.sensitive_paths.home_dirs[]? // empty' "$POLICY" 2>/dev/null | _segments_to_ere)
  PROJ_SEGS=$("$CPEG_JQ" -r '.sensitive_paths.project_secret_basenames[]? // empty' "$POLICY" 2>/dev/null | _segments_to_ere)
fi

HOME_SEGS="${HOME_SEGS:-\.ssh|\.aws|\.gnupg|\.config/op|\.config/gcloud|\.docker/config\.json|\.kube|\.netrc|\.pypirc|\.npmrc|\.git-credentials|\.gem/credentials|\.anthropic|\.claude/\.tokens}"
DIR_SEGS="${DIR_SEGS:-\.ssh|\.aws|\.gnupg|\.config/op|\.config/gcloud|\.kube|\.claude/\.tokens}"
PROJ_SEGS="${PROJ_SEGS:-\.env|\.pem|\.key|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.npmrc|\.pypirc|\.netrc|\.git-credentials}"

HOME_ESC="${HOME//\//\/}"
SENSITIVE='(\$HOME|\${HOME}|~|'"$HOME_ESC"')/('"$HOME_SEGS"')'
SENSITIVE_DIR='(\$HOME|\${HOME}|~|'"$HOME_ESC"')/('"$DIR_SEGS"')'
PROJECT_SECRET='('"$PROJ_SEGS"')([^A-Za-z0-9]|$)'

strip_safe_templates() {
  sed -E 's/[^[:space:]]*\.[e][n][v]\.(example|sample|template)[^[:space:]]*//g'
}

canonicalize() {
  local s="$1" prev=""
  while [ "$s" != "$prev" ]; do
    prev="$s"
    s=$(printf '%s' "$s" | sed -E 's|/\./|/|g; s|/[^/]+/\.\./|/|g')
  done
  printf '%s' "$s"
}

inline_simple_vars() {
  local s="$1" line name value changed=1
  while [ "$changed" -eq 1 ]; do
    changed=0
    while IFS= read -r line; do
      case "$line" in
        [A-Za-z_]*=*)
          name="${line%%=*}"
          value="${line#*=}"
          name="${name%%[!A-Za-z0-9_]*}"
          value="${value%%[;&|]*}"
          value="${value#[\"\']}"
          value="${value%[\"\']}"
          if [ -n "$name" ] && [ -n "$value" ]; then
            case "$s" in
              *'$'"$name"*|*'${'"$name"'}'*)
                s="${s//\$$name/$value}"
                s="${s//\${$name}/$value}"
                changed=1
                ;;
            esac
          fi
          ;;
      esac
    done <<< "$s"
  done
  printf '%s' "$s"
}

debrace_simple() {
  local s="$1" prev=""
  while [ "$s" != "$prev" ]; do
    prev="$s"
    s=$(printf '%s' "$s" | sed -E 's/\{([^{},]+),([^{},]+)\}/\1 \2/g')
  done
  printf '%s' "$s"
}

CMD_CANON=$(canonicalize "$CMD")
CMD_INLINED=$(inline_simple_vars "$CMD")
CMD_SCAN=$(printf '%s\n%s\n%s\n%s' "$CMD" "$CMD_CANON" "$(canonicalize "$CMD_INLINED")" "$(debrace_simple "$CMD")")
PROJ_SCAN=$(printf '%s' "$CMD_SCAN" | strip_safe_templates)

check_scan() {
  local pattern="$1" body="$2"
  printf '%s' "$body" | grep -qE "$pattern"
}

if printf '%s' "$CMD" | grep -qE "\\\$'[^']*\\\\[xX0-9][^']*'" || \
   printf '%s' "$CMD" | grep -qE '\$\(printf[[:space:]]'; then
  deny "Blocked (protect-sensitive-reads): command uses escape-sequence obfuscation that can hide sensitive paths."
fi

if check_scan "${CMD_POS}${READ_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): read-like command targeting a protected credential path."
fi
if check_scan "${CMD_POS}${LIST_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): list-like command targeting a protected credential path."
fi
if check_scan "${CMD_POS}${TEXT_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): text-processing command targeting a protected credential path."
fi
if check_scan "${CMD_POS}${COPY_CMDS}[[:space:]][^|&;]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): copy/archive command targeting a protected credential path."
fi

if printf '%s' "$CMD_SCAN" | grep -qE "${CMD_POS}ln[[:space:]]+(-[[:alnum:]]+[[:space:]]+)*[^|&;]*${SENSITIVE_DIR}"; then
  deny "Blocked (protect-sensitive-reads): symlink creation targeting a protected credential directory."
fi

if check_scan "<[[:space:]]*[^|&;]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): input redirection from a protected credential path."
fi
if check_scan "\\\$\\([[:space:]]*<[[:space:]]*[^)]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): command substitution reads a protected credential path."
fi
if check_scan "<\\([^)]*${SENSITIVE}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): process substitution reads a protected credential path."
fi
if check_scan "${CMD_POS}cd[[:space:]]+[^|&;]*${SENSITIVE_DIR}" "$CMD_SCAN"; then
  deny "Blocked (protect-sensitive-reads): changing directory into a protected credential directory."
fi

if check_scan "${CMD_POS}${READ_CMDS}[[:space:]][^|&;]*${PROJECT_SECRET}" "$PROJ_SCAN"; then
  deny "Blocked (protect-sensitive-reads R1): read-like command targeting a project secret file."
fi
if check_scan "${CMD_POS}${TEXT_CMDS}[[:space:]][^|&;]*${PROJECT_SECRET}" "$PROJ_SCAN"; then
  deny "Blocked (protect-sensitive-reads R1): text-processing command targeting a project secret file."
fi
if check_scan "${CMD_POS}${COPY_CMDS}[[:space:]][^|&;]*${PROJECT_SECRET}" "$PROJ_SCAN"; then
  deny "Blocked (protect-sensitive-reads R1): copy/archive command targeting a project secret file."
fi
if check_scan "<[[:space:]]*[^|&;]*${PROJECT_SECRET}" "$PROJ_SCAN"; then
  deny "Blocked (protect-sensitive-reads R1): input redirection from a project secret file."
fi
if check_scan "\\\$\\([[:space:]]*<[[:space:]]*[^)]*${PROJECT_SECRET}" "$PROJ_SCAN"; then
  deny "Blocked (protect-sensitive-reads R1): command substitution reads a project secret file."
fi

sens_abs() {
  printf '%s' "$HOME_SEGS" | tr '|' '\n' | sed 's/\\//g' | while IFS= read -r seg; do
    [ -n "$seg" ] && printf '%s/%s\n' "$HOME" "$seg"
  done
}

# shellcheck disable=SC2088,SC2053
glob_token_hits_sensitive() {
  local tok norm candidate
  for tok in $CMD; do
    tok="${tok%[\"\']}"
    tok="${tok#[\"\']}"
    case "$tok" in
      *'['*|*'*'*|*'?'*) ;;
      *) continue ;;
    esac
    norm="$tok"
    case "$norm" in
      '~/'*) norm="$HOME/${norm#\~/}" ;;
      '$HOME/'*) norm="$HOME/${norm#\$HOME/}" ;;
      '${HOME}/'*) norm="$HOME/${norm#\${HOME}/}" ;;
    esac
    case "$norm" in
      "$HOME"/*) ;;
      *) continue ;;
    esac
    while IFS= read -r candidate; do
      [ -n "$candidate" ] || continue
      [[ "$candidate" == $norm ]] && return 0 # Intentional pattern match for glob-expanded sensitive path.
      [[ "$candidate" == ${norm%/*} ]] && return 0 # Intentional pattern match for glob-expanded sensitive dir.
    done < <(sens_abs)
  done
  return 1
}

VERB_RE="${CMD_POS}(${READ_CMDS}|${LIST_CMDS}|${TEXT_CMDS}|${COPY_CMDS}|cd)"
if printf '%s' "$CMD" | grep -qE "$VERB_RE" && glob_token_hits_sensitive; then
  deny "Blocked (protect-sensitive-reads): glob or bracket path resolves to a protected credential directory."
fi

if printf '%s' "$CMD" | grep -qE '\beval[[:space:]]+["'\''"]?\$'; then
  deny "Blocked (protect-sensitive-reads): eval of a shell variable can hide a credential read from static inspection."
fi

SENS_BASENAMES='id_rsa|id_ed25519|id_ecdsa|id_dsa|credentials\.db|credentials|\.git-credentials|\.netrc'
if printf '%s' "$CMD" | grep -qE "${CMD_POS}find\b" && \
   printf '%s' "$CMD" | grep -qiE -- "-i?name[[:space:]]+[\"'\`]?[^\"'[:space:]]*${SENS_BASENAMES}"; then
  deny "Blocked (protect-sensitive-reads): find -name targets a credential basename."
fi

exit 0
