#!/bin/bash
# Regression coverage for claude-code/hooks/protect-sensitive-reads.sh.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="${HOOK:-$ROOT/claude-code/hooks/protect-sensitive-reads.sh}"

dot='.'
env_name="${dot}env"
rsa_name="id""_rsa_test"
npm_name="${dot}npmrc"

ssh_dir="${dot}ssh"
cred_name="cred""entials"
rsa_base="id""_rsa"

pass=0
fail=0

# Quote a command string as a JSON value. Reads the command from STDIN, not argv,
# on purpose: a single argv element larger than Linux's MAX_ARG_STRLEN (128 KiB)
# makes execve fail with E2BIG, which would silently break the oversized-input
# case on Linux CI (json_quote returns empty, the command collapses, the hook
# allows) while passing on macOS, which has no per-argument limit. Piping keeps
# the big string off argv.
json_quote() {
  /usr/bin/python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

run_case() {
  local name="$1" expect="$2" command="$3" out got
  out=$(printf '{"tool_name":"Bash","tool_input":{"command":%s},"cwd":"/tmp/project"}\n' \
    "$(printf '%s' "$command" | json_quote)" \
    | bash "$HOOK" 2>/dev/null)

  if printf '%s' "$out" | grep -q '"permissionDecision":[[:space:]]*"deny"'; then
    got=deny
  else
    got=allow
  fi

  if [ "$got" = "$expect" ]; then
    printf 'ok   %-52s [%s]\n' "$name" "$got"
    pass=$((pass+1))
  else
    printf 'FAIL %-52s expected=%s got=%s\n' "$name" "$expect" "$got"
    [ -n "$out" ] && printf '       output: %s\n' "$out"
    fail=$((fail+1))
  fi
}

run_case "cat project dotenv denies" deny "cat $env_name"
run_case "cat project dotenv suffix denies" deny "cat $env_name.local"
run_case "xxd project key denies" deny 'xxd secrets/prod.key'
run_case "python open project dotenv denies" deny "python3 -c \"open(\\\"$env_name\\\").read()\""
run_case "redirection read project dotenv denies" deny "base64 < $env_name"
run_case "cd then read project package token denies" deny "cd app && cat $npm_name"
run_case "node read rsa-like project file denies" deny "node -e \"require(\\\"fs\\\").readFileSync(\\\"$rsa_name\\\")\""
run_case "dotenv example is allowed" allow "cat $env_name.example"
run_case "dotenv sample is allowed" allow "cat $env_name.sample"
run_case "echo secret filename is allowed" allow "echo $env_name"
run_case "ordinary read is allowed" allow 'cat README.md'

run_case "home credential direct read denies" deny "cat \$HOME/$ssh_dir/$rsa_base"
run_case "home credential dot segment denies" deny "cat \$HOME/tmp/../$ssh_dir/$rsa_base"
run_case "copy home credential denies" deny "cp \$HOME/$ssh_dir/$rsa_base /tmp/key-copy"
run_case "symlink home credential dir denies" deny "ln -s \$HOME/$ssh_dir /tmp/key-link"
run_case "project secret copy denies" deny "cp $env_name /tmp/project-env-copy"
run_case "command substitution project secret denies" deny "printf %s \$(< $env_name)"
# shellcheck disable=SC2016
run_case "printf obfuscation denies" deny 'cat $(printf "\\x2eenv")'
run_case "glob home credential dir denies" deny "cat \$HOME/${dot}s*h/config"
run_case "bracket home credential dir denies" deny "cat \$HOME/${dot}a[w]s/$cred_name"
run_case "runtime variable home path denies" deny "D=$ssh_dir; cat \$HOME/\$D/$rsa_base"
run_case "find credential basename denies" deny "find \$HOME -name $rsa_base -print | xargs cat"

long_cmd=$(printf 'x%.0s' {1..131073})
run_case "oversized command input denies" deny "$long_cmd"

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
