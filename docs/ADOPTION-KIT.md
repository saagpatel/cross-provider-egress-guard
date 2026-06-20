# Cross-Provider Egress Guard Adoption Kit

This kit is for an operator who wants local AI coding agents to keep useful tool
access without giving every shell command or MCP connector an unbounded egress
path.

The guard is a control layer. It decides whether a proposed network or send-class
action is allowed before the action runs. It is not an agent benchmark, a
sandbox, or a vendor certification.

## What It Protects

The primary threat is read-to-egress: an agent reads local state, credentials, or
private project data, then sends it to a destination the operator did not intend.

The guard narrows that path with three checks:

- URL-host egress: commands or tools with explicit URLs are allowed only when
  every extracted host is on the policy allow-list.
- Connector egress: fixed-backend MCP connectors are allowed only by full tool
  name glob, then scoped where the policy knows how to extract an owner.
- Generic network catch-all: new send, upload, fetch, http, or webhook-like MCP
  tools fail closed unless they come from a known local non-egress server.

The sensitive-read floor denies common credential and project-secret paths before
the egress step, so the highest-value local files are not casually available to
send.

## Why This Is Cross-Provider

Claude Code and Codex can share the same filesystem, local databases, shell, and
operator workflow. Hardening one provider while leaving the other permissive
creates a soft path through the weaker harness.

This repo's control claim is parity: Claude Code hooks and Codex hook logic read
the same `mcp-gate-policy.json` egress block and fail closed on malformed or
missing policy. `tests/parity-check.sh` verifies that the two enforcement
surfaces consume the same policy keys instead of embedding divergent allow-lists
in code.

## Install Path

This is a hook-and-policy adoption path, not a package install.

1. Read `docs/THREAT-MODEL.md`, `docs/DESIGN.md`, and `LIMITATIONS.md`.
2. Copy `policy/mcp-gate-policy.example.json` to your live policy location and
   replace sample owners, hosts, and connector scopes with your own values.
3. Deploy the Claude Code hooks from `claude-code/hooks/`.
4. Apply the Codex hook patch from `codex/codex-egress.patch`.
5. Run the local checks below before treating the guard as active.

Do not put tokens, API keys, or provider secrets in the policy. The policy should
contain hostnames, tool-name globs, owner scopes, and thresholds only.

## Default-Deny Examples

These are decision examples. Deny cases should be blocked before execution.

| Example | Expected | Why |
| --- | --- | --- |
| `curl https://blocked.example/x` | deny | host is not allow-listed |
| `curl https://github.com@blocked.example/x` | deny | normalized true host is `blocked.example` |
| `mcp__codex_apps__unlisted_demo__create_page` | deny | unknown or non-allow-listed connector |
| GitHub connector with owner `notmine` | deny | owner scope blocks the destination |
| `curl https://github.com/cli/cli` | allow | host is allow-listed |
| `curl http://localhost:9999/health` | allow | loopback is local, not egress |

If a connector such as Notion is intentionally present in your live
`allow_connectors`, test it as an allowed connector, not as the "unknown
connector" deny case.

## Local Verification

No-secret, no-network checks:

```bash
bash tests/run-all.sh
bash tests/parity-check.sh
bash tests/run-sensitive-read-tests.sh
```

For a compact demo without installing hooks:

```bash
bash demo/demo.sh
```

## Demo Asset References

- `demo/demo.sh`: offline demo used by the README GIF.
- `tests/run-all.sh`: deterministic regression suite against in-repo hooks.
- `tests/parity-check.sh`: cross-provider policy parity check.
- `docs/INSTALL.md`: deployment instructions.
- `docs/THREAT-MODEL.md`: threat model and control model.
- `docs/DESIGN.md`: implementation design.
- `LIMITATIONS.md`: residuals and non-goals.

## How To Know It Worked

You have a useful receipt when all of these are true:

- The shared policy parses and has `egress.default == "deny"`.
- `tests/parity-check.sh` passes, proving both provider surfaces use the shared
  policy keys.
- The local regression suite passes.
- A local spot check blocks at least one non-allow-listed egress attempt before
  it runs and allows at least one benign local or allow-listed read path.

Record the receipt as the command names, date, policy location, and the final
pass/fail summary. Do not paste secrets, raw private file contents, or provider
tokens into the receipt.

## Provider Parity Caveats

Parity is only as strong as the currently adopted hook versions and policy keys.
Some controls are opt-in or policy-sensitive, including GitHub shell owner/host
scoping and connector owner scoping.

The guard is also deliberately input-side:

- It cannot prove that data sent to an allow-listed destination is harmless.
- It does not solve prompt injection in tool output.
- It uses best-effort shell parsing for some transport forms.
- It cannot certify a hosted MCP server or connector implementation by itself.

Treat it as a local enforcement layer that complements MCP security audits,
server hardening, network-layer controls, and agent calibration benchmarks.

