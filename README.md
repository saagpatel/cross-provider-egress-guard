# cross-provider-egress-guard

**Destination-aware, default-deny egress control for AI coding agents, enforced at the
agent's own tool-dispatch boundary, across both Claude Code and Codex.**

[![CI](https://github.com/saagpatel/cross-provider-egress-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/cross-provider-egress-guard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/saagpatel/cross-provider-egress-guard)](https://github.com/saagpatel/cross-provider-egress-guard/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> A default-deny firewall for your coding agent's tool calls: a hijacked or prompt-injected
> classified egress calls are gated against your allow-list, and the **same policy covers
> both Claude Code and Codex**.

![The egress guard denying exfiltration attempts in a terminal: an attacker host, a userinfo-spoofed github.com@evil.tld, an unknown connector, and an arbitrary http_post tool are all denied; a legitimate github.com call is allowed; and the guard fails closed when the policy is missing](demo/egress-guard.gif)

*Six representative tool calls against the example policy. Reproduce it offline with `bash demo/demo.sh`.*

---

## The threat

An AI coding agent holds broad capability: it reads your files, calls tools, and reaches the
network through MCP connectors and the shell. A single hostile instruction (whether the
model goes off the rails or a **prompt-injection payload rides in tool output**) can turn
into one tool call that ships data to an attacker-controlled host. Most agent setups have
**no destination control** on that call: if the agent can name a URL, it can reach it.

This guard closes that: **classified network/send tool calls and supported shell network
commands are gated against an allow-list you control.** See [docs/DESIGN.md](docs/DESIGN.md) for coverage
and policy-failure differences.

## What it is

A small set of **PreToolUse hooks** (Claude Code) and an equivalent **hook patch** (Codex)
that classify every tool call and gate the network-shaped ones against one shared JSON
allow-list policy. It runs *inside the agent's own dispatch cycle* (no network
reconfiguration, no proxy to stand up, no per-app SDK changes) and enforces the **same
policy across both agents** from a single source of truth.

- **Default-deny** for classified network/send tools when `egress.default` is `"deny"`;
  separate content, token, and sensitive-read guards can also deny calls.
- **Per-destination** host allow-listing and **per-connector** scoping (including resource
  owner scoping, e.g. only your GitHub org).
- **Policy failure handling**: shell network verbs deny when the policy is unavailable.
  MCP fallback coverage differs by provider; see [docs/DESIGN.md](docs/DESIGN.md).
- **Cross-provider**: Claude Code (`mcp-guard.sh` + `bash-egress-guard.sh`) and Codex
  (`codex-egress.patch`) default to the *same* `mcp-gate-policy.json`; enforcement coverage
  differs in some cases (see [docs/DESIGN.md](docs/DESIGN.md)).

## Where it sits (honest positioning)

Agent egress can be controlled at two layers, and they are **complementary**:

- **Network-proxy layer**: a forward proxy / firewall / DLP outside the agent (e.g.
  [Pipelock](https://github.com/luckyPipewrench/pipelock), Promptfoo's MCP proxy, MCP
  gateways). Independent of the agent; strong, but needs network plumbing and lives outside
  the agent's semantics.
- **Agent hook layer**: *this project*. Gates each tool call **before dispatch**, with
  per-tool/per-connector/per-owner semantics, with no network reconfiguration.

Nothing published (as of mid-2026) does default-deny, per-destination egress control at the
**hook layer, cross-provider across Claude Code *and* Codex**, off one shared policy. That's
the gap this fills. For real defense in depth, run **both** layers; see
[LIMITATIONS.md](LIMITATIONS.md) on why an in-process hook is not a substitute for a network
choke point.

## How it works

With a valid default-deny policy, MCP tool calls use the following modes (checked in
order; local `non_egress_servers` bypass after URL-host matching):

1. **URL-host**: tools carrying an explicit URL (browser navigate, fetch). Allowed iff every
   extracted host ∈ `allow_hosts`. Deceptive hosts (userinfo-spoof, trailing-dot, punycode,
   IP-literal) are normalized to their true host first; no extractable host ⇒ deny.
   Codex also allows loopback hosts independently of `allow_hosts`.
2. **Connector-class**: fixed-backend connectors with no URL in the payload. Allowed iff the
   full tool name matches an `allow_connectors` glob; unknown/renamed connector ⇒ deny.
   Optional `connector_owner_scope` further restricts a connector to allow-listed resource
   owners.
3. **Generic-network catch-all**: any tool whose *name* signals network/send behavior but
   matches neither mode above ⇒ **fail-closed deny** unless its server is local
   (`non_egress_servers`).
4. **Unknown tool carrying a `scheme://host` payload** ⇒ fail-closed deny in the Claude
   MCP hook; the Codex patch has no equivalent catch-all.

The shell hook (`bash-egress-guard.sh`, and the Codex side) applies the same allow-list to
`curl`/`wget`/`ssh` and optionally owner/host-scopes `git push` / `gh` **writes**
when `github_shell_owners` / `github_shell_hosts` are present. Git/`gh` reads skip those
write gates, but explicit shell network verbs can still trigger the host gate. Full model:
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and
[docs/DESIGN.md](docs/DESIGN.md). Mapped to the
[OWASP Top 10 for LLM Applications (2025)](docs/OWASP-LLM-MAPPING.md).

## Quickstart

No install required — runs entirely offline against the in-repo hooks:

```bash
git clone https://github.com/saagpatel/cross-provider-egress-guard
cd cross-provider-egress-guard
CODEX_EGRESS_POLICY="$PWD/tests/fixtures/policy-r6r7.json" bash tests/run-all.sh
# runs the full deterministic suite against the in-repo hooks
```

You'll watch egress denies fire across every mode (navigation to a non-allow-listed host,
unknown connectors, deceptive GitHub hosts, oversized novel-host payloads) and legitimate
allow-listed calls pass. Requires `bash`, `jq`, `git`, and `/usr/bin/python3` (used by the
sensitive-read harness);
install missing prerequisites separately.
See [CONTRIBUTING.md](CONTRIBUTING.md#development-setup) for focused checks and the
additional bats mirrors run by CI.
This suite (200+ assertions against the Claude Code hooks, plus static checks of policy
key references in the hooks and Codex patch) is part of the CI gate. It does not execute
the Codex tests embedded in the patch.

## Install

Quick deploy (three steps):
1. Copy `policy/mcp-gate-policy.example.json` to `~/.claude/mcp-gate-policy.json` and set your `allow_hosts`, `allow_connectors`, and owner values.
2. Copy `claude-code/hooks/lib/deny.sh` to `~/.claude/hooks/lib/` and `claude-code/hooks/*.sh` to `~/.claude/hooks/` (CC); apply `codex/codex-egress.patch` to your Codex checkout.
3. Wire the hooks into `~/.claude/settings.json` per the `PreToolUse` entries in [docs/INSTALL.md](docs/INSTALL.md).

See [docs/INSTALL.md](docs/INSTALL.md) for the full runbook and [policy/mcp-gate-policy.example.json](policy/mcp-gate-policy.example.json) for the annotated starter policy.

## Adoption Kit

If you want the shortest receipt-producing path, start with [docs/ADOPTION-KIT.md](docs/ADOPTION-KIT.md). It summarizes the threat model, install path, default-deny examples, local verification commands, demo references, and provider-parity caveats. For the broader trust story across Egress Guard, OPERANT, MCPAudit, and mcpforge, see [docs/CONTROL-PLUS-CALIBRATION.md](docs/CONTROL-PLUS-CALIBRATION.md).

## What it does *not* do

It is **one layer, not a silver bullet.** It does not track output-side data flow, decode
encoded payloads, or detect injection carried in tool output, and an in-process hook shares
the agent's trust domain. Read [LIMITATIONS.md](LIMITATIONS.md) before relying on it, and
pair it with network-layer controls.

## Security

Found a bypass? Please report it privately; see [SECURITY.md](SECURITY.md). A bypass is a
vulnerability; don't open a public issue for one.

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). The short version: egress
logic is additive (never weaken an existing deny), both agents stay in parity off the shared
policy, and every behavior change ships with a test.

## License

[Apache-2.0](LICENSE).
