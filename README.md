# cross-provider-egress-guard

**Destination-aware, default-deny egress control for AI coding agents, enforced at the
agent's own tool-dispatch boundary, across both Claude Code and Codex.**

[![CI](https://github.com/saagpatel/cross-provider-egress-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/cross-provider-egress-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> A default-deny firewall for your coding agent's tool calls: a hijacked or prompt-injected
> agent can't ship your data to a host you didn't allow-list, and the **same policy covers
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

This guard closes that: **network/send-class tool calls and shell network commands are denied
by default unless their destination is on an allow-list you control.**

## What it is

A small set of **PreToolUse hooks** (Claude Code) and an equivalent **hook patch** (Codex)
that classify every tool call and gate the network-shaped ones against one shared JSON
allow-list policy. It runs *inside the agent's own dispatch cycle* (no network
reconfiguration, no proxy to stand up, no per-app SDK changes) and enforces the **same
policy across both agents** from a single source of truth.

- **Default-deny** for network/send-class tools; everything else is unaffected.
- **Per-destination** host allow-listing and **per-connector** scoping (including resource
  owner scoping, e.g. only your GitHub org).
- **Fail-closed**: a missing, unreadable, or invalid policy denies; it never falls open.
- **Cross-provider**: Claude Code (`mcp-guard.sh` + `bash-egress-guard.sh`) and Codex
  (`codex-egress.patch`) read the *same* `mcp-gate-policy.json`, so the two agents can't drift
  to different blast radii.

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

A tool call is classified into exactly one mode (checked in order):

1. **URL-host**: tools carrying an explicit URL (browser navigate, fetch). Allowed iff every
   extracted host ∈ `allow_hosts`. Deceptive hosts (userinfo-spoof, trailing-dot, punycode,
   IP-literal) are normalized to their true host first; no extractable host ⇒ deny.
2. **Connector-class**: fixed-backend connectors with no URL in the payload. Allowed iff the
   full tool name matches an `allow_connectors` glob; unknown/renamed connector ⇒ deny.
   Optional `connector_owner_scope` further restricts a connector to allow-listed resource
   owners.
3. **Generic-network catch-all**: any tool whose *name* signals network/send behavior but
   matches neither mode above ⇒ **fail-closed deny** unless its server is local
   (`non_egress_servers`).
4. **Unknown tool carrying a `scheme://host` payload** ⇒ fail-closed deny.

The shell hook (`bash-egress-guard.sh`, and the Codex side) applies the same allow-list to
`curl`/`wget`/`ssh` and owner/host-scopes `git push` / `gh` **writes** (reads are never
gated). Full model: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and
[docs/DESIGN.md](docs/DESIGN.md). Mapped to the
[OWASP Top 10 for LLM Applications (2025)](docs/OWASP-LLM-MAPPING.md).

## Quickstart: see it work (no install, offline)

```bash
git clone https://github.com/saagpatel/cross-provider-egress-guard
cd cross-provider-egress-guard
bash tests/run-all.sh        # runs the full deterministic suite against the in-repo hooks
```

You'll watch egress denies fire across every mode (navigation to a non-allow-listed host,
unknown connectors, deceptive GitHub hosts, oversized novel-host payloads) and legitimate
allow-listed calls pass. Requires only `bash` and `jq` (preinstalled on macOS/Linux).
This same suite (200+ assertions across both agents' enforcement, plus a cross-provider
parity check proving they read one shared policy) is the CI gate.

## Install

See [docs/INSTALL.md](docs/INSTALL.md) to deploy the Claude Code hooks and apply the Codex
patch, and [policy/mcp-gate-policy.example.json](policy/mcp-gate-policy.example.json) for a
commented starter policy to copy and edit for your environment.

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
