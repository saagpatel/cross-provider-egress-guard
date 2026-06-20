# Contributing

Thanks for your interest in the cross-provider egress guard. This is a security tool, so
contributions are held to a security tool's bar: additive, fail-closed, tested, and in
parity across both agents. Please read this before opening a PR.

## Reporting a bypass (do this privately)

**If you found a way around the guard, that is a vulnerability, not a bug. Do not open a
public issue.** Report it privately through the process in [SECURITY.md](SECURITY.md). A
public issue for a working bypass hands every user of this tool an exploit before there is a
fix.

Functional bugs that are not bypasses (a false-positive deny, a crash, a doc error) are fine
as public issues. Use the templates.

## Ground rules

These are non-negotiable for any change to enforcement logic:

1. **Additive only.** Never weaken, reorder, or remove an existing deny pattern or
   `require_token` gate. New coverage is added alongside the old, never by loosening it. If
   you believe an existing deny is wrong, open an issue to discuss it first; do not quietly
   drop it in a PR.
2. **Fail closed.** Network/send-class classification must deny on any ambiguity: parse
   error, missing policy, unreadable policy, invalid JSON, or an unextractable destination.
   A safe false-positive deny always beats an exfil false-negative.
3. **Cross-provider parity.** Claude Code and Codex enforce the *same* policy. A change to
   one enforcement surface needs the matching change to the other, and
   `tests/parity-check.sh` must stay green. The whole value of the project is that the two
   agents cannot drift to different blast radii; a PR that moves only one side will be asked
   to do both.
4. **One source of truth.** Destination and connector allow-lists live in the shared policy
   JSON. Do not embed a divergent allow-list in hook code; the parity check asserts there is
   none.

## Development setup

You need `bash` and `jq` (preinstalled on macOS and most Linux). For the unit tests you also
need [`bats-core`](https://github.com/bats-core/bats-core) (`brew install bats-core` or your
package manager).

Run the full deterministic suite, which is also the CI gate:

```bash
bash tests/run-all.sh        # 200+ assertions + cross-provider parity, offline
```

Every behavior change ships with a test. A PR that changes what is allowed or denied without
a corresponding test case will not be merged. Add cases to the relevant harness under
`tests/` and, for Claude Code hook logic, the `bats` mirror under
`claude-code/hooks/tests/`.

## Code conventions

**Bash (Claude Code hooks):**
- shellcheck-clean; quote all expansions; prefer `case`/`fnmatch` over regex where the
  existing code does.
- Source `claude-code/hooks/lib/deny.sh` before any policy JSON parsing, so `jq` resolution
  cannot be PATH-poisoned and an unavailable `jq` fails closed.
- Deny on parse error for any network-class tool.

**Python (Codex hook patch):**
- Type hints throughout; frozen dataclasses for decision objects.
- No new runtime dependencies. The hook runs in the agent's own environment; keep it stdlib.

**Both:**
- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`). One logical change per PR.
- Do not widen the destination allow-list in the example policy without a clear, documented
  rationale; allow-list widening is the one change most likely to reduce security.

## What makes a good PR

- A new network/send-class tool added to the policy globs, with a test proving it is now
  gated (the project does not auto-cover new tool names; this is exactly the kind of
  contribution that helps).
- A new deceptive-host normalization case, with the attack form as a test.
- A false-positive fix that narrows an over-broad deny without opening a real egress path,
  with a regression test pinning both the fixed case and the still-denied attack.
- Documentation that makes the threat model or install steps clearer.

## Licensing

This project is licensed under [Apache-2.0](LICENSE). By contributing, you agree that your
contributions are licensed under the same terms.
