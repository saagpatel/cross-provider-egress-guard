# Security Policy

## Reporting a vulnerability

This is a security tool, so a bypass *is* a vulnerability. Please report privately:
**do not open a public issue for a working bypass.**

Use GitHub's private vulnerability reporting: the **Security** tab → **Report a
vulnerability** (GitHub Security Advisories). That opens a private channel with the
maintainers.

Please include:
- The category (e.g. egress bypass, owner-scope bypass, false-allow, fail-open).
- A minimal reproduction: the tool call or shell command, the policy in effect, and the
  decision you observed vs. expected.
- The hook(s) and version/commit involved.

### What to expect
- Acknowledgement within a few days.
- An initial assessment (in scope / out of scope, severity) after triage.
- Coordinated disclosure: we will agree on a timeline before any public write-up, and credit
  you unless you prefer to remain anonymous.

## Scope

**In scope**: anything that causes the guard to *allow* egress it should deny, or to *fail
open* (allow on error) where it should fail closed:
- A network/send-class tool call reaching a non-allow-listed destination.
- A connector or git/`gh` write reaching a disallowed owner/host.
- A malformed/missing policy resulting in allow rather than deny.
- A parsing bypass (deceptive host, indirection) that yields a false allow.

**Out of scope**: the documented, by-design limitations in
[LIMITATIONS.md](LIMITATIONS.md): output-side exfil to an *already-allow-listed* host,
injection carried in tool output, runtime-indirected hosts that fail closed, and the fact
that an in-process hook shares the agent's trust domain. These are known and documented; a
report restating them is not a vulnerability. A *novel* technique that defeats a control the
guard claims to enforce **is** in scope.

## Hardening note

The guard is **fail-closed by construction**: a missing, unreadable, or invalid policy
denies network/send-class tools rather than allowing them. If you find a path where an error
condition yields *allow*, that is a high-severity report.
