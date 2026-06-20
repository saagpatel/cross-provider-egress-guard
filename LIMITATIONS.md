# Limitations: what this does *not* protect against

This guard is one layer, not a silver bullet. It enforces **destination** control at the
agent's tool-dispatch boundary: a network/send-class tool call (or shell network command)
is denied unless its destination is on your allow-list. That closes a specific, important
gap: an agent, or a prompt-injection payload riding in tool output, exfiltrating to an
**arbitrary** host in a single call. It does **not** make an agent safe on its own.

Below are the categories of risk it does not address, why, and what to pair it with. These
are inherent to an *input-side, hook-layer* control; they are not bugs.

### 1. Exfiltration to an already-allow-listed destination
The gate decides **where** a call may go, not **what** leaves or whether it should. If an
attacker can route data through a host you have allow-listed (e.g. write to a document on a
service you trust, then read it back), the destination check passes. Defending this requires
output-side data-flow / content classification, which is stateful and out of scope here.
**Pair with:** least-privilege allow-lists (only the hosts you truly need), and treat
allow-listed services that accept third-party content as semi-trusted.

### 2. Encoding or chunking below the payload-size heuristic
A novel-host payload above a size threshold is denied, but small or encoded payloads are not
decoded and inspected. The size guard is a heuristic, not a DLP engine.
**Pair with:** secret-scanning and read-side controls so high-value data never reaches a
network tool in the first place.

### 3. Runtime-assembled or indirected destinations
A host that is built at runtime (assembled from variables, rewritten by client config, or
hidden behind an opaque command argument) cannot always be determined statically. The guard
**fails closed** for the common case (a network command with *no verifiable destination
host* is denied), so the residual is narrow: a literal host that passes inspection but
resolves elsewhere at execution time.
**Pair with:** network-layer egress controls (below), which see the real connection.

### 4. Prompt injection carried in tool *output*
Egress control is **input-side**: it inspects the tool call being made, not the (untrusted)
content a previous tool returned. It does not detect or neutralize injection instructions
embedded in tool output.
**Pair with:** output-side provenance/trust tagging and not pointing agents at untrusted,
attacker-controlled content without additional review.

### 5. Best-effort coverage of exotic shell transports
Common shell egress (`curl`, `wget`, `ssh`) is parsed and destination-checked. Less common
transports in unusual forms (e.g. bare `scp host:path`, exotic `nc` flags) fall through to a
fail-closed "no verifiable host" deny rather than a precise allow-list check. The direction
is safe (deny), but the message is less specific.

### 6. Not a replacement for network-layer controls
This enforces *inside* the agent's own dispatch cycle. A guard that runs in-process is, by
design, in the same trust domain as the agent. It is **complementary to**, not a substitute
for, an external network egress proxy / firewall / DLP. For defense in depth, run both: the
hook layer for per-tool/per-connector semantics, the network layer for an independent choke
point the agent cannot reason its way around.

### 7. Scope of the write-destination gates
The git/`gh` write owner- and host-scoping targets GitHub. Other forges (GitLab, Gitea,
self-managed installs) are not covered by those write gates. Reads are intentionally never gated
(local-only data that cannot leave without hitting an already-gated send).

---

**The honest summary:** this raises the cost of single-call, arbitrary-destination
exfiltration from trivial to blocked, and gives you a default-deny choke point you control.
It does not solve output-side data flow, injection in tool output, or in-process trust. Use
it as one layer in a defense-in-depth posture. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
for the enforcement model and [SECURITY.md](SECURITY.md) to report an issue.
