# OWASP Top 10 for LLM Applications (2025): control mapping

This document maps the cross-provider egress guard to the
[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/). It is
deliberately conservative: this project is **one hook-layer control**, not a full LLM
security program. The ratings below describe what destination-aware, default-deny egress
control contributes to each risk, and where it stops. Read it alongside
[LIMITATIONS.md](../LIMITATIONS.md) and [THREAT-MODEL.md](THREAT-MODEL.md).

## Coverage legend

| Rating | Meaning |
|--------|---------|
| **Primary** | A direct, designed mitigation for a core part of this risk. |
| **Partial** | Meaningfully reduces impact or one vector, but not the whole risk. |
| **Marginal** | Incidental benefit; not a control this project was designed to provide. |
| **Out of scope** | Not addressed. Use other controls. |

## Summary

| ID | Risk | Coverage | What the egress guard contributes |
|----|------|----------|-----------------------------------|
| LLM01 | Prompt Injection | **Partial** | Cannot stop injection; caps its blast radius by denying the exfil/callback egress a payload needs. |
| LLM02 | Sensitive Information Disclosure | **Primary** | Default-deny on every network/send-class call is the exfiltration choke point: data cannot leave to a host you did not allow-list. |
| LLM03 | Supply Chain | Out of scope | Does not vet models, packages, or plugins. |
| LLM04 | Data and Model Poisoning | Out of scope | No control over training or retrieval data. |
| LLM05 | Improper Output Handling | **Marginal** | The shell gate incidentally blocks some generated-command egress (SSRF-shaped `curl` to a disallowed host); not a substitute for output sanitization. |
| LLM06 | Excessive Agency | **Primary** | Removes unrestricted network/send reach from the agent's standing capability; egress becomes allow-list-gated and fail-closed. |
| LLM07 | System Prompt Leakage | **Partial** | Cannot stop the prompt being read or echoed; denies the egress path that would ship it to an attacker. |
| LLM08 | Vector and Embedding Weaknesses | Out of scope | No control over RAG stores or embeddings. |
| LLM09 | Misinformation | Out of scope | Not a content-quality control. |
| LLM10 | Unbounded Consumption | Out of scope | Not a rate, cost, or DoS control. The novel-host payload cap limits exfil volume, not consumption. |

## Where the guard does real work

### LLM02: Sensitive Information Disclosure (Primary)

This is the risk the project exists for. Every network/send-class tool call, MCP connector
action, and shell network command (`curl`/`wget`/`ssh`, and `git`/`gh` writes) is denied by
default unless its destination is on an allow-list you control. A model that has read your
secrets, source, or customer data still cannot ship them to an attacker-controlled host,
because the destination of that send is gated before the call dispatches.

**Residual:** the gate controls the *destination*, not the *payload*. Exfiltration to a
host that is on your allow-list (for example, writing to a Gist on an allow-listed GitHub
host, then reading it back) is not prevented. See R1/R2 in
[THREAT-MODEL.md](THREAT-MODEL.md). Pair this with output-side controls for the full risk.

### LLM06: Excessive Agency (Primary)

OWASP's recommended mitigations for excessive agency include minimizing the agent's
permissions and gating high-impact actions. Default-deny egress does exactly that for one
high-impact capability: the ability to reach arbitrary network destinations. Out of the box
the agent can reach nothing it was not explicitly granted, and a missing or malformed policy
fails closed rather than open. The same policy binds both Claude Code and Codex, so the
agent's network blast radius cannot quietly differ between the two runtimes.

**Residual:** this constrains the *egress* facet of agency only. Excessive agency over the
local filesystem, destructive shell commands, or in-process state is the job of other hooks
(this repo ships a sensitive-read guard as one example, not a complete agency control).

### LLM01: Prompt Injection (Partial)

The guard does not detect or prevent prompt injection. Injection carried in tool output is
explicitly out of scope (R4 in [THREAT-MODEL.md](THREAT-MODEL.md)). What it does is cap the
*consequences*: the most common goal of an injection payload against a coding agent is to
exfiltrate data or call back to an attacker host, and that step is a gated egress call. A
successful injection that tells the agent to POST your environment to `evil.tld` still
fails at the wall. It reduces impact, not likelihood; treat it as defense in depth behind
input controls, not a prompt-injection defense on its own.

### LLM07: System Prompt Leakage (Partial)

Same shape as LLM02. The guard cannot stop a system prompt from being extracted or echoed
into a response, but if the exfiltration route is a tool call to a non-allow-listed
destination, that route is denied. It narrows the leak-to-attacker path; it does not protect
secrets that should never have been in the system prompt to begin with.

### LLM05: Improper Output Handling (Marginal)

LLM05 is about downstream components trusting unvalidated model output (injection into a
shell, SQL, browser, or SSRF target). The shell egress hook will incidentally deny a
generated `curl`/`wget` to a disallowed host, which blunts one SSRF-shaped variant. This is
a side effect, not a designed control: it does no output encoding, escaping, or
content-type validation. Do not rely on it for LLM05.

## What this does not address

LLM03 (Supply Chain), LLM04 (Data and Model Poisoning), LLM08 (Vector and Embedding
Weaknesses), LLM09 (Misinformation), and LLM10 (Unbounded Consumption) are out of scope. An
egress allow-list has no view into model provenance, training or retrieval data, embedding
stores, output truthfulness, or resource consumption. Address those with the controls OWASP
recommends for each; this guard is complementary to, not a replacement for, them.
