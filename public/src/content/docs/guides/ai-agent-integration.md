---
title: AI agent integration
description: Connect agents to mvm sandboxes with explicit policy and audit boundaries.
---

Agents should treat sandboxes as controlled tools, not ambient shell access.
For a concrete model-facing request/response contract, see [Agent tool contract](/guides/agent-tool-contract/).

## Recommended tool contract

- `create_sandbox(policy, image, resources)`
- `write_file(path, content)`
- `run_command(argv, timeout)`
- `read_file(path)`
- `snapshot_or_cold(name)`
- `stop_or_destroy()`

Every tool result should include a sandbox identifier and audit/run identifier where available.

## Security defaults

- Keep egress deny-by-default.
- Grant only the secrets needed for the current operation.
- Treat structured PII the same way as secrets on runtime-owned cleartext paths:
  detect it, replace it before egress, and only restore it on an owned return
  path when policy allows that plaintext back to the caller.
- Redact command output before returning it to a model if it may contain credentials or user data.
- Use short TTLs for transient sandboxes.
- Preserve cold state only when the workflow needs memory or filesystem continuity.


## Egress metering for AI calls

When the sandbox is allowed to reach AI providers, set a token budget so a
runaway or compromised agent cannot consume unbounded API quota. Add the
`[network.ai]` table to `mvm.toml`, or use the `ai_policy` / `aiBudget`
helpers in the Python and TypeScript SDKs.

- Metering is provider-specific; only known AI hosts are inspected.
- Streaming responses require the provider to report trailing usage.
- Budget enforcement refuses the next request after the limit is crossed.
- Metrics and audit records include counts and metadata only.

See [Network egress policy](/guides/network-egress-policy/) for configuration
examples and metric names.


## Request and response mediation

When an agent calls an external model or API through a runtime-owned path, keep
the contract narrow and auditable:

- detect and replace secrets plus supported structured PII before the outbound
  request leaves the runtime;
- use opaque, flow-scoped tokens rather than stable pseudonyms;
- restore original bytes only for exact token round trips on the owned response
  path;
- deny or redact when the response is transformed, delayed, replayed, or comes
  back through an unowned path;
- record the protection and reinjection decisions with the run or audit
  identifier.

This is exact-token restoration, not semantic reconstruction. If the upstream
service rewrites the value in natural language, the safe behavior is to leave
it redacted or tokenized.
