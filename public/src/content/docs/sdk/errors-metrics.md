---
title: Errors & metrics
description: Error classes, exit results, metrics, and audit identifiers expected from mvm SDK surfaces.
---

SDKs should make runtime failures easy to handle without hiding security
semantics. A command failure, a policy denial, and a transport failure are
different events and should not collapse into one generic exception.

## Error taxonomy

| Error | Meaning | Caller action |
| --- | --- | --- |
| `CommandFailed` | The guest command exited non-zero. | Inspect exit code and bounded stdout/stderr. |
| `Timeout` | The operation exceeded its deadline. | Stop, retry, or snapshot intentionally. |
| `PolicyDenied` | Admission, network, secret, filesystem, or profile policy refused the operation. | Fix policy or remove the operation. |
| `SandboxUnavailable` | The named sandbox is not running or cannot be reached. | Recreate, resume, or inspect lifecycle state. |
| `BackendUnsupported` | The selected backend cannot provide the requested feature. | Choose another backend or avoid that feature. |
| `TransportError` | CLI, vsock, socket, or SDK transport failed before guest result was available. | Retry only if the operation is idempotent. |

Current Python and TypeScript runtime SDKs expose lower-level errors for mode
selection and live transport failures. The table above is the product parity
target for higher-level lifecycle clients.

## Command result shape

Runtime SDK command execution should converge on a result shape like:

```text
exit_code
stdout
stderr
duration_ms
run_id
audit_id
timed_out
```

Security requirements:

- stdout and stderr are bounded;
- raw secret values are redacted before surfacing in errors or logs;
- command args and env values are not written into audit detail strings;
- callers can correlate a result with an audit record without exposing payload bytes.

## Metrics

Metrics should be split by scope:

| Scope | Examples |
| --- | --- |
| Runtime | active sandboxes, build queue depth, backend selection, failed launches. |
| Sandbox | CPU, memory, disk, network counters, lifecycle state, last readiness transition. |
| Command | duration, exit status, timeout, output byte counts, backpressure events. |
| Build | builder VM status, cache hit/miss, artifact hash, elapsed build phases. |

Metrics are operational metadata. They should not include argv values, env
values, file contents, stdout/stderr payloads, or secret names unless a policy
explicitly permits the label.


## AI egress metrics

When AI egress metering is enabled, the runtime emits Prometheus counters per
microVM instance. These counters contain counts only — no request bodies,
headers, prompts, or credentials.

| Metric | Type | Description |
| --- | --- | --- |
| `mvm_instance_ai_requests_total` | counter | Number of AI API requests observed. |
| `mvm_instance_ai_tokens_input_total` | counter | Input tokens reported by the provider. |
| `mvm_instance_ai_tokens_output_total` | counter | Output tokens reported by the provider. |
| `mvm_instance_ai_tokens_total_total` | counter | Total tokens reported by the provider. |

A budget is enforced on the next request after a limit is crossed, so a
single response may slightly exceed the cap before refusal takes effect.


## Debug logging

Debug logs are useful but risky. Recommended rules:

- log IDs, hashes, counts, state names, and backend names;
- do not log raw credentials, stdin, stdout, stderr, or guest file contents;
- gate verbose logs behind an explicit env var or CLI flag;
- include the audit/run identifier when available.

## Current CLI tools

Use these while SDK error and metric helpers mature:

```sh
mvmctl run --receipt /tmp/receipt.json -- python task.py
mvmctl machine boot-report devbox --json
mvmctl machine logs devbox
mvmctl trust audit tail -n 20
mvmctl trust audit verify --tenant local
mvmctl doctor --json
```

The SDK reference should move rows from target behavior to shipped behavior only
when shared tests prove the shape across the relevant languages.

## Related pages

- [Audit and receipts](/guides/audit-and-receipts/)
- [Observability and results](/guides/observability-and-results/)
- [Run commands and processes](/working/commands/)
