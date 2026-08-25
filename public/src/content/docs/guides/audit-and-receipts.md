---
title: Audit and receipts
description: Use signed run receipts, audit chain entries, metrics, and boot reports without exposing payload data.
---

`mvm` treats auditability as part of the runtime contract. A run should be
explainable after the fact without forcing raw command arguments, environment
values, stdout, stderr, or guest file contents into logs.

Use this guide when you need to prove what ran, connect an SDK result to host
evidence, or give CI a portable artifact to verify.
For application-level result correlation and redaction rules, see
[Observability and results](/guides/observability-and-results/).

## Evidence surfaces

| Surface | Purpose | Payload rule |
| --- | --- | --- |
| Signed run receipt | Portable proof for one `mvmctl run` execution. | Stores invocation hashes, output hashes, exit status, timing, and signature metadata. |
| Audit chain | Host-local sequence of signed lifecycle and policy events. | Stores event metadata and chain links, not guest payload bytes. |
| Boot report | Machine-readable launch and guest readiness state. | Reports boot and probe metadata. |
| Metrics | Operational counters and gauges. | Use labels for IDs, states, and counts, not raw command or file data. |
| Logs | Debug stream for an operator. | Treat as sensitive because guest-controlled output can appear there. |

Receipts and audit entries are complementary. A receipt is the artifact to hand
to CI, a customer, or a later verifier. The audit chain is the local evidence
stream that lets an operator inspect lifecycle history on the host.

## Write a run receipt

```sh
mvmctl run --receipt /tmp/run-receipt.json -- python task.py
```

The receipt contains hashes and result metadata. It does not store raw argv,
environment values, stdout, stderr, or host paths.

For automation, request JSON on stdout and a receipt on disk:

```sh
mvmctl run --json --receipt /tmp/run-receipt.json -- python task.py
```

`--json` returns a redacted execution summary for machine callers. Guest stdout
and stderr are not streamed in that summary.

## Verify a receipt

Verify with the default host signer public key:

```sh
mvmctl trust receipt verify /tmp/run-receipt.json
```

Verify with an explicit Ed25519 public key:

```sh
mvmctl trust receipt verify /tmp/run-receipt.json --pubkey ./host-signer.pub
```

Verification should happen before a receipt is trusted by CI, copied into a
release artifact bundle, or attached to an external audit record.

## Read the audit stream

Show recent audit events:

```sh
mvmctl trust audit tail -n 20
```

Follow new events:

```sh
mvmctl trust audit tail -f
```

Read the chain-backed audit stream for the local tenant:

```sh
mvmctl trust audit tail --chain --tenant local -n 20
```

Verify the chain links and signatures:

```sh
mvmctl trust audit verify --tenant local
```

Show chain entries for a specific plan identifier:

```sh
mvmctl trust audit show 018f2d9b-7b52-7c9a-9233-2a62a4d8d521 --tenant local
```

Use the audit chain for host-local investigation. Use receipts when another
system needs a portable artifact for a specific command result.

## Export decision provenance

`mvm` can export the chain-signed decision records it caches from audit events.
These exports are read-only views of the derived decision store; the
chain-signed audit log remains the source of truth.

Export all cached decision records for a tenant as JSON:

```sh
mvmctl trust audit decisions export --tenant local
```

Export as TIBET-compatible JSON tokens:

```sh
mvmctl trust audit decisions export --tenant local --format tibet
```

Write the export to a file:

```sh
mvmctl trust audit decisions export --tenant local --format tibet -o decisions.tibet.json
```

Trace the causal chain that led to a decision (backward traversal):

```sh
mvmctl trust audit decisions trace <decision-id> --tenant local
```

Show decisions that depend on or were caused by a decision (forward traversal):

```sh
mvmctl trust audit decisions impact <decision-id> --tenant local
```

Find cached decisions that are similar to a given decision:

```sh
mvmctl trust audit decisions similar <decision-id> --tenant local
```

Export the full audit chain as W3C PROV-O/Turtle for compliance reporting:

```sh
mvmctl trust audit provenance export --tenant local -o provenance.ttl
```

Use `--local` with `provenance export` to read the local `mvmctl` audit log
instead of the chain-signed tenant log.

The TIBET export is informational: `token_id` is derived deterministically
from the decision content address, `hash` covers the canonical token body, and
`signature` is empty because the read-only export path does not have access to
the host signer. Verify the underlying chain-signed audit entry when a
signature is required.

## Inspect boot and metrics data

Boot reports are useful when the question is "did the sandbox boot and become
ready?"

```sh
mvmctl machine boot-report devbox --json
```

Metrics are useful for dashboards and automated health checks:

```sh
mvmctl ops metrics --json
```

Metrics should stay operational: counts, durations, byte totals, IDs, states,
and backend names. Do not add labels that contain argv values, env values,
secret names, stdout, stderr, or file contents.

## Security rules

- Put secrets in the local secret store or an explicit secret injection path,
  not in command-line arguments.
- Store receipts outside the repository, such as `/tmp`, a CI artifact store,
  or a controlled evidence bucket.
- Treat logs as sensitive because guest code controls stdout and stderr.
- Verify receipts and chain links before using them as evidence.
- Include run and audit identifiers in higher-level traces instead of copying
  raw payloads into those traces.

## SDK parity target

SDK result types should expose correlation fields such as `run_id` and
`audit_id` when the underlying command path can provide them. Higher-level SDKs
should also make receipt verification and metrics access available without
weakening the same redaction rules:

- do not log raw args, env values, stdout, stderr, or file contents by default;
- keep receipts portable and verifiable;
- return typed policy, timeout, transport, and command-failure errors;
- let callers opt into bounded output capture explicitly.

Current language SDK pages mark these lifecycle helpers as parity targets until
shared tests prove the same behavior across supported languages.

## Related pages

- [Run commands and processes](/working/commands/)
- [Errors and metrics](/sdk/errors-metrics/)
- [Observability and results](/guides/observability-and-results/)
- [Security and isolation](/architecture/security-isolation/)
- [CLI commands](/reference/cli-commands/)
