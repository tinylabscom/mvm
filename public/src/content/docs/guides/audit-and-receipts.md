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

Use the audit chain for host-local investigation. Use receipts when another
system needs a portable artifact for a specific command result.

## Sessions

A session is one admitted run: every chain entry carrying the plan id that a
`plan.admitted` entry introduced. When the run exits, fails to boot, or — for a
persistent machine — is stopped, the host appends a chain-signed
`session.sealed` entry. The seal records:

- how many entries the session had
- the position and hash of its first and last entries
- the chain head it was computed against
- an RFC 6962 Merkle root over exactly those entries
- how the session ended (exit code, failure class, or stopped)
- the measured compute-environment digest from the signed plan, when the plan
  recorded one

List sessions, newest last:

```sh
mvmctl trust audit sessions
mvmctl trust audit sessions --since 7d --json
mvmctl trust audit sessions --since 2026-09-01 --until 2026-09-02T12:00:00Z
```

`--since` and `--until` accept an RFC 3339 timestamp, a `YYYY-MM-DD` date, or a
duration back from now (`30m`, `12h`, `7d`, up to 30 days). A session is listed
when any part of it falls in the range.

Show one session's entries. The session is its plan id, or at least eight
leading hex characters of it; an ambiguous prefix is refused:

```sh
mvmctl trust audit show 1e9fca73063e
mvmctl trust audit show 1e9fca73063e --kind 'plan.*' --since 1h --json
```

`--kind` is a shell-style glob over the event name.

Verify one session:

```sh
mvmctl trust audit verify 1e9fca73063e
mvmctl trust audit verify 1e9fca73063e --json
```

The verdict is one of the following. Each has its own exit status, so a
script can branch on it.

| Verdict     | Exit | Meaning                                                                                                                                                                                                                                                                                                    |
| ----------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VERIFIED`  | 0    | The whole chain verifies from genesis, and every seal of the session matches the chain it sits in.                                                                                                                                                                                                       |
| `MISMATCH`  | 1    | Either the chain does not verify, or a seal disagrees with it. The reason is named: `chain_break`, `signature`, `malformed`, `truncated_tail`, `count_mismatch`, `sequence_mismatch`, `root_mismatch`, `head_mismatch`, `ledger_break`, `malformed_seal`, or `io`.                                          |
| `UNSEALED`  | 2    | The chain verifies but the session has no seal. It may still be running, it may have ended without a seal (a crash or power loss), or the log may have been truncated through the seal. Treat this verdict as "cannot vouch for completeness".                                                             |
| `NOT_FOUND` | 3    | No such session in this chain.                                                                                                                                                                                                                                                                              |

A seal inside a broken chain vouches for nothing. That is why a chain that does
not verify makes every session a `MISMATCH` with the chain's own reason. Entries
the session gained after its last seal are reported as `late_entries`; they are
not a mismatch, but the seal does not cover them.

### The session ledger

Each seal names the one before it (`seal.prev_seal`, the SHA-256 of the
previous `session.sealed` line). The seals are therefore a hash-chained ledger
of sessions. `trust audit sessions` checks that linkage and reports it on its
last line (`ledger` in `--json`).

The ledger lives inside the audit chain rather than in a file of its own. That
keeps it under the same host key and the same verification as every other
entry, so there is no second trust root to keep consistent with the first.

### What a seal detects, and what it does not

- **An edited, removed, or reordered entry.** The chain already refuses these,
  and the session verdict carries the chain's reason.
- **A seal that misdescribes its session.** A seal whose count, positions,
  root, head, or ledger link do not match the chain is refused field by field.
  Such a seal can come from a faulty writer or from anyone holding the host
  key.
- **Truncation through a session's seal.** The session becomes `UNSEALED`,
  which is visible.
- **Truncation after a seal.** The session stays `VERIFIED`, because
  everything the seal claimed is still present.
- **Not detected: a session that never sealed, or a whole session cut from
  the tail.** From the log alone, these are indistinguishable from a crash
  and from a shorter history. Detecting them needs an anchor outside the host
  (next section).

## Durability

The signer decides per event whether an append must reach stable storage
before the call returns.

- **Synced before the call returns (barrier).** Every event that authorizes
  something, or bounds something: `plan.admitted`, `plan.failed`,
  `plan.exited`, `session.sealed`, the segment `chain.sealed` /
  `chain.continued` / `chain.pruned` records, and every command's terminal
  `cmd.*.completed` / `cmd.*.failed`. An event the signer does not recognise
  is synced by default.
- **Written immediately, synced by the next barrier on the same file.**
  Descriptive records of a decision already durable: `plan.policy_resolved`,
  `plan.boot_posture`, `plan.shares_admitted`, `plan.oci_provenance`,
  `plan.launched`, and `cmd.*.invoked`.

An admission writes its burst of entries and syncs them once before the boot
proceeds.

This is deliberately not "fsync every entry". Measured on 1 KiB appends:

| Host                       | Append only | Append + fsync |
| -------------------------- | ----------- | -------------- |
| macOS 26, internal SSD     | 6–10 µs     | 4.3–5.2 ms     |
| Linux 6.8, rotational RAID | 2–10 µs     | 44–49 ms       |

A deferred entry lost in a crash leaves a shorter log. With a barrier after
every authorization, it can never leave an action whose authorization is
missing. A seal is a barrier because it is a completeness claim: losing the
claim while keeping the entries it describes would afterwards read as a
truncation.

## Rotation

The chain rotates into sequenced segments once the active file reaches
`MVM_AUDIT_SEGMENT_BYTES`. The default is 4 MiB, and `0` disables rotation.
The active segment stays at `~/.mvm/audit/<tenant>.jsonl`, and retired ones
become `<tenant>.seg-NNNNNN.jsonl`. Every segment after the first opens with a
signed handoff naming its predecessor's final chain hash. `trust audit
verify`, `sessions`, `show`, and session seals all span the whole segment
set, and a session may cross a rotation.

The per-VM workload chains (`<tenant>.<vm>.workload.jsonl`) are not rotated:
each is bounded by one machine's life. The unsigned command log read by
`trust audit tail` without `--chain` rolls over to `.1` at 10 MiB.

## Anchoring the chain head

The chain proves nothing was altered among the entries it holds. On its own it
cannot notice entries that were removed from the end.

`mvmctl trust audit publish-root` signs a Merkle root over the whole segment
set and appends it to `~/.mvm/audit/<tenant>.roots.jsonl`. It also writes the
latest root to `<tenant>.root.json`. The host publishes one at every
admission, exit, and stop. A root is a host-signed statement that "the first
`tree_size` entries hash to `root_hash`". A later log shorter than a published
`tree_size`, or one whose prefix no longer hashes to it, contradicts a
signature. `trust audit verify` reports whether the published roots still
describe the log.

Those roots are stored beside the log they describe, so a host that rewrites
the log can rewrite them too. Set `MVM_AUDIT_WITNESS` to a file path or an
`http(s)://` URL to copy each root off the host as it is published. After
that, a rewrite of anything before the newest witnessed root is detectable by
comparing the host's claims against the witness. Entries appended after the
newest witnessed root remain unprotected until the next one lands.

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
