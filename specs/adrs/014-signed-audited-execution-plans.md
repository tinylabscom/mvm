# ADR-014: Signed, audited `ExecutionPlan` — the contract behind every boot

## Status

Accepted

## Context

A workload boot is a security-relevant event: it decides which image runs,
under which network/filesystem/secret/tool policy, for how long, and with
which host capabilities. Without a typed, signed record of that decision,
"what did this VM see at admission" is only answerable by re-deriving it
from CLI args and config — not from anything that survives tampering or a
process restart.

Every microVM boot needs one artifact that is synthesized from the
caller's intent, signed under a host-local key, verified before the
backend ever starts a VM, and permanently recorded in a tamper-evident
log — regardless of whether the caller is a local `mvmctl` invocation
today or a fleet-orchestrated launch tomorrow.

## Decision

### Every boot synthesizes, signs, admits, and audits a plan

```
mvmctl machine run <image|flake|manifest>
  │
  ├── build/resolve rootfs
  │
  ├── admit_plan_for_boot(...)                    [crates/mvm-cli/src/commands/vm/up.rs]
  │     │
  │     ├── sha256_file(rootfs.ext4)
  │     ├── synthesize_plan(SynthesisInput { .. })  [mvm-core::plan::synthesis]
  │     │     fresh UUIDv4 plan_id, 128-bit nonce, short validity window
  │     ├── host_signer::load_or_init(~/.mvm/keys/) [crates/mvm-cli/src/commands/vm/host_signer.rs]
  │     │     mode-0600 secret half, refuses loose perms
  │     ├── admit_for_run(input, clock, nonce_ledger, ...) [mvm-hostd::plan_admission]
  │     │     ├── sign_plan + verify_plan (roundtrip)
  │     │     ├── check_window (validity)
  │     │     └── nonce_store.check_and_insert (replay)
  │     └── AuditEmitter::emit_admitted(...)        [crates/mvm-cli/src/commands/vm/audit_chain.rs]
  │           appends a signed envelope to ~/.mvm/audit/<tenant>.jsonl
  │
  ├── backend.start(&start_config)                  [mvm-backend::AnyBackend]
  ├── on Ok:  emit_launched_if(ctx, backend_name)
  └── on Err: emit_failed_if(ctx, "backend-start", &e); return Err
```

`ExecutionPlan` and its signing/verification primitives live in
`mvm-core::plan` (`execution_plan.rs`, `signing.rs`, `synthesis.rs`); the
admission pipeline (`admit_for_run`, the nonce ledger, the system clock)
lives in `mvm-hostd::plan_admission` — a library the CLI links directly.
The CLI still calls `admit_for_run` and `backend.start()` itself rather
than handing the whole boot to a resident supervisor object; that lift is
future work, not a gap in what's enforced today.

### What the plan carries

`ExecutionPlan` is a single typed struct covering: identity (`plan_id`,
`plan_version`, `tenant`, `workload`), what runs (`runtime_profile`,
`image` — SHA-256 plus an optional cosign bundle), `resources`, the
intent-bound `admission_profile` (seccomp tier, secret-release posture,
audit taxonomy), `network_policy` / `network_mode` (closed by default —
no guest NIC, nothing reachable, until the plan says otherwise),
`fs_policy`, `secrets`, `auth`, `egress_policy`, per-destination
`redaction` and `reversible_replacement` policy, `tool_policy`,
`artifact_policy`, `audit_labels`, `key_rotation`, `attestation`, an
optional `release_pin`, `post_run` lifecycle, the `valid_from`/
`valid_until` validity window, and a replay-protecting `nonce`.

Several `*Ref`-typed fields (`network_policy`, `fs_policy`,
`egress_policy`, `tool_policy`) resolve at admission through
`policy_resolver::resolve_supervisor_components`: a `"local-default"` ref
resolves to fail-closed no-op components (deny by construction, not by
omission); a `"<tenant>:<workload>"` ref loads
`~/.mvm/policies/<tenant>/<workload>.toml`. The validity window is
deliberately short — long enough for boot plus verification, short enough
that a captured plan cannot be replayed hours later — and is checked
together with the nonce ledger so neither a stale-window replay nor a
same-window duplicate gets through.

### Per-workload guest verb grants ride the same signature

`agent_verbs: Option<Vec<VerbId>>` is an optional field on the signed
plan. Absent, the guest agent applies only its existing class/profile
gate (every `ProdSafe` verb available to every sealed-prod workload).
Present, admission mints a `VerbGrant` — session-bound, nonce-bound,
signed by the same host-signer authority that signs the plan — and the
guest intersects every subsequent control-vsock request against it after
the class/profile gate. The grant is strictly subtractive: it narrows
what the profile already allows and can never widen a sealed-prod agent
to accept a dev-only verb. A refusal returns a wire-stable
`GuestResponse::VerbNotAuthorized` and is audited.

### Audit chain

Each entry in `~/.mvm/audit/<tenant>.jsonl` is one JSON line carrying a
`SignedEnvelope`: the event (`plan.admitted`, `plan.launched`,
`plan.failed`, plus verb-grant denials and other plan-bound events),
labels, the previous entry's hash, and an Ed25519 signature over
`entry || prev_hash`. The genesis `prev_hash` is 32 zero bytes;
`verify_audit_chain` (`mvm-hostd::supervisor`) walks the file and fails on
any broken link or bad signature. Emission is per-VM and file-locked so
two supervisor processes writing the same tenant's chain concurrently
cannot both restore the same `prev_hash`.

Backend symmetry: the `labels.backend` field accepts any backend name
(`libkrun`, `hvf`, `firecracker`, `qemu`); the chain format itself is
hypervisor-agnostic, and `mvmctl trust audit verify` round-trips
identically regardless of which backend produced the entries.

### Operator-facing surface

- `mvmctl machine run` (and the other boot paths): every invocation
  admits and audits; there is no flag that boots a workload while
  skipping either step.
- `mvmctl trust audit verify [--tenant <name>]` — runs
  `verify_audit_chain` against the tenant's chain file and exits nonzero
  on any detected drift.
- `mvmctl trust audit show <plan_id> [--tenant <name>]` — filters the
  chain to entries bound to one plan.
- `mvmctl trust audit tail [--chain] [--tenant <name>] [-f]` — tails the
  chain-signed log with `--chain`; without it, tails the separate
  legacy `~/.mvm/log/audit.jsonl` operator-facing stream (a different
  log, unrelated to plan signing, used by day-to-day CLI verbs).

## Consequences

- Every boot is forensically explainable: `mvmctl trust audit show
  <plan_id>` answers "what did this VM see at admission" from the chain
  alone, with no separate observability stack.
- Tamper evidence is detection, not prevention — a host that can write
  `~/.mvm/audit/` or rotate the host-signer key can still forge a fresh
  chain. The plan-signer and audit-signer keys are the same key today; a
  compromised host key defeats both. This mirrors the standing threat
  model's "malicious host is out of scope" carve-out, not a gap specific
  to this design.
- The `*Ref` policy fields resolve to real fail-closed no-ops today, not
  live enforcement — a plan can name a policy bundle and have it parsed,
  but the enforcement components (`EgressProxy`, `ToolGate`,
  `KeystoreReleaser`, `ArtifactCollector`) that would act on it are a
  forward-compatible seam, not yet wired to a live consumer.
- `agent_verbs` gives the same signed-plan mechanism a guest-side
  capability dimension: least-privilege per workload, not just per
  profile class, without inventing a second signing authority — the
  grant chains to the same host-signer key that signs the plan itself.
