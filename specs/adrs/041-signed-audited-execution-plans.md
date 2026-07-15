---
title: "ADR-041: Signed, audited `ExecutionPlan` — the contract behind every `mvmctl up`"
status: Accepted
date: 2026-05-11
related: ADR-002 (microVM security posture); ADR-005 (libkrun + libkrun pivot); plan 60 (libkrun migration); plan 64 (supervisor wiring)
---

## Status

Accepted. Implementation shipped in plan 64 W1–W6 (`specs/plans/64-supervisor-wiring.md`, commits ae81767 W1, a71e60a W2, 2671f5f + bc91d77 W3, 587a33e W4, 7184b9a W6, and the W5 commit that adds `crates/mvm-cli/src/commands/vm/policy_resolver.rs`). With W5 landed, plan 64 closes; the remaining `*Ref → real-impl` work (TOML policy bundle format, mvm-hostd consumer lift) is plan 60 Phase 3 / Phase 6 hardware attestation.

The plan-60 §"Security model" claim 8 — *every workload runs from a signed, audited `ExecutionPlan`* — went from "proposed" to user-observably true with the W3 callsite + W4 audit chain landing together. CLAUDE.md updated 2026-05-11.

## Context

Through plan-60 the supervisor and plan crates (`mvm-plan`, `mvm-supervisor`) shipped extensive substrate — 28 plan tests, 228 supervisor tests, fail-closed Noop slots for every component (inspector, egress proxy, tool gate, keystore releaser, artifact collector), and a chain-signed audit signer. None of it ran in production: `mvmctl up` parsed args into `VmStartConfig`, called `backend.start()`, and never touched `ExecutionPlan` or `Supervisor::launch`.

That meant claim 8 from plan 60's security model — every workload runs from a signed, audited plan — was *substrate-true*: the types existed, the verifier worked, the chain signer worked, but no live caller produced or consumed any of it on a real boot.

Plan 64 closed that gap: every `mvmctl up` invocation now synthesizes an `ExecutionPlan` from CLI args, signs it under a host-local Ed25519 keypair, verifies it, checks the validity window and nonce replay-store, then emits a chain-signed audit trail bound to the resulting plan_id. Tampering with the audit log breaks `verify_audit_chain`, surfaced via `mvmctl audit verify`.

## Decision

### Lifecycle: plan synthesis → signing → admission → audit → boot

```
mvmctl up <flake|template|default>
  │
  ├── build/resolve rootfs                              [mvm-build dev_build / template loader]
  │     produces: rootfs.ext4 (PathBuf), vmlinux, initrd
  │
  ├── admit_plan_for_boot(...)                         [crates/mvm-cli/src/commands/vm/up.rs]
  │     │
  │     ├── sha256_file(rootfs.ext4)                    [mvm-security::image_verify]
  │     │
  │     ├── synthesize_plan(SynthesisInput { ... })    [W1 — crates/mvm-cli/src/commands/vm/plan_builder.rs]
  │     │     fresh UUIDv4 plan_id, 128-bit nonce, 10-min validity window
  │     │
  │     ├── host_signer::load_or_init_at(~/.mvm/keys/) [W2 — crates/mvm-cli/src/commands/vm/host_signer.rs]
  │     │     mode-0600 secret half, refuses loose perms
  │     │
  │     ├── admit_for_run(input, &SystemClock,         [W3 — crates/mvm-cli/src/commands/vm/plan_admission.rs]
  │     │                 &InMemoryNonceLedger, ...)
  │     │     ├── sign_plan + verify_plan (roundtrip)
  │     │     ├── check_window (G4 validity)
  │     │     └── nonce_store.check_and_insert (G4 replay)
  │     │
  │     └── AuditEmitter::emit_admitted(...)            [W4 — crates/mvm-cli/src/commands/vm/audit_chain.rs]
  │           appends signed envelope to ~/.mvm/audit/<tenant>.jsonl
  │
  ├── backend.start(&start_config)                      [mvm-backend::AnyBackend]
  │
  ├── if Ok(_):  emit_launched_if(ctx, backend_name)
  ├── if Err(e): emit_failed_if(ctx, "backend-start", &e); return Err(e)
  │
  └── ... rest of cmd_run (port forwarding, ctrl-c loop, etc.)
```

### Who builds, who signs, who consumes

| Role | Today | Phase 3 (plan 60 §Phase 3 / plan 63 W3) |
|---|---|---|
| **Plan builder** | `mvmctl` (`synthesize_plan` from CLI args) | mvmd remote-launch path + mvmforge IR-derived plans |
| **Plan signer** | host-local Ed25519 key at `~/.mvm/keys/host-signer.ed25519` (mode 0600) | mvmd's tenant key + on-host attestation key |
| **Plan verifier** | `mvm_plan::verify_plan` against the host's own pubkey + G4 window/nonce checks | supervisor's trusted-keys list (mvmd-issued, host-attested) |
| **Audit signer** | same host key (`AuditEmitter` wraps `FileAuditSigner`) | separate audit-signer key (split from plan-signer per plan 60 §Phase 3) |
| **Audit verifier** | `mvm_supervisor::verify_audit_chain` via `mvmctl audit verify` | same, plus mvmd-side aggregation + cold-stream replication |

### `*Ref` semantics — today vs. eventual

Each `Ref`-typed field of `ExecutionPlan` is a placeholder that resolves to a concrete component or policy at admission. Today most resolve to fail-closed Noops; W5 + Phase 3 give them real impls.

| Field | Today | Eventual resolver | Eventual home |
|---|---|---|---|
| `plan_id` | fresh UUIDv4 per invocation | same | — |
| `plan_version` | always `1` | mvmd revisions get monotonic versions | mvmd |
| `tenant` | `--tenant` flag, default `"local"` | mvmd-issued `TenantId` (cryptographic, not name) | mvmd |
| `workload` | VM name (post-validation) | image-baked workload manifest | mvm-build |
| `runtime_profile` | backend name (`firecracker` / `libkrun` / `apple-container`) | flake `passthru.mvm.profile` | mvm-build |
| `image` | `{ name: vm_name, sha256: <rootfs-hash>, cosign_bundle: None }` | `mvm-security::image_verify` signed-manifest path with cosign bundle | mvm-security |
| `admission_profile` | intent-bound binding of `intent`, selected seccomp tier, policy refs, secret-release posture, and audit taxonomy; direct `mvmctl up` defaults to `intent = "vm:boot"` | mvmd / SDK intent resolver picks named profiles such as `code:execute`, `agent:web-research`, `deploy:publish`, then refuses inconsistent requested powers | mvm-plan + mvmd policy resolver |
| `network_policy` / `fs_policy` / `egress_policy` / `tool_policy` | `"local-default"` → Noops, OR `"<tenant>:<workload>"` → loads `~/.mvm/policies/<tenant>/<workload>.toml` (still returns Noops; no live consumer yet) | real `EgressProxy` / `ToolGate` / `KeystoreReleaser` / `ArtifactCollector` impls reading the parsed bundle | plan 60 Phase 3 (proxies) + mvm-hostd lift |
| `secrets` | empty | mvmd-resolved `SecretGrant` set | mvmd + plan 63 W3 keyring |
| `artifact_policy` | `{ capture_paths: [], retention_days: 0 }` | per-policy bundle | W5 |
| `audit_labels` | empty | inherited from policy bundle + tags | W5 |
| `key_rotation` | `{ interval_days: 0 }` | plan 63 W3 rotation schedule | plan 63 |
| `attestation` | `AttestationRequirement { mode: Noop }` | TPM2 / SEV-SNP / TDX | plan 60 Phase 3 |
| `release_pin` | `None` | optional digest pin from policy | W5 |
| `post_run` | `{ destroy_on_exit: true, snapshot_on_idle: false, idle_secs: 0 }` | per-policy | W5 |
| `valid_from` / `valid_until` | `now` .. `now + 10 min` | unchanged (G4 invariant) | — |
| `nonce` | 128 random bits from `OsRng` | unchanged | — |

The validity window is deliberately short. Long enough for boot + signature verification + state machine walk; short enough that a captured plan can't be replayed hours later. G4 (`mvm_plan::check_window` + `NonceStore`) catches both directions.

### Audit chain shape

Each entry is one line of `~/.mvm/audit/<tenant>.jsonl` carrying a JSON-serialized `mvm_supervisor::SignedEnvelope`:

```json
{
  "entry": {
    "timestamp": "2026-05-11T18:34:21.043Z",
    "tenant": "local",
    "plan_id": "9f7c…",
    "plan_version": 1,
    "image_name": "vm-clever-koala",
    "image_sha256": "8c1f…",
    "event": "plan.launched",
    "labels": { "backend": "firecracker" }
  },
  "prev_hash": "<base64 url-safe-no-pad of SHA-256 of previous envelope>",
  "signature": "<base64 url-safe-no-pad of Ed25519 over `entry || prev_hash`>"
}
```

The chain seed (genesis `prev_hash`) is 32 zero bytes. `FileAuditSigner` restores its in-memory cursor from disk on construction so a process restart resumes without gaps.

Three event types today:

- `plan.admitted` — fires right after `admit_for_run` returns Ok; labels carry `signer_id`.
- `plan.launched` — fires after `backend.start()` Ok (or after `restore_from_template_snapshot` Ok on the snapshot path, or after `install_launchd_direct` Ok on the apple-container detach path); labels carry `backend`.
- `plan.failed` — fires on any error path between admission and successful boot; labels carry `error_class` (`backend-start` / `snapshot-restore` / `launchd-install`) and `error_message` (the rendered anyhow chain).

Audit emission failures `tracing::warn` and continue — a flaky audit fs cannot block a VM that already booted. W6's follow-up tightens this to "audit failure fails the boot" once the chain is reliably reachable on every supported host.

**Backend symmetry (Plan 98).** The `labels.backend` field accepts either `libkrun` or `vz` (and `firecracker` on Linux) — the chain itself is hypervisor-agnostic. `mvmctl up --prod` driven by `MVM_BUILDER_BACKEND=vz` emits the same `plan.admitted` / `plan.launched` / `plan.failed` sequence as the libkrun path, and `mvmctl audit verify` round-trips cleanly across both. Plan 98 §2.S3 ships the cross-backend audit-chain integrity test.

### Operator-facing surface

- `mvmctl up` (existing, instrumented): every invocation admits + audits. `--no-supervisor` is a one-release escape hatch that prints a deprecation warning and skips both.
- `mvmctl audit verify [--tenant <name>]` (new): runs `mvm_supervisor::verify_audit_chain` against `~/.mvm/audit/<tenant>.jsonl` using the host signer's verifying key. Nonzero exit on detected drift. Meant for scripting.
- `mvmctl audit show <plan_id> [--tenant <name>]` (new): filters the chain to entries for a specific `plan_id`.
- `mvmctl audit tail --chain [--tenant <name>] [-f]` (new): tails the plan-64 chain. The unflagged `mvmctl audit tail` still reads the legacy `~/.mvm/log/audit.jsonl` LocalAudit stream (no backward-compat break).

The CLI surface intentionally stops short of `mvmctl plan create / sign / verify`. Synthesis is internal-only for v0; the user-facing plan CLI is a follow-up after W5 lands and policy resolution gives plans meaningful surface area to inspect.

## Consequences

### Positive

- **Claim 8 is true on every host.** A `cargo test --workspace` run exercises the rejection paths on every PR; no special CI job needed because the workspace suite is the gate.
- **Forensic operability.** `mvmctl audit show <plan_id>` answers "what did this VM see at admission?" in O(file-scan) — no log re-derivation, no separate observability stack.
- **Tamper evidence is detection, not prevention.** A compromised host can still delete the audit file or rotate the host key. Plan 60 Phase 3's split-signer model (audit-signer ≠ plan-signer) and cold-stream replication change this.
- **The eventual `mvm-hostd` lift is a one-line change.** `AdmissionContext { admitted, emitter }` is exactly the shape `Supervisor::launch` consumes; the inline `admit + backend.start` body becomes `supervisor.launch(&signed, &trusted_keys).await` once the supervisor is in-process.

### Negative / honest deferrals

- **No `BackendLauncher` adapter yet.** Plan 64 W3 was originally scoped to replace the three inline `backend.start()` callsites with `Supervisor::launch` via a `BackendLauncher` adapter. Investigating `up.rs` (1084 LOC at the start of the session) showed that a faithful refactor was multi-day work that didn't fit cleanly into one slice. The substrate landed; the supervisor lift waits for `mvm-hostd`.
- **Audit signer = plan signer.** v0 uses the host's single Ed25519 key for both. A compromised host can mint a fresh chain. Splitting these keys is plan 60 Phase 3.
- **No trusted clock.** `SystemClock` reads the host wall-clock. A host can wind the clock back to admit a replayed plan within an expired window. `HostBoundRequest::QueryHostTime` (vsock-level) is plan 60 Phase 3.
- **No attestation.** `AttestationRequirement { mode: Noop }` is honored but ignored. Real TPM2 / SEV-SNP / TDX integration is plan 60 Phase 3.
- **PolicyRef slots all Noop.** `network_policy`, `fs_policy`, `egress_policy`, `tool_policy` all resolve to `"local-default"`, which W5's `policy_resolver::resolve_supervisor_components` maps to fail-closed Noops (`NoopEgressProxy` / `NoopToolGate` / `NoopKeystoreReleaser` / `NoopArtifactCollector`). For `"<tenant>:<workload>"` refs, the resolver loads `~/.mvm/policies/<tenant>/<workload>.toml` via `mvm_policy::toml_loader` — operators can stage the bundle file *now*, but the returned slots remain Noops because no live consumer (L4/L7 proxies, real ToolGate) exists yet to read the parsed bundle. Phase 3 builds those consumers. The W5 substrate has no live consumer yet — `up.rs::admit_plan_for_boot` ships `admit + backend.start()` rather than `Supervisor::launch`, so the resolver's `Box<dyn Trait>` slots are not yet handed to a supervisor builder. That happens with the mvm-hostd lift.

### Out of scope (named in plan 64's non-goals)

- Real policy file format (W5 / Phase 3)
- Multi-signer audit chain (Phase 3)
- Trusted clock via vsock (Phase 3)
- Attestation (Phase 3)
- Plan-bound key release (plan 63 W3 keyring)
- `mvmctl plan create / sign / verify` user-facing CLI (post-W5 follow-up)

## References

- `specs/plans/64-supervisor-wiring.md` — full sprint plan for plan 64.
- `specs/plans/60-mvm-libkrun-migration.md` Phase 6 — the cornerstone this ADR documents the shipping of.
- ADR-002 (`specs/adrs/002-microvm-security-posture.md`) — the seven claims this ADR's claim 8 joins.
- `crates/mvm-plan/src/` — `ExecutionPlan`, `SignedExecutionPlan`, `sign_plan`, `verify_plan`, `check_window`, `NonceStore`.
- `crates/mvm-supervisor/src/audit.rs` + `audit_file.rs` — `AuditEntry`, `AuditSigner`, `FileAuditSigner`, `verify_audit_chain`.
- `crates/mvm-cli/src/commands/vm/plan_builder.rs` — W1 synthesis.
- `crates/mvm-cli/src/commands/vm/host_signer.rs` — W2 keystore.
- `crates/mvm-cli/src/commands/vm/plan_admission.rs` — W3 admission pipeline substrate.
- `crates/mvm-cli/src/commands/vm/up.rs::admit_plan_for_boot` — W3 callsite.
- `crates/mvm-cli/src/commands/vm/audit_chain.rs` — W4 audit emitter.
- `crates/mvm-cli/src/commands/ops/audit.rs` — `mvmctl audit verify / show / tail --chain` CLI surface.
- `crates/mvm-cli/src/commands/vm/policy_resolver.rs` — W5 `PolicyRef → ResolvedSlots` resolver substrate.
