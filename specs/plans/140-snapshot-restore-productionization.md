# Plan 140 — Snapshot/restore productionization (ms boot, security-correct)

## Context

Snapshot/restore (Firecracker base+delta) is the only way to true ms boot, and
`mvm/src/vm/instance/{lifecycle,snapshot}.rs` already implements it: base Full
snapshot per pool, per-instance delta, compression, drain-on-sleep, fresh
secrets/config disks + unique IP/ID on wake. But the restore path has four
security-correctness gaps that make it **not production-ready** as written. This
plan closes the mvm-side gaps. The warm-pool orchestration and wake-time
admission *policy* live in mvmd — see `../mvmd/specs/plans/53-warm-pool-ms-restore.md`.
The local single-host *idle-stop / wake / memory-pressure-evict* mechanism that
*triggers* this sleep/wake machinery (vs. the snapshot correctness gaps below)
lives in **Plan 170** (host-lifecycle convergence + density).

Backend scope: Firecracker / cloud-hypervisor (`caps.snapshots == true`).
libkrun + apple-container report `false` — no snapshot there, so the dev/libkrun
loop relies on Plan 139 cold-boot shaving instead.

**Backend reality (found 2026-06-02):** there's a *third* snapshot path that is
**macOS-native and already implemented** — `Vz::snapshot_save` /
`snapshot_restore` (`mvm-backend/src/vz.rs:678/708`, via
`VZVirtualMachine.saveMachineStateTo` / `restoreMachineStateFrom`, macOS 14+),
gated by `macos_supports_vz_snapshots()`. So the snapshot lever splits:
- **Firecracker/CH** — Linux/KVM; the fleet target; E2E-testable only on Linux
  (or Lima KVM). The four gaps below were written against this path.
- **Vz** — macOS-native, testable on a dev Mac *today*. The gaps map differently:
  entropy-reseed (#2), clock-resync (#3), and wake-admission (#4) all apply;
  seccomp-on-restore (#1) is FC-jailer-specific and **N/A to Vz** (Vz isolation
  isn't jailer+seccomp). Vz also needs its own "is restore wired into a fast-boot
  flow?" check (FC templates are wired into `up`; Vz may not be yet).

## Gaps to close (all confirmed in `lifecycle.rs`)

### 1. seccomp is OFF on restore — regresses claim 1
- [ ] `instance_wake` calls `jailer::launch_direct(…, None /* no seccomp for
      snapshot restore */)` (`lifecycle.rs:609`). Cold boot passes
      `seccomp_filter.as_deref()` (`:305/:316`) and runs
      `seccomp::ensure_strict_profile()` when `spec.seccomp_policy == "strict"`.
      → Restore must resolve and pass the **same** filter as cold boot. This is
      the host/FC-process jailer seccomp; the guest's in-VM seccomp is already
      preserved in the snapshotted memory. Small, self-contained fix.

### 2. No entropy reseed — shared-base RNG hazard
- [ ] N instances restored from one base share kernel RNG internal state →
      predictable randomness (TLS keys, nonces) across clones. On resume, the
      guest agent must reseed: pull fresh bytes from virtio-rng (or host-provided
      seed over vsock) and `RNDADDENTROPY` into `/dev/random`. Add an on-resume
      agent action; host provides a unique seed per wake.

  > **Substrate already shipped (plan 122 D):** `mvm_guest::genid::GenIdReseeder`
  > *is* the on-resume agent action — it tracks the host's per-wake
  > `mvm_core::crypto::vmgenid::GenerationToken` (content-bound, fresh per
  > resume) and reseeds on a change. It currently stirs `/dev/urandom` with the
  > token, so this gap is to **extend the reseed source** to virtio-rng (or a
  > vsock-delivered seed) + `RNDADDENTROPY` into `/dev/random` — `GenIdReseeder`
  > isolates the reseed source from the change-detection, so swap the source,
  > don't rebuild the detector. The host→guest **delivery** (send
  > `GuestRequest::PostRestore` carrying the token; call `GenIdReseeder::on_genid`
  > in the guest handler) is unwired today — no host `PostRestore` sender exists —
  > and lands with plan 123 C2/C3's restore round-trip.

### 3. No clock resync — frozen wallclock
- [ ] Restored VM resumes at snapshot wallclock. On resume the guest agent reads
      host time over vsock and `settimeofday()` (pairs with #2 in one on-resume
      hook). kvm-clock covers monotonic; this covers wallclock/RTC.

### 4. Wake bypasses plan admission — regresses claims 8/10  **(must fix)**
- [ ] Cold boot dispatches a signed `ExecutionPlan` (synthesize → sign → verify
      → G4 window/nonce → `plan.launched` chain entry). `instance_wake` only
      logs `InstanceWoken` — a restored workload is not re-bound to an admitted
      plan. → Wake must re-admit: verify the instance still corresponds to a
      valid admitted plan (or re-admit a fresh one for the wake), enforce the
      validity window + nonce, and emit `plan.launched`/equivalent to the
      chain-signed audit log before resuming vCPUs. The **policy** for what a
      "wake admission" requires is mvmd's call (see the mvmd plan); this plan
      wires the mvm-side admission/audit call into `instance_wake` so resume
      cannot happen without it.

## On-resume hook
Gaps 2+3 (and the guest half of 4) share one mechanism: an **on-resume agent
action** invoked by the host right after `restore_snapshot` resumes vCPUs and
before the instance is marked Running:
- [ ] Define `GuestRequest::Resume { unix_time_ms, entropy_seed }` (or extend the
      existing agent protocol) → guest settimeofday + RNDADDENTROPY, ACK.
- [ ] `instance_wake`: after restore, send Resume; gate `InstanceStatus::Running`
      on its ACK (with a bounded timeout, fail-closed).

## Files
- `crates/mvm/src/vm/instance/lifecycle.rs` — seccomp on restore (`:609`),
  admission/audit call before resume, on-resume hook dispatch.
- `crates/mvm/src/vm/instance/snapshot.rs` — restore returns enough state for
  the resume hook.
- `crates/mvm-guest/src/...` (agent) — Resume action: settimeofday + reseed.
- `crates/mvm-core` plan/audit — reuse the claim-8 `synthesize_plan` /
  `admit_for_run` / `AuditEmitter` path for the wake admission.

## Verification
- [ ] Restored FC process runs under the same seccomp filter as cold boot
      (assert the launch arg is non-None; negative test that a missing filter
      fails closed).
- [ ] Two instances from one base produce **different** `/dev/random` draws
      post-resume (entropy reseed regression test).
- [ ] Restored guest wallclock is within N ms of host post-resume.
- [ ] `instance_wake` refuses to reach Running without a valid admission + a
      `plan.launched` audit entry; `mvm_supervisor::verify_audit_chain` still
      passes across a sleep/wake cycle.
- [ ] `cargo fmt --all`, `cargo clippy --workspace -D warnings`, workspace tests.

## Notes
- ADR needed: re-admitting a restored VM is a security-model decision (does wake
  reuse the original admitted plan or mint a fresh one?). Draft an ADR alongside
  this plan; it interacts with ADR-002 claims 1/8/10.
