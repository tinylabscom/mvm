# Plan 119 — live `bench microvm-launch` probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `LibkrunProbe::measure_once` stub in
`mvmctl bench microvm-launch` with a real boot-measure-teardown cycle
that drives the claim-8 admission path and produces a committed
baseline.

**Architecture:** The probe resolves the canonical `default-microvm`
image, synthesizes + admits a signed `ExecutionPlan` (the same
`admit_for_run` path `mvmctl up` uses), threads it onto a
`VmStartConfig` via `populate_audit_substrate`, boots through
`LibkrunBackend::start`, polls the guest vsock control plane to
readiness, records four host-clock spans + the guest
`BootTimingReport`, then tears down with `LibkrunBackend::stop`. The
span arithmetic is a pure, unit-tested unit; the live boot is gated
behind a `libkrun-live` cargo feature so stock CI skips it.

**Tech Stack:** Rust, `mvm-cli` (`commands/ops/bench.rs`,
`commands/vm/plan_admission.rs`), `mvm-backend` (`LibkrunBackend`),
`mvm-plan` (`admit_for_run`, `SynthesisInput`), `mvm-core`
(`VmStartConfig`), `mvm-guest` (`BootTimingReport`).

---

## Design spec

`specs/plans/118-supervisor-standby-pool-and-live-bench.md`
(Part A). Read it first.

## File structure

- **Modify** `crates/mvm-cli/src/commands/ops/bench.rs` — replace the
  `LibkrunProbe::measure_once` stub; add the span-from-timestamps
  pure helper + its tests; add the `libkrun-live` live test.
- **Create** `crates/mvm-cli/src/commands/ops/bench_probe.rs` — the
  live boot orchestration (`boot_measure_once`) kept out of
  `bench.rs` so the pure substrate stays VM-free. Declared `#[cfg]`-
  agnostic but its body calls backend/admission code.
- **Modify** `crates/mvm-cli/src/commands/ops/mod.rs` — `mod
  bench_probe;`.
- **Modify** `crates/mvm-cli/Cargo.toml` — add the `libkrun-live`
  feature.
- **Reuse, do not copy:**
  `crates/mvm-cli/src/commands/vm/plan_admission.rs:246`
  `pub fn populate_audit_substrate(start_config: &mut VmStartConfig,
  admitted: &AdmittedPlan)`; `ensure_default_microvm_image()`
  (`commands/env/apple_container.rs:4220`,
  `-> Result<(String, String)>` = (kernel_path, rootfs_path));
  `LibkrunBackend` (`mvm-backend`, `VmBackend::{start,stop}`); the
  existing `LaunchProbe` / `IterationTiming` / `run_benchmark`
  substrate already in `bench.rs`.

## Pre-flight (one-time, not a code change)

Confirm the visibility seams the probe needs are reachable from
`commands/ops/`. Two are already `pub`
(`populate_audit_substrate`) or `pub(crate)`
(`ensure_default_microvm_image`); `admit_for_run` is re-exported from
`mvm_plan`. If any is narrower than the probe's module, widen it to
`pub(crate)` in the **same task** that first calls it (noted inline).

---

## Task 1: Pure span arithmetic from boot timestamps

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/bench.rs`
- Test: same file, `#[cfg(test)] mod tests`

The four `IterationTiming` spans are derived from four `Instant`s
captured during a boot. Isolating the arithmetic makes it unit-
testable without a VM.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `bench.rs`:

```rust
#[test]
fn spans_from_marks_are_non_negative_and_ordered() {
    use std::time::Duration;
    let t0 = std::time::Instant::now();
    let marks = BootMarks {
        start: t0,
        pid_seen: t0 + Duration::from_millis(10),
        connected: t0 + Duration::from_millis(25),
        ready: t0 + Duration::from_millis(40),
    };
    let it = marks.to_timing();
    approx(it.start_to_pid_ms, 10.0);
    approx(it.pid_to_connect_ms, 15.0);
    approx(it.handshake_ms, 15.0);
    approx(it.total_ready_ms, 40.0);
    // total is the full span, never less than any sub-span.
    assert!(it.total_ready_ms >= it.start_to_pid_ms);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-cli --lib spans_from_marks -- --nocapture`
Expected: FAIL — `BootMarks` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to `bench.rs` (near `IterationTiming`):

```rust
/// Four host-monotonic instants captured during one boot. `start` is
/// `LibkrunBackend::start` entry; `pid_seen` is when the supervisor
/// PID file first appears; `connected` is the first successful vsock
/// connect to the guest agent; `ready` is when the guest reports the
/// control plane Ready.
#[derive(Debug, Clone, Copy)]
pub struct BootMarks {
    pub start: std::time::Instant,
    pub pid_seen: std::time::Instant,
    pub connected: std::time::Instant,
    pub ready: std::time::Instant,
}

impl BootMarks {
    /// Collapse the marks into the four reported spans. All arithmetic
    /// is `Instant`-difference so it can never go negative for marks
    /// captured in order.
    pub fn to_timing(&self) -> IterationTiming {
        let ms = |a: std::time::Instant, b: std::time::Instant| {
            b.saturating_duration_since(a).as_secs_f64() * 1000.0
        };
        IterationTiming {
            start_to_pid_ms: ms(self.start, self.pid_seen),
            pid_to_connect_ms: ms(self.pid_seen, self.connected),
            handshake_ms: ms(self.connected, self.ready),
            total_ready_ms: ms(self.start, self.ready),
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-cli --lib spans_from_marks -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench.rs
git commit -m "feat(bench): plan 93 PR-10a — BootMarks span arithmetic"
```

---

## Task 2: `libkrun-live` cargo feature

**Files:**
- Modify: `crates/mvm-cli/Cargo.toml`

The live boot test and the live probe body must be excluded from
stock CI (hosted macOS runners lack HVF nested virt — see spec
"CI caveat"). A cargo feature gates them.

- [ ] **Step 1: Add the feature**

In `crates/mvm-cli/Cargo.toml`, under `[features]` (create the table
if absent):

```toml
[features]
# Opt-in lane for tests that boot a real libkrun guest. Off by
# default so `cargo test --workspace` on stock CI stays VM-free;
# enabled on a dev host / self-hosted macOS runner with the
# slp/krun Homebrew trio installed.
libkrun-live = []
```

- [ ] **Step 2: Verify it builds both ways**

Run: `cargo build -p mvm-cli && cargo build -p mvm-cli --features libkrun-live`
Expected: both succeed, no warnings.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/Cargo.toml
git commit -m "feat(bench): plan 93 PR-10a — libkrun-live test feature gate"
```

---

## Task 3: Probe config resolution (image + names)

**Files:**
- Create: `crates/mvm-cli/src/commands/ops/bench_probe.rs`
- Modify: `crates/mvm-cli/src/commands/ops/mod.rs`
- Test: `bench_probe.rs` `#[cfg(test)] mod tests`

Resolve the canonical runtime image the same way `mvmctl up` does —
**no artifact flags**. This step is the thin, VM-free part of the
orchestration and is unit-testable by asserting it returns the cached
default-microvm paths.

- [ ] **Step 1: Register the module**

In `crates/mvm-cli/src/commands/ops/mod.rs` add near the other
`mod` lines:

```rust
mod bench_probe;
```

- [ ] **Step 2: Write the failing test**

Create `bench_probe.rs` with:

```rust
//! Live boot orchestration for `mvmctl bench microvm-launch`. Kept
//! out of `bench.rs` so the pure stats/schema substrate stays
//! VM-free. See Plan 93 PR-10a.

use anyhow::{Context, Result};

use crate::commands::env::apple_container::ensure_default_microvm_image;

/// Resolved inputs for one benchmarked boot. `kernel`/`rootfs` come
/// from the same `ensure_default_microvm_image()` `mvmctl up` uses —
/// the canonical runtime image, NOT the dev-shell rootfs.
pub struct ProbeImage {
    pub kernel: String,
    pub rootfs: String,
}

/// Resolve the canonical default-microvm image (kernel + rootfs).
pub fn resolve_probe_image() -> Result<ProbeImage> {
    let (kernel, rootfs) =
        ensure_default_microvm_image().context("resolving default-microvm bench image")?;
    Ok(ProbeImage { kernel, rootfs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "touches ~/.cache/mvm; run on a host with the image cached"]
    fn resolve_probe_image_returns_existing_paths() {
        let img = resolve_probe_image().unwrap();
        assert!(std::path::Path::new(&img.kernel).exists());
        assert!(std::path::Path::new(&img.rootfs).exists());
    }
}
```

If `ensure_default_microvm_image` is not visible from
`commands::ops`, widen it to `pub(crate)` at
`commands/env/apple_container.rs:4220` in this step.

- [ ] **Step 3: Run the (ignored) test compiles + the crate builds**

Run: `cargo test -p mvm-cli --lib resolve_probe_image -- --ignored --nocapture`
Expected: PASS on a host with the image cached (this dev host has
`~/.cache/mvm/default-microvm/` populated); compiles everywhere.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench_probe.rs \
        crates/mvm-cli/src/commands/ops/mod.rs \
        crates/mvm-cli/src/commands/env/apple_container.rs
git commit -m "feat(bench): plan 93 PR-10a — resolve canonical probe image"
```

---

## Task 4: Synthesize + admit a plan for the probe boot

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/bench_probe.rs`
- Test: same file, `tests`

The probe must drive **real admission** (claim 8) — never a bypass.
Reuse `mvm_plan::admit_for_run` with a minimal `SynthesisInput`
mirroring `admit_plan_for_boot` (no bundle, no deps, default seccomp).
This is unit-testable with a tempdir `keys_dir` so it never writes
into the real `~/.mvm/keys/`.

- [ ] **Step 1: Write the failing test**

Add to `bench_probe.rs`:

```rust
#[cfg(test)]
mod admit_tests {
    use super::*;

    #[test]
    fn admit_probe_plan_produces_admitted_plan_with_tempdir_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"not a real rootfs but hashable").unwrap();
        let admitted = admit_probe_plan(&rootfs, "bench-probe", tmp.path()).unwrap();
        // The admitted plan binds the workload name we passed.
        assert_eq!(admitted.plan.image.name, "bench-probe");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-cli --lib admit_probe_plan -- --nocapture`
Expected: FAIL — `admit_probe_plan` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to `bench_probe.rs`:

```rust
use mvm_plan::{
    InMemoryNonceLedger, PlanSeccompTier, SecretReleasePolicy, SynthesisInput, SystemClock,
    admit_for_run, AdmittedPlan,
};

/// Synthesize → sign → verify → window → nonce a minimal plan for the
/// probe's boot, mirroring `up.rs::admit_plan_for_boot` minus bundle /
/// deps / policy. `keys_dir` is the host-signer directory; production
/// callers pass `~/.mvm/keys/` (via `None` at the call site that wraps
/// this), tests pass a tempdir.
pub fn admit_probe_plan(
    rootfs: &std::path::Path,
    vm_name: &str,
    keys_dir: &std::path::Path,
) -> Result<AdmittedPlan> {
    let sha = mvm_security::image_verify::sha256_file(rootfs)
        .with_context(|| format!("hashing probe rootfs {}", rootfs.display()))?;
    let input = SynthesisInput {
        vm_name,
        tenant: Some("bench"),
        backend_name: "libkrun",
        image_name: vm_name,
        image_sha256: &sha,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: SecretReleasePolicy::default(),
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: 2,
        mem_mib: 512,
        disk_mib: 0,
        boot_timeout_secs: 60,
        exec_timeout_secs: 0,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
    };
    let ledger = InMemoryNonceLedger::default();
    admit_for_run(&input, &SystemClock, &ledger, Some(keys_dir), None)
        .context("admitting probe plan")
}
```

If `PlanSeccompTier::Standard` / `SecretReleasePolicy::default()`
field names differ, mirror exactly what `up.rs::admit_plan_for_boot`
passes (it is the authority for this shape). Confirm by reading
`up.rs:251-289` before writing.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-cli --lib admit_probe_plan -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench_probe.rs
git commit -m "feat(bench): plan 93 PR-10a — synth+admit probe plan via admit_for_run"
```

---

## Task 5: Live boot → readiness → teardown (`libkrun-live`)

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/bench_probe.rs`

This is the only VM-touching code. It composes Tasks 3 + 4 + the
backend + readiness poll into one `boot_measure_once` returning
`BootMarks`. The whole function is `#[cfg(feature = "libkrun-live")]`
so stock builds never link it.

- [ ] **Step 1: Write the live boot function**

Add to `bench_probe.rs`:

```rust
#[cfg(feature = "libkrun-live")]
use crate::commands::ops::bench::BootMarks;

/// Boot the canonical image once through real admission, time the
/// four marks, and tear down. Returns the host-clock marks; the
/// caller converts to `IterationTiming`.
///
/// Order matches `up.rs`: resolve image → admit → build
/// `VmStartConfig` → `populate_audit_substrate` (threads tenant_id /
/// plan_json so libkrun takes the bridge path) → `start` → poll
/// readiness → `stop`.
#[cfg(feature = "libkrun-live")]
pub fn boot_measure_once(vm_name: &str) -> Result<BootMarks> {
    use std::time::Instant;
    use mvm_backend::{LibkrunBackend, VmBackend, VmId};
    use mvm_core::vm_backend::VmStartConfig;
    use crate::commands::vm::plan_admission::populate_audit_substrate;

    let img = resolve_probe_image()?;
    let keys = mvm_core::config::mvm_keys_dir(); // ~/.mvm/keys
    let admitted = admit_probe_plan(std::path::Path::new(&img.rootfs), vm_name, &keys)?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: 512,
        ..Default::default()
    };
    // Threads tenant_id / plan_json / bundle_json so libkrun re-verifies
    // and boots the admitted plan (claim 8) rather than the legacy path.
    populate_audit_substrate(&mut cfg, &admitted)?;

    let backend = LibkrunBackend;
    let start = Instant::now();
    backend.start(&cfg).context("probe backend.start")?;

    // pid_seen: the supervisor PID file under the per-VM state dir.
    let pid_seen = wait_for_pid_file(vm_name, start)?;
    // connected + ready: poll the guest vsock control plane.
    let (connected, ready) = wait_for_ready(vm_name, start)?;

    // Teardown: SIGTERM the supervisor + clean state so the next
    // iteration is a true cold start.
    backend
        .stop(&VmId(vm_name.to_string()))
        .context("probe backend.stop")?;

    Ok(BootMarks { start, pid_seen, connected, ready })
}
```

- [ ] **Step 2: Add the two poll helpers**

Add to `bench_probe.rs` (also `#[cfg(feature = "libkrun-live")]`).
These reuse the backend's per-VM state dir + the guest vsock `ping`
the `up` readiness path uses; confirm the exact state-dir accessor
(`mvm_backend::libkrun::vm_state_dir` or the public equivalent) and
the readiness call (`mvmctl::guest::vsock::ping` /
`request_readiness`) by reading `commands/vm/readiness.rs` before
writing — use whichever that module already calls so the probe and
`up` agree:

```rust
#[cfg(feature = "libkrun-live")]
fn wait_for_pid_file(vm_name: &str, start: std::time::Instant) -> Result<std::time::Instant> {
    use mvm_guest::vsock::adaptive_backoff;
    let pid_path = mvm_backend::libkrun::vm_state_dir(vm_name).join("libkrun.pid");
    for attempt in 0..600 {
        if pid_path.exists() {
            return Ok(std::time::Instant::now());
        }
        std::thread::sleep(adaptive_backoff(attempt));
        let _ = start; // start retained for span math by the caller
    }
    anyhow::bail!("probe: supervisor pid file never appeared at {}", pid_path.display())
}

#[cfg(feature = "libkrun-live")]
fn wait_for_ready(
    vm_name: &str,
    _start: std::time::Instant,
) -> Result<(std::time::Instant, std::time::Instant)> {
    use mvm_guest::vsock::adaptive_backoff;
    let dir = mvm_backend::libkrun::vm_state_dir(vm_name);
    let dir_str = dir.to_string_lossy().into_owned();
    let mut connected: Option<std::time::Instant> = None;
    for attempt in 0..600 {
        // `ping` returns Ok(true) once the guest agent's control plane
        // is bound and answering — the same readiness signal `up` uses.
        match mvmctl::guest::vsock::ping(&dir_str) {
            Ok(true) => {
                let now = std::time::Instant::now();
                let c = connected.unwrap_or(now);
                return Ok((c, now));
            }
            Ok(false) | Err(_) => {
                if connected.is_none() {
                    // First successful socket connect is the handshake
                    // start; `ping` connects before it gets a false, so
                    // stamp connect on the first non-refused attempt.
                    connected = Some(std::time::Instant::now());
                }
            }
        }
        std::thread::sleep(adaptive_backoff(attempt));
    }
    anyhow::bail!("probe: guest control plane never reached Ready")
}
```

> Note: if `ping` does not distinguish "connected but not ready" from
> "connection refused", split it: use a raw vsock UDS connect for the
> `connected` mark (path from `KrunContext::vsock_socket_path` under
> the state dir) and `ping`/readiness for the `ready` mark. Read
> `mvm-guest/src/vsock.rs:2144` (`ping`) +
> `commands/vm/readiness.rs` first and use whichever distinction
> those already expose. Do not invent a new wire call.

- [ ] **Step 3: Verify it compiles under the feature**

Run: `cargo build -p mvm-cli --features libkrun-live`
Expected: compiles; resolve any signature drift against the real
`vm_state_dir` / `ping` / `populate_audit_substrate` signatures.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench_probe.rs
git commit -m "feat(bench): plan 93 PR-10a — live boot_measure_once (libkrun-live)"
```

---

## Task 6: Wire `LibkrunProbe::measure_once` to the live boot

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/bench.rs`

Replace the `bail!` stub. Under `libkrun-live`, call
`boot_measure_once`; without the feature, keep an explicit
`bail!` that tells the user to rebuild with the feature (so a stock
binary fails honestly rather than silently faking a number).

- [ ] **Step 1: Replace the stub body**

In `bench.rs`, change `LibkrunProbe::measure_once` to:

```rust
fn measure_once(&mut self) -> Result<IterationTiming> {
    #[cfg(feature = "libkrun-live")]
    {
        // Unique name per iteration so teardown of run N never races
        // the cold start of run N+1.
        self.iter += 1;
        let name = format!("mvm-bench-{}", self.iter);
        let marks = crate::commands::ops::bench_probe::boot_measure_once(&name)?;
        return Ok(marks.to_timing());
    }
    #[cfg(not(feature = "libkrun-live"))]
    {
        bail!(
            "bench microvm-launch: this binary was built without the \
             `libkrun-live` feature, so it cannot boot a real guest. \
             Rebuild with `cargo build -p mvm-cli --features libkrun-live` \
             on a host where libkrun boots (the slp/krun Homebrew trio \
             installed). The measurement substrate is otherwise complete."
        )
    }
}
```

Add an `iter: u32` field to `LibkrunProbe` (init `0` in `new`).

- [ ] **Step 2: Build both feature states**

Run: `cargo build -p mvm-cli && cargo build -p mvm-cli --features libkrun-live`
Expected: both compile. Stock build still `bail!`s (no behavior
regression); feature build links the live path.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench.rs
git commit -m "feat(bench): plan 93 PR-10a — wire LibkrunProbe to live boot"
```

---

## Task 7: Live integration test (`libkrun-live`)

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/bench.rs`

- [ ] **Step 1: Write the live test**

Add to `bench.rs` `tests` module:

```rust
#[cfg(feature = "libkrun-live")]
#[test]
fn live_probe_returns_finite_ordered_spans() {
    let mut probe = LibkrunProbe::new(&MicrovmLaunchArgs {
        runs: 1,
        warmup: 0,
        hypervisor: "libkrun".to_string(),
        out: None,
        json: false,
        baseline: None,
        max_regression_pct: 10.0,
    })
    .unwrap();
    let it = probe.measure_once().expect("live boot should succeed on a libkrun host");
    for v in [it.start_to_pid_ms, it.pid_to_connect_ms, it.handshake_ms, it.total_ready_ms] {
        assert!(v.is_finite() && v >= 0.0, "span must be finite and non-negative: {v}");
    }
    assert!(it.total_ready_ms >= it.start_to_pid_ms);
}
```

- [ ] **Step 2: Run the live test on this host**

Run: `cargo test -p mvm-cli --features libkrun-live --lib live_probe_returns_finite_ordered_spans -- --nocapture`
Expected: PASS — boots the cached default-microvm image, reaches
`control plane ready`, tears down. (This is the gate that proves the
probe works; it runs on this dev host, not stock CI.)

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench.rs
git commit -m "test(bench): plan 93 PR-10a — libkrun-live probe integration test"
```

---

## Task 8: Generate + commit the first baseline

**Files:**
- Create: `crates/mvm-cli/tests/fixtures/bench/microvm-launch-baseline.json`
  (or the repo's existing bench-fixture location — confirm before
  writing)

- [ ] **Step 1: Run the bench on this host**

Run:
```bash
cargo run -p mvm-cli --features libkrun-live -- \
  bench microvm-launch --runs 20 --warmup 2 --json \
  --out /tmp/microvm-launch-baseline.json
```
Expected: prints `median total_ready_ms=…`; writes the JSON report.

- [ ] **Step 2: Sanity-check the report**

Run: `jq '.schema_version, .host, .total_ready_ms.p50' /tmp/microvm-launch-baseline.json`
Expected: `schema_version` = 1, a populated `host` descriptor, a
finite `p50`.

- [ ] **Step 3: Commit the baseline**

```bash
mkdir -p crates/mvm-cli/tests/fixtures/bench
cp /tmp/microvm-launch-baseline.json \
   crates/mvm-cli/tests/fixtures/bench/microvm-launch-baseline.json
git add crates/mvm-cli/tests/fixtures/bench/microvm-launch-baseline.json
git commit -m "test(bench): plan 93 PR-10a — committed libkrun launch baseline"
```

---

## Task 9: Populate `HostDescriptor` (libkrun version + kernel sha)

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/bench.rs`
  (`LibkrunProbe::host_descriptor`)

The regression gate (`compare_to_baseline`) refuses to compare across
differing `HostDescriptor`s. Today the probe leaves `libkrun_version`
/ `kernel_sha256` / `cmdline` as `None`, so a kernel swap would *not*
invalidate the baseline — a false-green risk. Fill them in.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
#[cfg(feature = "libkrun-live")]
fn host_descriptor_is_populated() {
    let probe = LibkrunProbe::new(&MicrovmLaunchArgs {
        runs: 1, warmup: 0, hypervisor: "libkrun".into(),
        out: None, json: false, baseline: None, max_regression_pct: 10.0,
    }).unwrap();
    let h = probe.host_descriptor();
    assert!(h.kernel_sha256.is_some(), "kernel sha must be set so a kernel swap invalidates the baseline");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-cli --features libkrun-live --lib host_descriptor_is_populated`
Expected: FAIL — `kernel_sha256` is `None`.

- [ ] **Step 3: Implement**

In `host_descriptor`, set `kernel_sha256` from the resolved image
kernel via `mvm_security::image_verify::sha256_file`, and
`cmdline` from the libkrun runtime cmdline constant the backend uses
(`console=hvc0 root=/dev/vda rw init=/init` — confirm against the
backend's `build_supervisor_config`). Leave `libkrun_version`
`None` only if no accessor exists; otherwise read it.

```rust
fn host_descriptor(&self) -> HostDescriptor {
    let kernel_sha256 = bench_probe::resolve_probe_image()
        .ok()
        .and_then(|img| mvm_security::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok());
    HostDescriptor {
        os: self.os.clone(),
        arch: self.arch.clone(),
        hypervisor: "libkrun".to_string(),
        libkrun_version: None,
        kernel_sha256,
        cmdline: Some("console=hvc0 root=/dev/vda rw init=/init".to_string()),
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p mvm-cli --features libkrun-live --lib host_descriptor_is_populated`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/bench.rs
git commit -m "feat(bench): plan 93 PR-10a — populate HostDescriptor kernel sha + cmdline"
```

---

## Task 10: Tick the plan + workspace gate

**Files:**
- Modify: `specs/plans/93-fast-secure-dev-path-followups.md`
- Modify: `specs/SPRINT.md`

- [ ] **Step 1: Tick the checkboxes**

In `specs/SPRINT.md` Sprint 59, change the PR-1 line's note and add a
ticked PR-10a entry; in `specs/plans/93-fast-secure-dev-path-followups.md`
tick "Benchmark harness lands first" under Phase 2 (the live probe
completes it). In the PR-10a design spec, tick the PR-10a ship
checklist boxes.

- [ ] **Step 2: Full workspace gate**

Run:
```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: fmt clean; all tests pass (the `libkrun-live` tests are
**not** in this run — they're feature-gated off by default); clippy
zero warnings. Also run once *with* the feature on this host:
`cargo clippy -p mvm-cli --features libkrun-live --all-targets -- -D warnings`.

- [ ] **Step 3: Commit**

```bash
git add specs/
git commit -m "docs(plans): plan 93 PR-10a — tick live bench probe landed"
```

---

## Self-review notes

- **Spec coverage:** PR-10a ship checklist items map to Tasks
  3+4+5+6 (boot through admit_for_run, no flags), 5 (BootTimingReport
  cross-check — fold the guest report read into `wait_for_ready` when
  wiring the readiness call), 7 (libkrun-live test), 8 (baseline),
  9 (HostDescriptor). The `BootTimingReport` cross-check is recorded
  but deliberately NOT folded into host spans (spec: clock-domain
  mixing) — capture it in `boot_measure_once` and log it, don't add
  it to `IterationTiming`.
- **Confirm-before-write seams** (flagged inline; these are *known
  existing* functions whose exact signature must be read first, not
  invented): `populate_audit_substrate`
  (`plan_admission.rs:246`), `SynthesisInput` field names
  (`up.rs:251`), `vm_state_dir` accessor + `ping` semantics
  (`mvm-backend/src/libkrun.rs`, `mvm-guest/src/vsock.rs:2144`,
  `commands/vm/readiness.rs`), `mvm_core::config::mvm_keys_dir`.
- **No stock-CI false green:** the regression gate + substrate stay
  CI-covered; the live lane is feature-gated and host-run only.
