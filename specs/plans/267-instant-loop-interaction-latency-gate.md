# Instant-Loop Interaction-Latency Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the microVM interaction round-trip latency baseline (host↔guest `Ping` over the vsock control plane) as a dev/CI gate, reusing the existing benchmark harness, and remove benchmarking from the shipped CLI.

**Architecture:** Relocate the existing `ops bench` harness out of the CLI command tree into a `pub` library module (`crate::bench`), add an `InteractionProbe` that measures cold RPC (fresh dial + authenticated handshake + one `Ping`) and warm RPC (N `Ping`s over one held `ControlSession`), drive it from a feature-gated Rust integration test, then delete the user-facing `ops bench` verb. The measurement speaks only vsock RPC, so it is backend-agnostic (FC/HVF/libkrun measured through identical code).

**Tech Stack:** Rust, `mvm-cli` (lib target `mvm_cli`), `mvm-agentd::vsock` (`ControlSession`, `GuestRequest::Ping`), `mvm-runtime::vsock_transport`, existing `crate::bench` stats/report/regression helpers, `libkrun-live` feature gate.

## Global Constraints

- Rust best practices are binding: traits/enums over stringly-typed flags, exhaustive matches, builder/config struct for many-field types. Never `#[allow(clippy::...)]` in hand-written code.
- No plan/PR/ADR/issue references in code comments (CI-gated: `Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` are banned). Reword to the underlying concept.
- Never name the no-OS competitor as a proper noun in any committed file or commit message; refer to it obliquely ("the no-OS micro-isolation tier").
- All `~/.mvm` paths go through `mvm_core::config` helpers — never inline `$HOME/.mvm`.
- Live VM code is gated behind the `libkrun-live` Cargo feature and `bail!`s honestly (never fabricates numbers) when built without it.
- No user-facing CLI verb is added; benchmarking is a dev/CI gate only.
- Gates before any push: `rustup run nightly cargo fmt --all -- --check`; `cargo nextest run --workspace`; `cargo test --workspace --doc`; `cargo clippy --workspace -- -D warnings`; `cargo build --all-targets` clean.
- Spec of record: `specs/notes/2026-07-27-instant-loop-benchmark-design.md`.

---

## File Structure

**Relocated (Task 1), from `crates/mvm-cli/src/commands/ops/` → `crates/mvm-cli/src/bench/`:**
- `bench/mod.rs` — module root; re-exports; `write_report_with_latest` + report-path helpers; the verb glue (temporary, deleted Task 5).
- `bench/harness.rs` — `LaunchProbe` trait, `run_benchmark`, `run_launch_distribution`, footprint readers (unchanged).
- `bench/probes.rs` — live `LaunchProbe` impls (unchanged).
- `bench/report.rs` — report schemas + persistence (unchanged; consumed by new code).
- `bench/stats.rs` — `percentile`, `summarize`, `IterationTiming`, `BootMarks` (unchanged).
- `bench/regression.rs` — baseline comparison (unchanged).
- `bench/probe.rs` — the relocated `bench_probe.rs` (live boot orchestration; `boot_hold_once`, `HeldProbeVm`).

**New:**
- `crates/mvm-cli/src/bench/interaction.rs` — interaction measurement: pure types + aggregation (`InteractionTimings`, `SloVerdict`, `InstantLoopReport`, `build_instant_loop_report`, `interaction_verdict`) and, under `libkrun-live`, the live `InteractionRunCfg` / `measure_interaction` / `run_instant_loop`.
- `crates/mvm-cli/tests/instant_loop.rs` — feature-gated live integration-test gate.

**Modified:**
- `crates/mvm-cli/src/lib.rs` — add `pub mod bench;`.
- `crates/mvm-cli/src/commands/ops/mod.rs` — drop `bench` / `bench_probe` submodules.
- `crates/mvm-cli/src/commands/ops/group.rs` — Task 5 deletes the `Bench` verb.
- `crates/mvm-cli/tests/cli.rs` — Task 5 updates help snapshots.
- `public/src/content/docs/reference/cli-commands.md` — Task 5 removes bench rows.

---

## Task 1: Relocate the bench harness to a `pub` library module

Behavior-preserving move: the `ops bench` verb keeps working; only the module *home* and visibility change. This isolates the mechanical move from the new measurement (Task 2+) and the verb deletion (Task 5).

**Files:**
- Move: `crates/mvm-cli/src/commands/ops/bench/*` → `crates/mvm-cli/src/bench/*`
- Move: `crates/mvm-cli/src/commands/ops/bench_probe.rs` → `crates/mvm-cli/src/bench/probe.rs`
- Modify: `crates/mvm-cli/src/lib.rs`, `crates/mvm-cli/src/commands/ops/mod.rs`, `crates/mvm-cli/src/commands/ops/group.rs`

**Interfaces:**
- Produces: `crate::bench` module (pub) re-exporting `harness`, `probes`, `report`, `stats`, `regression`, `probe`, plus `pub fn write_report_with_latest`. `crate::bench::probe::{boot_hold_once, boot_measure_once, HeldProbeVm}` (libkrun-live). `crate::bench::stats::{BootMarks, IterationTiming, percentile, summarize}`. `crate::bench::report::{HostDescriptor, TailLatencyStats, summarize_tail_latency, write_json_report}`.

- [ ] **Step 1: Move the files with git (preserve history)**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-instant-loop
git mv crates/mvm-cli/src/commands/ops/bench crates/mvm-cli/src/bench
git mv crates/mvm-cli/src/bench/bench_probe.rs crates/mvm-cli/src/bench/probe.rs 2>/dev/null || \
  git mv crates/mvm-cli/src/commands/ops/bench_probe.rs crates/mvm-cli/src/bench/probe.rs
```

- [ ] **Step 2: Register the module and de-register the old paths**

In `crates/mvm-cli/src/lib.rs`, add near the other top-level `mod`/`pub mod` declarations:

```rust
pub mod bench;
```

In `crates/mvm-cli/src/commands/ops/mod.rs`, delete these two lines:

```rust
pub(super) mod bench;
pub(super) mod bench_probe;
```

In `crates/mvm-cli/src/bench/mod.rs`, add the relocated probe as a submodule (near the other `mod` lines at the top):

```rust
pub mod probe;
```

- [ ] **Step 3: Fix cross-module paths and visibilities**

In `crates/mvm-cli/src/bench/mod.rs`:
- Change every submodule declaration `mod harness;` … to `pub mod harness; pub mod probes; pub mod regression; pub mod report; pub mod stats;` (they must be reachable from `crate::bench::…` and the integration test).
- Change `pub(super) fn write_report_with_latest` to `pub fn write_report_with_latest`.
- The `#[cfg(feature = "libkrun-live")] pub use stats::BootMarks;` and `pub(in crate::commands::ops) use probes::write_boot_timing_sidecar;` re-exports: change `pub(in crate::commands::ops)` to `pub(crate)`.
- The verb glue types (`Args`, `BenchAction`, `MicrovmLaunchArgs`, `MicrovmDensityArgs`) carry `pub(in crate::commands)` — change to `pub(crate)`. The `run` fn `pub(in crate::commands) fn run` → `pub(crate) fn run`.

In `crates/mvm-cli/src/bench/probe.rs`:
- Change `use crate::commands::ops::bench::BootMarks;` → `use super::stats::BootMarks;`.
- Change `super::bench::write_boot_timing_sidecar(...)` → `super::probes::write_boot_timing_sidecar(...)` (now a sibling under `crate::bench`).
- Leave `crate::commands::vm::wait::fetch_readiness` and `crate::commands::env::builder_vm::ensure_default_microvm_image` untouched — those paths are still valid.

In `crates/mvm-cli/src/bench/mod.rs` where it references the probe (`crate::commands::ops::bench_probe::boot_hold_once`), change to `crate::bench::probe::boot_hold_once` (or `probe::boot_hold_once`).

In `crates/mvm-cli/src/commands/ops/group.rs`, change the import and dispatch to the new path:

```rust
use crate::bench;                 // was: use super::{bench, config, metrics};  → keep config, metrics from super
// dispatch arm stays: OpsCmd::Bench(a) => bench::run(cli, a, cfg),
```

Keep `config`/`metrics`/`mcp` imports from `super` as they are; only `bench` moves to `crate::bench`.

- [ ] **Step 4: Build and run the existing bench unit tests to prove the move is behavior-preserving**

Run:
```bash
cargo build -p mvm-cli 2>&1 | tail -20
cargo nextest run -p mvm-cli bench:: 2>&1 | tail -30
```
Expected: build clean; the relocated unit tests (`percentile_*`, `summarize_*`, `report_json_roundtrips`, `run_benchmark_*`, `microvm_launch_rejects_*`, etc.) all PASS. Fix any remaining path/visibility error until green.

- [ ] **Step 5: Confirm the verb still resolves (no behavior change)**

Run:
```bash
cargo run -p mvm-cli -- ops bench --help 2>&1 | tail -20
```
Expected: help text for `microvm-launch` / `microvm-density` prints unchanged.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(mvm-cli): relocate bench harness to a pub library module

Move the launch/density benchmark harness out of the ops command tree into
crate::bench so it can be driven by tests rather than a user verb. Pure move:
the ops bench verb still works and all bench unit tests pass unchanged."
```

---

## Task 2: Pure interaction types + aggregation

The VM-free half of the interaction measurement: sample containers, the report schema, and aggregation that reuses the existing percentile/tail-latency helpers. Fully unit-testable without a backend.

**Files:**
- Create: `crates/mvm-cli/src/bench/interaction.rs`
- Modify: `crates/mvm-cli/src/bench/mod.rs` (add `pub mod interaction;`)

**Interfaces:**
- Consumes: `crate::bench::report::{HostDescriptor, TailLatencyStats, summarize_tail_latency}`, `crate::bench::stats::{IterationTiming, percentile, BENCH_SCHEMA_VERSION}`.
- Produces: `InteractionTimings { cold_rtt_ms: Vec<f64>, warm_rtt_ms: Vec<f64> }`; `SloVerdict { warm_p50_ms, budget_ms, within_budget }`; `InstantLoopReport { schema_version, host, start_boot, interaction_cold_rtt_ms, interaction_warm_rtt, interaction_verdict }`; `pub const WARM_RPC_P50_BUDGET_MS: f64`; `pub fn interaction_verdict(&TailLatencyStats, f64) -> SloVerdict`; `pub fn build_instant_loop_report(HostDescriptor, IterationTiming, &InteractionTimings, f64) -> InstantLoopReport`.

- [ ] **Step 1: Register the module**

In `crates/mvm-cli/src/bench/mod.rs` add:

```rust
pub mod interaction;
```

- [ ] **Step 2: Write the failing test**

Create `crates/mvm-cli/src/bench/interaction.rs` with only the test module for now:

```rust
//! Interaction round-trip latency: cold RPC (fresh dial + handshake + one
//! Ping) vs warm RPC (N Pings over one held session). The steady warm p50 is
//! the number the "feels instant" budget is set against.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::report::HostDescriptor;
    use crate::bench::stats::IterationTiming;

    fn host() -> HostDescriptor {
        HostDescriptor {
            os: "macos".into(),
            arch: "aarch64".into(),
            hypervisor: "libkrun".into(),
            libkrun_version: Some("1.0".into()),
            kernel_sha256: Some("deadbeef".into()),
            cmdline: Some("root=/dev/vda rw init=/init".into()),
            readiness_boundary: Some("guest-agent-ping".into()),
        }
    }

    fn boot() -> IterationTiming {
        IterationTiming {
            start_to_pid_ms: 5.0,
            pid_to_connect_ms: 3.0,
            handshake_ms: 2.0,
            total_ready_ms: 40.0,
        }
    }

    #[test]
    fn report_aggregates_cold_median_and_warm_tail() {
        let timings = InteractionTimings {
            cold_rtt_ms: vec![4.0, 6.0, 5.0],       // median 5.0
            warm_rtt_ms: vec![1.0, 1.0, 2.0, 3.0, 4.0],
        };
        let report = build_instant_loop_report(host(), boot(), &timings, WARM_RPC_P50_BUDGET_MS);
        assert_eq!(report.interaction_cold_rtt_ms, 5.0);
        assert_eq!(report.interaction_warm_rtt.p50, 2.0);
        assert_eq!(report.start_boot.total_ready_ms, 40.0);
    }

    #[test]
    fn verdict_boundary_is_inclusive() {
        let at = TailLatencyStats { p50: 2.0, p95: 2.0, p99: 2.0 };
        assert!(interaction_verdict(&at, 2.0).within_budget); // == budget passes
        let over = TailLatencyStats { p50: 2.001, p95: 3.0, p99: 4.0 };
        assert!(!interaction_verdict(&over, 2.0).within_budget);
    }

    #[test]
    fn report_json_roundtrips() {
        let timings = InteractionTimings { cold_rtt_ms: vec![5.0], warm_rtt_ms: vec![1.0, 2.0] };
        let report = build_instant_loop_report(host(), boot(), &timings, 2.0);
        let json = serde_json::to_string(&report).unwrap();
        let back: InstantLoopReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.interaction_verdict, report.interaction_verdict);
        assert_eq!(back.interaction_cold_rtt_ms, report.interaction_cold_rtt_ms);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-cli bench::interaction 2>&1 | tail -20`
Expected: FAIL to compile — `InteractionTimings`, `build_instant_loop_report`, etc. not defined.

- [ ] **Step 4: Write the implementation**

Prepend to `crates/mvm-cli/src/bench/interaction.rs` (above the test module):

```rust
use serde::{Deserialize, Serialize};

use super::report::{HostDescriptor, TailLatencyStats, summarize_tail_latency};
use super::stats::{BENCH_SCHEMA_VERSION, IterationTiming, percentile};

/// Warm-RPC p50 budget (ms): a local vsock encrypted round-trip. A working
/// hypothesis pending the first clean baseline; the verdict is recorded, not
/// gating, until a committed baseline ratchets it down.
pub const WARM_RPC_P50_BUDGET_MS: f64 = 2.0;

/// Raw per-sample interaction round-trips, milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InteractionTimings {
    /// One fresh dial + handshake + Ping each; median is reported.
    pub cold_rtt_ms: Vec<f64>,
    /// Sequential Pings over one held session.
    pub warm_rtt_ms: Vec<f64>,
}

/// Warm p50 measured against the budget.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct SloVerdict {
    pub warm_p50_ms: f64,
    pub budget_ms: f64,
    pub within_budget: bool,
}

/// Compare a warm-RPC tail against the budget (inclusive at the boundary).
pub fn interaction_verdict(warm: &TailLatencyStats, budget_ms: f64) -> SloVerdict {
    SloVerdict {
        warm_p50_ms: warm.p50,
        budget_ms,
        within_budget: warm.p50 <= budget_ms,
    }
}

/// One instant-loop measurement: a single cold boot's timing plus the cold and
/// warm interaction round-trips. Start is cold-boot only; a warm-start field is
/// intentionally absent until a warm-restore path exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantLoopReport {
    pub schema_version: u32,
    pub host: HostDescriptor,
    pub start_boot: IterationTiming,
    pub interaction_cold_rtt_ms: f64,
    pub interaction_warm_rtt: TailLatencyStats,
    pub interaction_verdict: SloVerdict,
}

/// Collapse raw interaction samples into the report, reusing the shared
/// percentile / tail-latency helpers.
pub fn build_instant_loop_report(
    host: HostDescriptor,
    start_boot: IterationTiming,
    timings: &InteractionTimings,
    budget_ms: f64,
) -> InstantLoopReport {
    let warm = summarize_tail_latency(&timings.warm_rtt_ms);
    InstantLoopReport {
        schema_version: BENCH_SCHEMA_VERSION,
        host,
        start_boot,
        interaction_cold_rtt_ms: percentile(&timings.cold_rtt_ms, 50.0),
        interaction_warm_rtt: warm,
        interaction_verdict: interaction_verdict(&warm, budget_ms),
    }
}
```

Add `use super::report::TailLatencyStats;` is already covered; ensure the test module's `TailLatencyStats` reference resolves (it uses `super::*`, so re-export is automatic).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-cli bench::interaction 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(mvm-cli): interaction latency report schema + aggregation

Pure, VM-free half of the instant-loop measurement: cold/warm RPC sample
containers, the SLO verdict, and the report that reuses the shared percentile
and tail-latency helpers."
```

---

## Task 3: Live interaction probe + `run_instant_loop`

The `libkrun-live` half: boot one VM through the existing probe, measure cold and warm `Ping` RTT over vsock, and assemble the report. Backend-agnostic dial (works on FC/HVF/libkrun); no edit to the shared `rpc.rs` hot path — the timer wraps `ControlSession::call_unary` from outside.

**Files:**
- Modify: `crates/mvm-cli/src/bench/interaction.rs` (add the `libkrun-live` section)
- Modify: `crates/mvm-cli/src/bench/probe.rs` (add `HeldProbeVm::marks()` accessor)

**Interfaces:**
- Consumes: `crate::bench::probe::{boot_hold_once, HeldProbeVm}`, `crate::bench::probes::LibkrunProbe`, `crate::bench::harness::LaunchProbe` (for `host_descriptor()`), `mvm_agentd::vsock::{ControlSession, GuestRequest, GuestResponse, GUEST_AGENT_PORT}`, `mvm_runtime::vsock_transport`.
- Produces: `InteractionRunCfg { cold_samples, warmup, samples }` (+ `Default`); `pub fn measure_interaction(&str, &InteractionRunCfg) -> Result<InteractionTimings>`; `pub fn run_instant_loop(&str, &InteractionRunCfg, f64) -> Result<InstantLoopReport>`.

- [ ] **Step 1: Add the `marks()` accessor to `HeldProbeVm`**

In `crates/mvm-cli/src/bench/probe.rs`, inside `impl HeldProbeVm` (the `#[cfg(feature = "libkrun-live")]` block that already has `vm_name`/`pid`), add:

```rust
    /// The four boot marks captured for this VM (`BootMarks` is `Copy`).
    pub fn marks(&self) -> BootMarks {
        self.marks
    }
```

- [ ] **Step 2: Add the live measurement to `interaction.rs`**

Append to `crates/mvm-cli/src/bench/interaction.rs` (after the pure section, before `#[cfg(test)] mod tests`):

```rust
/// Sample counts for one interaction measurement.
#[cfg(feature = "libkrun-live")]
#[derive(Debug, Clone, Copy)]
pub struct InteractionRunCfg {
    /// Fresh dial+handshake+Ping sessions (cold RPC); median reported.
    pub cold_samples: u32,
    /// Warm Pings discarded before measuring, to settle the held session.
    pub warmup: u32,
    /// Measured warm Pings over the held session.
    pub samples: u32,
}

#[cfg(feature = "libkrun-live")]
impl Default for InteractionRunCfg {
    fn default() -> Self {
        Self { cold_samples: 10, warmup: 20, samples: 200 }
    }
}

/// Open a fresh authenticated session, issue one Ping, and confirm Pong.
/// Used both as the cold-RPC sample and to seed the warm loop.
#[cfg(feature = "libkrun-live")]
fn ping_once_cold(vm_name: &str) -> anyhow::Result<f64> {
    use std::time::Instant;

    use mvm_agentd::vsock::{ControlSession, GUEST_AGENT_PORT, GuestRequest, GuestResponse};

    let t = Instant::now();
    // Mirror the backend-agnostic dial used by `mvmctl fs`/`proc`:
    // `mvm_runtime::vsock_transport::for_vm(name).connect(GUEST_AGENT_PORT)`.
    let mut stream = mvm_runtime::vsock_transport::for_vm(vm_name)?.connect(GUEST_AGENT_PORT)?;
    let mut session = ControlSession::open(&mut stream)?;
    let resp = session.call_unary(&mut stream, &GuestRequest::Ping)?;
    anyhow::ensure!(matches!(resp, GuestResponse::Pong), "cold ping: expected Pong");
    Ok(t.elapsed().as_secs_f64() * 1000.0)
}

/// Measure cold and warm interaction RTT against an already-booted VM.
#[cfg(feature = "libkrun-live")]
pub fn measure_interaction(
    vm_name: &str,
    cfg: &InteractionRunCfg,
) -> anyhow::Result<InteractionTimings> {
    use std::time::Instant;

    use mvm_agentd::vsock::{ControlSession, GUEST_AGENT_PORT, GuestRequest, GuestResponse};

    let mut cold = Vec::with_capacity(cfg.cold_samples as usize);
    for _ in 0..cfg.cold_samples {
        cold.push(ping_once_cold(vm_name)?);
    }

    // Warm: one held session, timer around each call_unary write→read.
    let mut stream = mvm_runtime::vsock_transport::for_vm(vm_name)?.connect(GUEST_AGENT_PORT)?;
    let mut session = ControlSession::open(&mut stream)?;
    for _ in 0..cfg.warmup {
        let _ = session.call_unary(&mut stream, &GuestRequest::Ping)?;
    }
    let mut warm = Vec::with_capacity(cfg.samples as usize);
    for _ in 0..cfg.samples {
        let t = Instant::now();
        let resp = session.call_unary(&mut stream, &GuestRequest::Ping)?;
        anyhow::ensure!(matches!(resp, GuestResponse::Pong), "warm ping: expected Pong");
        warm.push(t.elapsed().as_secs_f64() * 1000.0);
    }

    Ok(InteractionTimings { cold_rtt_ms: cold, warm_rtt_ms: warm })
}

/// Boot one VM, capture its cold-boot start timing, measure interaction RTT,
/// tear it down, and assemble the report.
#[cfg(feature = "libkrun-live")]
pub fn run_instant_loop(
    vm_name: &str,
    cfg: &InteractionRunCfg,
    budget_ms: f64,
) -> anyhow::Result<InstantLoopReport> {
    use crate::bench::harness::LaunchProbe;
    use crate::bench::probes::LibkrunProbe;

    let host = LibkrunProbe::new_with_prefix(format!("{vm_name}-host"))?.host_descriptor();
    let held = crate::bench::probe::boot_hold_once(vm_name)?;
    let start_boot = held.marks().to_timing();
    let timings = measure_interaction(vm_name, cfg)?;
    drop(held); // RAII teardown
    Ok(build_instant_loop_report(host, start_boot, &timings, budget_ms))
}
```

Note: confirm the exact dial expression against a real call site — `crates/mvm-cli/src/commands/vm/invoke.rs` `dispatch_inner` uses `mvm_runtime::vsock_transport::for_vm(vm).connect(GUEST_AGENT_PORT)`. Copy its precise form (the method name and whether `?` applies to `for_vm` and/or `connect`).

- [ ] **Step 3: Build with the live feature to verify it compiles**

Run: `cargo build -p mvm-cli --features libkrun-live 2>&1 | tail -25`
Expected: clean build. Fix any signature mismatch on `for_vm(...).connect(...)` by matching the real call site cited above.

- [ ] **Step 4: Verify the stock (no-feature) build still compiles (live code excluded)**

Run: `cargo build -p mvm-cli 2>&1 | tail -10`
Expected: clean; the `libkrun-live` section is excluded.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(mvm-cli): live interaction probe over a held vsock session

Boot one VM, measure cold RPC (fresh dial+handshake+Ping) and warm RPC (N Pings
over one held ControlSession), assemble the instant-loop report. Backend-agnostic
dial; the warm timer wraps call_unary externally with no rpc.rs change."
```

---

## Task 4: Feature-gated live integration-test gate

The gate itself: a `libkrun-live` integration test that boots one VM, measures, asserts the invariants (warm p50 beats cold; stats finite), records the verdict, and persists the report. Compiles to nothing without the feature, so stock CI is unaffected.

**Files:**
- Create: `crates/mvm-cli/tests/instant_loop.rs`

**Interfaces:**
- Consumes: `mvm_cli::bench::interaction::{run_instant_loop, InteractionRunCfg, WARM_RPC_P50_BUDGET_MS}`, `mvm_cli::bench::write_report_with_latest`.

- [ ] **Step 1: Write the gate test**

Create `crates/mvm-cli/tests/instant_loop.rs`:

```rust
//! Live interaction-latency gate. Boots one real VM, measures cold + warm Ping
//! RTT over vsock, and asserts the steady-interaction invariants. Runs only
//! under `libkrun-live` on a host where libkrun boots; excluded from stock
//! builds, so it never fabricates a number.

#![cfg(feature = "libkrun-live")]

use mvm_cli::bench::interaction::{InteractionRunCfg, WARM_RPC_P50_BUDGET_MS, run_instant_loop};
use mvm_cli::bench::write_report_with_latest;

#[test]
fn warm_interaction_beats_cold_and_records_verdict() {
    let cfg = InteractionRunCfg { cold_samples: 10, warmup: 20, samples: 200 };
    let report = run_instant_loop("mvm-instant-loop-gate", &cfg, WARM_RPC_P50_BUDGET_MS)
        .expect("instant-loop measurement");

    // Finite, non-empty stats.
    assert!(report.interaction_warm_rtt.p50.is_finite(), "warm p50 not finite");
    assert!(report.interaction_cold_rtt_ms.is_finite(), "cold median not finite");
    assert!(report.start_boot.total_ready_ms > 0.0, "boot never reached ready");

    // The held session amortizes the handshake, so steady warm p50 must beat a
    // cold dial. This is the load-bearing invariant of the whole measurement.
    assert!(
        report.interaction_warm_rtt.p50 < report.interaction_cold_rtt_ms,
        "warm p50 {:.3}ms should be < cold median {:.3}ms",
        report.interaction_warm_rtt.p50,
        report.interaction_cold_rtt_ms,
    );

    // Record the numbers + soft verdict (not a hard failure until a committed
    // baseline ratchets the budget) and persist the JSON report artifact.
    eprintln!(
        "[instant-loop] start_ready={:.2}ms cold_median={:.3}ms warm_p50={:.3}ms \
         warm_p99={:.3}ms budget={:.1}ms within_budget={}",
        report.start_boot.total_ready_ms,
        report.interaction_cold_rtt_ms,
        report.interaction_warm_rtt.p50,
        report.interaction_warm_rtt.p99,
        report.interaction_verdict.budget_ms,
        report.interaction_verdict.within_budget,
    );
    let path = write_report_with_latest(&report, None, "instant-loop").expect("persist report");
    eprintln!("[instant-loop] report at {}", path.display());
}
```

- [ ] **Step 2: Confirm the test compiles under the feature**

Run: `cargo test -p mvm-cli --features libkrun-live --test instant_loop --no-run 2>&1 | tail -20`
Expected: compiles. (Execution needs a host where libkrun boots; run it live in Step 3 when on such a host.)

- [ ] **Step 3: Run the gate live (on a libkrun/HVF host — this Mac)**

Run: `cargo test -p mvm-cli --features libkrun-live --test instant_loop -- --nocapture 2>&1 | tail -30`
Expected: PASS, with an `[instant-loop] …` line reporting real cold/warm/boot numbers. Record the printed warm p50/p99 in the design note's budget section as the first baseline.

- [ ] **Step 4: Confirm stock build ignores the test**

Run: `cargo test -p mvm-cli --test instant_loop --no-run 2>&1 | tail -10`
Expected: compiles to an empty test binary (the `#![cfg(...)]` excludes everything); no error.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(mvm-cli): live instant-loop interaction-latency gate

Feature-gated integration test: boot one VM, measure cold+warm Ping RTT, assert
warm p50 beats cold, record the verdict, persist the report. Excluded from stock
builds; establishes the first interaction-latency baseline."
```

---

## Task 5: Remove the user-facing `ops bench` verb + sweep help/docs

Benchmarking is now a dev/CI gate, so delete the shipped verb and its glue. The reusable `pub` harness (used by the gate) stays.

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/group.rs` (drop the `Bench` variant + arms)
- Modify: `crates/mvm-cli/src/bench/mod.rs` (delete verb glue: `Args`, `BenchAction`, `MicrovmLaunchArgs`, `MicrovmDensityArgs`, `run`, `run_microvm_launch`, `run_microvm_density`, `validate_launch_hypervisor`, `validate_density_hypervisor`, the `new_*_probe` / `run_*_launch_distribution` / `run_*_density` verb dispatchers, and their `#[cfg(test)] mod tests`)
- Modify: `crates/mvm-cli/tests/cli.rs` (help-text snapshots)
- Modify: `public/src/content/docs/reference/cli-commands.md` (remove bench rows)

**Interfaces:**
- Produces: no `ops bench` verb. The reusable harness (`harness`, `probes`, `report`, `stats`, `regression`, `probe`, `interaction`, `write_report_with_latest`) remains `pub` under `crate::bench` and is exercised only by the gate.

- [ ] **Step 1: Write/adjust the failing CLI test first**

In `crates/mvm-cli/tests/cli.rs`, find the assertion(s) that reference `bench` under `ops` help (search for `bench`). Change them to assert `bench` is ABSENT from `ops --help`. If none exists, add:

```rust
#[test]
fn ops_help_no_longer_lists_bench() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["ops", "--help"])
        .output()
        .expect("run mvmctl ops --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("bench"), "ops help still lists the removed bench verb:\n{text}");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p mvm-cli --test cli ops_help_no_longer_lists_bench 2>&1 | tail -15`
Expected: FAIL — `ops --help` still lists `bench`.

- [ ] **Step 3: Delete the verb from the group**

In `crates/mvm-cli/src/commands/ops/group.rs`:
- Remove the `Bench(bench::Args)` variant from `enum OpsCmd` and its doc line.
- Remove the `OpsCmd::Bench(_) => "bench",` arm in `verb_name`.
- Remove the `OpsCmd::Bench(a) => bench::run(cli, a, cfg),` arm in `run`.
- Remove the `use crate::bench;` import.

- [ ] **Step 4: Delete the verb glue from the harness**

In `crates/mvm-cli/src/bench/mod.rs`, delete: `Args`, `BenchAction`, `MicrovmLaunchArgs`, `MicrovmDensityArgs`, `run`, `run_microvm_launch`, `run_microvm_density`, `validate_launch_hypervisor`, `validate_density_hypervisor`, `new_firecracker_probe`/`new_hvf_probe`, `run_firecracker_launch_distribution`/`run_hvf_launch_distribution`, `run_libkrun_density`/`run_firecracker_density`/`run_hvf_density`, and the module's `#[cfg(test)] mod tests` (the reject-cap tests, which tested the deleted glue). Keep `write_report_with_latest`, `default_report_path`, `timestamp_for_report_path`, and all `pub mod` declarations. Remove now-unused `use` imports (clap, `harness::*`, `probes::*`, `regression::*`, `report::*` that only the glue referenced) — let the compiler flag them.

- [ ] **Step 5: Remove the doc rows**

In `public/src/content/docs/reference/cli-commands.md`, delete every row mentioning `microvm-launch`, `microvm-density`, or the `overall` benchmark (grep: `microvm-launch|microvm-density|\| \`mvmctl n `). These describe the removed benchmarking surface.

- [ ] **Step 6: Build, run the CLI test, and full gates**

Run:
```bash
cargo build -p mvm-cli --all-targets 2>&1 | tail -20
cargo test -p mvm-cli --test cli ops_help_no_longer_lists_bench 2>&1 | tail -10
cargo clippy -p mvm-cli --all-targets -- -D warnings 2>&1 | tail -20
```
Expected: build clean (no dead-code warnings — the reusable harness is `pub`); the CLI test PASSES; clippy clean.

- [ ] **Step 7: Doc-guard + workspace regression check**

Run:
```bash
cargo run -p xtask -- check-no-spec-refs 2>&1 | tail -5
cargo nextest run -p mvm-cli 2>&1 | tail -15
```
Expected: no spec-ref violations; mvm-cli suite green. If a doc-guard Rust test (e.g. `tests/*` asserting doc headings) references the removed rows, update it in this commit.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(mvm-cli): remove the ops bench user verb; benchmarking is a dev gate

Benchmarking microVM latency is not an end-user action. Delete the ops bench
verb and its glue; the reusable harness stays a library the instant-loop gate
drives. Sweep help snapshots and the CLI command reference."
```

---

## Self-Review

- **Spec coverage:** interaction baseline (cold+warm RPC) → Tasks 2–4; reuse of existing stats/report/regression → Tasks 1–2; no fabricated warm-start (start half is cold-boot only, no `warm_start_ms`) → Task 2 schema; console byte-pipe excluded (RPC `Ping` only) → Tasks 2–3; CLI verb removed + harness relocated → Tasks 1, 5; feature-gated test not cucumber → Task 4; docs/help sweep → Task 5. Deferred (warm-start probe, observability metric, cucumber witness, density fold-in, concurrency) are recorded in the spec, not implemented here.
- **Placeholder scan:** all code blocks are complete; the one "confirm the exact dial" note points at a specific real call site to copy, not a TBD.
- **Type consistency:** `InteractionTimings`, `InstantLoopReport`, `SloVerdict`, `InteractionRunCfg`, `build_instant_loop_report`, `interaction_verdict`, `measure_interaction`, `run_instant_loop`, `HeldProbeVm::marks()` are named identically across Tasks 2–4. `TailLatencyStats`/`HostDescriptor`/`IterationTiming`/`percentile`/`summarize_tail_latency`/`BootMarks`/`write_report_with_latest` are reused from the relocated modules with their real signatures (verified against the current source).

## Deferred follow-ups (record in the spec, not this plan)

- Warm-start probe added to the report once a warm-restore path lands in `main`; `--baseline` then enforces warm < cold.
- Promote per-RPC interaction latency to a runtime observability metric (mirror `vsock_handshake_rtt_ms`).
- Optional cucumber `.feature` witness driven by a dev-only non-shipped entry point.
- Fold density (C) into one unified "instant" report; concurrent-interaction measurement for the fan-out workflow.
