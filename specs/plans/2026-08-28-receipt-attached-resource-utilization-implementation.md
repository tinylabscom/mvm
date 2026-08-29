# Receipt-attached resource utilization — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record a microVM run's measured CPU, memory, host-state, and wall consumption as signed integers in the `ExecutionReceipt`'s `mvm.usage` extension, each carrying explicit provenance.

**Architecture:** The process that owns a VM writes a `workload.usage` sidecar at teardown, mirroring the existing `workload.exit` convention. The single production `plan.exited` emission site reads it, the audit emitter carries it as one chain-signed label, and receipt export folds it into `extensions["mvm.usage"]`. A per-backend observation matrix — a sibling of the existing control matrix, under the same anti-wildcard gate — declares what each tier can honestly observe.

**Tech Stack:** Rust (17-crate workspace), serde + JCS canonical JSON, Ed25519 receipt signing, `libc` for `/proc` and Mach process probing, `cargo nextest`, `xtask` claim gates.

**Spec:** `specs/2026-08-28-receipt-attached-resource-utilization.md`

## Global Constraints

- **Integers only, ASCII only.** `validate_value_space` (`crates/mvm-core/src/receipt.rs:329`) rejects floats and non-ASCII in receipt extensions. No percentages, ratios, or fractional seconds anywhere in `mvm.usage`.
- **Only host-side observations may be stamped `measured`.** A guest self-report uses `guest_reported` and can never be constructed as `measured`.
- **A metric key is always present.** Unobservable is `{"source":"unavailable"}` — never absent, never `0`.
- **No `#[allow(clippy::too_many_arguments)]`.** Introduce a params struct instead. Banned outright in hand-written code.
- **No plan, PR, or ADR references in code comments.** Those belong in specs only.
- **All `~/.mvm` paths go through `mvm-core::config` helpers.** Never build them from `std::env::var("HOME")`.
- **No ADR-001 change.** This adds no claim number; the ledger and Preview claim 18's row are untouched.
- **Scratch files go in `/tmp/`,** never inside the repo working tree.
- Gate before declaring any task done: `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo clippy --workspace -- -D warnings`.

---

### Task 1: `usage_capture` types and file convention

The wire types and the sidecar convention, with no platform code and no callers yet. Everything downstream depends on these names.

**Files:**
- Create: `crates/mvm-core/src/usage_capture.rs`
- Modify: `crates/mvm-core/src/lib.rs` (add `pub mod usage_capture;` beside the existing `pub mod disk_usage;` at line 41)

**Interfaces:**
- Consumes: nothing.
- Produces: `UsageSource`, `Mechanism`, `Metric` (with `Metric::measured(u64, Mechanism)`, `Metric::guest_reported(u64)`, `Metric::unavailable()`), `UsageCapture` (fields `cpu_ms`, `peak_rss_mib`, `host_state_bytes`, `wall_ms`, `guest_peak_rss_kib`, all `Metric`; `Default` is all-unavailable), `WORKLOAD_USAGE_FILE`, `usage_file_path(&Path) -> PathBuf`, `read_captured(&Path) -> UsageCapture`, `write_captured(&Path, &UsageCapture) -> std::io::Result<()>`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/mvm-core/src/usage_capture.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unavailable_metric_carries_no_number_to_misread() {
        let json = serde_json::to_string(&Metric::unavailable()).expect("serialize");
        assert_eq!(json, r#"{"source":"unavailable"}"#);
    }

    #[test]
    fn a_measured_metric_names_the_mechanism_that_produced_it() {
        let json = serde_json::to_string(&Metric::measured(4210, Mechanism::HvfSummedVcpuClock))
            .expect("serialize");
        assert_eq!(
            json,
            r#"{"source":"measured","value":4210,"mechanism":"hvf_summed_vcpu_clock"}"#
        );
    }

    #[test]
    fn a_guest_report_is_a_distinct_source_and_names_no_mechanism() {
        let json = serde_json::to_string(&Metric::guest_reported(204_800)).expect("serialize");
        assert_eq!(json, r#"{"source":"guest_reported","value":204800}"#);
    }

    #[test]
    fn an_unavailable_metric_carrying_a_value_is_refused_on_the_wire() {
        // Presence of a number under `unavailable` is the exact ambiguity the
        // encoding exists to prevent, so it must not survive a round trip.
        let err = serde_json::from_str::<Metric>(r#"{"source":"unavailable","value":5}"#);
        assert!(err.is_err(), "unavailable must not carry a value");
    }

    #[test]
    fn a_measured_metric_without_a_mechanism_is_refused_on_the_wire() {
        let err = serde_json::from_str::<Metric>(r#"{"source":"measured","value":5}"#);
        assert!(err.is_err(), "measured must name its mechanism");
    }

    #[test]
    fn a_guest_report_claiming_a_mechanism_is_refused_on_the_wire() {
        let err = serde_json::from_str::<Metric>(
            r#"{"source":"guest_reported","value":5,"mechanism":"host_process_rss"}"#,
        );
        assert!(err.is_err(), "a guest report names no host mechanism");
    }

    #[test]
    fn a_capture_round_trips_through_the_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let usage = UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            ..UsageCapture::default()
        };
        write_captured(dir.path(), &usage).expect("write");
        assert_eq!(read_captured(dir.path()), usage);
    }

    #[test]
    fn an_absent_sidecar_reads_as_unavailable_never_as_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_captured(dir.path()), UsageCapture::default());
        assert_eq!(read_captured(dir.path()).cpu_ms, Metric::unavailable());
    }

    #[test]
    fn a_malformed_sidecar_reads_as_unavailable_never_as_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(usage_file_path(dir.path()), "{ not json").expect("write");
        assert_eq!(read_captured(dir.path()), UsageCapture::default());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-core usage_capture`
Expected: FAIL — the module does not compile, `Metric` and friends are undefined.

- [ ] **Step 3: Write the implementation**

Prepend to `crates/mvm-core/src/usage_capture.rs`:

```rust
//! Measured resource consumption for one workload run, and the sidecar
//! convention that carries it off the process that owned the VM.
//!
//! A metric is a three-way choice rather than a number plus flags, so a guest
//! self-report cannot be spelled as a host observation and an unobservable
//! dimension cannot carry a number that reads as zero. The wire form is flat
//! (`source`/`value`/`mechanism`) and is validated on the way in, because the
//! file is written by one process and read by another.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where a metric's number came from, or that there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// Observed by the host. The only source a verifier may treat as attested.
    Measured,
    /// Reported by the untrusted guest about itself.
    GuestReported,
    /// This host could not observe this dimension on this backend.
    Unavailable,
}

/// How a measured value was observed. Named on every measurement because the
/// mechanisms do not measure the same quantity: guest vCPU time excludes the
/// host-side device emulation that a process total includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// Summed Mach clocks of every vCPU thread: guest execution only.
    HvfSummedVcpuClock,
    /// CPU time of the in-process VMM's own process: guest plus VMM overhead.
    HostProcessCpu,
    /// `getrusage` over a reaped VMM child: guest plus VMM overhead.
    HostChildRusage,
    /// Kernel-kept resident high-water mark of the VMM process.
    HostProcessRss,
    /// Byte total of the VM state directory tree.
    StateDirTreeBytes,
    /// The host's own observation of the span from launch to teardown.
    HostLaunchSpan,
}

/// One dimension's consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "MetricWire", try_from = "MetricWire")]
pub enum Metric {
    Measured { value: u64, mechanism: Mechanism },
    GuestReported { value: u64 },
    Unavailable,
}

impl Metric {
    #[must_use]
    pub const fn measured(value: u64, mechanism: Mechanism) -> Self {
        Self::Measured { value, mechanism }
    }

    #[must_use]
    pub const fn guest_reported(value: u64) -> Self {
        Self::GuestReported { value }
    }

    #[must_use]
    pub const fn unavailable() -> Self {
        Self::Unavailable
    }

    /// The number, when there is one.
    #[must_use]
    pub const fn value(self) -> Option<u64> {
        match self {
            Self::Measured { value, .. } | Self::GuestReported { value } => Some(value),
            Self::Unavailable => None,
        }
    }

    #[must_use]
    pub const fn source(self) -> UsageSource {
        match self {
            Self::Measured { .. } => UsageSource::Measured,
            Self::GuestReported { .. } => UsageSource::GuestReported,
            Self::Unavailable => UsageSource::Unavailable,
        }
    }
}

/// The flat wire form. Private: the validated enum is the only public shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricWire {
    source: UsageSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mechanism: Option<Mechanism>,
}

impl From<Metric> for MetricWire {
    fn from(metric: Metric) -> Self {
        match metric {
            Metric::Measured { value, mechanism } => Self {
                source: UsageSource::Measured,
                value: Some(value),
                mechanism: Some(mechanism),
            },
            Metric::GuestReported { value } => Self {
                source: UsageSource::GuestReported,
                value: Some(value),
                mechanism: None,
            },
            Metric::Unavailable => Self {
                source: UsageSource::Unavailable,
                value: None,
                mechanism: None,
            },
        }
    }
}

impl TryFrom<MetricWire> for Metric {
    type Error = &'static str;

    fn try_from(wire: MetricWire) -> Result<Self, Self::Error> {
        match (wire.source, wire.value, wire.mechanism) {
            (UsageSource::Measured, Some(value), Some(mechanism)) => {
                Ok(Self::Measured { value, mechanism })
            }
            (UsageSource::Measured, _, _) => {
                Err("a measured metric must carry both a value and a mechanism")
            }
            (UsageSource::GuestReported, Some(value), None) => Ok(Self::GuestReported { value }),
            (UsageSource::GuestReported, _, _) => {
                Err("a guest-reported metric must carry a value and no host mechanism")
            }
            (UsageSource::Unavailable, None, None) => Ok(Self::Unavailable),
            (UsageSource::Unavailable, _, _) => {
                Err("an unavailable metric must carry neither a value nor a mechanism")
            }
        }
    }
}

/// One run's consumption across every dimension this version records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageCapture {
    pub cpu_ms: Metric,
    pub peak_rss_mib: Metric,
    pub host_state_bytes: Metric,
    pub wall_ms: Metric,
    pub guest_peak_rss_kib: Metric,
}

impl Default for UsageCapture {
    /// Every dimension unobserved. A run that measured nothing still says so.
    fn default() -> Self {
        Self {
            cpu_ms: Metric::unavailable(),
            peak_rss_mib: Metric::unavailable(),
            host_state_bytes: Metric::unavailable(),
            wall_ms: Metric::unavailable(),
            guest_peak_rss_kib: Metric::unavailable(),
        }
    }
}

/// File name under `vm_state_dir` holding the captured usage.
pub const WORKLOAD_USAGE_FILE: &str = "workload.usage";

#[must_use]
pub fn usage_file_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join(WORKLOAD_USAGE_FILE)
}

/// Read a previously-captured usage record.
///
/// An absent or unreadable file yields an all-unavailable record rather than
/// an error or a zero: "nothing was observed" is the honest answer, and it is
/// the same answer a backend that cannot observe anything writes deliberately.
#[must_use]
pub fn read_captured(vm_state_dir: &Path) -> UsageCapture {
    std::fs::read_to_string(usage_file_path(vm_state_dir))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Persist a usage record beside the exit code.
pub fn write_captured(vm_state_dir: &Path, usage: &UsageCapture) -> std::io::Result<()> {
    let encoded = serde_json::to_string(usage).map_err(std::io::Error::other)?;
    std::fs::write(usage_file_path(vm_state_dir), encoded)
}
```

Add to `crates/mvm-core/src/lib.rs`, beside `pub mod disk_usage;`:

```rust
pub mod usage_capture;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-core usage_capture`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/usage_capture.rs crates/mvm-core/src/lib.rs
git commit -m "feat(core): add the workload usage capture types and sidecar"
```

---

### Task 2: Observation matrix, and a gate that actually checks it

`ResourceObservation::for_backend` is a second exhaustive match in a file whose gate finds its target with `haystack.find(marker)` — the **first** occurrence only. Adding the matrix without fixing the gate produces a green check that inspects nothing. The two ship together because a reviewer could not sensibly accept one without the other.

**Files:**
- Modify: `crates/mvm-contract/src/protocol/resource_controls.rs` (append after the existing `ResourceControls` impl)
- Modify: `xtask/src/check_backend_resource_controls.rs:101-121` (`extract_marked_block`) and its `run` function

**Interfaces:**
- Consumes: `Mechanism` from Task 1 is *not* used here — this crate is `no_std`+alloc and sits below `mvm-core`. The matrix names its own `CpuObservation`/`MemoryObservation`/`HostStateObservation`/`WallObservation` enums.
- Produces: `ResourceObservation::for_backend(BackendKind) -> ResourceObservation` with public fields `cpu`, `memory`, `host_state`, `wall`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/mvm-contract/src/protocol/resource_controls.rs`:

```rust
#[test]
fn hvf_observes_guest_vcpu_time_rather_than_a_process_total() {
    let observation = ResourceObservation::for_backend(BackendKind::Hvf);
    if cfg!(target_os = "macos") {
        assert_eq!(observation.cpu, CpuObservation::HvfSummedVcpuClock);
    } else {
        assert_eq!(observation.cpu, CpuObservation::None);
    }
}

#[test]
fn apple_container_observes_exactly_what_hvf_does() {
    // It is the HVF tier with a substituted kernel image, so a divergence
    // here would be a claim about a difference that does not exist.
    assert_eq!(
        ResourceObservation::for_backend(BackendKind::AppleContainer),
        ResourceObservation::for_backend(BackendKind::Hvf)
    );
}

#[test]
fn a_cpu_bound_a_backend_cannot_apply_does_not_stop_it_observing_memory() {
    // The distinction the whole matrix exists for: a control is not an
    // observation. Firecracker off Linux bounds no CPU and still has a
    // resident process to measure.
    let controls = ResourceControls::for_backend(BackendKind::Firecracker);
    let observation = ResourceObservation::for_backend(BackendKind::Firecracker);
    if !cfg!(target_os = "linux") {
        assert_eq!(controls.cpu, CpuControl::None);
    }
    assert_eq!(observation.memory, MemoryObservation::HostProcessRss);
}

#[test]
fn the_non_vm_tiers_observe_only_the_span_the_host_saw() {
    for kind in [BackendKind::Wasm, BackendKind::WebLinux, BackendKind::Mock] {
        let observation = ResourceObservation::for_backend(kind);
        assert_eq!(observation.cpu, CpuObservation::None);
        assert_eq!(observation.memory, MemoryObservation::None);
        assert_eq!(observation.host_state, HostStateObservation::None);
        assert_eq!(observation.wall, WallObservation::HostLaunchSpan);
    }
}

#[test]
fn every_backend_observes_the_wall_span_because_it_needs_no_cooperation() {
    for kind in [
        BackendKind::Firecracker,
        BackendKind::Libkrun,
        BackendKind::Qemu,
        BackendKind::Mock,
        BackendKind::Hvf,
        BackendKind::Wasm,
        BackendKind::WebLinux,
        BackendKind::AppleContainer,
    ] {
        assert_eq!(
            ResourceObservation::for_backend(kind).wall,
            WallObservation::HostLaunchSpan
        );
    }
}
```

Add to `xtask/src/check_backend_resource_controls.rs`'s test module:

```rust
#[test]
fn a_wildcard_in_a_later_for_backend_is_caught_not_skipped() {
    // The gate used to locate its target with a first-match find, so a second
    // exhaustive match in the same file was never inspected at all.
    let body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuControl::None },
            BackendKind::Libkrun => Self { cpu: CpuControl::None },
        }
    }
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuObservation::None },
            _ => Self { cpu: CpuObservation::None },
        }
    }
"#;
    let tmp = write_controls_fixture("later_wildcard", body);
    let err = run(&tmp).unwrap_err();
    assert!(err.to_string().contains("never"), "got: {err}");
}

#[test]
fn both_for_backend_matches_must_be_present_for_the_gate_to_pass() {
    // A gate that passes when the second matrix has been deleted is a gate
    // that stops noticing when the second matrix stops existing.
    let body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuControl::None },
        }
    }
"#;
    let tmp = write_controls_fixture("only_one", body);
    assert!(run(&tmp).is_err(), "one matrix is not both matrices");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-contract resource_controls && cargo nextest run -p xtask check_backend_resource_controls`
Expected: FAIL — `ResourceObservation` undefined; the xtask tests fail because the gate inspects only the first match.

- [ ] **Step 3: Write the implementation**

Append to `crates/mvm-contract/src/protocol/resource_controls.rs`:

```rust
/// How a backend observes CPU consumption, if it can.
///
/// These do not measure the same quantity, which is why the choice is named
/// rather than reduced to a boolean: guest vCPU time excludes the host-side
/// device emulation that a process total includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuObservation {
    None,
    /// Summed Mach clocks of every vCPU thread: guest execution only.
    HvfSummedVcpuClock,
    /// The in-process VMM's own process CPU time: guest plus VMM overhead.
    HostProcessCpu,
    /// `getrusage` over a reaped VMM child: guest plus VMM overhead.
    HostChildRusage,
}

/// How a backend observes resident memory, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryObservation {
    None,
    /// The kernel-kept resident high-water mark of the VMM process.
    HostProcessRss,
}

/// How a backend observes host-side state growth, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStateObservation {
    None,
    /// Byte total of the VM state directory tree.
    StateDirTreeBytes,
}

/// How a backend observes wall-clock span.
///
/// There is no `None`: the span is the host's own observation of the run and
/// needs no cooperation from the backend. Distinct from the supervisor's
/// wall-clock *timer*, which bounds a run and is a control, not an
/// observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WallObservation {
    HostLaunchSpan,
}

/// What one backend can honestly report about a finished run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceObservation {
    pub cpu: CpuObservation,
    pub memory: MemoryObservation,
    pub host_state: HostStateObservation,
    pub wall: WallObservation,
}

impl ResourceObservation {
    /// What each backend can observe. Exhaustive on purpose, for the same
    /// reason [`ResourceControls::for_backend`] is: a new `BackendKind` must
    /// answer this rather than inherit an answer nobody chose for it.
    ///
    /// Observation is a different question from control. A tier that can bound
    /// nothing may still have a resident process to measure, and a tier that
    /// bounds CPU only under a grant can measure it without one.
    #[must_use]
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            // The vCPU threads are ours and their Mach clocks are readable
            // without a quota controller, so CPU here is measurable whether or
            // not a share was granted. AppleContainer is this same tier with a
            // substituted kernel image.
            BackendKind::Hvf | BackendKind::AppleContainer => Self {
                cpu: if cfg!(target_os = "macos") {
                    CpuObservation::HvfSummedVcpuClock
                } else {
                    CpuObservation::None
                },
                memory: MemoryObservation::HostProcessRss,
                host_state: HostStateObservation::StateDirTreeBytes,
                wall: WallObservation::HostLaunchSpan,
            },
            // The VMM runs inside our own supervisor process, so its CPU is
            // this process's CPU — measurable with no cgroup, no session bus,
            // and no grant.
            BackendKind::Libkrun => Self {
                cpu: CpuObservation::HostProcessCpu,
                memory: MemoryObservation::HostProcessRss,
                host_state: HostStateObservation::StateDirTreeBytes,
                wall: WallObservation::HostLaunchSpan,
            },
            // Superseded during execution: neither VMM is actually a child we
            // reap. Firecracker launches session-detached and is orphaned to
            // init before the launch call returns, and QEMU daemonizes
            // itself, so there is no rusage to collect. The shipped matrix
            // declares `CpuObservation::None` / `MemoryObservation::None` for
            // this arm; the spec's per-backend coverage table is the
            // authoritative record.
            //
            // The VMM is a child we reap, so its resource usage arrives with
            // the reap itself.
            BackendKind::Firecracker | BackendKind::Qemu => Self {
                cpu: CpuObservation::HostChildRusage,
                memory: MemoryObservation::HostProcessRss,
                host_state: HostStateObservation::StateDirTreeBytes,
                wall: WallObservation::HostLaunchSpan,
            },
            // Wasm's fuel counter is declared and unwired, so a fuel-derived
            // CPU number would assert a measurement that does not happen.
            // WebLinux runs in a browser with no host VMM process to observe.
            // Mock boots nothing.
            BackendKind::Wasm | BackendKind::WebLinux | BackendKind::Mock => Self {
                cpu: CpuObservation::None,
                memory: MemoryObservation::None,
                host_state: HostStateObservation::None,
                wall: WallObservation::HostLaunchSpan,
            },
        }
    }
}
```

In `xtask/src/check_backend_resource_controls.rs`, replace the single-match lookup with an all-matches walk. Change `extract_marked_block` to take a starting offset and return the block's end, then iterate:

```rust
/// Every block in `haystack` introduced by `marker`, in source order.
///
/// A first-match lookup was the original shape, and it silently stopped
/// inspecting this file the moment it grew a second exhaustive match: the
/// gate stayed green while the new matrix went unchecked. Anything that must
/// hold for one `for_backend` must hold for all of them.
fn marked_blocks<'a>(haystack: &'a str, marker: &str) -> Vec<MarkedBlock<'a>> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = haystack[cursor..].find(marker) {
        let marker_pos = cursor + found;
        let Some(block) = block_at(haystack, marker_pos) else {
            break;
        };
        cursor = block.end;
        blocks.push(block);
    }
    blocks
}
```

`block_at` is the existing brace-depth body of `extract_marked_block`, taking `marker_pos` directly and additionally recording `end` (the absolute offset one past the closing brace) on `MarkedBlock`. Keep the brace-depth counting exactly as it is — the `if cfg!(...)` nesting it was written for is still present, and now appears in both matrices.

Then in `run`, require at least two blocks and check every one:

```rust
    let fn_blocks = marked_blocks(&body, FN_MARKER);
    if fn_blocks.len() < 2 {
        bail!(
            "{CONTROLS_FILE} must declare both the control and the observation \
             matrix as `{FN_MARKER}`; found {}",
            fn_blocks.len()
        );
    }
    for fn_block in fn_blocks {
        let param = param_binding_name(fn_block.header).ok_or_else(|| {
            anyhow::anyhow!("{CONTROLS_FILE}'s for_backend has no parameter to read a binding from")
        })?;
        let match_marker = format!("match {param}");
        let match_block = extract_marked_block(fn_block.body, &match_marker).ok_or_else(|| {
            anyhow::anyhow!("{CONTROLS_FILE}'s for_backend no longer matches on its parameter")
        })?;
        for pattern in arm_patterns(match_block.body) {
            for alternative in pattern_alternatives(&pattern) {
                // the existing per-alternative ENUM_PATH check, unchanged
            }
        }
    }
```

Update the module doc comment's first paragraph to say every `for_backend` in the file is checked, not "the" one.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-contract resource_controls && cargo nextest run -p xtask check_backend_resource_controls`
Expected: PASS.

- [ ] **Step 5: Run the real gate against the real file**

Run: `cargo run -p xtask -- check-backend-resource-controls`
Expected: exit 0. Run it from inside this worktree — the xtask gates resolve paths from the invoking workspace.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-contract/src/protocol/resource_controls.rs xtask/src/check_backend_resource_controls.rs
git commit -m "feat(contract): declare what each backend can observe, and gate every matrix

The gate located its target with a first-match find, so a second exhaustive
match in the same file would have gone uninspected while the check stayed
green. It now walks every for_backend block and requires both to be present."
```

---

### Task 3: Host process probes

Platform readers returning `Metric`. Home is `crates/mvm-vmm/src/host/`, beside `process_liveness.rs`, which already reaches for `proc_pidinfo` on macOS — this is the established place for host-process probing, and `mvm-vmm` already depends on `mvm-core`.

**Files:**
- Create: `crates/mvm-vmm/src/host/process_usage.rs`
- Modify: `crates/mvm-vmm/src/host/mod.rs` (add `pub mod process_usage;`)

**Interfaces:**
- Consumes: `mvm_core::usage_capture::{Metric, Mechanism}` (Task 1).
- Produces: `peak_rss_mib_self() -> Metric`, `process_cpu_ms_self() -> Metric`, `host_state_bytes(&Path) -> Metric`, `wall_ms(Duration) -> Metric`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_a_resident_high_water_mark() {
        // Any live process has resident pages, so an unavailable answer here
        // means the probe failed rather than that there was nothing to see.
        let rss = peak_rss_mib_self();
        assert_eq!(rss.source(), mvm_core::usage_capture::UsageSource::Measured);
        assert!(rss.value().expect("a measured metric carries a value") > 0);
    }

    #[test]
    fn this_process_has_consumed_cpu() {
        let cpu = process_cpu_ms_self();
        assert_eq!(cpu.source(), mvm_core::usage_capture::UsageSource::Measured);
    }

    #[test]
    fn an_absent_state_dir_measures_zero_bytes_rather_than_failing() {
        // tree_bytes already answers 0 for an absent path; this is a real
        // measurement of an empty tree, not an unavailable one.
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = host_state_bytes(&dir.path().join("absent"));
        assert_eq!(bytes, Metric::measured(0, Mechanism::StateDirTreeBytes));
    }

    #[test]
    fn a_state_dir_with_content_measures_more_than_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("blob"), vec![0u8; 8192]).expect("write");
        assert!(host_state_bytes(dir.path()).value().expect("measured") >= 8192);
    }

    #[test]
    fn a_wall_span_is_recorded_in_whole_milliseconds() {
        assert_eq!(
            wall_ms(std::time::Duration::from_millis(61_004)),
            Metric::measured(61_004, Mechanism::HostLaunchSpan)
        );
    }

    #[test]
    fn a_sub_millisecond_span_is_zero_rather_than_rounded_up() {
        // Rounding up would let a run that never happened report time.
        assert_eq!(
            wall_ms(std::time::Duration::from_micros(400)),
            Metric::measured(0, Mechanism::HostLaunchSpan)
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-vmm process_usage`
Expected: FAIL — module undefined.

- [ ] **Step 3: Write the implementation**

```rust
//! Host-side readings of the process that owns a guest.
//!
//! Every reading here is taken by the host about itself or about a child it
//! reaped. Nothing in this module consults the guest, which is what allows the
//! results to be stamped as measured rather than reported.

use std::path::Path;
use std::time::Duration;

use mvm_core::usage_capture::{Mechanism, Metric};

/// Resident high-water mark of this process, in MiB.
///
/// The kernel keeps the high-water mark, so this is a single read at teardown
/// rather than a sampler running for the life of the VM.
#[must_use]
pub fn peak_rss_mib_self() -> Metric {
    peak_rss_bytes_self()
        .map(|bytes| Metric::measured(bytes / (1024 * 1024), Mechanism::HostProcessRss))
        .unwrap_or_else(Metric::unavailable)
}

#[cfg(target_os = "linux")]
fn peak_rss_bytes_self() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kib * 1024)
}

#[cfg(target_os = "macos")]
fn peak_rss_bytes_self() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::uninit();
    let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
        / std::mem::size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;
    // SAFETY: `task_info` fills the provided buffer when it returns KERN_SUCCESS,
    // and `count` describes that buffer's size in natural_t units.
    let rc = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if rc != libc::KERN_SUCCESS {
        return None;
    }
    // SAFETY: KERN_SUCCESS means the buffer was initialized.
    Some(unsafe { info.assume_init() }.resident_size_max)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peak_rss_bytes_self() -> Option<u64> {
    None
}

/// CPU consumed by this process — user plus system — in milliseconds.
///
/// On the in-process VMM tiers this process *is* the VMM, so the reading
/// covers guest execution together with device emulation and vsock pumping.
/// That is why the metric names [`Mechanism::HostProcessCpu`] rather than
/// claiming to be guest time.
#[must_use]
pub fn process_cpu_ms_self() -> Metric {
    // SAFETY: getrusage only writes the provided rusage struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, fully-owned rusage.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Metric::unavailable();
    }
    Metric::measured(rusage_cpu_ms(&usage), Mechanism::HostProcessCpu)
}

/// CPU consumed by a reaped child, in milliseconds.
#[must_use]
pub fn child_cpu_ms(usage: &libc::rusage) -> Metric {
    Metric::measured(rusage_cpu_ms(usage), Mechanism::HostChildRusage)
}

fn rusage_cpu_ms(usage: &libc::rusage) -> u64 {
    let to_ms = |seconds: i64, micros: i64| -> u64 {
        let seconds = u64::try_from(seconds).unwrap_or(0);
        let micros = u64::try_from(micros).unwrap_or(0);
        seconds.saturating_mul(1000).saturating_add(micros / 1000)
    };
    to_ms(usage.ru_utime.tv_sec as i64, usage.ru_utime.tv_usec as i64)
        .saturating_add(to_ms(usage.ru_stime.tv_sec as i64, usage.ru_stime.tv_usec as i64))
}

/// Byte total of a VM's state directory tree.
///
/// This is host-side overlay and copy-on-write growth, not the guest's view of
/// its own filesystem — which is why the recorded key is named for the host
/// state rather than for disk.
#[must_use]
pub fn host_state_bytes(vm_state_dir: &Path) -> Metric {
    Metric::measured(
        mvm_core::disk_usage::tree_bytes(vm_state_dir),
        Mechanism::StateDirTreeBytes,
    )
}

/// A launch-to-teardown span in whole milliseconds, truncated rather than
/// rounded so a span shorter than a millisecond never reports time.
#[must_use]
pub fn wall_ms(span: Duration) -> Metric {
    Metric::measured(
        u64::try_from(span.as_millis()).unwrap_or(u64::MAX),
        Mechanism::HostLaunchSpan,
    )
}
```

Add `pub mod process_usage;` to `crates/mvm-vmm/src/host/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-vmm process_usage`
Expected: PASS, 6 tests.

- [ ] **Step 5: Verify it compiles for Linux from a Mac**

Run: `cargo check -p mvm-vmm --target aarch64-unknown-linux-musl --all-targets`
Expected: clean. macOS-host checks do not compile `cfg(target_os = "linux")` files at all, so the Linux `VmHWM` arm is invisible to a plain `cargo check` here.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-vmm/src/host/process_usage.rs crates/mvm-vmm/src/host/mod.rs
git commit -m "feat(vmm): read host process CPU, resident high-water, and state size"
```

---

### Task 4: Carry usage on the `plan.exited` audit entry

**Files:**
- Modify: `crates/mvm-hostd/src/audit/emitter.rs:1053-1081`
- Modify: `crates/mvm-hostd/src/audit/emitter.rs` test module (near `emit_exited_records_capture_fidelity` at line 2177)

**Interfaces:**
- Consumes: `mvm_core::usage_capture::UsageCapture` (Task 1).
- Produces: `ExitRecord<'a> { exit_code: Option<i32>, backend: &'a str, usage: UsageCapture }`; `AuditEmitter::emit_exited_with_capture(&self, plan: &ExecutionPlan, record: ExitRecord<'_>) -> Result<()>`. `emit_exited(plan, exit_code, backend)` keeps its existing three-argument signature.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn an_exit_entry_carries_the_usage_record() {
    let (emitter, home) = test_emitter();
    let plan = sample_plan();
    let usage = UsageCapture {
        cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
        ..UsageCapture::default()
    };
    emitter
        .emit_exited_with_capture(
            &plan,
            ExitRecord { exit_code: Some(0), backend: "libkrun", usage },
        )
        .expect("emit");
    let content = home.audit_text();
    assert!(content.contains(r#"\"source\":\"measured\""#) || content.contains("host_process_cpu"));
}

#[test]
fn an_exit_that_measured_nothing_still_says_so_in_the_chain() {
    // Absence of the label would be indistinguishable from an older entry;
    // an explicit all-unavailable record is the attestable form.
    let (emitter, home) = test_emitter();
    let plan = sample_plan();
    emitter
        .emit_exited_with_capture(
            &plan,
            ExitRecord {
                exit_code: None,
                backend: "firecracker",
                usage: UsageCapture::default(),
            },
        )
        .expect("emit");
    let content = home.audit_text();
    assert!(content.contains("unavailable"), "got: {content}");
    assert!(content.contains("captured"), "capture fidelity is unchanged");
}
```

Reuse whatever emitter/home fixture the neighbouring tests already use; `emit_exited_records_capture_fidelity` at line 2177 is the template.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-hostd emitter`
Expected: FAIL — `ExitRecord` undefined and `emit_exited_with_capture` still takes three arguments.

- [ ] **Step 3: Write the implementation**

Replace the exit emitters in `crates/mvm-hostd/src/audit/emitter.rs`:

```rust
/// What a finished run reports about itself.
///
/// A struct rather than a positional list because this grows with each
/// dimension the host learns to observe, and a four-then-five-argument emit
/// is the shape the workspace's argument-count rule exists to prevent.
#[derive(Debug, Clone, Copy)]
pub struct ExitRecord<'a> {
    /// `None` when the guest never reported one.
    pub exit_code: Option<i32>,
    pub backend: &'a str,
    pub usage: UsageCapture,
}

    /// Emit `plan.exited` — fires after a waited-for workload powers off,
    /// carrying its captured exit code.
    pub fn emit_exited(&self, plan: &ExecutionPlan, exit_code: i32, backend: &str) -> Result<()> {
        self.emit_exited_with_capture(
            plan,
            ExitRecord {
                exit_code: Some(exit_code),
                backend,
                usage: UsageCapture::default(),
            },
        )
    }

    /// Emit `plan.exited` with capture fidelity: a missing exit capture is
    /// recorded as `exit_code=none` + `captured=false` rather than being
    /// attested as a successful exit 0 the guest never reported. The usage
    /// record follows the same rule — a dimension nobody observed is written
    /// as unavailable rather than left out, so a reader can tell an
    /// unmeasured run from an unmeasurable one.
    pub fn emit_exited_with_capture(
        &self,
        plan: &ExecutionPlan,
        record: ExitRecord<'_>,
    ) -> Result<()> {
        let (code, captured) = match record.exit_code {
            Some(code) => (code.to_string(), "true"),
            None => ("none".to_string(), "false"),
        };
        // One label rather than a field per metric: the record is a typed
        // document with its own validation, and flattening it here would put
        // that validation on the far side of a string round trip.
        let usage = serde_json::to_string(&record.usage)
            .context("encoding the usage record for the audit chain")?;
        self.emit(
            plan,
            "plan.exited",
            [
                ("exit_code".to_string(), code),
                ("captured".to_string(), captured.to_string()),
                ("backend".to_string(), record.backend.to_string()),
                ("usage".to_string(), usage),
            ],
        )
    }
```

Add `use mvm_core::usage_capture::UsageCapture;` to the file's imports.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-hostd emitter`
Expected: PASS.

- [ ] **Step 5: Fix every caller the signature change broke**

Run: `cargo check --workspace --all-targets`
Expected: errors only at `report_exit` (`crates/mvm-client/src/launch/mod.rs:975`) and in tests. Update them to pass `ExitRecord { exit_code, backend, usage: UsageCapture::default() }`; Task 6 replaces the default with a real reading.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-hostd/src/audit/emitter.rs crates/mvm-client/src/launch/mod.rs
git commit -m "feat(hostd): carry a usage record on the plan.exited chain entry"
```

---

### Task 5: Fold usage into the receipt extension

**Files:**
- Modify: `crates/mvm-hostd/src/audit/receipt_export.rs:54-146` (`audit_entry_to_receipt`)
- Modify: `crates/mvm-hostd/src/audit/receipt_export.rs` test module (near `exited_receipt_includes_exit_code_and_timing` at line 977)

**Interfaces:**
- Consumes: the `usage` label written in Task 4; `UsageCapture` from Task 1.
- Produces: `extensions["mvm.usage"]` on every `plan.exited` receipt. Adds `pub const USAGE: &str = "mvm.usage";` to `mvm_core::receipt::extension_key`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn an_exited_receipt_carries_the_usage_extension() {
    let receipts = export_fixture_with_usage(UsageCapture {
        cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
        ..UsageCapture::default()
    });
    let exited = receipts
        .iter()
        .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
        .expect("an exit receipt");
    let usage = exited
        .payload
        .extensions
        .get(mvm_core::receipt::extension_key::USAGE)
        .expect("mvm.usage");
    assert_eq!(usage["cpu_ms"]["value"], serde_json::json!(4210));
    assert_eq!(usage["cpu_ms"]["source"], serde_json::json!("measured"));
    assert_eq!(
        usage["cpu_ms"]["mechanism"],
        serde_json::json!("host_process_cpu")
    );
}

#[test]
fn a_dimension_nobody_observed_carries_no_number_to_misread() {
    let receipts = export_fixture_with_usage(UsageCapture::default());
    let exited = receipts
        .iter()
        .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
        .expect("an exit receipt");
    let usage = exited
        .payload
        .extensions
        .get(mvm_core::receipt::extension_key::USAGE)
        .expect("mvm.usage is present even when nothing was measured");
    assert_eq!(usage["cpu_ms"]["source"], serde_json::json!("unavailable"));
    assert!(usage["cpu_ms"].get("value").is_none(), "no number to read as zero");
}

#[test]
fn an_entry_with_no_usage_label_still_yields_an_all_unavailable_extension() {
    // An entry written before this feature must not be reported as a run
    // whose usage question was never asked.
    let receipts = export_fixture_without_usage_label();
    let exited = receipts
        .iter()
        .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
        .expect("an exit receipt");
    let usage = exited
        .payload
        .extensions
        .get(mvm_core::receipt::extension_key::USAGE)
        .expect("mvm.usage");
    assert_eq!(usage["wall_ms"]["source"], serde_json::json!("unavailable"));
}

#[test]
fn a_usage_extension_survives_the_receipt_value_space() {
    // Integers and ASCII only: the receipt refuses floats, so a percentage
    // added here later would break every verifier rather than degrade.
    let receipts = export_fixture_with_usage(UsageCapture {
        cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
        peak_rss_mib: Metric::measured(312, Mechanism::HostProcessRss),
        ..UsageCapture::default()
    });
    for receipt in &receipts {
        receipt.verify().expect("a signed receipt verifies");
        receipt.payload.verify_id().expect("the content address holds");
    }
}

#[test]
fn flipping_a_usage_integer_breaks_the_content_address() {
    let receipts = export_fixture_with_usage(UsageCapture {
        cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
        ..UsageCapture::default()
    });
    let mut tampered = receipts
        .iter()
        .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
        .expect("an exit receipt")
        .clone();
    tampered.payload.extensions.insert(
        mvm_core::receipt::extension_key::USAGE.to_string(),
        serde_json::json!({ "cpu_ms": { "source": "measured", "value": 1, "mechanism": "host_process_cpu" } }),
    );
    assert!(tampered.payload.verify_id().is_err());
    assert!(tampered.verify().is_err());
}

#[test]
fn a_float_in_the_usage_extension_is_refused_by_the_value_space() {
    // Guards the no-percentages rule directly rather than by convention.
    let mut receipt = sample_exited_receipt();
    receipt.extensions.insert(
        mvm_core::receipt::extension_key::USAGE.to_string(),
        serde_json::json!({ "cpu_percent": 42.5 }),
    );
    assert!(receipt.compute_id().is_err(), "floats must not be signable");
}
```

Write `export_fixture_with_usage`, `export_fixture_without_usage_label`, and `sample_exited_receipt` as small helpers in the test module, modelled on the existing `exited_receipt_includes_exit_code_and_timing` fixture at line 977.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-hostd receipt_export`
Expected: FAIL — `extension_key::USAGE` undefined and no `mvm.usage` key produced.

- [ ] **Step 3: Write the implementation**

Add to `crates/mvm-core/src/receipt.rs`'s `extension_key` module:

```rust
    /// Measured resource consumption for the run this receipt closes.
    /// Present on every `plan.exited` receipt, including runs where nothing
    /// could be observed — a dimension with no reading is recorded as
    /// unavailable rather than omitted.
    pub const USAGE: &str = "mvm.usage";
```

In `audit_entry_to_receipt`, after the `exit_code` block:

```rust
    // Every exit receipt answers the usage question, even when the answer is
    // that nothing was observed. An absent extension would be ambiguous
    // between "not measured" and "not asked", and only one of those is true.
    if receipt_type == receipt_type::PLAN_EXITED {
        let usage: UsageCapture = entry
            .labels
            .get("usage")
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default();
        if let Ok(value) = serde_json::to_value(usage) {
            extensions.insert(
                mvm_core::receipt::extension_key::USAGE.to_string(),
                value,
            );
        }
    }
```

Add `use mvm_core::usage_capture::UsageCapture;` to the file's imports. `extensions` is already `let mut` at line 56.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-hostd receipt_export`
Expected: PASS, 6 new tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/receipt.rs crates/mvm-hostd/src/audit/receipt_export.rs
git commit -m "feat(hostd): record measured usage in the exit receipt's extensions"
```

---

### Task 6: Wire the capture end to end

The walking skeleton. After this task the whole path runs on every backend; no backend writes a sidecar yet, so every metric is honestly `unavailable` except wall and host state, which the host observes for itself. That end state is correct and is what the tests assert.

**Files:**
- Modify: `crates/mvm-client/src/launch/mod.rs:969-1004` (`report_exit`)
- Modify: `crates/mvm-client/src/launch/tests.rs`

**Interfaces:**
- Consumes: `usage_capture::read_captured` (Task 1), `ExitRecord` (Task 4), `process_usage::{host_state_bytes, wall_ms}` (Task 3).
- Produces: nothing new; `report_exit` keeps its signature and its `ExitReport` return.

- [ ] **Step 1: Write the failing test**

In `crates/mvm-client/src/launch/tests.rs`:

```rust
#[test]
fn an_exit_records_the_host_state_size_even_when_the_backend_measured_nothing() {
    // The host observes its own state directory and its own launch span
    // without any cooperation from the VMM, so these are measured on every
    // tier — including one that wrote no usage sidecar at all.
    let home = TestHome::new();
    let outcome = launched_outcome(&home);
    let backend = local_backend(&home);
    backend.report_exit(&outcome).expect("report exit");
    let audit = home.audit_text();
    assert!(audit.contains("state_dir_tree_bytes"), "got: {audit}");
    assert!(audit.contains("host_launch_span"), "got: {audit}");
    // Nothing wrote a sidecar, so CPU stays honestly unobserved.
    assert!(audit.contains("unavailable"), "got: {audit}");
}
```

Model `launched_outcome` / `local_backend` / `TestHome` on the existing fixtures used by the tests at `launch/tests.rs:241` and `:879`, which already assert on `plan.exited` chain content.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-client report_exit`
Expected: FAIL — the chain carries an all-unavailable record with no mechanisms in it.

- [ ] **Step 3: Write the implementation**

In `report_exit`, replace the emit block:

```rust
    pub fn report_exit(&self, outcome: &LaunchOutcome) -> Result<ExitReport> {
        let name = outcome.machine.name.as_str();
        let state_dir = vm_state_dir(name);
        let exit_code = mvm_core::exit_capture::read_captured(&state_dir);
        // Whatever the process that owned the VM managed to observe. An absent
        // sidecar reads as all-unavailable, which is the honest answer for a
        // tier that cannot observe, a run that crashed before teardown, and a
        // backend that has not been taught to write one yet.
        let mut usage = mvm_core::usage_capture::read_captured(&state_dir);
        // Two dimensions the host observes about itself, so they hold on every
        // backend regardless of what the VMM could report.
        usage.host_state_bytes = process_usage::host_state_bytes(&state_dir);
        if let Some(span) = outcome.launched_at.map(|at| at.elapsed()) {
            usage.wall_ms = process_usage::wall_ms(span);
        }
        if let Some(emitter) = build_audit_emitter() {
            if let Err(e) = emitter.emit_exited_with_capture(
                &outcome.plan,
                ExitRecord {
                    exit_code,
                    backend: &outcome.machine.backend,
                    usage,
                },
            ) {
                tracing::warn!(error = %e, machine = name, "audit emit_exited failed (non-fatal)");
            }
            // ... the existing publish_root block, unchanged
        }
        if outcome.mode == LifecycleMode::Transient {
            self.cleanup_transient(name)?;
        }
        Ok(ExitReport { exit_code })
    }
```

`LaunchOutcome` needs a `launched_at: Option<std::time::Instant>` field, set where the outcome is constructed at launch. If the launch site cannot supply one — a `report_exit` on a machine this process did not launch — leave it `None` and the wall metric stays unavailable, which is accurate rather than a guess.

Add `use mvm_vmm::host::process_usage;` and `use mvm_hostd::audit::emitter::ExitRecord;`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo nextest run -p mvm-client report_exit`
Expected: PASS.

- [ ] **Step 5: Run the full client and hostd suites**

Run: `cargo nextest run -p mvm-client -p mvm-hostd -p mvm-core -p mvm-contract -p mvm-vmm`
Expected: PASS. A signature change to a shared type reaches further than the crate that owns it.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-client/src/launch/mod.rs crates/mvm-client/src/launch/tests.rs
git commit -m "feat(client): read the usage sidecar and record it at plan exit"
```

---

### Task 7: Firecracker and QEMU capture

**Files:**
- Modify: `crates/mvm-backends/src/driver/fc.rs` (the child reap path — locate with `graft grep "wait" --in crates/mvm-backends/src/driver/`)
- Test: same file's test module

**Interfaces:**
- Consumes: `process_usage::{child_cpu_ms, peak_rss_mib_self}` (Task 3), `usage_capture::write_captured` (Task 1).
- Produces: a `workload.usage` sidecar in the VM state dir at teardown.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn reaping_the_vmm_child_writes_a_usage_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    usage.ru_utime.tv_sec = 4;
    usage.ru_stime.tv_usec = 210_000;
    record_child_usage(dir.path(), &usage);
    let captured = mvm_core::usage_capture::read_captured(dir.path());
    assert_eq!(
        captured.cpu_ms,
        Metric::measured(4210, Mechanism::HostChildRusage)
    );
}

#[test]
fn a_state_dir_that_cannot_be_written_does_not_fail_the_teardown() {
    // Usage is best-effort for the same reason the exit capture is: a
    // workload that already ran must not fail its teardown over evidence.
    record_child_usage(std::path::Path::new("/nonexistent/state/dir"), &unsafe {
        std::mem::zeroed()
    });
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-backends usage_sidecar`
Expected: FAIL — `record_child_usage` undefined.

- [ ] **Step 3: Write the implementation**

```rust
/// Persist what the reaped VMM child consumed.
///
/// Best-effort: a failure here leaves no sidecar, which downstream reads as
/// unavailable. Evidence must never be the reason a teardown fails.
fn record_child_usage(vm_state_dir: &Path, rusage: &libc::rusage) {
    let usage = UsageCapture {
        cpu_ms: process_usage::child_cpu_ms(rusage),
        peak_rss_mib: process_usage::peak_rss_mib_self(),
        ..UsageCapture::default()
    };
    let _ = mvm_core::usage_capture::write_captured(vm_state_dir, &usage);
}
```

Call it from the reap site, switching the child wait to `wait4` with a `rusage` out-parameter so the reading arrives with the reap rather than being raced for afterwards. `host_state_bytes` and `wall_ms` are filled by `report_exit` (Task 6) and are deliberately not set here.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-backends usage_sidecar`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backends/src/driver/fc.rs
git commit -m "feat(backends): capture VMM child resource usage at reap"
```

---

### Task 8: libkrun supervisor capture

The VMM runs inside the supervisor process, so the supervisor measures itself.

**Files:**
- Modify: `crates/mvm-hostd/src/bin/mvm-libkrun-supervisor.rs`
- Test: same file's test module

**Interfaces:**
- Consumes: `process_usage::{process_cpu_ms_self, peak_rss_mib_self}` (Task 3), `usage_capture::write_captured` (Task 1).
- Produces: a `workload.usage` sidecar written on the supervisor's exit path.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn the_supervisor_records_its_own_consumption_as_the_machines() {
    // The VMM is in-process, so this process's CPU is the machine's CPU plus
    // this process's own overhead — which is why the mechanism says so.
    let dir = tempfile::tempdir().expect("tempdir");
    record_self_usage(dir.path());
    let captured = mvm_core::usage_capture::read_captured(dir.path());
    assert_eq!(captured.cpu_ms.source(), UsageSource::Measured);
    assert!(matches!(
        captured.cpu_ms,
        Metric::Measured { mechanism: Mechanism::HostProcessCpu, .. }
    ));
    assert_eq!(captured.peak_rss_mib.source(), UsageSource::Measured);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-hostd --bin mvm-libkrun-supervisor`
Expected: FAIL — `record_self_usage` undefined.

- [ ] **Step 3: Write the implementation**

```rust
/// Persist what this supervisor consumed on behalf of its machine.
///
/// The VMM shares this process, so the reading covers guest execution together
/// with device emulation and vsock pumping. Best-effort, like the exit capture
/// beside it.
fn record_self_usage(vm_state_dir: &Path) {
    let usage = UsageCapture {
        cpu_ms: process_usage::process_cpu_ms_self(),
        peak_rss_mib: process_usage::peak_rss_mib_self(),
        ..UsageCapture::default()
    };
    let _ = mvm_core::usage_capture::write_captured(vm_state_dir, &usage);
}
```

Call it on the supervisor's exit path, after the VMM run loop returns and before the process exits — including the wall-clock-expiry kill path, so a workload that outran its bound still leaves a reading.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-hostd libkrun_supervisor`
Expected: PASS.

- [ ] **Step 5: Rebuild the supervisor binary explicitly**

Run: `cargo build -p mvm-hostd --bin mvm-libkrun-supervisor`
Expected: success. The per-VM supervisors are separate binaries; a stale one silently makes a fixed build look broken at runtime.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-hostd/src/bin/mvm-libkrun-supervisor.rs
git commit -m "feat(hostd): record libkrun supervisor consumption at teardown"
```

---

### Task 9: HVF capture, and CPU measurement without a grant

The last task, and the only one that changes existing control flow. Today the vCPU clocks are constructed only inside the `cpu_millicores.and_then(...)` arm, so CPU is measured only when a share was granted. The clock moves out of that arm; the quota controller stays inside it.

**Files:**
- Modify: `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs:2006-2026`
- Test: same file's test module

**Interfaces:**
- Consumes: `SummedClock::new(clocks).consumed()` (`crates/mvm-vmm/src/quota/clock.rs`), `process_usage::peak_rss_mib_self` (Task 3), `usage_capture::write_captured` (Task 1).
- Produces: a `workload.usage` sidecar with `cpu_ms` under `Mechanism::HvfSummedVcpuClock`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn cpu_is_measured_on_a_machine_that_was_granted_no_share() {
    // The measurement and the bound are different questions. A machine with
    // no quota still runs vCPU threads whose clocks are readable.
    let clocks = vec![
        FixedClock::new(Duration::from_millis(2000)),
        FixedClock::new(Duration::from_millis(2210)),
    ];
    let usage = usage_from_clocks(SummedClock::new(clocks), None);
    assert_eq!(
        usage.cpu_ms,
        Metric::measured(4210, Mechanism::HvfSummedVcpuClock)
    );
}

#[test]
fn cpu_is_summed_across_vcpus_rather_than_read_off_one() {
    // A per-thread reading would understate an SMP guest by a factor of its
    // vCPU count.
    let one = usage_from_clocks(
        SummedClock::new(vec![FixedClock::new(Duration::from_millis(1000))]),
        None,
    );
    let four = usage_from_clocks(
        SummedClock::new(vec![FixedClock::new(Duration::from_millis(1000)); 4]),
        None,
    );
    assert_eq!(four.cpu_ms.value(), Some(4000));
    assert_eq!(one.cpu_ms.value(), Some(1000));
}

#[test]
fn a_machine_with_no_readable_clocks_reports_cpu_unavailable() {
    let usage = usage_from_clocks(SummedClock::new(Vec::<FixedClock>::new()), None);
    assert_eq!(usage.cpu_ms, Metric::unavailable());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-runtime hvf usage`
Expected: FAIL — `usage_from_clocks` undefined.

- [ ] **Step 3: Write the implementation**

Extract a testable helper rather than growing the already-large `run`:

```rust
/// What the machine consumed, from the clocks its vCPU threads carried.
///
/// The clock sum is the machine's CPU; a single thread's reading would
/// understate an SMP guest by its vCPU count. An empty clock set means nothing
/// was readable, which is unavailable rather than zero.
fn usage_from_clocks<C: ThreadCpuClock>(clocks: SummedClock<C>, empty: Option<()>) -> UsageCapture {
    let cpu_ms = if empty.is_some() {
        Metric::unavailable()
    } else {
        Metric::measured(
            u64::try_from(clocks.consumed().as_millis()).unwrap_or(u64::MAX),
            Mechanism::HvfSummedVcpuClock,
        )
    };
    UsageCapture {
        cpu_ms,
        peak_rss_mib: process_usage::peak_rss_mib_self(),
        ..UsageCapture::default()
    }
}
```

Adjust the emptiness signal to whatever `SummedClock` exposes; if it exposes none, keep the `clocks.is_empty()` check at the call site and pass the already-decided `Metric` in. The behaviour the tests pin is what matters: an empty clock set is `unavailable`, never `Metric::measured(0, ..)`.

Then restructure `kernel_boot.rs:2006-2026` so `clocks` is cloned for measurement before the quota arm consumes it, the `VcpuQuota::start_with_hold` call stays gated on `cpu_millicores`, and the measuring clock is read after `shared.end()` — once every vCPU is out of the guest and its final time is accounted. Write the sidecar there with `mvm_core::usage_capture::write_captured`, ignoring the error for the same reason every other capture site does.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-runtime hvf`
Expected: PASS.

- [ ] **Step 5: Confirm the quota path is unchanged**

Run: `cargo nextest run -p mvm-vmm quota`
Expected: PASS, unchanged. The controller stays grant-gated; only the measurement was hoisted. If any quota test changed behaviour, the hoist went too far.

- [ ] **Step 6: Rebuild the HVF supervisor binary explicitly**

Run: `cargo build -p mvm-hostd --bin mvm-hvf-supervisor`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-runtime/src/backends/hvf/kernel_boot.rs
git commit -m "feat(runtime): measure HVF guest vCPU time whether or not a share was granted"
```

---

### Task 10: Full gate and spec bookkeeping

**Files:**
- Modify: `specs/REFACTOR-STATUS.md`
- Create: `specs/sprint/delivery/receipt-attached-resource-utilization.md`

- [ ] **Step 1: Verify the Wasm state-dir question the spec left open**

The spec marks `host_state_bytes` unavailable on `Wasm`/`WebLinux`/`Mock` as the conservative answer, flagged as unverified. Check whether the Wasm tier keeps a VM state directory:

Run: `graft grep "vm_state_dir" --in crates/mvm-runtime/src/wasm_backend.rs`

If it does keep one, flip that cell to `StateDirTreeBytes` in `ResourceObservation::for_backend`, update the spec's coverage table, and add a test. If it does not, leave both as they are and note in the delivery file that this was checked rather than assumed.

- [ ] **Step 2: Run the full gate**

```bash
cargo fmt --all -- --check
cargo nextest run --workspace
cargo test --workspace --doc
cargo clippy --workspace -- -D warnings
just check-gated
```

Expected: all pass. `--all-targets` misses `required-features` targets and, on macOS, every `cfg(target_os = "linux")` file including Linux-gated tests — `just check-gated` covers both, and Task 3 added a Linux-gated arm.

- [ ] **Step 3: Run every xtask gate this change could touch**

```bash
cargo run -p xtask -- check-backend-resource-controls
cargo run -p xtask -- check-claim-catalog
cargo run -p xtask -- check-core-runtime-free
cargo run -p xtask -- check-single-network-path
```

Expected: all exit 0. `check-claim-catalog` must still pass unchanged — this feature adds no claim, and a red result there means something touched ADR-001's table.

- [ ] **Step 4: Write the delivery note**

Create `specs/sprint/delivery/receipt-attached-resource-utilization.md` describing what shipped, the per-backend coverage as built, and the two limits that stand: no macOS PR lane covers the real HVF measurement, and a host crash before teardown loses the reading exactly as it loses the exit code. Do **not** append to `specs/SPRINT.md` — `xtask check-sprint-append` fails if its delivery section grows.

- [ ] **Step 5: Update the refactor rollup**

Tick the matching entry in `specs/REFACTOR-STATUS.md` and bump its "Last updated" date in this same change.

- [ ] **Step 6: Commit**

```bash
git add specs/REFACTOR-STATUS.md specs/sprint/delivery/receipt-attached-resource-utilization.md
git commit -m "docs(specs): record the receipt usage delivery and refresh the rollup"
```

---

## Self-review

**Spec coverage.** Decisions 1–5 map to Tasks 5, 6, 1, 1, and 10 respectively. The data-flow steps map to Tasks 3 (observation), 7/8/9 (sidecar writers), 6 (`report_exit`), 4 (emitter), 5 (receipt export). The schema section maps to Task 1 with its wire validation, and Task 5 for the extension. The coverage matrix maps to Task 2. Every test named in the spec's testing section has a task: sidecar round trip and absent/malformed (Task 1), all-unavailable still emitted (Tasks 4 and 5), float guard (Task 5), tamper detection (Task 5), source separation (Task 1), exhaustiveness gate (Task 2). The GPU extension point is deliberately unimplemented per the spec and correctly has no task.

**One thing the spec did not anticipate**, found while reading the gate: `check_backend_resource_controls` locates its target with a first-match `find`, so adding a second `for_backend` to that file would have left the new matrix uninspected behind a green check. Task 2 fixes the gate and requires both matrices to be present. This is a plan addition, not a spec change.

**Known soft spots**, called out rather than hidden. Task 7's exact reap site and Task 9's clock-hoist restructure are described by behaviour and location rather than by a full diff, because both sit inside large existing functions whose surrounding code the implementer must read. Both carry tests that pin the required behaviour. Task 6 adds a `launched_at` field to `LaunchOutcome` whose construction sites the implementer must find; leaving it `None` degrades the wall metric to unavailable rather than to a wrong number, so a missed site fails safe.
