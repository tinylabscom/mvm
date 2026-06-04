//! Virtio-balloon reclaim controller.
//!
//! Workloads that opt into [`VmStartConfig::mem_initial_mib`] boot
//! with a pre-inflated balloon and only commit a fraction of their
//! cap. The host-side reclaim controller adjusts the balloon over
//! the VM's life so the host commits more when it has slack and
//! less when it's under pressure.
//!
//! This module ships the *policy* — a pure decision function that
//! takes a snapshot and returns an action. The wiring to a real
//! poller (sysinfo / Linux PSI / macOS memorystatus) plus the call
//! to `VmBackend::balloon_set_target` lives at the integration site
//! (the supervisor's main loop). Keeping policy and integration
//! separable makes the policy testable without spinning up a VMM.
//!
//! [`VmStartConfig::mem_initial_mib`]:
//!     mvm_core::vm_backend::VmStartConfig::mem_initial_mib

use std::sync::Mutex;

use mvm_core::vm_backend::{BalloonState, VmId};

/// Action to take on a single VM after a controller tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalloonAction {
    /// No change required — the current target stays.
    Hold,
    /// Inflate the balloon (reclaim from guest). `target_inflate_mib`
    /// is the new absolute target, not a delta.
    Inflate { vm: VmId, target_inflate_mib: u32 },
    /// Deflate the balloon (return memory to guest). `target_inflate_mib`
    /// is the new absolute target.
    Deflate { vm: VmId, target_inflate_mib: u32 },
}

/// Host memory pressure, normalised to 0.0..=1.0. Higher = more
/// pressure (more of host memory is in use). Exact source depends
/// on the host platform; the controller treats this as opaque.
///
/// Reasonable mappings:
/// - Linux: `MemAvailable / MemTotal` inverted (1 − available_ratio).
/// - Linux PSI: the 10-second `memory.pressure.full.avg10` is a
///   stronger signal than a flat used-fraction.
/// - macOS: vm_pressure (translate the qualitative state to a
///   numeric).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct HostPressure(pub f32);

impl HostPressure {
    /// Construct, clamping to `[0.0, 1.0]`. Defensive against
    /// platform shims that return out-of-range values under odd
    /// edge cases.
    pub fn clamped(p: f32) -> Self {
        Self(p.clamp(0.0, 1.0))
    }
}

/// Two-threshold band policy for v1. Above `inflate_above`, claim
/// pages from idle guests; below `deflate_below`, hand them back.
/// Between the two, hold the current target so we don't thrash.
#[derive(Debug, Clone, Copy)]
pub struct BalloonPolicy {
    /// Inflate when host pressure rises above this fraction.
    pub inflate_above: f32,
    /// Deflate when host pressure falls below this fraction.
    pub deflate_below: f32,
    /// MiB to adjust per tick. Keeping the step modest avoids
    /// thrashing the guest's allocator under marginal pressure.
    pub step_mib: u32,
    /// Floor for guest commitment in MiB. The balloon is never
    /// inflated past `max_mib - guest_floor_mib` — under-provisioned
    /// guests OOM-kill workloads, which is worse than the host
    /// taking the pressure.
    pub guest_floor_mib: u32,
}

impl Default for BalloonPolicy {
    fn default() -> Self {
        // Defaults tuned for dev-laptop ergonomics: inflate when the
        // host is at 80% memory (a real squeeze), deflate when it's
        // back below 60% (we have headroom). 64 MiB step + 64 MiB
        // guest floor balances responsiveness against thrash.
        Self {
            inflate_above: 0.80,
            deflate_below: 0.60,
            step_mib: 64,
            guest_floor_mib: 64,
        }
    }
}

impl BalloonPolicy {
    /// Decide the action for a single VM. Pure function: no I/O,
    /// no clock, no allocator state. The caller is responsible for
    /// reading `state` from the backend and `pressure` from the host
    /// before each invocation.
    ///
    /// Invariants:
    /// - Returns `Hold` when no progress can be made (already at
    ///   ceiling or floor in the relevant direction).
    /// - Never produces a target that would push the guest below
    ///   `guest_floor_mib` of commitment.
    /// - The dead-band between `deflate_below` and `inflate_above`
    ///   prevents pressure oscillations from thrashing the balloon.
    pub fn decide(&self, vm: &VmId, state: BalloonState, pressure: HostPressure) -> BalloonAction {
        // Inflate path — claim more pages back from the guest.
        if pressure.0 >= self.inflate_above {
            // Ceiling: leave at least `guest_floor_mib` to the guest.
            let max_inflate = state.max_mib.saturating_sub(self.guest_floor_mib);
            let new_target = state
                .inflated_mib
                .saturating_add(self.step_mib)
                .min(max_inflate);
            if new_target > state.inflated_mib {
                return BalloonAction::Inflate {
                    vm: vm.clone(),
                    target_inflate_mib: new_target,
                };
            }
            return BalloonAction::Hold;
        }

        // Deflate path — return pages to the guest.
        if pressure.0 <= self.deflate_below {
            let new_target = state.inflated_mib.saturating_sub(self.step_mib);
            if new_target < state.inflated_mib {
                return BalloonAction::Deflate {
                    vm: vm.clone(),
                    target_inflate_mib: new_target,
                };
            }
            return BalloonAction::Hold;
        }

        BalloonAction::Hold
    }
}

// ---------------------------------------------------------------------------
// HostPressureSource — pluggable platform reader
// ---------------------------------------------------------------------------

/// Pluggable provider of host memory pressure.
///
/// Production wiring uses [`SysinfoPressureSource`]. Linux PSI
/// (`/proc/pressure/memory`) and macOS `vm_pressure` are stronger
/// signals; wiring them as alternative implementations behind the
/// same trait is a deliberate follow-up (the controller doesn't
/// need to change, only the source).
pub trait HostPressureSource: Send + Sync {
    /// Read the current pressure. Errors propagate; the controller
    /// surfaces them as `TickOutcome::error` rather than panicking.
    fn current(&self) -> anyhow::Result<HostPressure>;
}

/// Cross-platform pressure source backed by the `sysinfo` crate.
///
/// Reports `used_memory / total_memory` as the pressure value. This
/// is a coarse signal — it doesn't distinguish "host actively
/// pressured" from "host has caches it could drop." Good enough for
/// v1 ergonomics on dev laptops; not good enough for production
/// scheduling decisions, where PSI is the right answer on Linux.
pub struct SysinfoPressureSource {
    sys: Mutex<sysinfo::System>,
}

impl SysinfoPressureSource {
    /// Construct with a fresh `sysinfo::System` ready for memory
    /// reads. Cheap; safe to keep one per process.
    pub fn new() -> Self {
        Self {
            sys: Mutex::new(sysinfo::System::new()),
        }
    }
}

impl Default for SysinfoPressureSource {
    fn default() -> Self {
        Self::new()
    }
}

impl HostPressureSource for SysinfoPressureSource {
    fn current(&self) -> anyhow::Result<HostPressure> {
        // sysinfo's API mutates the System on refresh, hence the
        // Mutex. The mutation is bounded — we hold the lock just
        // long enough to refresh + read.
        let mut sys = self
            .sys
            .lock()
            .map_err(|e| anyhow::anyhow!("sysinfo mutex poisoned: {e}"))?;
        sys.refresh_memory();
        let total = sys.total_memory() as f64;
        if total <= 0.0 {
            return Ok(HostPressure(0.0));
        }
        let used = sys.used_memory() as f64;
        let ratio = (used / total) as f32;
        Ok(HostPressure::clamped(ratio))
    }
}

/// Linux PSI-backed pressure source.
///
/// Reads `/proc/pressure/memory` and reports the 10-second
/// percentage that *every* runnable task spent stalled on memory
/// (`full avg10`), divided by 100 to land in `[0.0, 1.0]`. PSI is
/// the stronger signal on Linux because it distinguishes "host has
/// caches it could drop" (low PSI) from "host is actively stalled
/// freeing pages" (high PSI). sysinfo's `used/total` conflates the
/// two.
///
/// Some kernels (containers without `CONFIG_PSI=y`, or hosts where
/// the file lacks the `full` line) only expose `some`; this impl
/// falls back to the `some avg10` value in that case, which still
/// captures memory-pressure stalls on *at least one* task and is
/// strictly more informative than no signal at all.
///
/// Construction succeeds eagerly so callers can wire the source
/// up at process boot without an `Option<Box<dyn …>>`; the file
/// existence + parse round-trip is re-checked on every `current()`
/// call to gracefully tolerate transient I/O hiccups.
pub struct PsiPressureSource {
    path: std::path::PathBuf,
}

impl PsiPressureSource {
    /// Construct, defaulting to `/proc/pressure/memory`. Use
    /// [`from_path`](Self::from_path) for tests that point at a
    /// tempfile fixture.
    pub fn new() -> Self {
        Self::from_path("/proc/pressure/memory")
    }

    /// Construct from an explicit path. The path can be any file
    /// whose contents match Linux's PSI memory format —
    /// fixture-driven tests use this to drive deterministic
    /// pressure values without poking real procfs.
    pub fn from_path<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }
}

impl Default for PsiPressureSource {
    fn default() -> Self {
        Self::new()
    }
}

impl HostPressureSource for PsiPressureSource {
    fn current(&self) -> anyhow::Result<HostPressure> {
        let contents = std::fs::read_to_string(&self.path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", self.path.display()))?;
        let avg10 = parse_psi_full_avg10(&contents)
            .or_else(|| parse_psi_some_avg10(&contents))
            .ok_or_else(|| {
                anyhow::anyhow!("could not parse `full avg10` or `some avg10` from PSI file")
            })?;
        // PSI reports a percentage 0..100; the controller expects
        // a fraction 0..1.
        Ok(HostPressure::clamped(avg10 / 100.0))
    }
}

/// Parse the `full avg10=NN.NN` value from PSI memory output.
fn parse_psi_full_avg10(contents: &str) -> Option<f32> {
    parse_psi_avg10_for_prefix(contents, "full ")
}

/// Parse the `some avg10=NN.NN` value from PSI memory output.
fn parse_psi_some_avg10(contents: &str) -> Option<f32> {
    parse_psi_avg10_for_prefix(contents, "some ")
}

fn parse_psi_avg10_for_prefix(contents: &str, prefix: &str) -> Option<f32> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            for kv in rest.split_whitespace() {
                if let Some(v) = kv.strip_prefix("avg10=") {
                    return v.parse().ok();
                }
            }
        }
    }
    None
}

/// macOS pressure source backed by the
/// `kern.memorystatus_vm_pressure_level` sysctl.
///
/// macOS exposes a discrete pressure state — 1 (Normal), 2 (Warn),
/// 4 (Critical) — rather than a continuous fraction. The mapping
/// to a 0..1 value is approximate: Normal → 0.30 (controller sits
/// well below the inflate threshold), Warn → 0.70 (still under the
/// 0.80 inflate trigger but above the deflate floor, so the
/// controller holds), Critical → 0.95 (well above inflate, so
/// the controller actively reclaims).
///
/// Construction always succeeds; `current()` returns the live
/// reading or falls back to sysinfo if the sysctl call fails
/// (older macOS, unusual sandbox restrictions, etc.).
#[cfg(target_os = "macos")]
pub struct VmPressureLevelSource {
    fallback: SysinfoPressureSource,
}

#[cfg(target_os = "macos")]
impl VmPressureLevelSource {
    pub fn new() -> Self {
        Self {
            fallback: SysinfoPressureSource::new(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Default for VmPressureLevelSource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl HostPressureSource for VmPressureLevelSource {
    fn current(&self) -> anyhow::Result<HostPressure> {
        match read_macos_pressure_level() {
            Ok(level) => Ok(HostPressure::clamped(macos_level_to_pressure(level))),
            Err(_) => {
                // Sysctl unavailable on this build / sandbox /
                // macOS version: degrade to sysinfo's used/total
                // rather than failing the whole tick. The
                // controller's dead-band absorbs the difference.
                self.fallback.current()
            }
        }
    }
}

/// Read `kern.memorystatus_vm_pressure_level` via sysctl. The
/// kernel publishes one of: 1 (Normal), 2 (Warn), 4 (Critical).
#[cfg(target_os = "macos")]
fn read_macos_pressure_level() -> anyhow::Result<i32> {
    use std::ffi::CString;

    let name = CString::new("kern.memorystatus_vm_pressure_level")
        .expect("sysctl name has no interior NULs");
    let mut value: i32 = 0;
    let mut size: libc::size_t = std::mem::size_of::<i32>();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut value as *mut i32 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        anyhow::bail!(
            "sysctlbyname(kern.memorystatus_vm_pressure_level) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(value)
}

/// Map the discrete macOS pressure level to a fraction in `[0,1]`.
///
/// The thresholds chosen line up with `BalloonPolicy`'s defaults
/// (`inflate_above = 0.80`, `deflate_below = 0.60`):
///
/// - Normal (1) → 0.30: below `deflate_below`, controller releases
///   memory.
/// - Warn (2)   → 0.70: inside the dead-band, controller holds.
/// - Critical (4) → 0.95: above `inflate_above`, controller
///   reclaims aggressively.
///
/// Unknown values default to Normal (0.30) — the conservative
/// choice when the kernel reports a level the controller doesn't
/// recognise, since over-deflating is recoverable but over-
/// inflating risks OOM-killing the workload.
#[cfg(target_os = "macos")]
fn macos_level_to_pressure(level: i32) -> f32 {
    match level {
        1 => 0.30,
        2 => 0.70,
        4 => 0.95,
        _ => 0.30,
    }
}

/// Pick the best-available pressure source for the current host.
///
/// - Linux with PSI available → [`PsiPressureSource`].
/// - macOS → [`VmPressureLevelSource`] (which itself falls back
///   to sysinfo on sysctl failure).
/// - Anything else → [`SysinfoPressureSource`].
///
/// The return type is `Box<dyn HostPressureSource>` so the caller
/// can plumb a single value into `BalloonController` without
/// per-platform generics.
pub fn default_pressure_source() -> Box<dyn HostPressureSource> {
    #[cfg(target_os = "linux")]
    {
        let psi = PsiPressureSource::new();
        // Probe once: if the file exists + parses, prefer PSI;
        // otherwise fall through to sysinfo so a container without
        // `CONFIG_PSI=y` still gets a working signal.
        if psi.current().is_ok() {
            return Box::new(psi);
        }
    }
    #[cfg(target_os = "macos")]
    {
        return Box::new(VmPressureLevelSource::new());
    }
    #[allow(unreachable_code)]
    Box::new(SysinfoPressureSource::new())
}

// ---------------------------------------------------------------------------
// BalloonController — pressure-driven reclaim tick
// ---------------------------------------------------------------------------

/// Outcome of a single VM's tick. Surfaces both the decision and
/// whether application succeeded so the host can log + react.
#[derive(Debug, Clone)]
pub struct TickOutcome {
    pub vm: VmId,
    pub action: BalloonAction,
    /// Whether `apply` was actually called. `Hold` actions don't
    /// call apply; non-`Hold` actions do — `applied=true` here means
    /// the apply call returned Ok.
    pub applied: bool,
    /// Stringified error from the apply call. Held as a String (not
    /// `anyhow::Error`) so `TickOutcome` can derive `Clone`.
    pub error: Option<String>,
}

/// Pressure-driven balloon reclaim controller. Owns a `BalloonPolicy`
/// plus a `HostPressureSource`; produces decisions per-VM and (when
/// the caller hands it an apply fn) executes them.
///
/// Generic over the pressure source so tests can inject a fixed
/// pressure value without going through sysinfo. Production code
/// wires `SysinfoPressureSource` (or, once landed,
/// `PsiPressureSource` / `MacVmPressureSource`).
pub struct BalloonController<P: HostPressureSource> {
    pub policy: BalloonPolicy,
    pub pressure: P,
}

impl<P: HostPressureSource> BalloonController<P> {
    /// Construct with an explicit policy + pressure source.
    pub fn new(policy: BalloonPolicy, pressure: P) -> Self {
        Self { policy, pressure }
    }

    /// Single tick. For each `(vm, state)`, decide an action and
    /// apply it via the caller-provided `apply` closure. Pressure is
    /// read once at the start of the tick — same value drives every
    /// VM's decision for fairness.
    ///
    /// `apply(vm, target_inflate_mib)` is what the caller wires to
    /// `AnyBackend::balloon_set_target`. Splitting the apply out as
    /// a closure keeps the tick logic testable without a real
    /// backend.
    ///
    /// On pressure-read failure, returns an error before evaluating
    /// any VM — better to skip the whole tick than apply with a
    /// stale value.
    pub fn tick<A>(
        &self,
        vm_states: &[(VmId, BalloonState)],
        mut apply: A,
    ) -> anyhow::Result<Vec<TickOutcome>>
    where
        A: FnMut(&VmId, u32) -> anyhow::Result<()>,
    {
        let pressure = self.pressure.current()?;
        let mut out = Vec::with_capacity(vm_states.len());
        for (vm, state) in vm_states {
            let action = self.policy.decide(vm, *state, pressure);
            let target = match &action {
                BalloonAction::Hold => None,
                BalloonAction::Inflate {
                    target_inflate_mib, ..
                }
                | BalloonAction::Deflate {
                    target_inflate_mib, ..
                } => Some(*target_inflate_mib),
            };
            let (applied, error) = match target {
                None => (false, None),
                Some(t) => match apply(vm, t) {
                    Ok(()) => (true, None),
                    Err(e) => (false, Some(format!("{e:#}"))),
                },
            };
            out.push(TickOutcome {
                vm: vm.clone(),
                action,
                applied,
                error,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(max_mib: u32, inflated_mib: u32) -> BalloonState {
        BalloonState {
            max_mib,
            inflated_mib,
            host_committed_mib: max_mib.saturating_sub(inflated_mib),
        }
    }

    fn vm() -> VmId {
        VmId("test-vm".to_string())
    }

    #[test]
    fn high_pressure_inflates_by_step() {
        let p = BalloonPolicy::default();
        let action = p.decide(&vm(), state(1024, 0), HostPressure(0.85));
        assert_eq!(
            action,
            BalloonAction::Inflate {
                vm: vm(),
                target_inflate_mib: p.step_mib,
            }
        );
    }

    #[test]
    fn low_pressure_deflates_by_step() {
        let p = BalloonPolicy::default();
        let action = p.decide(&vm(), state(1024, 512), HostPressure(0.40));
        assert_eq!(
            action,
            BalloonAction::Deflate {
                vm: vm(),
                target_inflate_mib: 512 - p.step_mib,
            }
        );
    }

    #[test]
    fn dead_band_holds_position() {
        let p = BalloonPolicy::default();
        // 0.70 is between 0.60 and 0.80.
        let action = p.decide(&vm(), state(1024, 256), HostPressure(0.70));
        assert_eq!(action, BalloonAction::Hold);
    }

    #[test]
    fn inflate_caps_at_guest_floor() {
        let p = BalloonPolicy {
            inflate_above: 0.80,
            deflate_below: 0.60,
            step_mib: 64,
            guest_floor_mib: 64,
        };
        // 1024 - 64 floor = 960 ceiling. Inflated already at 940;
        // adding step (64) would land at 1004, but we cap at 960.
        let action = p.decide(&vm(), state(1024, 940), HostPressure(0.95));
        assert_eq!(
            action,
            BalloonAction::Inflate {
                vm: vm(),
                target_inflate_mib: 960,
            }
        );
    }

    #[test]
    fn inflate_at_ceiling_holds() {
        let p = BalloonPolicy::default();
        // Already at the ceiling — no more headroom.
        let ceiling = 1024 - p.guest_floor_mib;
        let action = p.decide(&vm(), state(1024, ceiling), HostPressure(0.95));
        assert_eq!(action, BalloonAction::Hold);
    }

    #[test]
    fn deflate_at_zero_holds() {
        let p = BalloonPolicy::default();
        // Balloon already fully deflated — nothing to return.
        let action = p.decide(&vm(), state(1024, 0), HostPressure(0.10));
        assert_eq!(action, BalloonAction::Hold);
    }

    #[test]
    fn deflate_saturates_at_zero() {
        let p = BalloonPolicy {
            inflate_above: 0.80,
            deflate_below: 0.60,
            step_mib: 256,
            guest_floor_mib: 64,
        };
        // Only 32 MiB inflated; step is 256 — deflating must
        // saturate at 0, not underflow.
        let action = p.decide(&vm(), state(1024, 32), HostPressure(0.10));
        assert_eq!(
            action,
            BalloonAction::Deflate {
                vm: vm(),
                target_inflate_mib: 0,
            }
        );
    }

    #[test]
    fn host_pressure_clamps_out_of_range_input() {
        // Defensive clamping on the wire: a platform shim returning
        // 1.5 or -0.1 must not break the policy.
        let high = HostPressure::clamped(1.5);
        let low = HostPressure::clamped(-0.1);
        assert!((high.0 - 1.0).abs() < f32::EPSILON);
        assert!(low.0.abs() < f32::EPSILON);
    }

    #[test]
    fn exact_threshold_is_inclusive() {
        // At exactly inflate_above and deflate_below, behave as the
        // boundary direction. (`>=` / `<=` semantics.)
        let p = BalloonPolicy::default();
        let inflate = p.decide(&vm(), state(1024, 0), HostPressure(0.80));
        assert!(matches!(inflate, BalloonAction::Inflate { .. }));
        let deflate = p.decide(&vm(), state(1024, 256), HostPressure(0.60));
        assert!(matches!(deflate, BalloonAction::Deflate { .. }));
    }

    #[test]
    fn default_policy_sanity_band() {
        let p = BalloonPolicy::default();
        assert!(p.deflate_below < p.inflate_above);
        assert!(p.step_mib > 0);
        assert!(p.guest_floor_mib > 0);
    }

    // ── Pressure source + controller tests ───────────────────────

    /// Test-only fixed-value pressure source. The controller is
    /// generic over the source trait so this stays out of the
    /// production code path.
    struct FixedPressure(HostPressure);
    impl HostPressureSource for FixedPressure {
        fn current(&self) -> anyhow::Result<HostPressure> {
            Ok(self.0)
        }
    }

    /// Pressure source that always errors. Exercises the
    /// "skip-whole-tick on read failure" guarantee.
    struct ErroringPressure;
    impl HostPressureSource for ErroringPressure {
        fn current(&self) -> anyhow::Result<HostPressure> {
            anyhow::bail!("pretend the platform reader failed")
        }
    }

    #[test]
    fn sysinfo_pressure_source_returns_in_range_value() {
        let src = SysinfoPressureSource::new();
        let p = src.current().expect("sysinfo read");
        // Used / total memory is always within [0, 1] after the
        // clamp; this asserts the impl plumbs through to a sane
        // number rather than a panic.
        assert!((0.0..=1.0).contains(&p.0), "got {}", p.0);
    }

    #[test]
    fn controller_tick_holds_in_dead_band() {
        let c = BalloonController::new(BalloonPolicy::default(), FixedPressure(HostPressure(0.70)));
        // No calls should happen — Hold doesn't fire `apply`.
        let mut apply_calls = 0;
        let outcomes = c
            .tick(&[(vm(), state(1024, 256))], |_, _| {
                apply_calls += 1;
                Ok(())
            })
            .expect("tick succeeds");
        assert_eq!(apply_calls, 0);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].action, BalloonAction::Hold);
        assert!(!outcomes[0].applied);
        assert!(outcomes[0].error.is_none());
    }

    #[test]
    fn controller_tick_applies_inflate_under_high_pressure() {
        let c = BalloonController::new(BalloonPolicy::default(), FixedPressure(HostPressure(0.95)));
        let mut applied_targets: Vec<(VmId, u32)> = Vec::new();
        let outcomes = c
            .tick(&[(vm(), state(1024, 0))], |v, t| {
                applied_targets.push((v.clone(), t));
                Ok(())
            })
            .expect("tick succeeds");
        assert_eq!(applied_targets.len(), 1);
        assert_eq!(applied_targets[0].0, vm());
        assert_eq!(applied_targets[0].1, BalloonPolicy::default().step_mib);
        assert!(outcomes[0].applied);
        assert!(matches!(outcomes[0].action, BalloonAction::Inflate { .. }));
    }

    #[test]
    fn controller_tick_applies_deflate_under_low_pressure() {
        let c = BalloonController::new(BalloonPolicy::default(), FixedPressure(HostPressure(0.30)));
        let mut targets: Vec<u32> = Vec::new();
        c.tick(&[(vm(), state(1024, 512))], |_, t| {
            targets.push(t);
            Ok(())
        })
        .expect("tick succeeds");
        assert_eq!(targets, vec![512 - BalloonPolicy::default().step_mib]);
    }

    #[test]
    fn controller_tick_records_apply_error_per_vm() {
        let c = BalloonController::new(BalloonPolicy::default(), FixedPressure(HostPressure(0.95)));
        let outcomes = c
            .tick(&[(vm(), state(1024, 0))], |_, _| {
                anyhow::bail!("backend.balloon_set_target failed")
            })
            .expect("tick itself succeeds even when apply errors");
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].applied);
        let err = outcomes[0].error.as_deref().expect("error captured");
        assert!(err.contains("balloon_set_target failed"), "got: {err}");
    }

    #[test]
    fn controller_tick_skips_whole_tick_on_pressure_read_failure() {
        let c = BalloonController::new(BalloonPolicy::default(), ErroringPressure);
        // apply must never get called when pressure read fails —
        // a stale-value tick is worse than a missed tick.
        let mut apply_calls = 0;
        let result = c.tick(&[(vm(), state(1024, 0))], |_, _| {
            apply_calls += 1;
            Ok(())
        });
        assert!(result.is_err(), "tick must error when pressure errors");
        assert_eq!(apply_calls, 0, "apply must not run when pressure errors");
    }

    #[test]
    fn controller_tick_pressure_read_is_per_tick_not_per_vm() {
        // Drive a controller with two VMs through one tick — the
        // pressure source should be consulted once, not twice. A
        // counting source enforces this; AtomicU32 keeps the source
        // Sync without an unsafe impl.
        use std::sync::atomic::{AtomicU32, Ordering};
        struct CountingPressure(AtomicU32, HostPressure);
        impl HostPressureSource for CountingPressure {
            fn current(&self) -> anyhow::Result<HostPressure> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(self.1)
            }
        }
        let src = CountingPressure(AtomicU32::new(0), HostPressure(0.95));
        let c = BalloonController::new(BalloonPolicy::default(), src);
        c.tick(
            &[
                (VmId("a".into()), state(1024, 0)),
                (VmId("b".into()), state(1024, 0)),
            ],
            |_, _| Ok(()),
        )
        .expect("tick");
        assert_eq!(
            c.pressure.0.load(Ordering::SeqCst),
            1,
            "pressure should be read once per tick, not once per VM"
        );
    }

    // ── PsiPressureSource tests ─────────────────────────────────────

    #[test]
    fn psi_parses_full_avg10() {
        // Real-shape PSI content with both `some` and `full`. The
        // controller prefers `full avg10` because it captures the
        // stronger "every task stalled" signal.
        let raw = "some avg10=12.34 avg60=23.45 avg300=34.56 total=12345\n\
                   full avg10=42.50 avg60=12.34 avg300=5.67 total=2345\n";
        let pressure = parse_psi_full_avg10(raw).expect("parse");
        assert!((pressure - 42.50).abs() < 0.001);
    }

    #[test]
    fn psi_falls_back_to_some_when_full_absent() {
        // Container kernels without CONFIG_PSI=y sometimes expose
        // only the `some` line. The source must still produce a
        // signal.
        let raw = "some avg10=7.50 avg60=5.00 avg300=3.00 total=999\n";
        assert!(parse_psi_full_avg10(raw).is_none());
        let pressure = parse_psi_some_avg10(raw).expect("parse some");
        assert!((pressure - 7.50).abs() < 0.001);
    }

    #[test]
    fn psi_returns_none_for_garbage() {
        // Malformed input shouldn't panic — return None so the
        // source surfaces an error instead.
        assert!(parse_psi_full_avg10("nope\nnothing\nuseful").is_none());
        assert!(parse_psi_some_avg10("nope\nnothing\nuseful").is_none());
    }

    #[test]
    fn psi_source_reads_from_fixture_path() {
        // Drive the full source against a tempfile so we can pin
        // behaviour without poking real procfs (which may not
        // exist on macOS / BSD test runners).
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(
            tmp.path(),
            "some avg10=80.00 avg60=70.00 avg300=60.00 total=100\n\
             full avg10=85.50 avg60=70.00 avg300=60.00 total=100\n",
        )
        .expect("write fixture");
        let src = PsiPressureSource::from_path(tmp.path());
        let p = src.current().expect("current");
        // 85.50 / 100 = 0.855 (clamped to <=1.0).
        assert!((p.0 - 0.855).abs() < 0.001);
    }

    #[test]
    fn psi_source_clamps_percentage_above_100() {
        // PSI is well-defined as 0..100 but the parser doesn't
        // reject out-of-range values — clamping is the source's
        // responsibility so the controller never sees a >1.0
        // pressure that would break its 0..1 contract.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(
            tmp.path(),
            "full avg10=150.00 avg60=10.00 avg300=10.00 total=1\n",
        )
        .expect("write fixture");
        let src = PsiPressureSource::from_path(tmp.path());
        let p = src.current().expect("current");
        assert_eq!(p.0, 1.0);
    }

    #[test]
    fn psi_source_surfaces_io_error_when_path_missing() {
        let src = PsiPressureSource::from_path("/this/path/does/not/exist");
        let err = src.current().unwrap_err();
        assert!(err.to_string().contains("read"));
    }

    // ── macOS VmPressureLevelSource tests ───────────────────────────

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_level_mapping_lines_up_with_policy_thresholds() {
        // Defaults: inflate at 0.80, deflate at 0.60.
        // Normal (1) → 0.30 sits below deflate threshold (controller releases).
        // Warn (2)   → 0.70 sits in the dead-band (controller holds).
        // Critical (4) → 0.95 sits above inflate threshold (controller reclaims).
        let default_policy = BalloonPolicy::default();
        assert!(macos_level_to_pressure(1) < default_policy.deflate_below);
        let warn = macos_level_to_pressure(2);
        assert!(warn > default_policy.deflate_below);
        assert!(warn < default_policy.inflate_above);
        assert!(macos_level_to_pressure(4) > default_policy.inflate_above);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unknown_level_maps_to_normal() {
        // Unknown values default to the conservative (Normal)
        // mapping — over-deflating is recoverable, over-inflating
        // risks OOM.
        let expected = macos_level_to_pressure(1);
        assert_eq!(macos_level_to_pressure(99), expected);
        assert_eq!(macos_level_to_pressure(-1), expected);
        assert_eq!(macos_level_to_pressure(0), expected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vm_pressure_source_returns_in_range() {
        // Live sysctl call — every macOS host returns a valid
        // level. Test asserts the resulting pressure is bounded
        // in [0, 1] (the clamp covers any future kernel returning
        // an unmapped value).
        let src = VmPressureLevelSource::new();
        let p = src.current().expect("sysctl read");
        assert!(p.0 >= 0.0 && p.0 <= 1.0);
    }

    // ── default_pressure_source() tests ─────────────────────────────

    #[test]
    fn default_pressure_source_returns_something_callable() {
        // Smoke test: the factory returns a working source on
        // every platform the test suite runs on.
        let src = default_pressure_source();
        let p = src.current().expect("current");
        assert!(p.0 >= 0.0 && p.0 <= 1.0);
    }
}
