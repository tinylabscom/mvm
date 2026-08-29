//! Which resource dimensions a backend can actually bound, and what it
//! achieved when asked to.
//!
//! Declaring the mechanism separately from applying it is what keeps a receipt
//! honest: `EnforcedTier` is built from reading the control back off the
//! system, so a label can never assert an enforcement that did not happen.

use serde::{Deserialize, Serialize};

use crate::protocol::vm_backend::BackendKind;

/// How a backend bounds CPU, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuControl {
    /// No CPU bound is available on this tier.
    None,
    /// cgroup v2 `cpu.max` on the per-VM supervisor process.
    CgroupShare,
    /// A deterministic wasmtime instruction budget.
    WasmFuel,
    /// The HVF scheduler's own per-thread quota controller.
    HvfVcpuQuota,
}

impl CpuControl {
    /// Whether this control can serve a `CpuGrant::Share`. Fuel cannot: an
    /// instruction count and a fraction of a host core are different units
    /// with no conversion between them.
    #[must_use]
    pub const fn serves_share(self) -> bool {
        matches!(self, Self::CgroupShare | Self::HvfVcpuQuota)
    }

    /// Whether this control can serve a `CpuGrant::Fuel`.
    #[must_use]
    pub const fn serves_fuel(self) -> bool {
        matches!(self, Self::WasmFuel)
    }
}

/// How a backend bounds wall-clock runtime, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WallClockControl {
    /// No wall-clock bound is available on this tier.
    None,
    /// A host-side timer owned by the per-VM supervisor process, which outlives
    /// the CLI invocation and owns the VMM for the workload's whole life.
    /// Answerable only by a tier that *has* such a process — a timer in a
    /// process that exits at launch cannot fire.
    SupervisorTimer,
    /// wasmtime epoch interruption, which preempts a module that a fuel
    /// budget alone would never stop.
    WasmEpoch,
}

/// The controls one backend offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceControls {
    pub cpu: CpuControl,
    pub wall_clock: WallClockControl,
}

impl ResourceControls {
    /// The controls each backend has. Exhaustive on purpose: a new
    /// `BackendKind` must answer this question rather than inherit a default
    /// that might silently claim or silently drop enforcement.
    #[must_use]
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            // libkrun is *not* Linux-only — it is the macOS 13-25 workload
            // default — and macOS has no cgroup, so the CPU answer depends on
            // the host rather than the kind alone. Declaring `CgroupShare` on a
            // Mac would let a share grant be accepted and then fail at apply
            // time, the overstatement the macOS arm below exists to avoid.
            // `cfg!` is the right test because mvm runs on the host it was
            // built for; there is no cross-host execution to disagree with it.
            //
            // It is also the one VMM tier with a per-VM supervisor process of
            // ours: `mvm-libkrun-supervisor` blocks in the VMM run loop for the
            // workload's whole life, which is what a timer needs in order to be
            // able to fire at all.
            BackendKind::Libkrun => Self {
                cpu: if cfg!(target_os = "linux") {
                    CpuControl::CgroupShare
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::SupervisorTimer,
            },
            // A cgroup can bound any Linux process, so on Linux these tiers
            // carry a real CPU quota. Their wall clock is a different story:
            // the VMM is a bare child of a `mvmctl` that exits at launch, so
            // there is no process of ours left to hold a deadline. Answering
            // `SupervisorTimer` here would be the same overstatement the macOS
            // CPU arm below exists to avoid — a bound accepted at admission and
            // enforced by nothing.
            BackendKind::Firecracker | BackendKind::Qemu => Self {
                cpu: if cfg!(target_os = "linux") {
                    CpuControl::CgroupShare
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::None,
            },
            // macOS has no cgroup equivalent; thread QoS is priority, not quota.
            // `mvm-hvf-supervisor` is a per-VM process that outlives the
            // launching `mvmctl`, and it is now handed the admitted plan, so it
            // holds a timer that can actually fire. AppleContainer shares this
            // arm because it *is* this tier: it runs an `HvfRunner` over the
            // same driver and supervisor, substituting only the kernel image.
            BackendKind::Hvf | BackendKind::AppleContainer => Self {
                cpu: if cfg!(target_os = "macos") {
                    CpuControl::HvfVcpuQuota
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::SupervisorTimer,
            },
            // Fuel bounds instructions; epoch preempts a module parked in a
            // host call, which fuel alone would never stop.
            BackendKind::Wasm => Self {
                cpu: CpuControl::WasmFuel,
                wall_clock: WallClockControl::WasmEpoch,
            },
            BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
            // Browser-hosted software emulation. CPU and wall-clock bounds are
            // declared in the plan but cannot be enforced by the host OS; the
            // browser runtime refuses rather than claiming an unenforceable
            // control.
            BackendKind::WebLinux => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }
}

impl Default for ResourceControls {
    /// Enforces nothing — the value that understates rather than overstates.
    fn default() -> Self {
        Self {
            cpu: CpuControl::None,
            wall_clock: WallClockControl::None,
        }
    }
}

/// How a backend observes CPU consumption, if it can.
///
/// These do not measure the same quantity, which is why the choice is named
/// rather than reduced to a boolean: guest vCPU time excludes the host-side
/// device emulation that a process total includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuObservation {
    /// Nothing about CPU can be measured on this tier.
    None,
    /// Summed Mach clocks of every vCPU thread: guest execution only.
    HvfSummedVcpuClock,
    /// The in-process VMM's own process CPU time: guest plus VMM overhead.
    HostProcessCpu,
    /// `getrusage` over a reaped VMM child: guest plus VMM overhead.
    HostChildRusage,
}

impl CpuObservation {
    /// The mechanism a capture site uses on a backend carrying this control,
    /// or `None` where there is nothing to measure.
    #[must_use]
    pub const fn mechanism(self) -> Option<Mechanism> {
        match self {
            Self::None => None,
            Self::HvfSummedVcpuClock => Some(Mechanism::HvfSummedVcpuClock),
            Self::HostProcessCpu => Some(Mechanism::HostProcessCpu),
            Self::HostChildRusage => Some(Mechanism::HostChildRusage),
        }
    }
}

/// How a backend observes resident memory, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryObservation {
    /// Nothing about resident memory can be measured on this tier.
    None,
    /// The kernel-kept resident high-water mark of the VMM process.
    HostProcessRss,
}

impl MemoryObservation {
    /// The mechanism a capture site uses on a backend carrying this control,
    /// or `None` where there is nothing to measure.
    #[must_use]
    pub const fn mechanism(self) -> Option<Mechanism> {
        match self {
            Self::None => None,
            Self::HostProcessRss => Some(Mechanism::HostProcessRss),
        }
    }
}

/// How a backend observes host-side state growth, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStateObservation {
    /// Nothing about host-side state growth can be measured on this tier.
    None,
    /// Byte total of the VM state directory tree.
    StateDirTreeBytes,
}

impl HostStateObservation {
    /// The mechanism a capture site uses on a backend carrying this control,
    /// or `None` where there is nothing to measure.
    #[must_use]
    pub const fn mechanism(self) -> Option<Mechanism> {
        match self {
            Self::None => None,
            Self::StateDirTreeBytes => Some(Mechanism::StateDirTreeBytes),
        }
    }
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
    /// The host's own observation of the span from launch to teardown.
    HostLaunchSpan,
}

impl WallObservation {
    /// The mechanism a capture site uses. Unconditional, because every tier
    /// can be timed by the host that launched it.
    #[must_use]
    pub const fn mechanism(self) -> Mechanism {
        match self {
            Self::HostLaunchSpan => Mechanism::HostLaunchSpan,
        }
    }
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
            // Neither VMM is a child of ours. Firecracker is launched
            // session-detached and orphaned to init before the launch call
            // returns, and usually runs as root while `mvmctl` does not; qemu
            // daemonizes itself, so the process the launch reaps is not the one
            // that ends up running the guest. Both are followed by pid through
            // a process-exit observer rather than by a wait, which is exactly
            // why the teardown path is written around an observer. There is no
            // rusage to collect from a process we never reap, and no process of
            // ours whose resident size says anything about the guest.
            BackendKind::Firecracker | BackendKind::Qemu => Self {
                cpu: CpuObservation::None,
                memory: MemoryObservation::None,
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

/// What actually bounded one dimension. Constructed from a read-back of the
/// live control, never from the value that was written.
///
/// An enum rather than a string: a receipt label is a security-relevant
/// assertion, and a typo in a free-form mechanism string would be
/// indistinguishable from a real tier. `label()` renders for display; nothing
/// dispatches on the rendered text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcedTier {
    /// Nothing bounded this dimension; the value is a declaration only.
    Declared,
    Cgroup2CpuMax,
    WasmFuel,
    WasmEpoch,
    SupervisorTimer,
    HvfVcpuQuota,
}

impl EnforcedTier {
    /// Whether a mechanism actually bounded this dimension.
    #[must_use]
    pub const fn is_enforced(self) -> bool {
        !matches!(self, Self::Declared)
    }

    /// Display rendering for receipts and `doctor` output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Cgroup2CpuMax => "cgroup2:cpu.max",
            Self::WasmFuel => "wasmtime:fuel",
            Self::WasmEpoch => "wasmtime:epoch",
            Self::SupervisorTimer => "supervisor:timer",
            Self::HvfVcpuQuota => "hvf:vcpu-quota",
        }
    }
}

/// What a backend achieved across every dimension for one VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedGrants {
    pub cpu: EnforcedTier,
    pub wall_clock: EnforcedTier,
}

impl EnforcedGrants {
    /// The honest answer for a backend that enforces nothing.
    #[must_use]
    pub const fn all_declared() -> Self {
        Self {
            cpu: EnforcedTier::Declared,
            wall_clock: EnforcedTier::Declared,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vm_backend::BackendKind;

    #[test]
    fn every_backend_kind_declares_its_controls() {
        // Exhaustive by construction: adding a BackendKind variant without
        // answering here is a compile error, not a silent default.
        for kind in [
            BackendKind::Firecracker,
            BackendKind::Libkrun,
            BackendKind::Qemu,
            BackendKind::Mock,
            BackendKind::Hvf,
            BackendKind::Wasm,
            BackendKind::AppleContainer,
        ] {
            let _ = ResourceControls::for_backend(kind);
        }
    }

    #[test]
    fn the_wasm_tier_uses_fuel_and_epoch() {
        let c = ResourceControls::for_backend(BackendKind::Wasm);
        assert_eq!(c.cpu, CpuControl::WasmFuel);
        assert_eq!(c.wall_clock, WallClockControl::WasmEpoch);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_hvf_tier_bounds_cpu_with_its_own_scheduler_on_macos() {
        let c = ResourceControls::for_backend(BackendKind::Hvf);
        assert_eq!(c.cpu, CpuControl::HvfVcpuQuota);
        assert!(c.cpu.serves_share());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_hvf_tier_cannot_bound_cpu_off_macos() {
        // No Mach host thread accounting exists on this host, so a share grant
        // must be refused at negotiation time rather than accepted and left to
        // fail at apply.
        let c = ResourceControls::for_backend(BackendKind::Hvf);
        assert_eq!(c.cpu, CpuControl::None);
        assert!(!c.cpu.serves_share());
    }

    /// Only a tier with a per-VM supervisor process of ours may claim a
    /// supervisor timer. A timer needs two things: a process that outlives the
    /// CLI, and the admitted plan to read a bound from. On the remaining VMM
    /// tiers the VMM is a bare child of an `mvmctl` that has already exited —
    /// so the answer there is `None`, not a bound that would be admitted and
    /// never fire.
    #[test]
    fn only_a_tier_with_a_live_supervisor_claims_a_supervisor_timer() {
        for kind in [
            BackendKind::Libkrun,
            // HVF gained its half of this when the supervisor started being
            // handed the plan; AppleContainer runs the same driver and
            // supervisor, so it is the same tier for this purpose.
            BackendKind::Hvf,
            BackendKind::AppleContainer,
        ] {
            assert_eq!(
                ResourceControls::for_backend(kind).wall_clock,
                WallClockControl::SupervisorTimer,
                "{kind:?} has a per-VM supervisor holding the admitted plan"
            );
        }
        for kind in [
            BackendKind::Firecracker,
            BackendKind::Qemu,
            BackendKind::Mock,
        ] {
            assert_eq!(
                ResourceControls::for_backend(kind).wall_clock,
                WallClockControl::None,
                "{kind:?} has no supervisor process to hold a deadline"
            );
        }
    }

    #[test]
    fn a_share_grant_is_unenforceable_on_the_wasm_tier() {
        let c = ResourceControls::for_backend(BackendKind::Wasm);
        assert!(!c.cpu.serves_share());
    }

    // libkrun is a live macOS 13-25 workload backend, not a Linux-only tier,
    // so its CPU control must depend on the host rather than the kind alone.
    // Written as a pair of `cfg`-gated halves rather than one assertion so
    // the test is a witness on whichever host runs it, instead of only
    // passing on the machine the author happened to be using.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_libkrun_tier_bounds_cpu_via_cgroup_on_linux() {
        let c = ResourceControls::for_backend(BackendKind::Libkrun);
        assert_eq!(c.cpu, CpuControl::CgroupShare);
        assert!(c.cpu.serves_share());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_libkrun_tier_cannot_bound_cpu_off_linux() {
        // No cgroup exists on this host, so a share grant must be refused at
        // negotiation time rather than accepted and left to fail at apply.
        let c = ResourceControls::for_backend(BackendKind::Libkrun);
        assert_eq!(c.cpu, CpuControl::None);
        assert!(!c.cpu.serves_share());
    }

    #[test]
    fn a_declared_tier_reports_itself_as_unenforced() {
        assert!(!EnforcedTier::Declared.is_enforced());
        assert_eq!(EnforcedTier::Declared.label(), "declared");
    }

    #[test]
    fn every_enforced_tier_names_its_mechanism() {
        assert!(EnforcedTier::Cgroup2CpuMax.is_enforced());
        assert_eq!(EnforcedTier::Cgroup2CpuMax.label(), "cgroup2:cpu.max");
        assert_eq!(EnforcedTier::WasmFuel.label(), "wasmtime:fuel");
        assert_eq!(EnforcedTier::WasmEpoch.label(), "wasmtime:epoch");
        assert_eq!(EnforcedTier::SupervisorTimer.label(), "supervisor:timer");
        assert_eq!(EnforcedTier::HvfVcpuQuota.label(), "hvf:vcpu-quota");
    }

    #[test]
    fn every_enforced_tier_has_a_distinct_label() {
        let labels = [
            EnforcedTier::Declared.label(),
            EnforcedTier::Cgroup2CpuMax.label(),
            EnforcedTier::WasmFuel.label(),
            EnforcedTier::WasmEpoch.label(),
            EnforcedTier::SupervisorTimer.label(),
            EnforcedTier::HvfVcpuQuota.label(),
        ];
        for (i, a) in labels.iter().enumerate() {
            for (j, b) in labels.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "enforced tier labels must be unique");
                }
            }
        }
    }

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
    fn a_cpu_bound_a_backend_can_apply_does_not_mean_it_can_observe_one() {
        // The distinction the whole matrix exists for: a control is not an
        // observation, and neither direction implies the other.
        //
        // A cgroup bounds any process on Linux, including one we never forked,
        // so Firecracker carries a real CPU quota there — and still observes no
        // CPU, because a usage reading needs a process we reaped and that VMM
        // detaches before the launch returns.
        let firecracker_controls = ResourceControls::for_backend(BackendKind::Firecracker);
        let firecracker = ResourceObservation::for_backend(BackendKind::Firecracker);
        if cfg!(target_os = "linux") {
            assert_eq!(firecracker_controls.cpu, CpuControl::CgroupShare);
        }
        assert_eq!(firecracker.cpu, CpuObservation::None);

        // The other direction, on libkrun: off Linux there is no cgroup to
        // bound it with, and its CPU is still measurable — the VMM runs inside
        // our own supervisor process, whose usage reads without any quota
        // controller.
        let libkrun_controls = ResourceControls::for_backend(BackendKind::Libkrun);
        let libkrun = ResourceObservation::for_backend(BackendKind::Libkrun);
        if !cfg!(target_os = "linux") {
            assert_eq!(libkrun_controls.cpu, CpuControl::None);
        }
        assert_eq!(libkrun.cpu, CpuObservation::HostProcessCpu);
    }

    #[test]
    fn a_backend_whose_vmm_is_not_our_child_observes_neither_cpu_nor_memory() {
        // Firecracker launches session-detached and orphaned to init; qemu
        // daemonizes itself. Neither is ever reaped, so there is no rusage, and
        // the resident size of this process describes this process rather than
        // the guest. Pinned because the alternative is a declaration nobody can
        // honour: the capture site would have to fabricate a measurement or
        // silently write nothing while the matrix promised a number.
        for kind in [BackendKind::Firecracker, BackendKind::Qemu] {
            let observation = ResourceObservation::for_backend(kind);
            assert_eq!(observation.cpu, CpuObservation::None, "{kind:?}");
            assert_eq!(observation.memory, MemoryObservation::None, "{kind:?}");
            // The two the host takes for itself still hold: the state directory
            // is on our disk and the launch span is on our clock.
            assert_eq!(
                observation.host_state,
                HostStateObservation::StateDirTreeBytes,
                "{kind:?}"
            );
            assert_eq!(
                observation.wall,
                WallObservation::HostLaunchSpan,
                "{kind:?}"
            );
        }
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

    #[test]
    fn every_observation_maps_to_a_distinct_mechanism() {
        // The observation enums deliberately mirror `Mechanism`'s vocabulary.
        // Mapping every measurable variant into that one vocabulary, and
        // requiring the mapping to be injective, is what catches a variant
        // added to one enum and not the other: without it the two would drift
        // into carrying duplicate wire strings for different quantities.
        let mapped = [
            CpuObservation::HvfSummedVcpuClock.mechanism(),
            CpuObservation::HostProcessCpu.mechanism(),
            CpuObservation::HostChildRusage.mechanism(),
            MemoryObservation::HostProcessRss.mechanism(),
            HostStateObservation::StateDirTreeBytes.mechanism(),
            Some(WallObservation::HostLaunchSpan.mechanism()),
        ];
        for (i, a) in mapped.iter().enumerate() {
            assert!(
                a.is_some(),
                "a measurable observation must name a mechanism"
            );
            for (j, b) in mapped.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "two observations claim the same mechanism");
                }
            }
        }
        assert_eq!(CpuObservation::None.mechanism(), None);
        assert_eq!(MemoryObservation::None.mechanism(), None);
        assert_eq!(HostStateObservation::None.mechanism(), None);
    }
}
