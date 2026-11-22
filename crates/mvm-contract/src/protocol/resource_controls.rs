//! Which resource dimensions a backend can actually bound, and what it
//! achieved when asked to.
//!
//! Declaring the mechanism separately from applying it is what keeps a receipt
//! honest: `EnforcedTier` is built from reading the control back off the
//! system, so a label can never assert an enforcement that did not happen.

use serde::{Deserialize, Serialize};

use crate::plan::topology::IsolationTier;
use crate::protocol::cpu_set::CpuSet;
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

/// How a backend keeps a unit's vCPUs on cores no other unit uses, if it can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementControl {
    /// Scheduling is left to the host; exclusive placement cannot be served.
    #[default]
    None,
    /// An allowed-CPU set on the transient scope the VMM process is born into,
    /// read back off the scope's `cpuset.cpus.effective`.
    SpawnScopeCpuSet,
}

impl PlacementControl {
    /// What `kind` offers on a host where the spawn scope can, or cannot,
    /// carry an allowed-CPU set.
    ///
    /// Host-conditional rather than kind-conditional, which is why it is not a
    /// field of [`ResourceControls::for_backend`]: the scope needs a systemd
    /// user session with the cpuset controller delegated to it, and the kind
    /// alone cannot say whether this host has that. Only Firecracker answers
    /// with a mechanism. The other scoped VMMs run on the same scope, but no
    /// admission path places them, and the in-house VMMs would need per-vCPU
    /// thread affinity, which does not exist yet.
    #[must_use]
    pub const fn for_host(kind: BackendKind, scope_cpuset: bool) -> Self {
        match kind {
            // The probe behind `scope_cpuset` needs systemd and a cgroup v2
            // hierarchy, so it answers true only on Linux.
            BackendKind::Firecracker if scope_cpuset => Self::SpawnScopeCpuSet,
            BackendKind::Firecracker
            | BackendKind::Libkrun
            | BackendKind::Qemu
            | BackendKind::Hvf
            | BackendKind::AppleContainer
            | BackendKind::Wasm
            | BackendKind::Mock
            | BackendKind::WebLinux => Self::None,
        }
    }
}

/// How a backend keeps a failover standby, if it can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyControl {
    /// No standby of any class is kept, so only a pair of class `None` can be
    /// served.
    #[default]
    None,
}

/// How a backend holds a single-writer state cell, if it can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateCellControl {
    /// No host-held cell exists on this tier.
    #[default]
    None,
    /// The host's own cell store: reserved at topology admission, written
    /// only by the writer unit's current epoch, independent of the VMM.
    HostStore,
}

/// How a backend holds a unit's liveness deadline, if it can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessControl {
    /// No host-held deadline exists, so a liveness period cannot be served.
    #[default]
    None,
    /// The host's own deadline store, which the host-side liveness pass reads:
    /// reset only by traffic the epoch gate accepts from the unit's current
    /// epoch, and expired by fencing that epoch in the workload ledger.
    HostDeadline,
}

/// Which cryptographic suites a backend's admission path implements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiteControl {
    /// Only [`CryptoSuite::CLASSICAL`](crate::plan::topology::CryptoSuite::CLASSICAL).
    #[default]
    ClassicalOnly,
}

/// The controls one backend offers.
///
/// The fields after `wall_clock` answer the critical-profile requirements a
/// topology can state. Each defaults to the answer that serves nothing, so an
/// encoding from a peer that predates them decodes fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceControls {
    pub cpu: CpuControl,
    pub wall_clock: WallClockControl,
    #[serde(default)]
    pub placement: PlacementControl,
    #[serde(default)]
    pub standby: StandbyControl,
    #[serde(default)]
    pub state_cells: StateCellControl,
    #[serde(default)]
    pub liveness: LivenessControl,
    /// The strongest isolation tier the backend provides on every run, or
    /// `None` where it provides none at all.
    #[serde(default)]
    pub isolation: Option<IsolationTier>,
    #[serde(default)]
    pub suite: SuiteControl,
}

impl ResourceControls {
    /// The controls each backend has. Exhaustive on purpose: a new
    /// `BackendKind` must answer this question rather than inherit a default
    /// that might silently claim or silently drop enforcement.
    ///
    /// No backend pins cores exclusively, keeps a standby, or implements a
    /// suite beyond the classical one, so every arm answers `None` /
    /// `ClassicalOnly` for those. They are spelled out per arm
    /// anyway: when one backend gains a mechanism, its arm changes and no
    /// other does.
    ///
    /// State cells live in the host's own store, so they do not depend on the
    /// VMM. They are offered by every tier whose unit is a guest with a vsock
    /// channel to the host, the only path a cell is reached by, and by the
    /// mock, whose store is the same host store. A wasm module has no such
    /// channel and a browser-hosted guest has no host store.
    ///
    /// The liveness deadline is held in the host's store too, but something
    /// has to fence the unit once it passes. That is the per-VM supervisor,
    /// so the tiers with one offer a period: libkrun, HVF and AppleContainer,
    /// the same answer as `wall_clock` for the same reason, and the mock,
    /// whose tests run the pass themselves. Firecracker and QEMU leave no
    /// process of ours beside the guest, and a wasm module or a
    /// browser-hosted guest has no unit timer at all, so a period is refused
    /// there rather than declared and watched by nothing.
    ///
    /// A host that suspends does not refuse a period. The deadline is an
    /// absolute time and is not extended across the suspend, so a deadline
    /// that passed while the host slept fences when the supervisor next runs,
    /// and the expiry records how long the host was seen suspended.
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
                // KVM on Linux, Hypervisor.framework on macOS: hardware
                // virtualization either way.
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::HostStore,
                liveness: LivenessControl::HostDeadline,
                isolation: Some(IsolationTier::Vm),
                suite: SuiteControl::ClassicalOnly,
            },
            // A cgroup can bound any Linux process — including one we never
            // forked — so on Linux these tiers carry a real CPU quota. Their
            // wall clock is a different story: neither VMM is a child of ours
            // at all. Firecracker detaches its session and is orphaned to init
            // before the launch returns, and qemu daemonizes itself, so there
            // is no process of ours left to hold a deadline. Answering
            // `SupervisorTimer` here would be the same overstatement the macOS
            // CPU arm below exists to avoid — a bound accepted at admission and
            // enforced by nothing. A liveness deadline is refused for the same
            // want of an owner.
            //
            // The two part on isolation. Firecracker refuses to start without
            // `/dev/kvm`. QEMU falls back to TCG software emulation when KVM is
            // absent, which leaves only the host process boundary, and the
            // kind alone cannot say which of the two a launch will get.
            BackendKind::Firecracker => Self {
                cpu: if cfg!(target_os = "linux") {
                    CpuControl::CgroupShare
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::None,
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::HostStore,
                liveness: LivenessControl::None,
                isolation: Some(IsolationTier::Vm),
                suite: SuiteControl::ClassicalOnly,
            },
            BackendKind::Qemu => Self {
                cpu: if cfg!(target_os = "linux") {
                    CpuControl::CgroupShare
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::None,
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::HostStore,
                liveness: LivenessControl::None,
                isolation: Some(IsolationTier::Task),
                suite: SuiteControl::ClassicalOnly,
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
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::HostStore,
                liveness: LivenessControl::HostDeadline,
                isolation: Some(IsolationTier::Vm),
                suite: SuiteControl::ClassicalOnly,
            },
            // Fuel bounds instructions; epoch preempts a module parked in a
            // host call, which fuel alone would never stop. The module runs
            // inside our own process, confined by wasmtime's linear-memory
            // bounds and nothing beneath them: memory protection without
            // virtualization.
            BackendKind::Wasm => Self {
                cpu: CpuControl::WasmFuel,
                wall_clock: WallClockControl::WasmEpoch,
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::None,
                liveness: LivenessControl::None,
                isolation: Some(IsolationTier::Task),
                suite: SuiteControl::ClassicalOnly,
            },
            // Mock boots nothing, so it isolates nothing.
            BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::HostStore,
                liveness: LivenessControl::HostDeadline,
                isolation: None,
                suite: SuiteControl::ClassicalOnly,
            },
            // Browser-hosted software emulation. CPU and wall-clock bounds are
            // declared in the plan but cannot be enforced by the host OS; the
            // browser runtime refuses rather than claiming an unenforceable
            // control. The emulated guest is confined by the browser's process
            // sandbox, not by hardware virtualization.
            BackendKind::WebLinux => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
                placement: PlacementControl::None,
                standby: StandbyControl::None,
                state_cells: StateCellControl::None,
                liveness: LivenessControl::None,
                isolation: Some(IsolationTier::Task),
                suite: SuiteControl::ClassicalOnly,
            },
        }
    }
}

impl ResourceControls {
    /// [`Self::for_backend`] with the placement this host can serve, given
    /// whether its spawn scope can carry an allowed-CPU set.
    #[must_use]
    pub const fn on_host(kind: BackendKind, scope_cpuset: bool) -> Self {
        let mut controls = Self::for_backend(kind);
        controls.placement = PlacementControl::for_host(kind, scope_cpuset);
        controls
    }
}

impl Default for ResourceControls {
    /// Enforces nothing — the value that understates rather than overstates.
    fn default() -> Self {
        Self {
            cpu: CpuControl::None,
            wall_clock: WallClockControl::None,
            placement: PlacementControl::None,
            standby: StandbyControl::None,
            state_cells: StateCellControl::None,
            liveness: LivenessControl::None,
            isolation: None,
            suite: SuiteControl::ClassicalOnly,
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
}

impl CpuObservation {
    /// The mechanism a capture site uses on a backend carrying this
    /// observation, or `None` where there is nothing to measure.
    #[must_use]
    pub const fn mechanism(self) -> Option<Mechanism> {
        match self {
            Self::None => None,
            Self::HvfSummedVcpuClock => Some(Mechanism::HvfSummedVcpuClock),
            Self::HostProcessCpu => Some(Mechanism::HostProcessCpu),
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
    /// The mechanism a capture site uses on a backend carrying this
    /// observation, or `None` where there is nothing to measure.
    #[must_use]
    pub const fn mechanism(self) -> Option<Mechanism> {
        match self {
            Self::None => None,
            Self::HostProcessRss => Some(Mechanism::HostProcessRss),
        }
    }
}

/// How a backend observes host-side state growth.
///
/// There is no `None`, for the same reason [`WallObservation`] has none: every
/// run the host launches, it launches out of a state directory on its own
/// disk, and reading that directory's size needs no cooperation from the VMM.
/// A variant meaning "unobservable" would be declared by no backend, and would
/// let the matrix disagree with a capture site that measures unconditionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStateObservation {
    /// Byte total of the VM state directory tree.
    StateDirTreeBytes,
}

impl HostStateObservation {
    /// The mechanism a capture site uses. Unconditional, because the host can
    /// measure its own state directory on every tier.
    #[must_use]
    pub const fn mechanism(self) -> Mechanism {
        match self {
            Self::StateDirTreeBytes => Mechanism::StateDirTreeBytes,
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
            // CPU number would assert a measurement that does not happen, and
            // the module runs in-process with no separate VMM to hold a
            // resident size. It does keep a host-side state directory,
            // though: `start_in_mode` unconditionally writes
            // `wasm-activation/activation.json` under `vm_state_dir`, and
            // that directory outlives the synchronous run (only the
            // egress-endpoint subdirectory, when spawned, is reaped inline),
            // so a tree-size reading at exit observes something real.
            BackendKind::Wasm => Self {
                cpu: CpuObservation::None,
                memory: MemoryObservation::None,
                host_state: HostStateObservation::StateDirTreeBytes,
                wall: WallObservation::HostLaunchSpan,
            },
            // WebLinux runs in a browser and Mock boots nothing, so neither
            // has a host VMM process whose CPU or resident size says anything
            // about a guest. The two dimensions the host takes for itself do
            // still hold: every run is launched out of a state directory on
            // our disk, whose tree size reads without any cooperation from the
            // tier, and every run is timed on our clock.
            BackendKind::WebLinux | BackendKind::Mock => Self {
                cpu: CpuObservation::None,
                memory: MemoryObservation::None,
                host_state: HostStateObservation::StateDirTreeBytes,
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
    /// cgroup v2 `memory.max` on the scope the VMM process was born into.
    Cgroup2MemoryMax,
    /// cgroup v2 `pids.max` on the scope the VMM process was born into.
    Cgroup2PidsMax,
    /// cgroup v2 `cpuset.cpus.effective` on the scope the VMM process was born
    /// into.
    Cgroup2CpusetEffective,
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
            Self::Cgroup2MemoryMax => "cgroup2:memory.max",
            Self::Cgroup2PidsMax => "cgroup2:pids.max",
            Self::Cgroup2CpusetEffective => "cgroup2:cpuset.cpus.effective",
        }
    }
}

/// A host ceiling read back off a live control: the mechanism holding it and
/// the value that control reported.
///
/// The value travels with the tier because a ceiling, unlike a CPU tier, is a
/// number a reader can check against the guest it bounds. It is always the
/// value read back, never the value that was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedCeiling {
    tier: EnforcedTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
}

impl EnforcedCeiling {
    /// Nothing bounded this dimension.
    #[must_use]
    pub const fn declared() -> Self {
        Self {
            tier: EnforcedTier::Declared,
            limit: None,
        }
    }

    /// `tier` holds this dimension at `limit`, in the dimension's own unit:
    /// bytes for memory, tasks for a task count.
    #[must_use]
    pub const fn enforced(tier: EnforcedTier, limit: u64) -> Self {
        Self {
            tier,
            limit: Some(limit),
        }
    }

    /// The mechanism holding this ceiling.
    #[must_use]
    pub const fn tier(self) -> EnforcedTier {
        self.tier
    }

    /// The ceiling in effect, or `None` when nothing bounds it.
    #[must_use]
    pub const fn limit(self) -> Option<u64> {
        self.limit
    }
}

/// The CPU set a VMM's scope was confined to: the set admission asked for and
/// the set read back off the scope.
///
/// Unlike a CPU tier, the request is recorded beside the read-back. A launch
/// whose read-back differs from its request is refused before this is
/// written, so a recorded pair always agrees; both are kept so a reader can
/// see that without trusting the code that compared them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedPlacement {
    /// The set admission computed for this launch, or `None` when it asked for
    /// no confinement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<CpuSet>,
    /// The scope's `cpuset.cpus.effective`, or `None` when it was not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<CpuSet>,
}

impl EnforcedPlacement {
    /// Nothing asked for and nothing read.
    #[must_use]
    pub fn is_unset(&self) -> bool {
        self.requested.is_none() && self.effective.is_none()
    }

    /// The mechanism holding the placement: the cpuset read-back when one
    /// was read, otherwise a declaration.
    #[must_use]
    pub const fn tier(&self) -> EnforcedTier {
        match self.effective {
            Some(_) => EnforcedTier::Cgroup2CpusetEffective,
            None => EnforcedTier::Declared,
        }
    }
}

/// What a backend achieved across every dimension for one VM.
///
/// `memory` and `tasks` are not grants a plan asks for. They are the host's own
/// ceilings on the VMM process, reported here because they bound the same
/// workload and are read back off the same controls. `placement` is the core
/// set the scope was confined to, present only when admission asked for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedGrants {
    pub cpu: EnforcedTier,
    pub wall_clock: EnforcedTier,
    pub memory: EnforcedCeiling,
    pub tasks: EnforcedCeiling,
    #[serde(default, skip_serializing_if = "EnforcedPlacement::is_unset")]
    pub placement: EnforcedPlacement,
}

impl EnforcedGrants {
    /// CPU and wall-clock tiers for a tier with no VMM process of its own for
    /// a spawn scope to hold, so both ceilings are declared.
    #[must_use]
    pub const fn without_spawn_ceilings(cpu: EnforcedTier, wall_clock: EnforcedTier) -> Self {
        Self {
            cpu,
            wall_clock,
            memory: EnforcedCeiling::declared(),
            tasks: EnforcedCeiling::declared(),
            placement: EnforcedPlacement {
                requested: None,
                effective: None,
            },
        }
    }

    /// The honest answer for a backend that enforces nothing.
    #[must_use]
    pub const fn all_declared() -> Self {
        Self {
            cpu: EnforcedTier::Declared,
            wall_clock: EnforcedTier::Declared,
            memory: EnforcedCeiling::declared(),
            tasks: EnforcedCeiling::declared(),
            placement: EnforcedPlacement {
                requested: None,
                effective: None,
            },
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
            BackendKind::WebLinux,
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
    /// tiers the VMM is not a process of ours at all — it detaches or
    /// daemonizes itself away from the launching `mvmctl` — so the answer there
    /// is `None`, not a bound that would be admitted and never fire.
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
        assert_eq!(EnforcedTier::Cgroup2MemoryMax.label(), "cgroup2:memory.max");
        assert_eq!(EnforcedTier::Cgroup2PidsMax.label(), "cgroup2:pids.max");
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
            EnforcedTier::Cgroup2MemoryMax.label(),
            EnforcedTier::Cgroup2PidsMax.label(),
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
    fn a_declared_ceiling_carries_no_value() {
        let ceiling = EnforcedCeiling::declared();
        assert_eq!(ceiling.tier(), EnforcedTier::Declared);
        assert_eq!(ceiling.limit(), None);
        assert!(!ceiling.tier().is_enforced());
    }

    #[test]
    fn an_enforced_ceiling_round_trips_with_its_read_back_value() {
        let grants = EnforcedGrants {
            cpu: EnforcedTier::Declared,
            wall_clock: EnforcedTier::Declared,
            memory: EnforcedCeiling::enforced(EnforcedTier::Cgroup2MemoryMax, 805_306_368),
            tasks: EnforcedCeiling::enforced(EnforcedTier::Cgroup2PidsMax, 1024),
            placement: EnforcedPlacement::default(),
        };
        let json = serde_json::to_string(&grants).expect("serialize");
        assert!(!json.contains("placement"), "{json}");
        assert!(json.contains(r#""memory":{"tier":"cgroup2_memory_max","limit":805306368}"#));
        assert!(json.contains(r#""tasks":{"tier":"cgroup2_pids_max","limit":1024}"#));
        let back: EnforcedGrants = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, grants);
    }

    /// The serde roundtrip above exercises the private field, not the reader a
    /// receipt consumer actually calls — a getter that stopped returning the
    /// stored value would leave every roundtrip green.
    #[test]
    fn an_enforced_ceiling_reads_back_its_limit_through_the_getter() {
        let memory = EnforcedCeiling::enforced(EnforcedTier::Cgroup2MemoryMax, 805_306_368);
        assert_eq!(memory.limit(), Some(805_306_368));
        let tasks = EnforcedCeiling::enforced(EnforcedTier::Cgroup2PidsMax, 1024);
        assert_eq!(tasks.limit(), Some(1024));
    }

    #[test]
    fn a_placement_round_trips_in_the_kernel_list_format() {
        let mut grants = EnforcedGrants::all_declared();
        grants.placement = EnforcedPlacement {
            requested: Some(CpuSet::parse("2-3").unwrap()),
            effective: Some(CpuSet::parse("2,3").unwrap()),
        };
        assert_eq!(
            grants.placement.tier(),
            EnforcedTier::Cgroup2CpusetEffective
        );
        let json = serde_json::to_string(&grants).expect("serialize");
        assert!(
            json.contains(r#""placement":{"requested":"2-3","effective":"2-3"}"#),
            "{json}"
        );
        let back: EnforcedGrants = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, grants);
        assert_eq!(EnforcedPlacement::default().tier(), EnforcedTier::Declared);
    }

    #[test]
    fn a_declared_ceiling_serializes_without_a_value() {
        let json = serde_json::to_string(&EnforcedGrants::all_declared()).expect("serialize");
        assert!(json.contains(r#""memory":{"tier":"declared"}"#), "{json}");
        let back: EnforcedGrants = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, EnforcedGrants::all_declared());
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
    fn the_non_vm_tiers_observe_no_guest_process_only_what_the_host_owns() {
        // The point being pinned is that these two tiers have no host VMM
        // process: WebLinux runs in a browser and Mock boots nothing, so a CPU
        // or resident-size reading would describe `mvmctl` rather than a
        // guest. It is not a claim that nothing at all is observable — the
        // state directory is the host's own and the span is on the host's own
        // clock, and `report_exit` measures both on every tier without asking
        // the backend for anything.
        for kind in [BackendKind::WebLinux, BackendKind::Mock] {
            let observation = ResourceObservation::for_backend(kind);
            assert_eq!(observation.cpu, CpuObservation::None, "{kind:?}");
            assert_eq!(observation.memory, MemoryObservation::None, "{kind:?}");
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
    fn every_backend_observes_its_host_state_directory() {
        // The host measures its own disk without cooperation from the tier, so
        // — like the wall span — there is no backend for which this dimension
        // is unobservable. Pinned as a matrix-wide property because
        // `report_exit` assigns it unconditionally, and a `None` cell here
        // would be a matrix that disagrees with the capture site.
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
                ResourceObservation::for_backend(kind).host_state,
                HostStateObservation::StateDirTreeBytes,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_wasm_tier_observes_its_activation_state_directory() {
        // `WasmBackend::start_in_mode` unconditionally writes
        // `wasm-activation/activation.json` under `vm_state_dir` before
        // running the module, and that directory is not cleaned up when the
        // synchronous run finishes — only a spawned egress endpoint's own
        // subdirectory is reaped inline. So unlike CPU and memory, which have
        // no in-process VMM to observe, the state directory is real and
        // measurable.
        let observation = ResourceObservation::for_backend(BackendKind::Wasm);
        assert_eq!(observation.cpu, CpuObservation::None);
        assert_eq!(observation.memory, MemoryObservation::None);
        assert_eq!(
            observation.host_state,
            HostStateObservation::StateDirTreeBytes
        );
        assert_eq!(observation.wall, WallObservation::HostLaunchSpan);
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
            MemoryObservation::HostProcessRss.mechanism(),
            Some(HostStateObservation::StateDirTreeBytes.mechanism()),
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
    }

    #[test]
    fn an_observation_round_trips_through_its_wire_form() {
        // These names end up inside a signed receipt, so a rename that
        // survives compilation still breaks every verifier that already
        // parsed the old spelling.
        let observation = ResourceObservation::for_backend(BackendKind::Libkrun);
        let json = serde_json::to_string(&observation).expect("serialize");
        assert_eq!(
            json,
            r#"{"cpu":"host_process_cpu","memory":"host_process_rss","host_state":"state_dir_tree_bytes","wall":"host_launch_span"}"#
        );
        assert_eq!(
            serde_json::from_str::<ResourceObservation>(&json).expect("deserialize"),
            observation
        );
    }

    #[test]
    fn an_observation_carrying_an_unknown_field_is_refused() {
        // `deny_unknown_fields` is what stops a future dimension from being
        // silently dropped by an older reader that then attests the rest as
        // complete.
        let err = serde_json::from_str::<ResourceObservation>(
            r#"{"cpu":"none","memory":"none","host_state":"state_dir_tree_bytes","wall":"host_launch_span","gpu":"none"}"#,
        );
        assert!(err.is_err(), "an unknown observation field must not parse");
    }

    #[test]
    fn every_observation_variant_round_trips_through_its_wire_string() {
        for cpu in [
            CpuObservation::None,
            CpuObservation::HvfSummedVcpuClock,
            CpuObservation::HostProcessCpu,
        ] {
            let json = serde_json::to_string(&cpu).expect("serialize");
            assert_eq!(
                serde_json::from_str::<CpuObservation>(&json).expect("deserialize"),
                cpu
            );
        }
        for memory in [MemoryObservation::None, MemoryObservation::HostProcessRss] {
            let json = serde_json::to_string(&memory).expect("serialize");
            assert_eq!(
                serde_json::from_str::<MemoryObservation>(&json).expect("deserialize"),
                memory
            );
        }
        let host_state =
            serde_json::to_string(&HostStateObservation::StateDirTreeBytes).expect("serialize");
        assert_eq!(host_state, r#""state_dir_tree_bytes""#);
        assert_eq!(
            serde_json::from_str::<HostStateObservation>(&host_state).expect("deserialize"),
            HostStateObservation::StateDirTreeBytes
        );
        let wall = serde_json::to_string(&WallObservation::HostLaunchSpan).expect("serialize");
        assert_eq!(wall, r#""host_launch_span""#);
        assert_eq!(
            serde_json::from_str::<WallObservation>(&wall).expect("deserialize"),
            WallObservation::HostLaunchSpan
        );
    }

    #[test]
    fn every_mechanism_round_trips_through_its_wire_string() {
        for (mechanism, wire) in [
            (Mechanism::HvfSummedVcpuClock, r#""hvf_summed_vcpu_clock""#),
            (Mechanism::HostProcessCpu, r#""host_process_cpu""#),
            (Mechanism::HostProcessRss, r#""host_process_rss""#),
            (Mechanism::StateDirTreeBytes, r#""state_dir_tree_bytes""#),
            (Mechanism::HostLaunchSpan, r#""host_launch_span""#),
        ] {
            assert_eq!(serde_json::to_string(&mechanism).expect("serialize"), wire);
            assert_eq!(
                serde_json::from_str::<Mechanism>(wire).expect("deserialize"),
                mechanism
            );
        }
    }

    #[test]
    fn the_default_controls_enforce_nothing_and_round_trip() {
        let default = ResourceControls::default();
        assert_eq!(default.cpu, CpuControl::None);
        assert_eq!(default.wall_clock, WallClockControl::None);
        assert_eq!(default.isolation, None);
        let json = serde_json::to_string(&default).expect("serialize");
        assert_eq!(
            serde_json::from_str::<ResourceControls>(&json).expect("deserialize"),
            default
        );
    }

    #[test]
    fn a_controls_encoding_without_the_critical_fields_decodes_serving_nothing() {
        let decoded: ResourceControls =
            serde_json::from_str(r#"{"cpu":"wasm_fuel","wall_clock":"wasm_epoch"}"#)
                .expect("deserialize");
        assert_eq!(
            decoded,
            ResourceControls {
                cpu: CpuControl::WasmFuel,
                wall_clock: WallClockControl::WasmEpoch,
                ..ResourceControls::default()
            }
        );
    }

    #[test]
    fn no_backend_serves_placement_or_standby_yet() {
        for &kind in BackendKind::ALL {
            let c = ResourceControls::for_backend(kind);
            assert_eq!(c.placement, PlacementControl::None, "{kind:?}");
            assert_eq!(c.standby, StandbyControl::None, "{kind:?}");
            assert_eq!(c.suite, SuiteControl::ClassicalOnly, "{kind:?}");
        }
    }

    /// A deadline needs a process that outlives the launch to fence it: the
    /// per-VM supervisor. This is the wall-clock matrix for the VMM tiers.
    #[test]
    fn a_liveness_deadline_is_held_only_where_a_supervisor_owns_the_guest() {
        for &kind in BackendKind::ALL {
            let expected = match kind {
                BackendKind::Libkrun
                | BackendKind::Hvf
                | BackendKind::AppleContainer
                | BackendKind::Mock => LivenessControl::HostDeadline,
                BackendKind::Firecracker
                | BackendKind::Qemu
                | BackendKind::Wasm
                | BackendKind::WebLinux => LivenessControl::None,
            };
            if expected == LivenessControl::HostDeadline && kind != BackendKind::Mock {
                assert_eq!(
                    ResourceControls::for_backend(kind).wall_clock,
                    WallClockControl::SupervisorTimer,
                    "{kind:?} holds a deadline without a supervisor to fence it"
                );
            }
            assert_eq!(
                ResourceControls::for_backend(kind).liveness,
                expected,
                "{kind:?}"
            );
        }
        let encoded = serde_json::to_value(LivenessControl::HostDeadline).unwrap();
        assert_eq!(encoded, "host_deadline");
    }

    #[test]
    fn state_cells_are_held_only_where_a_guest_has_a_vsock_channel_to_the_host() {
        for &kind in BackendKind::ALL {
            let expected = match kind {
                BackendKind::Wasm | BackendKind::WebLinux => StateCellControl::None,
                _ => StateCellControl::HostStore,
            };
            assert_eq!(
                ResourceControls::for_backend(kind).state_cells,
                expected,
                "{kind:?}"
            );
        }
        let encoded = serde_json::to_value(StateCellControl::HostStore).unwrap();
        assert_eq!(encoded, "host_store");
    }

    #[test]
    fn microvm_tiers_provide_vm_isolation() {
        use crate::plan::topology::IsolationTier;
        let tier = |kind| ResourceControls::for_backend(kind).isolation;
        for kind in [
            BackendKind::Firecracker,
            BackendKind::Libkrun,
            BackendKind::Hvf,
            BackendKind::AppleContainer,
        ] {
            assert_eq!(tier(kind), Some(IsolationTier::Vm), "{kind:?}");
        }
        // QEMU may run under TCG, so it cannot promise hardware virtualization.
        for kind in [BackendKind::Qemu, BackendKind::Wasm, BackendKind::WebLinux] {
            assert_eq!(tier(kind), Some(IsolationTier::Task), "{kind:?}");
        }
        assert_eq!(tier(BackendKind::Mock), None);
    }
}
