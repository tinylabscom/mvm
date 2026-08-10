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
}

impl CpuControl {
    /// Whether this control can serve a `CpuGrant::Share`. Fuel cannot: an
    /// instruction count and a fraction of a host core are different units
    /// with no conversion between them.
    #[must_use]
    pub const fn serves_share(self) -> bool {
        matches!(self, Self::CgroupShare)
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
    None,
    /// A host-side timer owned by the supervisor.
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
            // Linux VMM tiers: the per-VM supervisor process is cgroup-able.
            BackendKind::Firecracker | BackendKind::Libkrun | BackendKind::Qemu => Self {
                cpu: CpuControl::CgroupShare,
                wall_clock: WallClockControl::SupervisorTimer,
            },
            // macOS has no cgroup equivalent; thread QoS is priority, not quota.
            BackendKind::Hvf | BackendKind::AppleContainer => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::SupervisorTimer,
            },
            // Fuel bounds instructions; epoch preempts a module parked in a
            // host call, which fuel alone would never stop.
            BackendKind::Wasm => Self {
                cpu: CpuControl::WasmFuel,
                wall_clock: WallClockControl::WasmEpoch,
            },
            // Shares the host kernel; a cgroup here is the container runtime's
            // to own, not ours.
            BackendKind::Docker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::SupervisorTimer,
            },
            BackendKind::Mock => Self {
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
            BackendKind::Docker,
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

    #[test]
    fn the_hvf_tier_cannot_bound_cpu() {
        // macOS has no cgroup equivalent. Thread QoS is a scheduling priority,
        // not a quota, so claiming it would overstate the enforcement.
        let c = ResourceControls::for_backend(BackendKind::Hvf);
        assert_eq!(c.cpu, CpuControl::None);
        assert_eq!(c.wall_clock, WallClockControl::SupervisorTimer);
    }

    #[test]
    fn a_share_grant_is_unenforceable_on_the_wasm_tier() {
        let c = ResourceControls::for_backend(BackendKind::Wasm);
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
    }
}
