//! What a caller should do when a backend cannot serve a capability.
//!
//! [`VmCapabilities::shortfall`] answers *which* capabilities are missing.
//! That is enough for a host-side caller who already knows the backend
//! matrix by heart, and not enough for someone using this crate as a
//! library: a bare `["vcpu_state_snapshot"]` says a request was refused
//! without saying what to do instead.
//!
//! This module answers the second question. Every gap resolves to a
//! [`CapabilityAlternative`] — either a concrete substitute the caller can
//! take, or [`CapabilityAlternative::None`] carrying the reason no
//! substitute exists.
//!
//! **`None` is the load-bearing variant.** Some capabilities are security
//! boundaries, not features, and inventing a substitute for one would be
//! the silent degradation the backend ADR rules out. A backend that cannot
//! keep a routable NIC away from a workload has no alternative path to
//! offer; it has a refusal. Making that a distinct variant is what stops a
//! caller from treating "no alternative" as "alternative not written yet".
//!
//! Alternatives are resolved per (capability, backend) because the honest
//! answer differs: a tier with no vsock device reaches the host-side
//! substitution endpoint over a Unix socket, whereas the wasm tier reaches
//! the same endpoint through its `mvm:egress` host import. Both end at the
//! same governance seam, which is why both are real answers rather than
//! consolation prizes.

use alloc::vec::Vec;

use super::resource_controls::{ResourceControls, WallClockControl};
use super::vm_backend::{BackendKind, RequiredCapabilities, VmCapabilities};
use crate::grants::{CpuGrant, Grants, WallClockGrant};

/// The capability name a `CpuGrant::Share` asks a backend for.
pub const CAPABILITY_CPU_SHARE: &str = "cpu.share";
/// The capability name a `CpuGrant::Fuel` asks a backend for.
pub const CAPABILITY_CPU_FUEL: &str = "cpu.fuel";
/// The capability name a bounded `WallClockGrant` asks a backend for.
pub const CAPABILITY_WALL_CLOCK: &str = "wall_clock.secs";

/// The substitute for a capability a backend does not provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityAlternative {
    /// Boot from scratch and replay the signed plan rather than restoring
    /// saved machine state. Costs a cold start; the workload is identical
    /// because the plan is what defines it.
    ColdStartFromSignedPlan,
    /// Reach the per-VM substitution endpoint over a Unix socket instead of
    /// a vsock device. Same endpoint, same policy and audit path.
    NetworkEndpointOverUds,
    /// Reach the per-VM substitution endpoint through the wasm tier's
    /// `mvm:egress` host import. Same endpoint, same policy and audit path.
    NetworkEndpointOverWasmImport,
    /// Reach the per-VM substitution endpoint through a browser MessagePort /
    /// Worker channel. Same endpoint, same policy and audit path.
    NetworkEndpointOverBrowserChannel,
    /// Send bytes on the workload's stdin route rather than opening an
    /// interactive terminal. Not a terminal: no program selection, no argv
    /// or environment change.
    WorkloadStdinRoute,
    /// Prelaunch a standby rather than restoring a snapshot. Pays the setup
    /// cost in advance instead of recovering saved state.
    StandbyPool,
    /// Bound CPU with a deterministic instruction budget instead of a share of
    /// host CPU time. The wasm tier has no notion of a core fraction; fuel is
    /// its unit, and it is reproducible across hosts in a way a share is not.
    CpuBudgetAsDeterministicFuel,
    /// No substitute exists, for the stated reason. The request must be
    /// refused and a different backend chosen.
    None { why: &'static str },
}

impl CapabilityAlternative {
    /// Whether this names something the caller can actually do.
    pub fn is_actionable(&self) -> bool {
        !matches!(self, CapabilityAlternative::None { .. })
    }

    /// One-line description, suitable for an error message.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::ColdStartFromSignedPlan => {
                "cold start and replay the signed execution plan instead of restoring saved state"
            }
            Self::NetworkEndpointOverUds => {
                "reach the per-VM substitution endpoint over a Unix socket instead of vsock"
            }
            Self::NetworkEndpointOverWasmImport => {
                "reach the per-VM substitution endpoint through the `mvm:egress` host import"
            }
            Self::NetworkEndpointOverBrowserChannel => {
                "reach the per-VM substitution endpoint through a browser MessagePort/Worker channel"
            }
            Self::WorkloadStdinRoute => {
                "write to the workload's stdin route instead of opening an interactive terminal"
            }
            Self::StandbyPool => "prelaunch a standby instead of restoring a snapshot",
            Self::CpuBudgetAsDeterministicFuel => {
                "bound CPU with a deterministic instruction budget (fuel) instead of a share of host CPU time"
            }
            Self::None { why } => why,
        }
    }
}

/// One capability the backend was asked for and cannot provide, paired with
/// what to do instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGap {
    /// The capability name, matching [`VmCapabilities::shortfall`].
    pub capability: &'static str,
    /// What the caller can do instead, or why nothing will do.
    pub alternative: CapabilityAlternative,
}

impl CapabilityGap {
    /// Whether this gap can be worked around at all.
    pub fn is_actionable(&self) -> bool {
        self.alternative.is_actionable()
    }
}

/// Resolve the substitute for one missing capability on one backend.
///
/// Kept as a free function over `(capability, backend)` rather than a method
/// on either, because the answer is a property of the pair. Every arm is
/// explicit: a new capability or a new backend has to be answered here
/// rather than silently inheriting a neighbour's alternative.
fn alternative_for(capability: &'static str, backend: BackendKind) -> CapabilityAlternative {
    match capability {
        // Recovery capabilities. Losing any one of them costs a warm restore,
        // never correctness: the signed plan fully determines the workload, so
        // replaying it reaches the same state from cold.
        "eager_cow_restore"
        | "guest_memory_mapping"
        | "fixed_address_remap"
        | "device_state_snapshot"
        | "vcpu_state_snapshot" => match backend {
            // A tier that can hold prelaunched standbys can hide most of the
            // cold-start cost even without snapshot restore.
            BackendKind::Firecracker | BackendKind::Libkrun | BackendKind::Hvf => {
                CapabilityAlternative::StandbyPool
            }
            BackendKind::Qemu
            | BackendKind::Mock
            | BackendKind::Wasm
            | BackendKind::WebLinux
            | BackendKind::AppleContainer => CapabilityAlternative::ColdStartFromSignedPlan,
        },

        // Transport capabilities. Every one of these ends at the same per-VM
        // substitution endpoint, so the substitute changes how the workload
        // reaches the seam, never whether policy and audit apply to it.
        "vsock" | "host_vsock_proxy" => match backend {
            BackendKind::Wasm => CapabilityAlternative::NetworkEndpointOverWasmImport,
            BackendKind::WebLinux => CapabilityAlternative::NetworkEndpointOverBrowserChannel,
            BackendKind::Firecracker
            | BackendKind::Libkrun
            | BackendKind::Qemu
            | BackendKind::Mock
            | BackendKind::Hvf
            | BackendKind::AppleContainer => CapabilityAlternative::NetworkEndpointOverUds,
        },

        // Interactive access. The stdin route carries bytes to an already
        // running entrypoint; it is not a terminal and cannot become one.
        "pty_exec" => CapabilityAlternative::WorkloadStdinRoute,

        // Grant dimensions. Which mechanism a tier has is
        // `ResourceControls::for_backend`, so the substitute is derived from
        // that same answer rather than from a second per-backend table that
        // could disagree with it.
        CAPABILITY_CPU_SHARE => {
            if ResourceControls::for_backend(backend).cpu.serves_fuel() {
                CapabilityAlternative::CpuBudgetAsDeterministicFuel
            } else {
                CapabilityAlternative::None {
                    why: "this tier has no CPU quota mechanism, so a share of host CPU time \
                          cannot be bounded here — run on a tier that meters CPU, or drop the \
                          cpu grant and accept that nothing enforces it",
                }
            }
        }

        // A share is not a substitute for fuel. Fuel is reproducible across
        // hosts; a fraction of host CPU time is not, so offering one for the
        // other would trade the guarantee the caller asked for.
        CAPABILITY_CPU_FUEL => CapabilityAlternative::None {
            why: "an executed-instruction budget is metered only where the runtime counts \
                  instructions; a share of host CPU time is a different guarantee, not a \
                  substitute for a deterministic one",
        },

        CAPABILITY_WALL_CLOCK => CapabilityAlternative::None {
            why: "this tier runs no clock that can stop the workload, so a wall-clock bound \
                  would be a declaration only",
        },

        // A security boundary, not a feature. A backend that cannot keep a
        // routable NIC away from the workload cannot be made to by choosing a
        // different call — the host would stop being the originator of every
        // outbound connection, which is what makes egress policy and the audit
        // chain mean anything.
        "no_routable_guest_nic" => CapabilityAlternative::None {
            why: "a routable guest NIC removes the host from the egress path; \
                  no alternative call restores it — choose a backend that isolates the guest",
        },

        // An unrecognised capability gets no invented substitute.
        other => {
            debug_assert!(false, "capability {other} has no alternative arm");
            CapabilityAlternative::None {
                why: "unrecognised capability: no alternative is defined for it",
            }
        }
    }
}

/// Check a workload's `grants` against what `backend` can actually bound,
/// naming a substitute for every dimension it cannot serve.
///
/// `Ok(())` means every declared grant has a mechanism behind it on this tier.
/// `Err` carries one [`CapabilityGap`] per dimension that does not, in a fixed
/// order (cpu, then wall clock) so a message reads the same on every host.
///
/// Separate from [`VmCapabilities::negotiate`] because the two ask different
/// questions of different data: that one reads the capability matrix a backend
/// advertises, this one reads [`ResourceControls`], which is the mechanism
/// table. Answering both from one function would mean a backend could advertise
/// a control it has no mechanism for.
///
/// **Pure, and deliberately posture-free.** It reports what cannot be enforced;
/// whether that is fatal is an admission decision, which differs between a
/// sealed production run and a developer's laptop. Deciding here would put the
/// posture rule in a `no_std` DTO crate that has no way to know it.
pub fn negotiate_grants(grants: &Grants, backend: BackendKind) -> Result<(), Vec<CapabilityGap>> {
    let controls = ResourceControls::for_backend(backend);
    let mut gaps: Vec<CapabilityGap> = Vec::new();

    let cpu_capability = match grants.cpu {
        Some(CpuGrant::Share { .. }) if !controls.cpu.serves_share() => Some(CAPABILITY_CPU_SHARE),
        Some(CpuGrant::Fuel { .. }) if !controls.cpu.serves_fuel() => Some(CAPABILITY_CPU_FUEL),
        _ => None,
    };
    if let Some(capability) = cpu_capability {
        gaps.push(CapabilityGap {
            capability,
            alternative: alternative_for(capability, backend),
        });
    }

    // `Unbounded` asks for nothing, so a tier with no timer serves it fine.
    if matches!(grants.wall_clock, Some(WallClockGrant::Secs { .. }))
        && controls.wall_clock == WallClockControl::None
    {
        gaps.push(CapabilityGap {
            capability: CAPABILITY_WALL_CLOCK,
            alternative: alternative_for(CAPABILITY_WALL_CLOCK, backend),
        });
    }

    if gaps.is_empty() { Ok(()) } else { Err(gaps) }
}

impl VmCapabilities {
    /// Check `required` against this backend, naming a substitute for every
    /// capability it cannot serve.
    ///
    /// `Ok(())` means the backend serves the request outright. `Err` carries
    /// one [`CapabilityGap`] per missing capability, in the same order
    /// [`VmCapabilities::shortfall`] reports them.
    pub fn negotiate(
        &self,
        required: &RequiredCapabilities,
        backend: BackendKind,
    ) -> Result<(), Vec<CapabilityGap>> {
        let gaps: Vec<CapabilityGap> = self
            .shortfall(required)
            .into_iter()
            .map(|capability| CapabilityGap {
                capability,
                alternative: alternative_for(capability, backend),
            })
            .collect();
        if gaps.is_empty() { Ok(()) } else { Err(gaps) }
    }
}

/// A backend's identity and capability matrix, together.
///
/// This is what a client facade hands back so a caller can decide *before*
/// invoking a lifecycle method that the backend cannot serve. Both halves are
/// needed: an alternative depends on the pair, so a matrix without its
/// backend cannot be negotiated against.
///
/// Which facade operations a particular `MvmClient` implementation serves.
///
/// These are deliberately separate from [`VmCapabilities`]: two clients can
/// target the same hypervisor while exposing different transports. The
/// deny-all default keeps an older capability response safe when decoded by a
/// newer consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ClientOperationCapabilities {
    pub list: bool,
    pub inspect: bool,
    pub create: bool,
    pub run: bool,
    pub start: bool,
    pub stop: bool,
    pub pause: bool,
    pub resume: bool,
    pub remove: bool,
    pub logs: bool,
    pub exec: bool,
    pub reconfigure: bool,
    pub set_ttl: bool,
}

impl ClientOperationCapabilities {
    /// Start a deny-all operation declaration.
    pub fn builder() -> ClientOperationCapabilitiesBuilder {
        ClientOperationCapabilitiesBuilder::default()
    }
}

/// Builder for [`ClientOperationCapabilities`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientOperationCapabilitiesBuilder {
    operations: ClientOperationCapabilities,
}

macro_rules! operation_setter {
    ($name:ident) => {
        #[must_use]
        pub fn $name(mut self, enabled: bool) -> Self {
            self.operations.$name = enabled;
            self
        }
    };
}

impl ClientOperationCapabilitiesBuilder {
    operation_setter!(list);
    operation_setter!(inspect);
    operation_setter!(create);
    operation_setter!(run);
    operation_setter!(start);
    operation_setter!(stop);
    operation_setter!(pause);
    operation_setter!(resume);
    operation_setter!(remove);
    operation_setter!(logs);
    operation_setter!(exec);
    operation_setter!(reconfigure);
    operation_setter!(set_ttl);

    /// Finish the declaration.
    #[must_use]
    pub fn build(self) -> ClientOperationCapabilities {
        self.operations
    }
}

/// Serializable on purpose. A remote client answers this over the wire, and
/// [`negotiate`](Self::negotiate) then runs locally against the answer — so
/// negotiation costs no round trip and a gateway needs no negotiation
/// endpoint, only a capability one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCapabilityReport {
    /// Which backend answered.
    pub kind: BackendKind,
    /// What it advertises.
    pub capabilities: VmCapabilities,
    /// Which facade calls the selected client transport can serve.
    #[serde(default)]
    pub operations: ClientOperationCapabilities,
}

impl BackendCapabilityReport {
    pub fn new(kind: BackendKind, capabilities: VmCapabilities) -> Self {
        Self {
            kind,
            capabilities,
            operations: ClientOperationCapabilities::default(),
        }
    }

    /// Attach the operation surface of the client implementation returning
    /// this report.
    #[must_use]
    pub fn with_operations(mut self, operations: ClientOperationCapabilities) -> Self {
        self.operations = operations;
        self
    }

    /// Check `required` against this report, naming a substitute for every
    /// capability the backend cannot serve.
    ///
    /// Pure: no I/O, so a caller holding a report fetched once can negotiate
    /// as many requirement sets against it as it likes.
    pub fn negotiate(&self, required: &RequiredCapabilities) -> Result<(), Vec<CapabilityGap>> {
        self.capabilities.negotiate(required, self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A backend that advertises nothing, so any requirement is a gap.
    fn barren() -> VmCapabilities {
        VmCapabilities::default()
    }

    fn require(f: impl FnOnce(&mut RequiredCapabilities)) -> RequiredCapabilities {
        let mut r = RequiredCapabilities::default();
        f(&mut r);
        r
    }

    #[test]
    fn a_backend_that_serves_the_request_reports_no_gaps() {
        let caps = VmCapabilities {
            vsock: true,
            ..VmCapabilities::default()
        };
        let required = require(|r| r.vsock = true);
        assert_eq!(caps.negotiate(&required, BackendKind::Firecracker), Ok(()));
    }

    #[test]
    fn a_missing_transport_points_at_the_same_endpoint_over_uds() {
        let required = require(|r| r.vsock = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::Qemu)
            .expect_err("a barren backend cannot serve vsock");
        assert_eq!(
            gaps,
            vec![CapabilityGap {
                capability: "vsock",
                alternative: CapabilityAlternative::NetworkEndpointOverUds,
            }]
        );
        assert!(gaps[0].is_actionable());
    }

    #[test]
    fn the_wasm_tier_reaches_the_endpoint_through_its_host_import() {
        let required = require(|r| r.vsock = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::Wasm)
            .expect_err("the wasm tier has no vsock device");
        assert_eq!(
            gaps[0].alternative,
            CapabilityAlternative::NetworkEndpointOverWasmImport
        );
    }

    #[test]
    fn the_web_linux_tier_reaches_the_endpoint_through_its_browser_channel() {
        let required = require(|r| r.vsock = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::WebLinux)
            .expect_err("the browser-hosted tier has no native vsock device");
        assert_eq!(
            gaps[0].alternative,
            CapabilityAlternative::NetworkEndpointOverBrowserChannel
        );
    }

    #[test]
    fn a_missing_snapshot_tier_falls_back_to_replaying_the_signed_plan() {
        let required = require(|r| r.vcpu_state_snapshot = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::Wasm)
            .expect_err("the wasm tier holds no vcpu state");
        assert_eq!(
            gaps[0].alternative,
            CapabilityAlternative::ColdStartFromSignedPlan
        );
    }

    #[test]
    fn a_snapshotless_microvm_backend_is_offered_a_standby_instead() {
        let required = require(|r| r.vcpu_state_snapshot = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::Hvf)
            .expect_err("a barren backend holds no vcpu state");
        assert_eq!(gaps[0].alternative, CapabilityAlternative::StandbyPool);
    }

    #[test]
    fn a_missing_pty_is_offered_the_stdin_route_and_nothing_richer() {
        let required = require(|r| r.pty_exec = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::Wasm)
            .expect_err("the wasm tier has no pty");
        assert_eq!(
            gaps[0].alternative,
            CapabilityAlternative::WorkloadStdinRoute
        );
        // The substitute must not read as an equivalent: a caller who wanted a
        // terminal has to see that this is a byte route to an already-running
        // entrypoint, or they will reach for it expecting a shell.
        let described = gaps[0].alternative.describe();
        assert!(
            described.contains("instead of") && described.contains("interactive terminal"),
            "the description must distinguish the stdin route from a terminal: {described}"
        );
    }

    #[test]
    fn a_guest_nic_gap_has_no_alternative_and_says_why() {
        let required = require(|r| r.no_routable_guest_nic = true);
        let gaps = barren()
            .negotiate(&required, BackendKind::Wasm)
            .expect_err("a claim-free tier cannot promise a NIC-less guest");
        assert!(
            !gaps[0].is_actionable(),
            "a security boundary must not resolve to a workaround"
        );
        assert!(gaps[0].alternative.describe().contains("egress path"));
    }

    #[test]
    fn every_gap_is_reported_not_just_the_first() {
        let required = require(|r| {
            r.vsock = true;
            r.pty_exec = true;
            r.vcpu_state_snapshot = true;
        });
        let gaps = barren()
            .negotiate(&required, BackendKind::Wasm)
            .expect_err("a barren backend serves none of these");
        assert_eq!(gaps.len(), 3, "got {gaps:?}");
        let names: Vec<&str> = gaps.iter().map(|g| g.capability).collect();
        assert_eq!(names, vec!["vcpu_state_snapshot", "vsock", "pty_exec"]);
    }

    #[test]
    fn gap_order_matches_shortfall_order() {
        let required = require(|r| {
            r.pty_exec = true;
            r.vsock = true;
        });
        let caps = barren();
        let shortfall = caps.shortfall(&required);
        let gaps = caps
            .negotiate(&required, BackendKind::Libkrun)
            .expect_err("neither capability is served");
        let names: Vec<&'static str> = gaps.iter().map(|g| g.capability).collect();
        assert_eq!(names, shortfall);
    }

    #[test]
    fn share_grant_on_wasm_is_refused_at_negotiation_naming_fuel() {
        // The wasm tier bounds CPU, just in another unit. Saying so at
        // negotiation is what keeps the refusal in front of the boot instead of
        // surfacing as a failed apply after the workload is already running.
        let grants = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Grants::default()
        };
        let gaps = negotiate_grants(&grants, BackendKind::Wasm)
            .expect_err("a share is not the wasm tier's unit");
        assert_eq!(
            gaps,
            vec![CapabilityGap {
                capability: CAPABILITY_CPU_SHARE,
                alternative: CapabilityAlternative::CpuBudgetAsDeterministicFuel,
            }]
        );
        assert!(
            gaps[0].is_actionable(),
            "a wasm CPU bound exists; it is just a different unit"
        );
        assert!(gaps[0].alternative.describe().contains("fuel"));
    }

    #[test]
    fn a_fuel_grant_off_the_wasm_tier_gets_no_invented_substitute() {
        // A share would be a different guarantee, not a substitute: fuel is
        // reproducible across hosts and a fraction of host CPU time is not.
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
            ..Grants::default()
        };
        let gaps = negotiate_grants(&grants, BackendKind::Firecracker)
            .expect_err("no microVM tier counts instructions");
        assert_eq!(gaps[0].capability, CAPABILITY_CPU_FUEL);
        assert!(!gaps[0].is_actionable());
    }

    #[test]
    fn a_grant_the_tier_can_bound_produces_no_gap() {
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: core::num::NonZeroU32::new(30).expect("nonzero"),
            }),
            ..Grants::default()
        };
        assert_eq!(negotiate_grants(&grants, BackendKind::Wasm), Ok(()));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_share_grant_on_a_cgroup_backend_produces_no_gap() {
        // A CpuGrant::Share is the native unit for cgroup-backed microVM
        // tiers. The negotiation must not invent a gap for a grant the
        // mechanism can serve.
        let grants = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Grants::default()
        };
        assert_eq!(negotiate_grants(&grants, BackendKind::Firecracker), Ok(()));
    }

    #[test]
    fn an_undeclared_grant_asks_the_backend_for_nothing() {
        // Mock bounds neither dimension, so an empty grant set is the only
        // thing it can serve — and it must serve it, or every unbounded run
        // would negotiate a gap it never asked for.
        assert_eq!(
            negotiate_grants(&Grants::default(), BackendKind::Mock),
            Ok(())
        );
    }

    #[test]
    fn a_wall_clock_bound_needs_a_clock_that_can_stop_the_workload() {
        let bounded = Grants {
            wall_clock: Some(WallClockGrant::Secs {
                secs: core::num::NonZeroU32::new(600).expect("nonzero"),
            }),
            ..Grants::default()
        };
        let gaps =
            negotiate_grants(&bounded, BackendKind::Mock).expect_err("the mock tier runs no timer");
        assert_eq!(gaps[0].capability, CAPABILITY_WALL_CLOCK);
        assert!(!gaps[0].is_actionable());

        // `Unbounded` asks for nothing, so the absent timer serves it.
        let unbounded = Grants {
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Grants::default()
        };
        assert_eq!(negotiate_grants(&unbounded, BackendKind::Mock), Ok(()));
    }

    #[test]
    fn every_capability_shortfall_can_name_has_an_alternative_arm() {
        // The registry of capability names lives in `shortfall`. Ask for all
        // of them at once against a backend that serves none, and assert each
        // resolves to a deliberate arm rather than the unrecognised fallback.
        let required = RequiredCapabilities {
            eager_cow_restore: true,
            guest_memory_mapping: true,
            fixed_address_remap: true,
            device_state_snapshot: true,
            vcpu_state_snapshot: true,
            vsock: true,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            pty_exec: true,
        };
        let gaps = barren()
            .negotiate(&required, BackendKind::Firecracker)
            .expect_err("a barren backend serves nothing");
        assert_eq!(gaps.len(), 9, "every capability must produce a gap");
        for gap in &gaps {
            assert!(
                !gap.alternative
                    .describe()
                    .contains("unrecognised capability"),
                "{} fell through to the unrecognised arm",
                gap.capability
            );
        }
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn client_operations_default_to_deny_all() {
        assert_eq!(
            ClientOperationCapabilities::default(),
            ClientOperationCapabilities::builder().build()
        );
        assert!(!ClientOperationCapabilities::default().exec);
    }

    #[test]
    fn client_operations_builder_preserves_every_enabled_operation() {
        let operations = ClientOperationCapabilities::builder()
            .list(true)
            .inspect(true)
            .create(true)
            .run(true)
            .start(true)
            .stop(true)
            .pause(true)
            .resume(true)
            .remove(true)
            .logs(true)
            .exec(true)
            .reconfigure(true)
            .set_ttl(true)
            .build();

        assert!(operations.list);
        assert!(operations.inspect);
        assert!(operations.create);
        assert!(operations.run);
        assert!(operations.start);
        assert!(operations.stop);
        assert!(operations.pause);
        assert!(operations.resume);
        assert!(operations.remove);
        assert!(operations.logs);
        assert!(operations.exec);
        assert!(operations.reconfigure);
        assert!(operations.set_ttl);
    }

    #[test]
    fn client_operations_round_trip_through_json() {
        let operations = ClientOperationCapabilities::builder()
            .list(true)
            .run(true)
            .stop(true)
            .build();
        let json = serde_json::to_string(&operations).expect("operations serialize");
        let back: ClientOperationCapabilities =
            serde_json::from_str(&json).expect("operations deserialize");
        assert_eq!(back, operations);
    }

    #[test]
    fn a_legacy_report_without_operations_defaults_to_deny_all() {
        let mut legacy = serde_json::to_value(BackendCapabilityReport::new(
            BackendKind::Mock,
            VmCapabilities::default(),
        ))
        .expect("report serializes");
        legacy
            .as_object_mut()
            .expect("report is an object")
            .remove("operations");
        let report: BackendCapabilityReport = serde_json::from_value(legacy)
            .expect("a report written before operation discovery still decodes");
        assert_eq!(report.operations, ClientOperationCapabilities::default());
    }

    #[test]
    fn a_report_round_trips_through_json() {
        let report = BackendCapabilityReport::new(
            BackendKind::Wasm,
            VmCapabilities {
                vsock: false,
                pty_exec: false,
                ..VmCapabilities::default()
            },
        )
        .with_operations(
            ClientOperationCapabilities::builder()
                .list(true)
                .inspect(true)
                .build(),
        );
        let json = serde_json::to_string(&report).expect("report serializes");
        let back: BackendCapabilityReport =
            serde_json::from_str(&json).expect("report deserializes");
        assert_eq!(back, report, "a remote answer must survive the wire");
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // A gateway that grows a field this client does not know about must
        // fail loudly: silently dropping it is how a caller ends up reasoning
        // about a capability matrix that is not the one the server meant.
        let json = r#"{"kind":"mock","capabilities":{"pause_resume":true}}"#;
        let err = serde_json::from_str::<BackendCapabilityReport>(json);
        assert!(err.is_err(), "a partial capability matrix must not decode");
    }

    #[test]
    fn a_report_negotiates_without_touching_its_backend() {
        let report = BackendCapabilityReport::new(BackendKind::Wasm, VmCapabilities::default());
        let required = RequiredCapabilities {
            vsock: true,
            ..RequiredCapabilities::default()
        };
        let gaps = report
            .negotiate(&required)
            .expect_err("the wasm tier has no vsock device");
        assert_eq!(
            gaps,
            vec![CapabilityGap {
                capability: "vsock",
                alternative: CapabilityAlternative::NetworkEndpointOverWasmImport,
            }],
            "the report must resolve the same alternative the backend would"
        );
    }

    #[test]
    fn one_fetched_report_answers_many_requirement_sets() {
        // The reason the trait returns a report rather than taking a
        // requirement set: a remote caller pays one round trip, not one per
        // question.
        let report = BackendCapabilityReport::new(BackendKind::Qemu, VmCapabilities::default());
        assert!(report.negotiate(&RequiredCapabilities::default()).is_ok());
        assert!(
            report
                .negotiate(&RequiredCapabilities {
                    pty_exec: true,
                    ..RequiredCapabilities::default()
                })
                .is_err()
        );
    }
}
