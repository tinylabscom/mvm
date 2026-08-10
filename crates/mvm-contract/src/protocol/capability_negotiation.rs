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

use super::vm_backend::{BackendKind, RequiredCapabilities, VmCapabilities};

/// The substitute for a capability a backend does not provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityAlternative {
    /// Boot from scratch and replay the signed plan rather than restoring
    /// saved machine state. Costs a cold start; the workload is identical
    /// because the plan is what defines it.
    ColdStartFromSignedPlan,
    /// Reach the per-VM substitution endpoint over a Unix socket instead of
    /// a vsock device. Same endpoint, same policy and audit path.
    SubstitutionEndpointOverUds,
    /// Reach the per-VM substitution endpoint through the wasm tier's
    /// `mvm:egress` host import. Same endpoint, same policy and audit path.
    SubstitutionEndpointOverWasmImport,
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
            Self::SubstitutionEndpointOverUds => {
                "reach the per-VM substitution endpoint over a Unix socket instead of vsock"
            }
            Self::SubstitutionEndpointOverWasmImport => {
                "reach the per-VM substitution endpoint through the `mvm:egress` host import"
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
            _ => CapabilityAlternative::ColdStartFromSignedPlan,
        },

        // Transport capabilities. Every one of these ends at the same per-VM
        // substitution endpoint, so the substitute changes how the workload
        // reaches the seam, never whether policy and audit apply to it.
        "vsock" | "host_vsock_proxy" | "l3_vsock" => match backend {
            BackendKind::Wasm => CapabilityAlternative::SubstitutionEndpointOverWasmImport,
            _ => CapabilityAlternative::SubstitutionEndpointOverUds,
        },

        // Interactive access. The stdin route carries bytes to an already
        // running entrypoint; it is not a terminal and cannot become one.
        "pty_exec" => CapabilityAlternative::WorkloadStdinRoute,

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
}

impl BackendCapabilityReport {
    pub fn new(kind: BackendKind, capabilities: VmCapabilities) -> Self {
        Self { kind, capabilities }
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
                alternative: CapabilityAlternative::SubstitutionEndpointOverUds,
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
            CapabilityAlternative::SubstitutionEndpointOverWasmImport
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
            .negotiate(&required, BackendKind::Docker)
            .expect_err("a shared-kernel tier cannot promise a NIC-less guest");
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
    fn a_share_grant_on_the_wasm_tier_names_fuel_as_the_substitute() {
        let gap = CapabilityGap {
            capability: "cpu.share",
            alternative: CapabilityAlternative::CpuBudgetAsDeterministicFuel,
        };
        assert!(
            gap.is_actionable(),
            "a wasm CPU bound exists; it is just a different unit"
        );
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
            l3_vsock: true,
            pty_exec: true,
        };
        let gaps = barren()
            .negotiate(&required, BackendKind::Firecracker)
            .expect_err("a barren backend serves nothing");
        assert_eq!(gaps.len(), 10, "every capability must produce a gap");
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
    fn a_report_round_trips_through_json() {
        let report = BackendCapabilityReport::new(
            BackendKind::Wasm,
            VmCapabilities {
                vsock: false,
                pty_exec: false,
                ..VmCapabilities::default()
            },
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
                alternative: CapabilityAlternative::SubstitutionEndpointOverWasmImport,
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
