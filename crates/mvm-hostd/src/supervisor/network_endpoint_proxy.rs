//! Host substitution endpoint: request preparation.
//!
//! The guest's SDK client routes a secret-bearing request to this host-local
//! endpoint carrying an opaque placeholder. `prepare_request` is the
//! security-critical core: it locates the placeholder in each header, resolves
//! it against the session registry, binding-checks the request's destination
//! (claim 12), and substitutes the real credential — yielding a request ready
//! for the host to make the real TLS to the destination (the forward leg,
//! a separate transport step).
//!
//! Substitution happens HERE, on the host, never in the guest: the guest only
//! ever held the opaque placeholder. The prepared request carries the real
//! credential because it must reach the wire — the confinement is that this
//! host component is the only place it exists in the clear.

use std::sync::Arc;

use crate::keyholder::{SecretResolver, SubstitutionRegistry};
use crate::supervisor::ai_meter;
use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::redactor::RedactingSubstitution;
use crate::supervisor::reversible_replacement::ReplacementEngine;
pub use mvm_contract::substitution::{
    PrepareError, PreparedRequest, ProxyRequest, SubstitutionDriver,
    prepare_request as prepare_request_core,
};

mod ai_budget;
mod assembly;
mod audit;
mod classify;
mod forward;
mod ingress;
mod listen;
mod pinned_dns;
mod pipeline;
mod prepare;
mod redaction;
mod routing;
mod sign;

/// Host-side AF_VSOCK listener for the QEMU (`vhost-vsock`) guest→host
/// substitution path. Firecracker/libkrun bridge guest→host through a per-port
/// UDS — those use the `UnixListener` `serve`. Raw libc (no async-vsock dep);
/// blocking `accept` is driven from the async loop via `spawn_blocking`.
#[cfg(target_os = "linux")]
pub mod vsock;

pub use assembly::{FromPlanError, FromPlanInputs};
pub(crate) use classify::TerminationMode;
#[cfg(test)]
pub(crate) use forward::TestTransport;
pub use forward::{
    ForwardError, ForwardResponse, ForwardStreamResponse, Forwarder, HardenedForwarder,
};
pub use ingress::HostMaterialError;
pub(crate) use prepare::{PLACEHOLDER_OUTSIDE_HEADERS, REASON_PLACEHOLDER_IN_BODY};
pub use prepare::{ProxyError, prepare_request};

/// 16 MiB cap on a single routed request/response frame.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// The running host substitution endpoint: the admission-minted placeholder
/// registry, the secret resolver, and the forward leg. Placeholders are minted
/// at admission, so the registry is read-only while serving.
pub struct SubstitutionService {
    tenant: String,
    registry: Arc<SubstitutionRegistry>,
    resolver: Arc<dyn SecretResolver>,
    forwarder: Arc<dyn Forwarder>,
    /// Egress redactor. Masks *undeclared* secret-shaped / PII content out
    /// of an outbound request before forwarding, using the same
    /// `RedactingSubstitution` definition as the declared-ingress transform so
    /// every backend that routes egress through this endpoint scrubs
    /// identically. Built once (rule compilation).
    redactor: RedactingSubstitution,
    /// Optional chain-signed audit recorder. When set, each substitution emits
    /// a `secret.substituted` entry (metadata only — claim 13).
    recorder: Option<Arc<Recorder>>,
    /// The per-VM name-constrained intermediate the `https` terminator mints
    /// per-SNI leaves under. `None` ⇒ no TLS leg (`http`-only). Set from
    /// `EndpointConfig.tls_intermediate` at assemble.
    tls_intermediate: Option<Arc<mvm_core::crypto::egress_ca::VmEgressCa>>,
    /// Per-destination redaction policy. Default = curated baseline (entropy +
    /// names off); a profile opts a destination into entropy/name redaction.
    redaction_policy: mvm_core::policy::RedactionPolicy,
    /// Per-destination reversible replacement policy. Default = disabled.
    reversible_replacement_policy: mvm_core::policy::ReversibleReplacementPolicy,
    /// Request-scoped replacement / reinjection engine.
    replacement_engine: ReplacementEngine,
    /// Claim-10 egress gate. Every outbound destination is checked against the
    /// VM's resolved network policy before any forward, and an unadmitted
    /// `host:port` is refused here. Not optional: a VM with no admitted policy
    /// carries a default-deny gate, so no service forwards undecided.
    egress_gate: Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
    /// Per-VM AI egress metering/budget policy. `None` means AI egress is not
    /// metered and no budget is enforced.
    ai_policy: Option<mvm_contract::policy::network_policy::AiPolicy>,
    /// Per-VM AI token budget tracker, present only when metering is enabled.
    ai_tracker: Option<Arc<ai_meter::AiBudgetTracker>>,
    /// VM instance identifier used to attribute AI egress metrics.
    instance_id: Option<String>,
    /// Optional per-VM metrics registry for AI counters. When `None`, the
    /// process-global registry is used.
    instance_metrics:
        Option<Arc<mvm_core::observability::instance_metrics::InstanceMetricsRegistry>>,
    /// The addresses the egress gate admitted for each destination, shared
    /// with the forward leg's resolver so it connects to nothing else.
    admitted: Arc<pinned_dns::AdmittedAddresses>,
    /// Answers `ask` route decisions. [`crate::supervisor::egress_approval::NoApprovalBackend`]
    /// until an approval backend is configured, which refuses every one.
    approver: Arc<dyn crate::supervisor::egress_approval::EgressApprover>,
}

#[cfg(test)]
pub(crate) mod test_support;
