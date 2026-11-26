//! mvm-supervisor — trusted host-side supervisor components.
//!
//! The host-side pieces a per-VM supervisor is assembled from: the egress
//! datapath and its inspectors, the audit chain, the per-VM network endpoint,
//! and the lifecycle watchers. **Tenant code never runs in Zone B.**
//!
//! Structure:
//! - `egress` — `SupervisorEgressProxy` trait + `NoopEgressProxy`.
//! - `keystore` — `KeystoreReleaser` trait + `NoopKeystoreReleaser`.
//! - `audit` — `AuditSigner` trait + `NoopAuditSigner`.
//! - `artifact` — `ArtifactCollector` trait + `NoopArtifactCollector`.
//! - `policy_validation` — operator-policy validators and the canonical
//!   inspector chain.
//!
//! Everything else lives in a responsibility group:
//! - `admission` — caller registration and restored/warm-claimed plan checks.
//! - `audit` — the chain-signed audit log and per-subsystem audit events.
//! - `datapath` — guest-egress L4/L7 proxy, DNS/ICMP and firewall primitives.
//! - `endpoint` — the per-VM network endpoint, FlowMux and TLS termination.
//! - `inspection` — inspectors, scanners, redaction and destination policy.
//! - `lifecycle` — HVF stop, wall clock, session expiry, balloon.
//! - `telemetry` — AI budgets, action ledger, sampling and egress telemetry.
//! - `services` — the broker subprocess proxy clients.

pub mod admission;
pub mod artifact;
pub mod audit;
pub mod datapath;
pub mod egress;
pub mod endpoint;
pub mod inspection;
pub mod keystore;
pub mod lifecycle;
pub mod policy_validation;
pub mod services;
pub mod telemetry;

/// First index of `needle` in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub use artifact::{
    ArtifactCollector, ArtifactError, LiveArtifactCollector, NoopArtifactCollector,
};
pub use audit::audit_dedup::{Decision, DedupKey, RetryStormSummary, RetryStormSuppressor};
pub use audit::audit_file::{
    ChainCheckpoint, FileAuditSigner, IncrementalVerification, RotationPolicy, SegmentWalk,
    VerifyError, verify_audit_chain, verify_audit_chain_entries, verify_audit_chain_incremental,
    verify_chain_bytes,
};
pub use audit::audit_recorder::{
    EventCategory, Recorder, RecorderError, UNBOUND_IMAGE_NAME, UNBOUND_IMAGE_SHA256,
    UNBOUND_PLAN_ID,
};
pub use audit::signer::{
    AuditError, AuditSigner, CapturingAuditSigner, NoopAuditSigner, PlanAuditEntry, SignedEnvelope,
    flow_closed, flow_observer_fault, flow_opened, for_plan, transcript_sealed,
};
#[cfg(any(target_os = "linux", test))]
pub use datapath::firewall::linux_nft::{
    CommandNftApplier, LinuxNftFirewall, NftApplier, NftError,
};
pub use datapath::firewall::{FirewallEnforcer, FirewallError, FirewallSpec, NoopFirewallEnforcer};
#[cfg(feature = "custom-dns")]
pub use datapath::hickory_dns::HickoryDnsResolver;
pub use datapath::l7_proxy::{
    AuditFields, CapturingEgressAuditSink, ConnectParseError, ConnectRequest, DnsResolver,
    EgressAuditSink, EgressOutcome, EvaluationResult, L7EgressProxy, NoopEgressAuditSink,
    TokioDnsResolver, parse_connect,
};
pub use datapath::proxy::l4::{
    CanonicalL4Gate, L4Decision, L4Error, L4Gate, NoopL4Gate, Protocol as L4Protocol,
};
pub use egress::{EgressDecision, EgressError, NoopEgressProxy, SupervisorEgressProxy};
pub use inspection::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState, Clock as CircuitBreakerClock,
    InspectorReporter, SystemClock as CircuitBreakerSystemClock,
};
pub use inspection::destination::DestinationPolicy;
pub use inspection::injection_guard::{InjectionGuard, InjectionRule, RuleFamily};
pub use inspection::inspector::{Inspector, InspectorChain, InspectorVerdict, RequestCtx};
pub use inspection::pii_redactor::{
    Mode as PiiMode, PII_CATEGORY_NAMES, PiiPolicyError, PiiRedactor, PiiRule, PiiValidator,
};
pub use inspection::secrets_scanner::{DEFAULT_RULES, SecretRule, SecretsScanner};
pub use inspection::ssrf_guard::SsrfGuard;
pub use keystore::{
    KeystoreError, KeystoreReleaser, LiveKeystoreReleaser, NoopKeystoreReleaser, SecretGrant,
};
#[cfg(target_os = "macos")]
pub use lifecycle::balloon::VmPressureLevelSource;
pub use lifecycle::balloon::{
    BalloonAction, BalloonController, BalloonPolicy, HostPressure, HostPressureSource,
    PsiPressureSource, SysinfoPressureSource, TickOutcome, default_pressure_source,
};
pub use lifecycle::balloon_runtime::{BalloonRuntimeConfig, run_balloon_loop, run_one_tick};
pub use policy_validation::{
    AuditPolicyValidationError, EgressPolicyValidationError, KNOWN_AUDIT_STREAM_SCHEMES,
    KNOWN_INSPECTOR_NAMES, build_inspector_chain, build_pii_inspector_chain,
    validate_audit_policy_stream_destinations, validate_egress_policy_inspector_names,
};
pub use telemetry::instance_sampler::{OsSources, Sample, SampleTarget, Sources, sample_once};
