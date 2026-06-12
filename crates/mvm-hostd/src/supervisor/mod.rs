//! mvm-supervisor — trusted host-side supervisor.
//!
//! A single host-side process that owns: egress proxy, tool gate,
//! keystore releaser, audit signer, artifact collector, and the plan
//! execution state machine. **Tenant code never runs in Zone B.**
//!
//! Each component is a trait + a `Noop` impl returning a typed error /
//! pass-through, and the plan state machine carries every transition
//! the launch path walks.
//!
//! Why scaffold-first: each component lifts a sizeable chunk of
//! today's `mvm/src/security/*`. Landing the trait surface
//! first lets every sub-component move under it with a typed contract,
//! rather than the current grab-bag of free functions. The Noop impls
//! are the fail-closed default — a supervisor wired up with default
//! Noop slots refuses every non-trivial operation, so a misconfigured
//! deployment cannot accidentally pass tenant traffic through an
//! unwired component.
//!
//! Structure:
//! - `state` — `PlanState` + `PlanStateMachine` (transition rules
//!   for the supervisor's plan lifecycle).
//! - `egress` — `EgressProxy` trait + `NoopEgressProxy`.
//! - `tool_gate` — `ToolGate` trait + `NoopToolGate`.
//! - `keystore` — `KeystoreReleaser` trait + `NoopKeystoreReleaser`.
//! - `audit` — `AuditSigner` trait + `NoopAuditSigner`.
//! - `artifact` — `ArtifactCollector` trait + `NoopArtifactCollector`.
//! - `supervisor` — `Supervisor` aggregate that owns the slots.

pub mod artifact;
pub mod audit;
pub mod audit_dedup;
pub mod audit_file;
pub mod audit_recorder;
pub mod backend;
pub mod balloon;
pub mod balloon_runtime;
pub mod circuit_breaker;
pub mod destination;
pub mod egress;
pub mod entropy_scanner;
pub mod event_bus;
pub mod firewall;
// Per-VM gateway flow-event subscriber sink. Lives next to
// `event_bus` and `firewall` as a peer fan-out substrate; the gateway
// bridge emits each FlowEvent through here in parallel with the signer
// mpsc.
pub mod gateway_audit;
// Per-VM gateway audit bridge. Splices guest virtio-net <-> host
// gateway (passt / gvproxy / Vz ingest), emits FlowOpened/FlowClosed
// through a per-VM signer_task into the claim-8 chain, broadcasts
// NDJSON to gateway_audit subscribers, and exposes a `FlowPolicy` hook
// for SNI / L7 inspectors.
pub mod gateway_bridge;
#[cfg(feature = "custom-dns")]
pub mod hickory_dns;
pub mod injection_guard;
pub mod inspector;
pub mod instance_sampler;
pub mod keystore;
pub mod l7_proxy;
pub mod lifecycle_hooks;
pub mod name_scanner;
pub mod names_gazetteer;
// Observer trait + Pipeline builder for the gateway audit substrate.
// Observers consume `&FlowEvent` references inside `signer_task`
// (fan-out before chain signing). Host-allowlisted via
// `~/.mvm/observers/allowlist.toml` (mode 0600).
pub mod network;
pub mod pii_redactor;
pub mod policy_tool_gate;
pub mod proxy;
pub mod reaper;
pub mod redaction_resolve;
/// Chain-signed `secret.substituted` / `secret.placeholder_dropped`
/// audit events (claim 13: metadata only, never the secret value).
pub mod secret_audit;
pub mod secrets_scanner;
/// The per-VM substitution endpoint subprocess library half: the
/// stdin config contract + store-opening/service assembly. The
/// `mvm-substitution-endpoint` bin is the process wrapper.
pub mod substitution_endpoint;
/// Host substitution endpoint request preparation (placeholder → real
/// credential, binding-checked). The forward leg + the guest-facing
/// listener are separate transport steps.
pub mod substitution_proxy;
/// Transparent egress terminator primitives: original destination
/// recovery after nft REDIRECT, plus the future forward/substitute
/// legs (orig_dst is the only piece here now).
pub mod terminator;
// Supervisor-side UDS proxy clients for the three broker subprocesses
// (mvm-broker, mvm-host-signer, mvm-audit-signer). Stateless client
// libraries that open a fresh UDS connection per call.
pub mod aggregate;
pub mod services;
pub mod ssrf_guard;
pub mod state;
pub mod tool_gate;
pub mod tools;

pub use aggregate::{
    AuditPolicyValidationError, EgressPolicyValidationError, KNOWN_AUDIT_STREAM_SCHEMES,
    KNOWN_INSPECTOR_NAMES, Supervisor, SupervisorError, build_inspector_chain,
    build_inspector_chain_with_pii, validate_audit_policy_stream_destinations,
    validate_egress_policy_inspector_names,
};
pub use artifact::{
    ArtifactCollector, ArtifactError, LiveArtifactCollector, NoopArtifactCollector,
};
pub use audit::{AuditEntry, AuditError, AuditSigner, CapturingAuditSigner, NoopAuditSigner};
pub use audit_dedup::{Decision, DedupKey, RetryStormSummary, RetryStormSuppressor};
pub use audit_file::{FileAuditSigner, SignedEnvelope, VerifyError, verify_audit_chain};
pub use audit_recorder::{
    EventCategory, Recorder, RecorderError, UNBOUND_IMAGE_NAME, UNBOUND_IMAGE_SHA256,
    UNBOUND_PLAN_ID,
};
pub use backend::{
    BackendError, BackendLaunchSpec, BackendLauncher, FirecrackerRunConfigLauncher,
    NoopBackendLauncher,
};
#[cfg(target_os = "macos")]
pub use balloon::VmPressureLevelSource;
pub use balloon::{
    BalloonAction, BalloonController, BalloonPolicy, HostPressure, HostPressureSource,
    PsiPressureSource, SysinfoPressureSource, TickOutcome, default_pressure_source,
};
pub use balloon_runtime::{BalloonRuntimeConfig, run_balloon_loop, run_one_tick};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState, Clock as CircuitBreakerClock,
    InspectorReporter, SystemClock as CircuitBreakerSystemClock,
};
pub use destination::DestinationPolicy;
pub use egress::{EgressDecision, EgressError, EgressProxy, NoopEgressProxy};
pub use event_bus::{DEFAULT_CAPACITY as EVENT_BUS_DEFAULT_CAPACITY, EventBus, LifecycleEvent};
#[cfg(any(target_os = "linux", test))]
pub use firewall::linux_nft::{CommandNftApplier, LinuxNftFirewall, NftApplier, NftError};
pub use firewall::{FirewallEnforcer, FirewallError, FirewallSpec, NoopFirewallEnforcer};
#[cfg(feature = "custom-dns")]
pub use hickory_dns::HickoryDnsResolver;
pub use injection_guard::{InjectionGuard, InjectionRule, RuleFamily};
pub use inspector::{Inspector, InspectorChain, InspectorVerdict, RequestCtx};
pub use instance_sampler::{OsSources, Sample, SampleTarget, Sources, sample_once};
pub use keystore::{
    KeystoreError, KeystoreReleaser, LiveKeystoreReleaser, NoopKeystoreReleaser, SecretGrant,
};
pub use l7_proxy::{
    AuditFields, CapturingEgressAuditSink, ConnectParseError, ConnectRequest, DnsResolver,
    EgressAuditSink, EgressOutcome, EvaluationResult, L7EgressProxy, NoopEgressAuditSink,
    TokioDnsResolver, parse_connect,
};
pub use lifecycle_hooks::{LifecycleHooks, standard_hooks};
pub use pii_redactor::{
    Mode as PiiMode, PII_CATEGORY_NAMES, PiiPolicyError, PiiRedactor, PiiRule, PiiValidator,
};
pub use policy_tool_gate::{
    CapturingToolAuditSink, NoopToolAuditSink, PolicyToolGate, ToolAuditError, ToolAuditFields,
    ToolAuditSink, ToolOutcome,
};
pub use proxy::l4::{
    CanonicalL4Gate, L4Decision, L4Error, L4Gate, NoopL4Gate, Protocol as L4Protocol,
};
pub use reaper::{
    DEFAULT_INTERVAL as REAPER_DEFAULT_INTERVAL, DEFAULT_JITTER as REAPER_DEFAULT_JITTER,
    ReapOutcome, Reaper, TeardownFn, deregister_only_teardown, jittered_interval,
};
pub use secrets_scanner::{DEFAULT_RULES, SecretRule, SecretsScanner};
pub use ssrf_guard::SsrfGuard;
pub use state::{PlanState, PlanStateMachine, StateTransitionError};
pub use tool_gate::{NoopToolGate, ToolDecision, ToolError, ToolGate};
pub use tools::{HostMediatedTool, ToolInvokeError, ToolRegistry};
