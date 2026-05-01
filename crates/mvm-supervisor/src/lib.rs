//! mvm-supervisor — trusted host-side supervisor.
//!
//! Plan 37 §7B (CORNERSTONE). A single host-side process that owns:
//! egress proxy (§15), tool gate (§2.2/§15), keystore releaser (§12.2),
//! audit signer (§22), artifact collector (§21), and the plan
//! execution state machine. **Tenant code never runs in Zone B.**
//!
//! Wave 1.3 of plan 37 lands the *skeleton*: each component is a
//! trait + a `Noop` impl returning a typed error / pass-through, and
//! the plan state machine carries every transition the launch path
//! will eventually walk. The actual lift of `mvm-hostd`'s daemon
//! binary into a `mvm-supervisor` binary, plus systemd unit + launchd
//! plist, lands in Wave 1.4 (Supervisor::launch happy path).
//!
//! Why scaffold-first: each component lifts a sizeable chunk of
//! today's `mvm-runtime/src/security/*`. Landing the trait surface
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
pub mod backend;
pub mod egress;
pub mod keystore;
pub mod state;
pub mod supervisor;
pub mod tool_gate;

pub use artifact::{ArtifactCollector, ArtifactError, NoopArtifactCollector};
pub use audit::{AuditError, AuditSigner, NoopAuditSigner};
pub use backend::{BackendError, BackendLauncher, NoopBackendLauncher};
pub use egress::{EgressDecision, EgressError, EgressProxy, NoopEgressProxy};
pub use keystore::{KeystoreError, KeystoreReleaser, NoopKeystoreReleaser, SecretGrant};
pub use state::{PlanState, PlanStateMachine, StateTransitionError};
pub use supervisor::{Supervisor, SupervisorError};
pub use tool_gate::{NoopToolGate, ToolDecision, ToolError, ToolGate};
