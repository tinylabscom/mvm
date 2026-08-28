#![forbid(unsafe_code)]
//! The `MvmClient` facade users touch. One import surface fronts every piece:
//! the trait + DTOs + `MockBackend` (re-exported from `mvm-core`'s `client`
//! module), the in-process [`LocalBackend`], and the [`connect`] selector. A
//! remote fleet is reached with the `remote` feature (the `GatewayBackend`).
//!
//! The contract itself lives in `mvm-core` (behind its `client` feature) so this
//! crate and `mvm-sdk` share one trait without a dependency cycle — but callers
//! depend only on `mvm-client` and never name `mvm-core` directly.
//!
//! [`stream`] adds the read side of a workload's captured output on the same
//! terms: the trait and transport live in `mvm-core`, this crate is the
//! surface consumers import. [`stream_tracing`] republishes that stream into
//! a consumer's `tracing` setup, behind the `tracing-bridge` feature.

pub mod audit;
pub mod boot;
pub mod connect;
pub mod grants;
pub mod inventory;
pub mod launch;
pub mod local;
pub mod readiness;
pub mod registration;
pub mod secret;
pub mod stream;
#[cfg(feature = "tracing-bridge")]
pub mod stream_tracing;
pub mod volume;

pub use mvm_contract::policy::approval;
pub use mvm_contract::protocol::agent_session;
pub use mvm_core::client::dto;
pub use mvm_core::client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineSpecBuilder, MachineState,
    MachineStatus, PauseOpts, PauseOutcome, PortMapping, ReconfigureRequest, ResumeOpts,
    ResumeOutcome,
};
#[cfg(feature = "remote")]
pub use mvm_core::client::gateway;
pub use mvm_core::client::mock::{self, MockBackend};
pub use mvm_core::client::{
    BackendCapabilityReport, ClientOperationCapabilities, ClientOperationCapabilitiesBuilder,
    MvmClient, MvmError, Result,
};
pub use mvm_core::naming::validate_vm_name;

pub use boot::{
    ResumeBootLocalRequest, ResumeBootLocalRequestBuilder, backend_is_running, backend_kind_for,
    backend_stop_by_name, enforced_grants_after_start, require_hypervisor_selectable,
    resume_and_boot_local, start_prepared,
};
pub use connect::{Target, connect};
pub use grants::{enforced_grants_of, record_enforced_grants};
pub use launch::{
    ExitReport, LaunchNetworkPolicy, LaunchOutcome, LaunchRequest, LaunchRequestBuilder,
    LaunchVolumeSpec, LifecycleMode, RemoveOptions,
};
pub use local::{LocalBackend, default_vcpus};
pub use readiness::{readiness_of, record_readiness, touch_activity};
pub use registration::{
    MachineRegistration, StaleRegistration, gc_stale_registrations, name_registry_path,
    register_machine,
};
