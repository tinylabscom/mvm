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
//!
//! ## One library
//!
//! A Rust program that authors, launches or drives a workload depends on this
//! crate alone. Everything it needs to name is re-exported here: the launch
//! request and its parts ([`LaunchRequest`], [`RootfsSource`], [`Grants`],
//! [`HostPort`]), the results ([`LaunchOutcome`], [`MachineState`], the
//! [`inventory`] records), the guest operations and their payloads
//! ([`guest`]), the typed errors and their stable codes ([`MvmError`],
//! [`error_codes`]), signed plans ([`SignedExecutionPlan`]), and the workload
//! authoring surface ([`authoring`]). The language SDKs reach the same surface
//! through `libmvm_hostlib`, a C ABI over this crate.
//!
//! ```no_run
//! use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, RootfsSource};
//!
//! # async fn demo() -> mvm_client::Result<()> {
//! let image: RootfsSource = "docker.io/library/alpine:3.20".parse().expect("an OCI reference");
//! let request = LaunchRequest::builder(LifecycleMode::Transient, image)
//!     .name("hello")
//!     .memory_mib(256)
//!     .allow_egress("api.example.com", 443)
//!     .ttl_seconds(600)
//!     .build()?;
//! let launched = LocalBackend::new().launch(request).await?;
//! println!("{} admitted under plan {}", launched.machine.name, launched.plan_id);
//! # Ok(())
//! # }
//! ```

pub mod admission;
pub mod approval_broker;
pub mod audit;
pub mod boot;
pub mod connect;
pub mod drive;
pub mod grants;
pub mod grants_resolve;
pub mod guest;
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

/// The workload authoring surface: builders, constructors, IR emission.
pub use mvm_sdk as authoring;

pub use mvm_contract::grants::{CpuGrant, EgressGrant, Grants, WallClockGrant};
pub use mvm_contract::policy::approval;
pub use mvm_contract::policy::network_policy::{HostPort, NetworkPreset};
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
pub use mvm_core::error_codes;
pub use mvm_core::naming::validate_vm_name;
pub use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
pub use mvm_core::rootfs_source::{RootfsSource, RootfsSourceParseError};

pub use boot::{
    ResumeBootLocalRequest, ResumeBootLocalRequestBuilder, StartedVm, backend_is_running,
    backend_kind_for, backend_stop_by_name, clamp_vcpus_for_backend, require_hypervisor_selectable,
    resume_and_boot_local, start_prepared,
};
pub use connect::{Target, connect};
pub use drive::{DriveError, LocalDrive};
pub use grants::{enforced_grants_of, record_enforced_grants};
pub use inventory::{MachineInventoryRecord, WorkloadPosture};
pub use launch::{
    AccessMode, ExitReport, LaunchNetworkPolicy, LaunchOutcome, LaunchRequest,
    LaunchRequestBuilder, LaunchVolumeSpec, LifecycleMode, MachineSecretRef, RemoveOptions,
};
pub use local::{LocalBackend, auto_selected_backend_name, default_vcpus};
pub use readiness::{readiness_of, record_readiness, touch_activity};
pub use registration::{
    MachineRegistration, StaleRegistration, gc_stale_registrations, name_registry_path,
    register_machine,
};
