//! The `MvmClient` facade users touch. One import surface fronts every piece:
//! the trait + DTOs + `MockBackend` (re-exported from `mvm-core`'s `client`
//! module), the in-process [`LocalBackend`], and the [`connect`] selector. A
//! remote fleet is reached with the `remote` feature (the `GatewayBackend`).
//!
//! The contract itself lives in `mvm-core` (behind its `client` feature) so this
//! crate and `mvm-sdk` share one trait without a dependency cycle — but callers
//! depend only on `mvm-client` and never name `mvm-core` directly.

pub mod connect;
pub mod local;

pub use mvm_core::client::dto;
pub use mvm_core::client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineSpecBuilder, MachineState,
    MachineStatus, PauseOpts, PauseOutcome, PortMapping, ReconfigureRequest, ResumeOpts,
};
#[cfg(feature = "remote")]
pub use mvm_core::client::gateway;
pub use mvm_core::client::mock::{self, MockBackend};
pub use mvm_core::client::{MvmClient, MvmError, Result};

pub use connect::{Target, connect};
pub use local::LocalBackend;
