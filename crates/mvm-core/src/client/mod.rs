//! The `MvmClient` facade: one trait fronting local microVM operations and a
//! remote fleet, so a caller drives either target through the same calls. The
//! remote implementation is a courier with no enforcement authority — every
//! security decision is made by the authority that owns the path (the local
//! host, or the fleet), never by this client.
//!
//! Feature-gated behind `client` so the runtime-free default build of this
//! crate is unaffected: the trait pulls `async-trait` (a proc-macro that
//! desugars async methods to boxed futures — no async runtime), and the remote
//! gateway (`client-remote`) pulls `reqwest`. `LocalBackend` lives one crate
//! up in `mvm-client`, where it can link the runtime backend.

use async_trait::async_trait;

pub mod dto;
pub mod error;
#[cfg(feature = "client-remote")]
pub mod gateway;
pub mod inventory;
pub mod mock;

pub use error::{MvmError, Result};

use dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, PauseOpts,
    PauseOutcome, ReconfigureRequest, ResumeOpts, ResumeOutcome,
};

/// The single machine-driving contract. `async_trait` boxes the futures so
/// `dyn MvmClient` stays object-safe — callers hold one backend behind a trait
/// object and never see which transport is underneath.
#[async_trait]
pub trait MvmClient: Send + Sync {
    /// List machines matching `filter`.
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>>;

    /// Inspect one machine by id; returns its current state.
    async fn inspect_machine(&self, id: &MachineId) -> Result<MachineState>;

    /// Create a machine from `spec` **without** starting it; returns its initial
    /// (stopped) state. `run_machine` is the create-and-start shorthand.
    async fn create_machine(&self, spec: MachineSpec) -> Result<MachineState>;

    /// Launch a machine from `spec` (create + start); returns its initial state.
    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState>;

    /// Start an already-created (or stopped) machine by id; returns its state.
    async fn start_machine(&self, id: &MachineId) -> Result<MachineState>;

    /// Stop a machine by id. Idempotent: stopping a stopped machine is `Ok`.
    async fn stop_machine(&self, id: &MachineId) -> Result<()>;

    /// Pause a running machine: quiesce it, seal an epoch-bound snapshot of its
    /// vmstate + memory, mark it paused, and return the sealed [`PauseOutcome`].
    /// The snapshot transport is host-local and chosen by the backend, so it
    /// never appears in this signature — keeping the method REST-satisfiable.
    async fn pause_machine(&self, id: &MachineId, opts: PauseOpts) -> Result<PauseOutcome>;

    /// Resume a paused machine from its sealed snapshot. Verifies the snapshot
    /// envelope and **refuses a replayed (older-epoch) snapshot** before
    /// restoring, then finishes bringing the guest back. `opts.warm` selects the
    /// backend's live-memory warm-start path, which fails closed on a disk-only
    /// backend.
    async fn resume_machine(&self, id: &MachineId, opts: ResumeOpts) -> Result<ResumeOutcome>;

    /// Remove a machine by id (stopping it first if needed). Idempotent:
    /// removing an absent machine is `Ok`.
    async fn remove_machine(&self, id: &MachineId) -> Result<()>;

    /// Fetch a machine's captured console/log bytes.
    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>>;

    /// Run a non-interactive command in a machine and capture its result.
    /// (Interactive shells are not a facade operation — see [`ExecResult`].)
    async fn exec_machine(&self, id: &MachineId, command: Vec<String>) -> Result<ExecResult>;

    /// Patch a machine's config and relaunch it. Patch semantics: only
    /// the `Some` fields of `cfg` change; the rest are inherited.
    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        cfg: ReconfigureRequest,
    ) -> Result<MachineState>;

    /// Set or clear a machine's TTL — the `expires_at` the idle reaper honors.
    /// `Some(rfc3339)` arms it, `None` clears it. Errors if the machine is not
    /// registered.
    async fn set_ttl(&self, id: &MachineId, expires_at: Option<String>) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof the trait is object-safe: a `dyn MvmClient` must be
    // constructable, since callers (CLI, studio) hold one behind a box.
    #[test]
    fn trait_is_object_safe() {
        fn _accepts(_c: &dyn MvmClient) {}
    }
}
