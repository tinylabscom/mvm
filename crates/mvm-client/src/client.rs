//! The facade trait. `async_trait` boxes the futures so `dyn MvmClient` stays
//! object-safe — callers hold one backend behind a trait object and never see
//! which transport is underneath.

use async_trait::async_trait;

use crate::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, ReconfigureRequest,
};
use crate::error::Result;

#[async_trait]
pub trait MvmClient: Send + Sync {
    /// List machines matching `filter`.
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>>;

    /// Launch a machine from `spec`; returns its initial state.
    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState>;

    /// Stop a machine by id. Idempotent: stopping a stopped machine is `Ok`.
    async fn stop_machine(&self, id: &MachineId) -> Result<()>;

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
