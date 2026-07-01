//! The facade trait. `async_trait` boxes the futures so `dyn MvmClient` stays
//! object-safe — callers hold one backend behind a trait object and never see
//! which transport is underneath.

use async_trait::async_trait;

use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState};
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
