//! The stores `mvmctl cache prune` and `cache gc` sweep. Pure re-exports.

pub use mvm_hostd::supervisor::network::flow_byte_log::sweep_retention;
pub use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, SandboxResidency, pinned_checkpoints,
};
pub use mvm_runtime::vm::template::lifecycle::template_prune_orphan_slots;
pub use mvm_runtime::{checkpoint, standby_pool};
