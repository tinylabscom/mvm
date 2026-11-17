//! The machine lifecycle transition gate every local surface serializes on.
//!
//! One cross-process lock per machine name orders start, stop, removal and
//! reconfigure against each other and against crash recovery. Command surfaces
//! and embedders take it here rather than reaching into the runtime, so every
//! surface holds the same gate the library's own launch paths hold.

pub use mvm_runtime::vm::instance_snapshot::MachineLifecycleLock;
