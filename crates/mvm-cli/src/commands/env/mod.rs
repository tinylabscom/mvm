//! Environment lifecycle commands — bootstrap, setup, doctor, and friends.
//!
//! These commands provision and inspect the host-side development
//! environment (builder VM image, Firecracker binary, shell init,
//! default network).

pub(super) mod artifact_verify;
pub(super) mod bootstrap;
pub(crate) mod builder_vm;
pub(super) mod cleanup;
pub(super) mod completions;
pub(super) mod doctor;
pub(super) mod group;
pub(super) mod init;
pub(super) mod setup;
pub(super) mod shell_completion;
pub(super) mod shell_init;
pub(super) mod sign;
pub(super) mod uninstall;
pub(super) mod update;

// Re-export the top-level `Cli` so files inside this group can keep
// using `super::Cli`.
pub(super) use super::Cli;
