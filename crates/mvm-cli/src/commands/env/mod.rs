//! Environment lifecycle commands — bootstrap, setup, dev, and friends.
//!
//! These commands provision, inspect, and tear down the host-side
//! development environment (Apple Container, Firecracker binary,
//! shell init, default network).

pub(super) mod apple_container;
pub(super) mod artifact_verify;
pub(super) mod bootstrap;
pub(super) mod cleanup;
pub(super) mod dev;
pub(super) mod doctor;
pub(super) mod init;
pub(super) mod linux_native;
pub(super) mod setup;
pub(super) mod shell_init;
pub(super) mod uninstall;
pub(super) mod update;

// Re-export the top-level `Cli` so files inside this group can keep
// using `super::Cli`.
pub(super) use super::Cli;
