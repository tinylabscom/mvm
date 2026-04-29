//! Environment lifecycle commands — bootstrap, setup, dev, and friends.
//!
//! These commands provision, inspect, and tear down the host-side
//! development environment (Lima VM, Apple Container, Firecracker binary,
//! shell init, default network).

pub(super) mod apple_container;
pub(super) mod bootstrap;
pub(super) mod cleanup;
pub(super) mod completions;
pub(super) mod dev;
pub(super) mod doctor;
pub(super) mod init;
pub(super) mod setup;
pub(super) mod shell;
pub(super) mod shell_init;
pub(super) mod uninstall;
pub(super) mod update;

// Re-export the top-level `Cli` and `shared` helpers so files inside this
// group can keep using `super::Cli` / `super::shared::...`.
pub(super) use super::{Cli, shared};
