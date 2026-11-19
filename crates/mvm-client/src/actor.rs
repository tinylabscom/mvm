//! Explicit local actor launch through an independent, admitted host controller.

use std::path::Path;

use anyhow::{Context, Result};

pub use mvm_hostd::actor_bootstrap::{ActorBootstrap, NamedActorTemplate};
pub use mvm_hostd::actor_process::ActorLaunch;

/// Launch a host-authored workflow and return after actual parent activation.
///
/// The controller retains the original VM and helper owners after this caller
/// exits. Neither this process nor the guest receives a general backend handle.
/// Only the current native HVF ownership path is supported; other hosts refuse.
pub fn launch(bootstrap: &ActorBootstrap) -> Result<ActorLaunch> {
    mvm_hostd::actor_process::launch(bootstrap)
}

/// Read a strict bounded operator manifest and launch its exact parent/templates.
pub fn launch_file(path: &Path) -> Result<ActorLaunch> {
    let file = std::fs::File::open(path).context("opening actor bootstrap manifest")?;
    let bootstrap = ActorBootstrap::read(file)?;
    launch(&bootstrap)
}
