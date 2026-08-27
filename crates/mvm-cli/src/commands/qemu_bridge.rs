//! Internal `mvmctl __qemu-vsock-bridge` subcommand.
//!
//! Hidden helper spawned (detached) by the QEMU workload backend
//! (`mvm_runtime::qemu`). QEMU's virtio-vsock speaks real AF_VSOCK, but
//! the shared agent client and the runner's channel set are expressed as
//! per-port UNIX sockets. This process bridges the two, in both
//! directions, following the JSON `QemuBridgeSpec` the backend wrote next
//! to the VM's pid file: it listens on each host-dialed UNIX socket and
//! splices to the guest's `AF_VSOCK(cid, port)`, terminates each
//! guest-dialed AF_VSOCK channel and splices to its runner-bound UNIX
//! listener, captures the workload-exit report, and exits when the watched
//! qemu process dies.
//!
//! The AF_VSOCK + splice logic lives in `mvm_runtime::qemu` (beside the
//! backend that needs it); this is just the argument surface + forward.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Path to the JSON `QemuBridgeSpec` the backend wrote for this VM.
    #[arg(long)]
    spec: PathBuf,
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    mvm_backends::driver::qemu_process::run_vsock_bridge_from_spec_file(&args.spec)
}
