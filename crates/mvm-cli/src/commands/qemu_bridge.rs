//! Internal `mvmctl __qemu-vsock-bridge` subcommand.
//!
//! Hidden helper spawned (detached) by the QEMU workload backend
//! (`mvm_backend::qemu`). QEMU's virtio-vsock speaks real AF_VSOCK, but
//! the shared agent client connects to the per-port UNIX socket that
//! libkrun/Firecracker expose. This process bridges the two: it listens
//! on the UNIX socket and splices each connection to the guest's
//! `AF_VSOCK(cid, port)`, exiting when the watched qemu process dies.
//!
//! The AF_VSOCK + splice logic lives in `mvm_backend::qemu` (beside the
//! backend that needs it); this is just the argument surface + forward.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// UNIX socket to listen on (the agent client connects here).
    #[arg(long)]
    uds: PathBuf,
    /// Guest CID to dial over AF_VSOCK.
    #[arg(long)]
    cid: u32,
    /// Guest vsock port to dial.
    #[arg(long)]
    port: u32,
    /// Exit when this PID file's process is no longer alive (the VM is gone).
    #[arg(long)]
    watch_pid_file: PathBuf,
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    mvm_backend::qemu::run_vsock_bridge(&args.uds, args.cid, args.port, &args.watch_pid_file)
}
