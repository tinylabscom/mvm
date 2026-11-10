//! `mvm-mailbox` binary: the per-VM guest mailbox host process.
//!
//! Spawn contract:
//!
//! 1. The launch path spawns it only for a plan that carries a mailbox grant.
//! 2. It writes a JSON `MailboxProcessConfig` to stdin and closes it. The
//!    config holds keys derived for this one mailbox, never the host signing
//!    seed; nothing is passed in argv or the environment.
//! 3. The process dials the guest's mailbox port, serves it, and exits when
//!    its launcher and its VM are both gone.

use std::io::Read;

use anyhow::{Context, Result};
use mvm_hostd::mailbox_process::{parse, serve};

fn main() -> Result<()> {
    // First statement in the process: a panic before this line would print
    // its payload unredacted.
    mvm_hostd::panic_hook::install("mailbox");
    let mut raw = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut raw)
        .context("mvm-mailbox stdin read failed")?;
    let config = parse(&raw).context("mvm-mailbox config parse failed")?;
    std::process::exit(serve(config));
}
