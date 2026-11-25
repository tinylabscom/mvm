//! `mvmctl backend detect` — the backend install.sh selects on this host.
//!
//! This is the *install-time* answer, not the runtime auto-detect: it reads
//! the component table, and refuses a host no row covers. install.sh calls
//! `mvmctl backend detect --plain` against the just-extracted archive so the
//! shell never reimplements the table.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::host_binaries::backend_components::{detect_install_default_for, live_host};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Print just the backend name on stdout (for install.sh)
    #[arg(long)]
    pub plain: bool,
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    let host =
        live_host().ok_or_else(|| anyhow::anyhow!("this build has no release archive target"))?;
    let Some(kind) = detect_install_default_for(&host) else {
        anyhow::bail!(
            "no backend supports this host. Supported: Linux with /dev/kvm (firecracker), \
             Linux without KVM (qemu, dev/test), macOS 26+ Apple Silicon (hvf). \
             See https://runmvm.com/reference/platform-support/"
        );
    };
    if args.plain {
        println!("{}", kind.as_str());
    } else {
        println!("Install default backend on this host: {}", kind.as_str());
    }
    Ok(())
}
