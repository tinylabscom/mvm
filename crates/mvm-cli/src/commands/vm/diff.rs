//! `mvmctl diff` — show filesystem changes inside a running microVM.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_core::net::session::SessionError;
use std::time::Duration;

use crate::ui;

use mvm_agentd::vsock::FsChange;
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::{clap_vm_name, human_bytes};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;

    let changes = fs_diff(&args.name)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&changes)?);
    } else if changes.is_empty() {
        ui::info("No filesystem changes detected.");
    } else {
        ui::info(&format!("{} change(s):", changes.len()));
        for change in &changes {
            let prefix = match change.kind {
                mvm_agentd::vsock::FsChangeKind::Created => "+",
                mvm_agentd::vsock::FsChangeKind::Modified => "~",
                mvm_agentd::vsock::FsChangeKind::Deleted => "-",
            };
            if change.size > 0 {
                println!(
                    "  {} {} ({})",
                    prefix,
                    change.path,
                    human_bytes(change.size)
                );
            } else {
                println!("  {} {}", prefix, change.path);
            }
        }
    }

    Ok(())
}

/// Fetch the guest fs-diff over the backend-aware transport.
/// Like `fs::fs_request`, the `--hypervisor mock` fast path stays ahead of
/// the `vsock_transport::for_vm` probe — which resolves the right socket per
/// VMM (Firecracker's `v.sock`, or the per-port UNIX socket libkrun/QEMU
/// expose) but is unaware of the in-memory mock backend. Gated behind
/// `test-support` along with the mock backend itself.
fn fs_diff(name: &str) -> Result<Vec<FsChange>> {
    #[cfg(feature = "test-support")]
    {
        let mock_dir = mvm_runtime::MockBackend::vm_dir(name);
        if mock_dir.join("runtime").join("v.sock").exists() {
            return mvm_agentd::vsock::query_fs_diff(&mock_dir.to_string_lossy());
        }
    }
    retry_initial_handshake(|| {
        let mut stream = mvm_runtime::vsock_transport::for_vm(name)?
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
        mvm_agentd::vsock::query_fs_diff_on(&mut stream)
    })
}

/// Retry only an authenticated-session handshake that ended before the peer
/// sent any proof. The request cannot have reached the guest in that state, so
/// replaying it on a fresh connection is safe. An EOF after the request was
/// sent has a different error chain and is returned without retrying.
fn retry_initial_handshake<T>(mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
    match attempt() {
        Err(error) if is_handshake_peer_hangup(&error) => {
            std::thread::sleep(Duration::from_millis(100));
            attempt()
        }
        outcome => outcome,
    }
}

fn is_handshake_peer_hangup(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<SessionError>()
            .is_some_and(SessionError::is_peer_hangup)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Error, ErrorKind};

    fn handshake_hangup() -> anyhow::Error {
        anyhow::Error::new(SessionError::Io(Error::from(ErrorKind::UnexpectedEof)))
            .context("host session handshake failed")
    }

    #[test]
    fn a_peer_hangup_before_authentication_is_retried_once() {
        let attempts = Cell::new(0);
        let value = retry_initial_handshake(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                Err(handshake_hangup())
            } else {
                Ok(7)
            }
        })
        .expect("second connection succeeds");

        assert_eq!(value, 7);
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn an_eof_after_authentication_is_not_replayed() {
        let attempts = Cell::new(0);
        let error = retry_initial_handshake::<()>(|| {
            attempts.set(attempts.get() + 1);
            Err(anyhow::Error::new(Error::from(ErrorKind::UnexpectedEof))
                .context("control frame read failed"))
        })
        .expect_err("post-request EOF must be returned");

        assert_eq!(attempts.get(), 1);
        assert!(error.to_string().contains("control frame read failed"));
    }

    #[test]
    fn a_second_handshake_hangup_is_bounded() {
        let attempts = Cell::new(0);
        retry_initial_handshake::<()>(|| {
            attempts.set(attempts.get() + 1);
            Err(handshake_hangup())
        })
        .expect_err("the retry budget must be bounded");

        assert_eq!(attempts.get(), 2);
    }
}
