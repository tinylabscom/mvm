//! Firecracker stop-time helpers: the guest filesystem flush and the
//! process-identity binding recorded for canonical kernel custody.

use anyhow::{Context, Result, bail, ensure};
use mvm_agentd::vsock::{
    GUEST_AGENT_PORT, GuestRequest, GuestResponse, connect_to_port, send_request_stream,
};
#[cfg(test)]
use std::time::Instant;

use super::GUEST_STOP_DRAIN_TIMEOUT_SECS;

/// Observe `pid` and keep the identity only if that process serves this VM's
/// API socket. A pid file naming another VM's Firecracker, or a process that
/// is gone or not Firecracker, yields no identity or an error, never a binding.
pub(super) fn bind_process_to_socket(
    vm: &str,
    pid: u32,
    serves_socket: impl FnOnce(u32) -> Result<bool>,
    capture: impl FnOnce(&str, u32) -> std::io::Result<mvm_vmm::host::process_identity::ProcessIdentity>,
) -> Result<Option<mvm_vmm::host::process_identity::ProcessIdentity>> {
    let identity =
        capture(vm, pid).with_context(|| format!("observe Firecracker process {pid} of '{vm}'"))?;
    ensure!(
        serves_socket(pid)?,
        "process {pid} does not serve the API socket of '{vm}'; refusing to bind its identity"
    );
    Ok(Some(identity))
}

pub(super) fn require_guest_filesystem_flush(response: GuestResponse) -> Result<()> {
    match response {
        GuestResponse::SleepPrepAck { success: true, .. } => Ok(()),
        GuestResponse::SleepPrepAck {
            success: false,
            detail,
        } => bail!(
            "guest refused the stop-time filesystem flush: {}",
            detail.unwrap_or_else(|| "no detail supplied".to_string())
        ),
        other => bail!("guest returned an unexpected stop-time flush response: {other:?}"),
    }
}

pub(super) fn prepare_guest_filesystems_for_stop(vsock_uds: &str) -> Result<()> {
    let mut stream = connect_to_port(vsock_uds, GUEST_AGENT_PORT, GUEST_STOP_DRAIN_TIMEOUT_SECS)
        .with_context(|| format!("connect to guest agent for filesystem flush via {vsock_uds}"))?;
    let response = send_request_stream(
        &mut stream,
        &GuestRequest::SleepPrep {
            drain_timeout_secs: GUEST_STOP_DRAIN_TIMEOUT_SECS,
        },
    )
    .context("request guest filesystem flush before Firecracker stop")?;
    require_guest_filesystem_flush(response)
}

/// Two spans, emitted at debug, splitting teardown into the only two things it
/// does. `stop_transient` is one opaque number to the launch sample, and the
/// guest flush and the kill-and-wait have unrelated costs and unrelated fixes —
/// a vsock round-trip the guest controls, versus a signal plus a host-side poll
/// loop. Without the split, a slow teardown cannot be attributed to either.
#[cfg(test)]
pub(super) fn stop_after_guest_flush(
    prepare: impl FnOnce() -> Result<()>,
    terminate: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let flush_started = Instant::now();
    let prepared = prepare();
    tracing::debug!(
        ms = flush_started.elapsed().as_secs_f64() * 1000.0,
        ok = prepared.is_ok(),
        "fc stop: guest filesystem flush"
    );
    prepared?;

    let terminate_started = Instant::now();
    let terminated = terminate();
    tracing::debug!(
        ms = terminate_started.elapsed().as_secs_f64() * 1000.0,
        "fc stop: signal + exit wait"
    );
    terminated
}

/// Stop a guest, flushing through its agent only when it has one. Requiring the
/// flush of an agentless guest would make it unkillable: the connect fails and
/// the error returns before the process is ever signalled.
#[cfg(test)]
pub(super) fn stop_firecracker_guest(
    flush_via_agent: bool,
    prepare: impl FnOnce() -> Result<()>,
    terminate: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if flush_via_agent {
        stop_after_guest_flush(prepare, terminate)
    } else {
        terminate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(
        vm: &str,
        pid: u32,
    ) -> std::io::Result<mvm_vmm::host::process_identity::ProcessIdentity> {
        Ok(mvm_vmm::host::process_identity::ProcessIdentity {
            vm_id: vm.into(),
            pid,
            start_ticks: 9,
            boot_id: "boot".into(),
        })
    }

    #[test]
    fn a_pid_serving_this_sockets_vm_is_bound() {
        let bound = bind_process_to_socket("vm-a", 7, |_| Ok(true), observed).unwrap();
        assert_eq!(bound.unwrap().pid, 7);
    }

    #[test]
    fn a_pid_naming_another_vms_firecracker_is_refused() {
        let error = bind_process_to_socket("vm-a", 7, |_| Ok(false), observed).unwrap_err();
        assert!(format!("{error:#}").contains("does not serve the API socket"));
        // An unanswerable identity question is an error too, never a binding.
        assert!(bind_process_to_socket("vm-a", 7, |_| bail!("hidden"), observed).is_err());
        // A process that cannot be observed is never bound.
        let gone = |_: &str, _| Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(bind_process_to_socket("vm-a", 7, |_| Ok(true), gone).is_err());
    }
}
