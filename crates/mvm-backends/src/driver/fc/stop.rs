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

/// File a sealed `machine pause` writes beside `fc.pid`, naming the paused
/// Firecracker's pid.
pub const SEALED_PAUSE_MARKER: &str = "fc.paused";

/// Whether the VMM behind `api_socket` reports its vCPUs paused. `None` when
/// the API cannot be asked or its answer cannot be read; the caller then
/// treats the guest as running and lets the flush report.
pub(super) fn instance_paused(api_socket: &std::path::Path) -> Option<bool> {
    #[derive(serde::Deserialize)]
    struct InstanceInfo {
        state: String,
    }
    let body = crate::fc::call(api_socket, "GET", "/", None).ok()?;
    let info: InstanceInfo = serde_json::from_str(&body).ok()?;
    Some(info.state == "Paused")
}

/// Whether `state_dir`'s sealed-pause marker names process `pid`: the pause
/// was this host's own `machine pause` of this very process.
pub(super) fn paused_by_sealed_pause(state_dir: &std::path::Path, pid: u32) -> bool {
    std::fs::read_to_string(state_dir.join(SEALED_PAUSE_MARKER))
        .is_ok_and(|recorded| recorded.trim() == pid.to_string())
}

/// What a stop does to a guest before the VMM is terminated.
///
/// A running guest is asked to flush, and a refusal still stops the stop, as
/// before. A guest paused by `machine pause` is resumed so it can flush; from
/// then on the stop must end in termination, so a flush that fails is only
/// logged and unflushed writes may be lost, rather than leaving a resumed guest
/// running under a machine recorded as paused. Any other paused VMM (a
/// preloaded standby child, say, which has passed no claim-time gate) is never
/// resumed: it is stopped without a flush.
pub(super) fn prepare_firecracker_stop(
    paused: Option<bool>,
    sealed_pause: impl FnOnce() -> bool,
    resume: impl FnOnce() -> Result<()>,
    flush: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if paused != Some(true) {
        return flush();
    }
    if !sealed_pause() {
        tracing::warn!("stopping a paused Firecracker VM this host did not pause, without a flush");
        return Ok(());
    }
    resume().context("resume a paused Firecracker guest so it can flush before stop")?;
    if let Err(error) = flush() {
        tracing::warn!(
            error = %format!("{error:#}"),
            "the resumed guest did not flush; stopping it anyway, and writes it had not flushed may be lost"
        );
    }
    Ok(())
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

    /// Runs the stop the way the runner does: preparation, then termination
    /// only if preparation succeeded. Returns (result, resumed, flushed, terminated).
    fn stop_with(
        paused: Option<bool>,
        sealed: bool,
        flush_ok: bool,
    ) -> (Result<()>, bool, bool, bool) {
        let (resumed, flushed) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
        let mut terminated = false;
        let result = prepare_firecracker_stop(
            paused,
            || sealed,
            || {
                resumed.set(true);
                Ok(())
            },
            || {
                flushed.set(true);
                if flush_ok {
                    Ok(())
                } else {
                    bail!("guest refused the flush")
                }
            },
        )
        .inspect(|()| terminated = true);
        (result, resumed.get(), flushed.get(), terminated)
    }

    #[test]
    fn a_sealed_pause_is_resumed_flushed_and_terminated() {
        let (result, resumed, flushed, terminated) = stop_with(Some(true), true, true);
        assert!(result.is_ok() && resumed && flushed && terminated);
    }

    #[test]
    fn a_flush_that_fails_after_the_resume_still_terminates() {
        let (result, resumed, flushed, terminated) = stop_with(Some(true), true, false);
        assert!(result.is_ok(), "a resumed guest must not be left running");
        assert!(resumed && flushed && terminated);
    }

    #[test]
    fn a_pause_this_host_did_not_seal_is_never_resumed_or_flushed() {
        let (result, resumed, flushed, terminated) = stop_with(Some(true), false, true);
        assert!(result.is_ok() && terminated);
        assert!(!resumed && !flushed);
    }

    #[test]
    fn a_running_or_unknown_guest_keeps_the_flush_gate() {
        for paused in [Some(false), None] {
            let (result, resumed, _, terminated) = stop_with(paused, true, false);
            assert!(result.is_err() && !resumed && !terminated, "{paused:?}");
            let (result, resumed, flushed, terminated) = stop_with(paused, true, true);
            assert!(
                result.is_ok() && !resumed && flushed && terminated,
                "{paused:?}"
            );
        }
    }

    #[test]
    fn a_failed_resume_refuses_the_stop_with_the_guest_still_paused() {
        let mut flushed = false;
        let result = prepare_firecracker_stop(
            Some(true),
            || true,
            || bail!("API refused"),
            || {
                flushed = true;
                Ok(())
            },
        );
        assert!(result.is_err() && !flushed);
    }

    #[test]
    fn only_a_marker_naming_this_process_is_a_sealed_pause() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!paused_by_sealed_pause(dir.path(), 42));
        std::fs::write(dir.path().join(SEALED_PAUSE_MARKER), "41").unwrap();
        assert!(!paused_by_sealed_pause(dir.path(), 42));
        std::fs::write(dir.path().join(SEALED_PAUSE_MARKER), "42\n").unwrap();
        assert!(paused_by_sealed_pause(dir.path(), 42));
    }

    #[test]
    fn an_unreadable_instance_state_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(instance_paused(&dir.path().join("absent.sock")), None);
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
