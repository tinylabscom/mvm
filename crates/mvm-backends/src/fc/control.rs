//! Firecracker VM control: pause/resume/balloon and stop.

use anyhow::{Context, Result};
use tracing::{instrument, warn};

use mvm_vmm::host::shell::{run_in_vm, run_in_vm_stdout, shell_quote};
use mvm_vmm::host::ui;

use super::host;
use super::observe::list_vms;
use super::{abs_vms_dir, read_firecracker_pid};

/// Pause the vCPUs of a running Firecracker VM.
///
/// Sends `PATCH /vm` with `{"state":"Paused"}` to the per-VM control
/// socket. The VMM stays alive; vCPUs stop scheduling. Used by mvmd's
/// sleep path (snapshot-on-sleep, restore-on-wake).
///
/// Errors loudly if the VM is not running rather than silently treating
/// it as a no-op — a stale `pause` against a vanished VM should surface
/// the inconsistency, not be swallowed.
#[instrument(skip_all, fields(name))]
pub fn pause_vm(name: &str) -> Result<()> {
    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !host::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    run_in_vm(&format!(
        r#"sudo curl -fsS -X PATCH --unix-socket {q_socket} \
            -H 'Content-Type: application/json' \
            -d '{{"state":"Paused"}}' \
            'http://localhost/vm'"#,
    ))
    .with_context(|| format!("PATCH /vm Paused for VM '{}'", name))?;
    Ok(())
}

/// Resume vCPUs of a paused Firecracker VM.
///
/// Counterpart to [`pause_vm`]. Sends `PATCH /vm` with
/// `{"state":"Resumed"}` to the per-VM control socket.
#[instrument(skip_all, fields(name))]
pub fn resume_vm(name: &str) -> Result<()> {
    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !host::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    run_in_vm(&format!(
        r#"sudo curl -fsS -X PATCH --unix-socket {q_socket} \
            -H 'Content-Type: application/json' \
            -d '{{"state":"Resumed"}}' \
            'http://localhost/vm'"#,
    ))
    .with_context(|| format!("PATCH /vm Resumed for VM '{}'", name))?;
    Ok(())
}

/// Stop a specific named VM.
#[instrument(skip_all, fields(name))]
/// Adjust the virtio-balloon inflation target for a running FC VM.
///
/// `target_inflate_mib` is the amount the balloon should claim back
/// from the guest. The guest's effective commitment is `memory -
/// target_inflate_mib`. Firecracker expresses this through its
/// `PATCH /balloon` endpoint with `amount_mib`.
///
/// Returns an error if the VM was started without
/// `mem_initial.is_some()` — no balloon device exists to PATCH.
/// Firecracker surfaces this as HTTP 400 with a clear message.
pub fn balloon_set_target(name: &str, target_inflate_mib: u32) -> Result<()> {
    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !host::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    run_in_vm(&format!(
        r#"sudo curl -fsS -X PATCH --unix-socket {q_socket} \
            -H 'Content-Type: application/json' \
            -d '{{"amount_mib":{target}}}' \
            'http://localhost/balloon'"#,
        target = target_inflate_mib,
    ))
    .with_context(|| {
        format!(
            "PATCH /balloon (amount_mib={target_inflate_mib}) for VM '{name}'; \
             VM may have been launched without `mem_initial` (no balloon device)"
        )
    })?;
    Ok(())
}

/// Read the current balloon state of a running FC VM.
///
/// Returns the inflation amount in MiB. `0` means the balloon is
/// fully deflated (guest has all of `memory`). Combined with the
/// VM's declared `memory` cap (e.g. from `list_vms()`), the host
/// reclaim controller derives the effective commitment.
pub fn balloon_state(name: &str) -> Result<u32> {
    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !host::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    let body = run_in_vm_stdout(&format!(
        r#"sudo curl -fsS --unix-socket {q_socket} 'http://localhost/balloon'"#,
    ))
    .with_context(|| format!("GET /balloon for VM '{name}'"))?;

    let parsed: serde_json::Value = serde_json::from_str(body.trim())
        .with_context(|| format!("parse /balloon response: {body:?}"))?;
    let amount = parsed
        .get("amount_mib")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("/balloon response missing amount_mib: {body}"))?;
    Ok(amount as u32)
}

/// Wait for a Firecracker guest to power down on its own after an ACPI
/// shutdown request, polling `is_running` every `poll_interval` until it
/// reports the VM gone or `max_wait` elapses. Returns `true` when the
/// guest exited within the window (no hard kill needed), `false` on
/// timeout. The liveness probe, clock, and sleep are injected so the
/// escalation decision — "did the guest honor the ACPI request before we
/// fall back to SIGKILL?" — is unit-testable without a live guest or
/// real-time waits.
fn await_graceful_exit(
    max_wait: std::time::Duration,
    poll_interval: std::time::Duration,
    mut is_running: impl FnMut() -> Result<bool>,
    mut now: impl FnMut() -> std::time::Instant,
    mut sleep: impl FnMut(std::time::Duration),
) -> Result<bool> {
    let deadline = now() + max_wait;
    while now() < deadline {
        if !is_running()? {
            return Ok(true);
        }
        sleep(poll_interval);
    }
    Ok(false)
}

/// Remove per-VM runtime state only after the Firecracker process is proven
/// gone. Keeping the directory on failure preserves the pid marker, API socket,
/// logs, and other evidence needed to retry or diagnose the stop.
fn cleanup_stopped_vm_state(
    name: &str,
    is_running: impl FnOnce() -> Result<bool>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if is_running()? {
        anyhow::bail!(
            "Firecracker VM '{name}' is still running; retaining its state for retry and recovery"
        );
    }
    cleanup()
}

pub fn stop_vm(name: &str) -> Result<()> {
    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    // Tear down this VM's egress substitution moat BEFORE the
    // not-running early return. The endpoint is a live host process holding the
    // workload's DECRYPTED secrets and the nft REDIRECT table outlives the guest;
    // if an FC VM crashes/OOMs on its own, a later `stop_vm` must still reap the
    // moat — decrypted secrets must not outlive the guest, even on a crash. Both
    // are best-effort + idempotent (no-op when the VM carried no secrets). The
    // substitution sidecars live under `vm_state_dir(name)`, not the workspace
    // `abs_dir`. Mirrors qemu.rs ordering (reap-before-not-running-return).
    mvm_vmm::host::network_endpoint_spawn::reap_network_endpoint(
        &mvm_core::config::vm_state_dir(name),
        name,
    );
    if !host::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is not running.", name));
        return Ok(());
    }
    // Capture the process identity while the marker is known-good. From this
    // point onward, marker presence is recovery metadata only: every liveness
    // decision uses the captured PID so losing `fc.pid` cannot make a live
    // Firecracker look stopped.
    let pid = read_firecracker_pid(&abs_dir)
        .with_context(|| format!("read Firecracker pid for VM '{name}' before stop"))?;

    ui::info(&format!("Stopping VM '{}'...", name));

    // Ask the guest to power down via ACPI (SendCtrlAltDel), then poll for a
    // clean exit on a tight cadence. A headless workload guest has no
    // power-button handler, so the former unconditional 2s sleep-then-kill made
    // every `down` cost two seconds for nothing — escalate to a hard kill the
    // moment the short graceful window lapses instead of always waiting it out.
    if let Err(e) = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = socket,
    )) {
        warn!("failed to send graceful shutdown to VM: {e}");
    }

    let exited_gracefully = await_graceful_exit(
        std::time::Duration::from_millis(250),
        std::time::Duration::from_millis(25),
        || host::is_firecracker_pid_running(pid),
        std::time::Instant::now,
        std::thread::sleep,
    )?;

    // The driver owns the verified SIGTERM → SIGKILL escalation. It reports an
    // error and retains the pid marker if the process survives both signals.
    if !exited_gracefully {
        crate::driver::fc::terminate_firecracker_pid(name, pid, std::path::Path::new(&pid_file))
            .with_context(|| format!("terminate Firecracker VM '{name}'"))?;
    }

    let q_abs_dir = shell_quote(&abs_dir);
    cleanup_stopped_vm_state(
        name,
        || host::is_firecracker_pid_running(pid),
        || {
            run_in_vm(&format!("rm -rf {q_abs_dir}"))
                .map(|_| ())
                .with_context(|| format!("remove stopped VM state {abs_dir}"))
        },
    )?;

    ui::success(&format!("VM '{}' stopped.", name));
    Ok(())
}

/// Stop all running VMs.
#[instrument(skip_all)]
pub fn stop_all_vms() -> Result<()> {
    let vms = list_vms()?;
    if vms.is_empty() {
        ui::info("No VMs are running.");
        return Ok(());
    }

    for info in &vms {
        if let Some(ref name) = info.name {
            stop_vm(name)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- await_graceful_exit (Firecracker `stop_vm` shutdown escalation) ----
    //
    // The probe, clock, and sleep are injected, so these exercise the real
    // escalation decision with no VM and no wall-clock waits (sleep is a
    // no-op; the clock is a deterministic tick where it matters).
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    #[test]
    fn await_graceful_exit_true_when_guest_exits_in_window() {
        // Guest is still up on the first probe, gone on the second.
        let probes = Cell::new(0u32);
        let is_running = || {
            let n = probes.get();
            probes.set(n + 1);
            Ok(n < 1)
        };
        // Generous window with a slow-ticking clock so the deadline is never
        // the reason the loop ends — the guest exiting is.
        let base = Instant::now();
        let tick = Cell::new(0u64);
        let now = || {
            let n = tick.get();
            tick.set(n + 1);
            base + Duration::from_millis(n)
        };
        let exited = await_graceful_exit(
            Duration::from_secs(10),
            Duration::from_millis(25),
            is_running,
            now,
            |_| {},
        )
        .expect("probe never errors");
        assert!(exited, "guest exited within the window → no hard kill");
        assert_eq!(probes.get(), 2, "polled until the guest reported gone");
    }

    #[test]
    fn await_graceful_exit_false_on_timeout_with_bounded_polls() {
        // Guest never powers down.
        let probes = Cell::new(0u32);
        let is_running = || {
            probes.set(probes.get() + 1);
            Ok(true)
        };
        // Clock jumps 100ms per call; with a 250ms window the loop runs twice
        // before `now()` passes the deadline (calls at 0/100/200/300ms).
        let base = Instant::now();
        let tick = Cell::new(0u64);
        let now = || {
            let n = tick.get();
            tick.set(n + 1);
            base + Duration::from_millis(n * 100)
        };
        let slept = Cell::new(0u32);
        let sleep = |_| slept.set(slept.get() + 1);
        let exited = await_graceful_exit(
            Duration::from_millis(250),
            Duration::from_millis(25),
            is_running,
            now,
            sleep,
        )
        .expect("probe never errors");
        assert!(!exited, "guest ignored ACPI → caller must hard-kill");
        assert_eq!(probes.get(), 2, "polled only within the graceful window");
        assert_eq!(
            slept.get(),
            2,
            "slept once per poll, never past the deadline"
        );
    }

    #[test]
    fn await_graceful_exit_propagates_probe_error() {
        let is_running = || Err(anyhow::anyhow!("liveness probe failed"));
        let result = await_graceful_exit(
            Duration::from_secs(1),
            Duration::from_millis(25),
            is_running,
            Instant::now,
            |_| {},
        );
        assert!(
            result.is_err(),
            "a failing liveness probe must surface, not be swallowed"
        );
    }

    #[test]
    fn cleanup_refuses_to_remove_state_while_firecracker_is_alive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fc.pid"), "4242").unwrap();
        let cleanup_called = Cell::new(false);

        let err = cleanup_stopped_vm_state(
            "wedged-vm",
            || Ok(true),
            || {
                cleanup_called.set(true);
                std::fs::remove_dir_all(dir.path()).map_err(Into::into)
            },
        )
        .expect_err("live Firecracker state must be retained");

        assert!(
            err.to_string().contains("still running"),
            "unexpected error: {err:#}"
        );
        assert!(!cleanup_called.get());
        assert!(dir.path().join("fc.pid").exists());
    }

    #[test]
    fn cleanup_removes_state_after_firecracker_exit_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fc.pid"), "4242").unwrap();

        cleanup_stopped_vm_state(
            "stopped-vm",
            || Ok(false),
            || std::fs::remove_dir_all(dir.path()).map_err(Into::into),
        )
        .expect("verified-stopped state can be removed");

        assert!(!dir.path().exists());
    }
}
