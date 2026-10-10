//! Dispatching into an already-booted session VM, and waiting for its agent.
//!
//! Booting and tearing down a session VM are `mvm_client::entrypoint`'s; what
//! stays here is the dev-only shell dispatch (`session exec`, a machine's
//! `dev.init`) and the agent wait the transient runner times.

use super::*;

pub use mvm_client::entrypoint::SessionVm;

/// Dispatch a single command into an already-booted session VM,
/// capturing stdout/stderr. Equivalent to the dispatch step of
/// [`run_captured`] without any boot/teardown.
pub fn dispatch_in_session(
    vm: &SessionVm,
    code: String,
    timeout_secs: Option<u64>,
) -> Result<ExecOutput> {
    if !wait_for_agent(&vm.vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    // Reuse build_guest_wrapper by constructing a minimal ExecRequest
    // with no directory shares (sessions do not attach host directories). The wrapper
    // emits `set -e\n<env exports>\n<argv>\n`.
    let req = ExecRequest {
        name: None,
        warm_pool_size: 0,
        image: ImageSource::Template(String::new()),
        cpus: 0,
        memory_mib: 0,
        mem_initial_mib: None,
        dir_shares: vec![],
        disk_volumes: vec![],
        env: vec![],
        assets: Vec::new(),
        target: ExecTarget::Inline {
            argv: vec!["bash".to_string(), "-c".to_string(), code],
        },
        timeout_secs,
        pty: false,
        gpu: false,
        gpu_device: None,
        // Wrapper-string construction only — the session VM is already
        // running, so this never reaches a backend boot.
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        stdin: Vec::new(),
        healthcheck: None,
        hypervisor: None,
        sdk_host_services: Vec::new(),
        declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
    };
    let wrapper = build_guest_wrapper(&req);
    let transport = vsock_transport::for_vm(&vm.vm_name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    // Inbound vsock RPC audit. Mirrors run_in_guest's emit; was lost when
    // this function migrated from send_request to send_exec_streaming.
    let verb = "exec";
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: &vm.vm_name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );

    let mut out = Vec::<u8>::new();
    let mut err = Vec::<u8>::new();
    let terminal = mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        None,
        timeout_secs,
        |event| match event {
            mvm_agentd::vsock::ExecEvent::Stdout { chunk } => out.extend_from_slice(chunk),
            mvm_agentd::vsock::ExecEvent::Stderr { chunk } => err.extend_from_slice(chunk),
            _ => {}
        },
    )?;
    let exit_code = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => code,
        mvm_agentd::vsock::ExecEvent::TimedOut => {
            err.extend_from_slice(format!("{}\n", timeout_exit_message(timeout_secs)).as_bytes());
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };
    Ok(ExecOutput {
        exit_code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        phase_timing: None,
    })
}

pub fn wait_for_agent(vm_name: &str, timeout_secs: u64) -> bool {
    let mut untimed = crate::commands::vm::phase_timing::LaunchSubMarks::new(false);
    wait_for_agent_timed(vm_name, timeout_secs, &mut untimed)
}

#[derive(Debug, PartialEq, Eq)]
enum ReadinessProbePhase {
    SelectTransport,
    Connect,
    AuthenticatedPing,
}

/// Keep useful failure classification, never guest frames or key/session data.
#[derive(Debug)]
struct ReadinessFailure {
    phase: ReadinessProbePhase,
    io_kind: Option<std::io::ErrorKind>,
    os_error: Option<i32>,
}

impl ReadinessFailure {
    fn at(phase: ReadinessProbePhase, error: impl Into<anyhow::Error>) -> Self {
        let error = error.into();
        let io = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>());
        Self {
            phase,
            io_kind: io.map(std::io::Error::kind),
            os_error: io.and_then(std::io::Error::raw_os_error),
        }
    }
}

fn probe_agent_once(vm_name: &str) -> std::result::Result<(), ReadinessFailure> {
    let transport = vsock_transport::for_vm(vm_name)
        .map_err(|e| ReadinessFailure::at(ReadinessProbePhase::SelectTransport, e))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .map_err(|e| ReadinessFailure::at(ReadinessProbePhase::Connect, e))?;
    // This is a throwaway probe, not an RPC data stream. Bound the handshake
    // read so a bound endpoint that is not serving does not wait forever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .map_err(|e| ReadinessFailure::at(ReadinessProbePhase::Connect, e))?;
    mvm_agentd::vsock::probe_agent_ready(&mut stream)
        .map_err(|e| ReadinessFailure::at(ReadinessProbePhase::AuthenticatedPing, e))
}

/// [`wait_for_agent`], recording where the readiness wait went.
///
/// Two spans come out of it. `GuestKernelEntry` — opened when the VMM started
/// its vCPUs — closes at the start of the attempt that succeeded, so it is the
/// guest-boot window bounded below by the poll interval, not an exact mark.
/// `AgentAuth` covers only that successful attempt's connect and authenticated
/// ping, which is exact.
pub(super) fn wait_for_agent_timed(
    vm_name: &str,
    timeout_secs: u64,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> bool {
    use crate::commands::vm::phase_timing::SubPhase;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut attempt = 0u32;
    let mut last_failure = None;
    while std::time::Instant::now() < deadline {
        // Each attempt re-opens the handshake span, so a failed probe leaves
        // no partial span behind and the reported cost is the one that worked.
        sub.finish(SubPhase::GuestKernelEntry);
        sub.start(SubPhase::AgentAuth);
        // Re-pick the transport on each iteration: a Firecracker VM
        // that's still booting may not show up in
        // resolve_running_vm_dir until the daemon registers it.
        // "agent reachable" means it answered on the wire, not just that the
        // socket is open — the VMM binds the agent port before the guest kernel
        // starts, so a connect alone also succeeds against a guest that is still
        // booting or that panicked before userspace. `probe_agent_ready`
        // handshakes and pings, so returning true here means the caller's next
        // RPC reaches a live agent instead of reading EOF.
        match probe_agent_once(vm_name) {
            Ok(()) => {
                sub.finish(SubPhase::AgentAuth);
                return true;
            }
            Err(error) => last_failure = Some(error),
        }
        // Adaptive, not fixed: readiness is only observed on a tick, so the
        // cadence is a floor under the reported wait. A flat 50ms tick put
        // guest-ready at 53.8ms p50 on a backend whose VM creation takes
        // 53.8ms — the number was reporting the tick, not the guest. Starting
        // fine and backing off keeps a fast guest cheap to notice while a slow
        // one still costs few attempts. The probes are connect+hello and fail
        // fast while the guest is still booting.
        std::thread::sleep(mvm_core::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
    if let Some(failure) = last_failure {
        tracing::warn!(
            vm = vm_name,
            socket_directory = %mvm_core::config::vm_socket_dir(vm_name).display(),
            phase = ?failure.phase,
            io_kind = ?failure.io_kind,
            os_error = ?failure.os_error,
            "last guest readiness probe failed at the deadline"
        );
    }
    false
}

#[cfg(test)]
mod readiness_diagnostic_tests {
    use super::*;

    #[test]
    fn readiness_failure_keeps_io_classification_without_payloads() {
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "private diagnostic payload",
        ))
        .context("sensitive context");
        let failure = ReadinessFailure::at(ReadinessProbePhase::Connect, error);
        assert_eq!(failure.phase, ReadinessProbePhase::Connect);
        assert_eq!(failure.io_kind, Some(std::io::ErrorKind::NotFound));
        let diagnostic = format!("{failure:?}");
        assert!(!diagnostic.contains("private"));
        assert!(!diagnostic.contains("sensitive"));
    }

    #[test]
    fn readiness_protocol_failure_does_not_log_guest_response_data() {
        let failure = ReadinessFailure::at(
            ReadinessProbePhase::AuthenticatedPing,
            anyhow::anyhow!("untrusted response payload"),
        );
        assert_eq!(failure.io_kind, None);
        assert_eq!(failure.os_error, None);
        assert!(!format!("{failure:?}").contains("untrusted"));
    }
}
