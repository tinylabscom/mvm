//! Warm-VM session primitives.
//!
//! `mvmctl exec` goes through `run_inner` in the parent module — boot, run,
//! tear down. The session path instead keeps the VM alive across many calls,
//! so the three primitives here split that lifecycle apart: boot once into a
//! [`SessionVm`], dispatch N commands against it, tear down on idle / max /
//! close / shutdown.
//!
//! They deliberately do not take transient host-directory shares; those are
//! attached when the session itself is created rather than per command.

use super::transient::restore_via_snapshot;
use super::*;

pub struct SessionVm {
    pub vm_name: String,
}

/// Boot a session microVM from a registered template. Snapshot-resume
/// is taken when the template has one and the backend supports it
/// (matches the eligibility rule in [`snapshot_eligible`] for the
/// no-directory-share case), unless an admission hook supplies per-boot
/// state that must ride the fresh boot path.
///
/// `vm_name_prefix` becomes the human-readable part of the VM name —
/// callers typically pass a `"<kind>-session-<short-id>"` string so
/// `mvmctl ls` shows which session a VM belongs to.
/// The audit substrate an admitted plan contributes to a session VM so the
/// backend spawns the substitution endpoint (the guest never holds a raw
/// secret). The caller (`invoke --from-workload-ir`) admits the workload's
/// lowered secrets and hands these JSON-serialized fields back; `boot_session_vm`
/// threads them into the `VmStartConfig`. Strings (not typed `mvm-core::plan` values)
/// so this module carries no admission-type dep. **Do not log `plan_json`** — the
/// signed envelope carries secret bindings.
pub struct SessionAuditSubstrate {
    pub tenant_id: String,
    pub plan_json: String,
    pub bundle_json: Option<String>,
    pub config_files: Vec<mvm_core::vm_backend::VmFile>,
}

/// Admission callback: given the resolved rootfs, the kernel that will be
/// booted, and the generated vm_name (all known only inside `boot_session_vm`),
/// produce the audit substrate, or `None` when the workload declares no
/// secrets. Lives in the caller so admission stays in the command layer;
/// `boot_session_vm` just applies the result.
///
/// The kernel rides along for the same reason the rootfs does. A plan that
/// names the image but not the kernel pins what the workload *is* and nothing
/// about what confines it, so the callback cannot bind the environment it was
/// admitted onto unless it is told which kernel that is.
pub type SessionAdmit<'a> = dyn Fn(AdmitInputs<'_>) -> Result<Option<SessionAuditSubstrate>> + 'a;

/// What the launch resolution has established by the time admission runs.
///
/// A struct rather than a positional list because every field is something the
/// resolution *discovered* — the rootfs it materialized, the kernel it chose,
/// the name it generated, the sidecar variant that rootfs turned out to need.
/// Each was added on finding that the plan could not describe the boot without
/// it, and a fourth bare argument in a row is where they stop being readable.
#[derive(Debug, Clone, Copy)]
pub struct AdmitInputs<'a> {
    /// The materialized rootfs the workload will boot.
    pub rootfs: &'a std::path::Path,
    /// The kernel confining it, when the tier has one.
    pub kernel: Option<&'a std::path::Path>,
    /// The name this VM will be started under.
    pub vm_name: &'a str,
    /// The SDK sidecar this boot will attach, or `None`.
    ///
    /// Resolved once, after the rootfs exists — the guest's own recorded libc
    /// decides which variant it is — and handed to both halves from here, so
    /// the plan grant and the attached volume cannot describe different bytes.
    pub sdk_sidecar: Option<&'a crate::commands::vm::up::SdkSidecarAttachment>,
    /// Declared `--asset` bindings forwarded to admission for content
    /// identity hashing.
    pub assets: &'a [crate::commands::shared::AssetSpec],
}

pub fn boot_session_vm(
    env: &str,
    vm_name_prefix: &str,
    cpus: u32,
    memory_mib: u32,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    admit: Option<&SessionAdmit<'_>>,
    backend_name: Option<&str>,
) -> Result<SessionVm> {
    let (spec, vmlinux, initrd, rootfs, rev) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_for_boot(env)
            .with_context(|| format!("Loading template '{env}'"))?;
    let snap_info = mvm_runtime::vm::template::lifecycle::template_snapshot_info_dispatched(env)
        .ok()
        .flatten();

    let backend = if let Some(name) = backend_name {
        AnyBackend::require_hypervisor_selectable(name)?;
        AnyBackend::from_hypervisor(name)
    } else {
        AnyBackend::auto_select()
    };
    // Append the same nanosecond suffix transient_vm_name uses so
    // concurrent boots in the same session don't collide.
    let vm_name = format!("{}-{}", vm_name_prefix, transient_vm_name());

    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    // Session VMs default to the legacy no-admission path. When `admit`
    // returns a substrate, the plan-bearing fields below and any config-drive
    // files it supplies are populated before `backend.start()`.
    let mut start_config = VmStartConfig {
        name: vm_name.clone(),
        rootfs_path: rootfs.clone(),
        kernel_path: Some(vmlinux),
        initrd_path: initrd,
        verity_path,
        roothash,
        revision_hash: rev,
        flake_ref: spec.flake_ref,
        profile: Some(spec.profile),
        cpus,
        memory_mib,
        // Session VMs are short-lived boots; balloon
        // elasticity isn't useful here, so leave commit at boot.
        mem_initial_mib: None,
        ports: vec![],
        volumes: vec![],
        config_files: vec![],
        secret_files: vec![],
        runner_dir: None,
        network_policy: network_policy.clone(),
        ..Default::default()
    };

    // Session VMs are always block-rooted template boots; resolve the overlay
    // policy the same way the transient runner does so the runtime overlay is
    // the single source of the guest agent + helpers here too (a missing
    // required overlay is built/acquired by attach_runtime_overlay_if_cached,
    // never silently replaced by a baked rootfs copy).

    // Admit the workload's lowered secrets (the closure runs
    // synthesize→sign→verify with the now-known rootfs + vm_name) and thread the
    // signed plan into the config so `backend.start` spawns the substitution
    // endpoint. Force a cold boot when secrets are present: snapshot-restore
    // bypasses the endpoint-spawn path. `None` admit ⇒ unchanged legacy path.
    let mut admitted_workload = false;
    if let Some(admit_fn) = admit
        && let Some(sub) = admit_fn(AdmitInputs {
            rootfs: std::path::Path::new(&rootfs),
            kernel: start_config
                .kernel_path
                .as_deref()
                .map(std::path::Path::new),
            vm_name: &vm_name,
            // A session VM binds no SDK host service; `invoke` is the only
            // caller and it admits its own plan without one.
            sdk_sidecar: None,
            // `invoke` declares no standalone assets; its function payload is
            // admitted as the workload itself.
            assets: &[],
        })?
    {
        start_config.tenant_id = Some(sub.tenant_id);
        start_config.plan_json = Some(sub.plan_json);
        start_config.bundle_json = sub.bundle_json;
        start_config.config_files.extend(sub.config_files);
        admitted_workload = true;
        if mvm_runtime::catalog::descriptor(backend.kind()).is_workload {
            mvm_hostd::plan_admission::stash_plan_for_bridge(&start_config)
                .context("persisting admitted session plan before backend start")?;
        }
    }

    crate::commands::vm::up::attach_runtime_overlay_if_cached(&mut start_config, backend.name())?;
    crate::commands::vm::up::attach_universal_initramfs_if_cached(&mut start_config)?;

    let use_snapshot = !admitted_workload
        && snap_info.is_some()
        && backend.capabilities().snapshot_capability != SnapshotCapability::Unsupported;
    let booted = if use_snapshot {
        let snap = snap_info.as_ref().expect("use_snapshot implies snap_info");
        match restore_via_snapshot(&vm_name, env, snap, &start_config) {
            Ok(()) => true,
            Err(e) => return Err(e).context("restoring session VM snapshot"),
        }
    } else {
        false
    };

    if !booted {
        ui::info(&format!(
            "Booting session VM '{vm_name}' for env '{env}'..."
        ));
        backend
            .start(&start_config)
            .with_context(|| format!("starting session microVM '{vm_name}'"))?;
    }

    Ok(SessionVm { vm_name })
}

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

/// Tear down a session VM. Best-effort — failures (already-stopped,
/// backend mismatch) are logged via `tracing::warn!` rather than
/// propagated, since the reaper calls this from a background thread
/// where there's nobody to receive an error.
pub fn tear_down_session_vm(vm: SessionVm) {
    // Use the marker file in the VM's state dir to pick the backend that
    // actually launched it. Falling back to auto_select() would dispatch
    // teardown to the wrong VMM (e.g., libkrun instead of QEMU) and leave
    // the guest process running.
    let backend = AnyBackend::for_started_vm(&vm.vm_name).unwrap_or_else(AnyBackend::auto_select);
    if let Err(e) = backend.stop(&VmId(vm.vm_name.clone())) {
        tracing::warn!(vm = %vm.vm_name, err = %e, "session VM teardown failed");
    }
}

pub fn wait_for_agent(vm_name: &str, timeout_secs: u64) -> bool {
    let mut untimed = crate::commands::vm::phase_timing::LaunchSubMarks::new(false);
    wait_for_agent_timed(vm_name, timeout_secs, &mut untimed)
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
        if let Ok(transport) = vsock_transport::for_vm(vm_name)
            && let Ok(mut stream) = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            && {
                // Bound each probe: a transport whose socket is bound but whose
                // guest agent hasn't replied yet (e.g. still booting, or an
                // hvf VMM whose relay isn't answering) must not block the
                // whole handshake read forever — otherwise this loop never gets
                // back to the deadline check and hangs instead of timing out. A
                // short per-attempt read timeout lets the probe fail fast so
                // the outer loop retries and ultimately honours `timeout_secs`.
                // The stream is a throwaway probe (dropped below), so the timeout
                // never touches a real agent-RPC data stream.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                mvm_agentd::vsock::probe_agent_ready(&mut stream).is_ok()
            }
        {
            sub.finish(SubPhase::AgentAuth);
            return true;
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
    false
}
