//! Host-observed readiness milestones.
//!
//! Recording a readiness milestone is best-effort local observability, not a
//! machine-lifecycle operation: a remote fleet's daemon records its own
//! milestones, so this is a sync free function on the client boundary rather
//! than an `MvmClient` trait method (whose async, remote-capable shape would be
//! an impedance mismatch for a purely-local registry write). It lives here so
//! the CLI reaches the host name registry through the client crate instead of
//! naming `mvm-runtime` internals directly.

use mvm_core::domain::instance::InstanceReadiness;

/// Persist a host-observed readiness milestone on the VM's name-registry entry.
///
/// Best-effort: an unregistered VM or a registry I/O error degrades to a log
/// line inside the registry helper, never an error here — readiness is a
/// display signal for `mvmctl ls/ps --json`, never a control-flow gate.
pub fn record_readiness(vm_name: &str, readiness: InstanceReadiness) {
    mvm_runtime::vm::name_registry::record_readiness(vm_name, readiness);
}

/// Read a machine's last-recorded readiness milestone from the name registry —
/// the read counterpart to [`record_readiness`]. `None` if the machine has no
/// registry entry or no recorded milestone. Best-effort: a registry that can't
/// be loaded reads as `None`.
pub fn readiness_of(vm_name: &str) -> Option<InstanceReadiness> {
    let path = mvm_runtime::vm::name_registry::registry_path();
    let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).ok()?;
    registry
        .lookup(vm_name)
        .and_then(|reg| reg.readiness.clone())
}

/// Record a coarse guest-activity touch (`last_active`) on a machine's registry
/// entry. Best-effort like [`record_readiness`]: only rewrites when the name is
/// registered, and swallows any load/save hiccup so a console attach never
/// blocks on registry I/O.
pub fn touch_activity(vm_name: &str) {
    let path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut reg) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path)
        && reg
            .touch_last_active(vm_name, mvm_core::time::utc_now())
            .unwrap_or(false)
    {
        let _ = reg.save(&path);
    }
}

/// A live `ReadinessReport` from a running machine's guest agent — the
/// read counterpart to the registry milestones above. Drives the
/// protocol-hello prelude and a single `ReadinessStatus` request through
/// the machine's vsock transport, so Firecracker, libkrun, HVF, and the
/// other backends all answer without per-backend code in the caller. It
/// lives here so `mvmctl wait`/`boot-report` and the host library poll
/// the guest through one implementation.
pub use mvm_agentd::vsock::ReadinessReport;

/// Fetch one live readiness report. Typed `RpcError`s cover agent
/// `Error`, profile refusal, and off-contract frames, so the only `Ok`
/// variant is the contracted report.
pub fn fetch_live_readiness(vm_name: &str) -> anyhow::Result<ReadinessReport> {
    use mvm_agentd::vsock::{
        GUEST_AGENT_PORT, GuestCapability, GuestRequest, GuestResponse, call_unary,
        negotiate_protocol,
    };
    let transport: Box<dyn mvm_runtime::vsock_transport::VsockTransport> =
        mvm_runtime::vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(GUEST_AGENT_PORT)?;
    let _ = negotiate_protocol(&mut stream, vec![GuestCapability::Readiness])?;
    match call_unary(&mut stream, &GuestRequest::ReadinessStatus)? {
        GuestResponse::ReadinessStatusReport(report) => Ok(report),
        other => anyhow::bail!("unexpected response to ReadinessStatus: {other:?}"),
    }
}
