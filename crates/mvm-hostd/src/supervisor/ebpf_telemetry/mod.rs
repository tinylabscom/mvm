//! Host-side vsock egress telemetry integration.
//!
//! Wires an eBPF/procfs collector into the supervisor lifecycle: when a VM
//! starts, the supervisor reads the per-VM observability target from
//! `mode.json` and asks the telemetry collector to attach. When the VM stops,
//! the probe is detached. Events are reflected in metrics and optionally in
//! the chain-signed audit log.
//!
//! The eBPF program itself lives in `crates/mvm-hostd/ebpf/` and is built
//! separately with nightly + bpf-linker so the main workspace stays on stable
//! Rust.

mod events;
mod loader;
mod target;

pub use events::{EgressEvent, TelemetryEvent};
pub use loader::{EgressTelemetry, ProbeConfig, ProbeHandle, TelemetryError};
pub use target::ObservabilityTarget;

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use mvm_core::observability::metrics::global;
use tracing::warn;

use crate::supervisor::audit_recorder::{EventCategory, Recorder, RecorderError};

/// Manages per-VM egress telemetry probes.
pub struct EbpfTelemetryManager {
    telemetry: EgressTelemetry,
    handles: HashMap<String, ProbeHandle>,
}

impl Default for EbpfTelemetryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfTelemetryManager {
    pub fn new() -> Self {
        Self {
            telemetry: EgressTelemetry::new(ProbeConfig {
                ebpf_object_path: None,
                enable_procfs_fallback: true,
            }),
            handles: HashMap::new(),
        }
    }

    /// Test-only helper: returns whether a handle is currently stored for
    /// the given VM name.
    #[cfg(test)]
    pub fn is_attached(&self, vm_name: &str) -> bool {
        self.handles.contains_key(vm_name)
    }

    /// Attach a telemetry probe for the VM named `vm_name`.
    ///
    /// Reads the observability target sidecar written by the runtime.
    /// Best-effort: failures are logged but do not fail VM launch.
    pub fn attach(&mut self, vm_name: &str) {
        let target = match read_observability_target(vm_name) {
            Some(t) => t,
            None => {
                warn!(vm = %vm_name, "no observability target found; skipping egress telemetry");
                return;
            }
        };

        if self.handles.contains_key(&target.vm_name) {
            return;
        }

        match self.telemetry.attach(target) {
            Ok(handle) => {
                self.handles.insert(vm_name.to_string(), handle);
            }
            Err(e) => {
                warn!(vm = %vm_name, error = %e, "failed to attach egress telemetry probe");
            }
        }
    }

    /// Detach the telemetry probe for `vm_name`.
    pub fn detach(&mut self, vm_name: &str) {
        if let Some(handle) = self.handles.remove(vm_name) {
            self.telemetry.detach(handle);
        }
    }

    /// Poll pending events from all attached probes and update metrics /
    /// audit state.
    pub async fn poll_and_emit(&mut self, recorder: &Recorder) -> Result<(), RecorderError> {
        let handles: Vec<_> = self.handles.values().collect();
        for handle in handles {
            for event in self.telemetry.poll_events(handle) {
                self.record_event(event, recorder).await?;
            }
        }
        Ok(())
    }

    async fn record_event(
        &self,
        event: TelemetryEvent,
        recorder: &Recorder,
    ) -> Result<(), RecorderError> {
        match event {
            TelemetryEvent::Egress(evt) => {
                global()
                    .vsock_egress_events_total
                    .fetch_add(1, Ordering::Relaxed);
                global()
                    .vsock_egress_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                global()
                    .vsock_egress_bytes_total
                    .fetch_add(evt.bytes, Ordering::Relaxed);

                // Emit an unbound Flow audit event. This is host-observed
                // telemetry, not a policy decision, so it is recorded without
                // an ExecutionPlan binding.
                recorder
                    .record_unbound(
                        EventCategory::Flow,
                        "flow.egress.observed",
                        [
                            ("destination".to_string(), evt.destination.to_string()),
                            ("bytes".to_string(), evt.bytes.to_string()),
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

fn read_observability_target(vm_name: &str) -> Option<ObservabilityTarget> {
    let meta = mvm_runtime::base::runtime_meta::read(vm_name)
        .ok()
        .flatten()?;
    let target = meta.observability_target?;

    let backend_kind = parse_backend_kind(&target.backend_kind);
    let substitution_pid = target
        .substitution_target()
        .and_then(|h| mvm_runtime::base::observability_target::read_pid_file(&h.pid_file));

    let mut obs = ObservabilityTarget::new(vm_name)
        .with_backend(backend_kind)
        .with_state_dir(target.state_dir);
    if let Some(pid) = substitution_pid {
        obs = obs.with_substitution_pid(pid);
    }
    if let Some(tenant) = target.tenant_id {
        obs = obs.with_tenant(tenant);
    }
    if let Some(plan) = target.plan_id {
        obs = obs.with_plan(plan);
    }
    Some(obs)
}

/// Telemetry is observability-only, so an unreadable label degrades to the
/// inert tier rather than failing the attach.
fn parse_backend_kind(s: &str) -> mvm_core::vm_backend::BackendKind {
    mvm_core::vm_backend::BackendKind::from_label(s)
        .unwrap_or(mvm_core::vm_backend::BackendKind::Mock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn manager_attach_detach_is_idempotent() {
        let mut manager = EbpfTelemetryManager::new();
        manager.attach("nonexistent-vm");
        // No observability target exists, so no handle is stored.
        assert!(!manager.is_attached("nonexistent-vm"));
        manager.detach("nonexistent-vm");
    }

    #[test]
    fn attach_reads_observability_target_from_mode_json() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(tmp.path());

        let vm_name = "ebpf-attach-test";
        let target = mvm_runtime::base::observability_target::VmObservabilityTarget {
            backend_kind: "libkrun".to_string(),
            state_dir: tmp.path().join("vms").join(vm_name),
            socket_dir: tmp.path().join("sockets").join(vm_name),
            tenant_id: Some("tenant-42".to_string()),
            plan_id: Some("plan-abc".to_string()),
            vmm: mvm_runtime::base::observability_target::VmmTarget {
                process_name: "mvm-libkrun-supervisor".to_string(),
                pid_file: tmp.path().join("vmm.pid"),
                pid: None,
                runs_as_root: false,
            },
            helpers: vec![mvm_runtime::base::observability_target::ProcessTarget {
                role: "substitution".to_string(),
                process_name: "mvm-network-endpoint".to_string(),
                pid_file: tmp.path().join("substitution.pid"),
                pid: None,
            }],
            vsock: mvm_runtime::base::observability_target::VsockTarget {
                guest_cid: None,
                socket_dir: tmp.path().join("sockets").join(vm_name),
            },
            network: mvm_runtime::base::observability_target::NetworkTarget {
                substitution_socket: tmp.path().join("subst.sock"),
            },
            cgroup_path: None,
        };

        let mut meta = mvm_runtime::base::runtime_meta::dev_attached(
            mvm_core::vm_backend::StartMode::Detached,
        );
        meta.observability_target = Some(target);
        mvm_runtime::base::runtime_meta::write(vm_name, &meta).unwrap();

        // Write a substitution PID file so the Linux attach path has a
        // target process and falls through to the procfs fallback (the eBPF
        // object is not built in this test).
        std::fs::write(tmp.path().join("substitution.pid"), b"1234").unwrap();

        let mut manager = EbpfTelemetryManager::new();
        manager.attach(vm_name);
        assert!(manager.is_attached(vm_name));

        manager.detach(vm_name);
        assert!(!manager.is_attached(vm_name));
    }
}
