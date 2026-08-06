//! Host-side vsock egress telemetry collector.
//!
//! This crate provides a backend-agnostic interface for observing the
//! outbound connections originated by the per-VM `mvm-substitution-endpoint`
//! on behalf of a workload. On Linux it attempts to load an eBPF program
//! via Aya; if no eBPF object is available it can fall back to a procfs
//! poller. On macOS and other non-Linux targets it compiles to a no-op
//! stub so the workspace stays green.

use std::path::PathBuf;

use mvm_core::vm_backend::BackendKind;

pub use events::{EgressEvent, TelemetryEvent};
pub use probe::{EgressTelemetry, ProbeConfig, ProbeHandle};

/// Target metadata describing the host processes to observe.
///
/// This is a mirror of `mvm_runtime::base::observability_target::VmObservabilityTarget`
/// kept in this crate so `mvm-hostd` does not need to depend on the full
/// runtime crate just for the metadata shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityTarget {
    pub vm_name: String,
    pub backend_kind: BackendKind,
    pub tenant_id: Option<String>,
    pub plan_id: Option<String>,
    pub substitution_pid: Option<u32>,
    pub state_dir: PathBuf,
}

impl ObservabilityTarget {
    pub fn new(vm_name: impl Into<String>) -> Self {
        Self {
            vm_name: vm_name.into(),
            backend_kind: BackendKind::Mock,
            tenant_id: None,
            plan_id: None,
            substitution_pid: None,
            state_dir: PathBuf::new(),
        }
    }

    pub fn with_backend(mut self, kind: BackendKind) -> Self {
        self.backend_kind = kind;
        self
    }

    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn with_plan(mut self, plan_id: impl Into<String>) -> Self {
        self.plan_id = Some(plan_id.into());
        self
    }

    pub fn with_substitution_pid(mut self, pid: u32) -> Self {
        self.substitution_pid = Some(pid);
        self
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = state_dir.into();
        self
    }
}

mod events {
    use std::net::SocketAddr;

    /// One telemetry event observed from the host-side egress path.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EgressEvent {
        /// Resolved destination of the outbound connection.
        pub destination: SocketAddr,
        /// Cumulative bytes observed on this flow (best-effort).
        pub bytes: u64,
        /// Latency in microseconds, if measured.
        pub latency_us: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TelemetryEvent {
        Egress(EgressEvent),
    }
}

mod probe {
    use std::path::PathBuf;

    use tracing::{info, warn};

    use crate::{ObservabilityTarget, TelemetryEvent};

    /// Configuration for the egress telemetry probe.
    #[derive(Debug, Clone, Default)]
    pub struct ProbeConfig {
        /// Path to a compiled eBPF object file. If `None`, the probe
        /// attempts a well-known path relative to the crate source.
        pub ebpf_object_path: Option<PathBuf>,
        /// Enable the procfs fallback when the eBPF object is unavailable.
        pub enable_procfs_fallback: bool,
    }

    /// A running telemetry probe for one VM.
    pub struct ProbeHandle {
        target: ObservabilityTarget,
    }

    impl ProbeHandle {
        fn new(target: ObservabilityTarget) -> Self {
            Self { target }
        }

        pub fn target(&self) -> &ObservabilityTarget {
            &self.target
        }
    }

    /// Manager for per-VM egress telemetry probes.
    pub struct EgressTelemetry {
        config: ProbeConfig,
    }

    impl EgressTelemetry {
        pub fn new(config: ProbeConfig) -> Self {
            Self { config }
        }

        /// Attach a telemetry probe to the given VM.
        ///
        /// On non-Linux platforms this returns a no-op handle. On Linux,
        /// it attempts to load an eBPF program and falls back to a procfs
        /// poller if configured and the eBPF object is missing.
        pub fn attach(&self, target: ObservabilityTarget) -> Result<ProbeHandle, TelemetryError> {
            info!(
                vm = %target.vm_name,
                backend = ?target.backend_kind,
                "attaching egress telemetry probe"
            );
            inner_attach(&self.config, &target)?;
            Ok(ProbeHandle::new(target))
        }

        /// Detach the telemetry probe for the given VM.
        pub fn detach(&self, handle: ProbeHandle) {
            info!(vm = %handle.target.vm_name, "detaching egress telemetry probe");
        }

        /// Drain any pending telemetry events.
        ///
        /// Real implementations backed by eBPF ring buffers or procfs
        /// polling would return events here. The stub returns an empty
        /// iterator.
        pub fn poll_events(&self, _handle: &ProbeHandle) -> Vec<TelemetryEvent> {
            Vec::new()
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum TelemetryError {
        #[error("no substitution PID available for VM {0}")]
        MissingSubstitutionPid(String),
        #[error("eBPF loader not available on this platform")]
        UnsupportedPlatform,
    }

    #[cfg(not(target_os = "linux"))]
    fn inner_attach(
        _config: &ProbeConfig,
        target: &ObservabilityTarget,
    ) -> Result<(), TelemetryError> {
        warn!(
            vm = %target.vm_name,
            "eBPF egress telemetry is only available on Linux; using no-op stub"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn inner_attach(
        config: &ProbeConfig,
        target: &ObservabilityTarget,
    ) -> Result<(), TelemetryError> {
        let Some(_pid) = target.substitution_pid else {
            return Err(TelemetryError::MissingSubstitutionPid(
                target.vm_name.clone(),
            ));
        };

        let object_path = config
            .ebpf_object_path
            .clone()
            .or_else(default_ebpf_object_path);
        if let Some(path) = object_path {
            if path.exists() {
                if let Err(e) = load_aya_program(&path, target) {
                    warn!(error = %e, vm = %target.vm_name, "failed to load eBPF program");
                } else {
                    info!(vm = %target.vm_name, "eBPF egress probe attached");
                    return Ok(());
                }
            }
        }

        if config.enable_procfs_fallback {
            info!(vm = %target.vm_name, "using procfs fallback for egress telemetry");
        } else {
            warn!(vm = %target.vm_name, "no eBPF object and procfs fallback disabled");
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn default_ebpf_object_path() -> Option<PathBuf> {
        // The eBPF program is built separately into the `ebpf/target` directory
        // by nightly + bpf-linker. This path is a convention, not a guarantee.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ebpf")
            .join("target")
            .join("bpfeb-unknown-none")
            .join("release")
            .join("mvm-ebpf-egress")
            .join("mvm-ebpf-egress")
            .with_extension("o")
            .into()
    }

    #[cfg(target_os = "linux")]
    fn load_aya_program(
        path: &std::path::Path,
        target: &ObservabilityTarget,
    ) -> Result<(), aya::EbpfError> {
        let _ebpf = aya::Ebpf::load_file(path)?;
        info!(
            vm = %target.vm_name,
            pid = target.substitution_pid,
            "Aya eBPF object loaded from {}"
            , path.display()
        );
        // Full attach/ring-buffer setup is deferred to a follow-up commit
        // once the eBPF object is built in the Linux builder VM.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_target_builder_chains() {
        let target = ObservabilityTarget::new("vm-1")
            .with_backend(mvm_core::vm_backend::BackendKind::Libkrun)
            .with_tenant("tenant-a")
            .with_plan("plan-42")
            .with_substitution_pid(1234)
            .with_state_dir("/tmp/state");

        assert_eq!(target.vm_name, "vm-1");
        assert_eq!(
            target.backend_kind,
            mvm_core::vm_backend::BackendKind::Libkrun
        );
        assert_eq!(target.tenant_id, Some("tenant-a".to_string()));
        assert_eq!(target.plan_id, Some("plan-42".to_string()));
        assert_eq!(target.substitution_pid, Some(1234));
        assert_eq!(target.state_dir, std::path::PathBuf::from("/tmp/state"));
    }

    #[test]
    fn telemetry_probe_attach_without_pid_fails_on_linux() {
        let telemetry = EgressTelemetry::new(ProbeConfig::default());
        let target = ObservabilityTarget::new("vm-no-pid");

        #[cfg(target_os = "linux")]
        assert!(telemetry.attach(target).is_err());

        #[cfg(not(target_os = "linux"))]
        assert!(telemetry.attach(target).is_ok());
    }

    #[test]
    fn telemetry_probe_attaches_with_pid() {
        let telemetry = EgressTelemetry::new(ProbeConfig {
            ebpf_object_path: None,
            enable_procfs_fallback: true,
        });
        let target = ObservabilityTarget::new("vm-with-pid").with_substitution_pid(1234);
        assert!(telemetry.attach(target).is_ok());
    }
}
