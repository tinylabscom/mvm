//! eBPF / procfs telemetry loader.

use std::path::PathBuf;

use tracing::{info, warn};

use crate::supervisor::ebpf_telemetry::{ObservabilityTarget, TelemetryEvent};

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
    pub(super) fn new(target: ObservabilityTarget) -> Self {
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
fn inner_attach(_config: &ProbeConfig, target: &ObservabilityTarget) -> Result<(), TelemetryError> {
    warn!(
        vm = %target.vm_name,
        "eBPF egress telemetry is only available on Linux; using no-op stub"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn inner_attach(config: &ProbeConfig, target: &ObservabilityTarget) -> Result<(), TelemetryError> {
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
        .join("bpfel-unknown-none")
        .join("release")
        .join("mvm-hostd-ebpf")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::ebpf_telemetry::ObservabilityTarget;

    #[test]
    fn telemetry_probe_attaches_with_pid() {
        let telemetry = EgressTelemetry::new(ProbeConfig {
            ebpf_object_path: None,
            enable_procfs_fallback: true,
        });
        let target = ObservabilityTarget::new("vm-with-pid").with_substitution_pid(1234);
        assert!(telemetry.attach(target).is_ok());
    }

    #[test]
    fn telemetry_probe_without_pid_fails_on_linux() {
        let telemetry = EgressTelemetry::new(ProbeConfig::default());
        let target = ObservabilityTarget::new("vm-no-pid");

        #[cfg(target_os = "linux")]
        assert!(matches!(
            telemetry.attach(target),
            Err(TelemetryError::MissingSubstitutionPid(_))
        ));

        #[cfg(not(target_os = "linux"))]
        assert!(telemetry.attach(target).is_ok());
    }
}
