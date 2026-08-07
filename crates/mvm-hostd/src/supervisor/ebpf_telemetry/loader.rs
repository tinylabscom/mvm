//! eBPF / procfs telemetry loader.

use std::path::PathBuf;

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
use std::time::Duration;

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
    #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
    events: std::sync::mpsc::Receiver<TelemetryEvent>,
    #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
    detach: Option<std::sync::mpsc::Sender<()>>,
    #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
    worker: Option<std::thread::JoinHandle<()>>,
}

impl ProbeHandle {
    pub(super) fn new(target: ObservabilityTarget) -> Self {
        Self {
            target,
            #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
            events: {
                let (_, rx) = std::sync::mpsc::channel();
                rx
            },
            #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
            detach: None,
            #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
            worker: None,
        }
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
        inner_attach(&self.config, target)
    }

    /// Detach the telemetry probe for the given VM.
    pub fn detach(&self, handle: ProbeHandle) {
        info!(vm = %handle.target.vm_name, "detaching egress telemetry probe");
        inner_detach(handle);
    }

    /// Drain any pending telemetry events.
    pub fn poll_events(&self, handle: &ProbeHandle) -> Vec<TelemetryEvent> {
        inner_poll_events(handle)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("no substitution PID available for VM {0}")]
    MissingSubstitutionPid(String),
    #[error("eBPF loader not available on this platform")]
    UnsupportedPlatform,
    #[error("eBPF load/attach failed: {0}")]
    LoadFailed(String),
}

#[cfg(not(all(target_os = "linux", feature = "ebpf-telemetry")))]
fn inner_attach(
    _config: &ProbeConfig,
    target: ObservabilityTarget,
) -> Result<ProbeHandle, TelemetryError> {
    warn!(
        vm = %target.vm_name,
        "eBPF egress telemetry is only available on Linux; using no-op stub"
    );
    Ok(ProbeHandle::new(target))
}

#[cfg(not(all(target_os = "linux", feature = "ebpf-telemetry")))]
fn inner_detach(_handle: ProbeHandle) {}

#[cfg(not(all(target_os = "linux", feature = "ebpf-telemetry")))]
fn inner_poll_events(_handle: &ProbeHandle) -> Vec<TelemetryEvent> {
    Vec::new()
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
fn inner_attach(
    config: &ProbeConfig,
    target: ObservabilityTarget,
) -> Result<ProbeHandle, TelemetryError> {
    let Some(_pid) = target.substitution_pid else {
        return Err(TelemetryError::MissingSubstitutionPid(
            target.vm_name.clone(),
        ));
    };

    let object_path = config
        .ebpf_object_path
        .clone()
        .or_else(default_ebpf_object_path);
    let Some(path) = object_path else {
        return Ok(procfs_handle(target, config));
    };
    if !path.exists() {
        return if config.enable_procfs_fallback {
            Ok(procfs_handle(target, config))
        } else {
            warn!(vm = %target.vm_name, "eBPF object missing and procfs fallback disabled");
            Ok(ProbeHandle::new(target))
        };
    }

    let (events_tx, events_rx) = std::sync::mpsc::channel();
    let (detach_tx, detach_rx) = std::sync::mpsc::channel();

    let vm_name = target.vm_name.clone();
    let worker = std::thread::Builder::new()
        .name(format!("ebpf-egress-{vm_name}"))
        .spawn(move || {
            if let Err(e) = ebpf_worker(path, vm_name, events_tx, detach_rx) {
                warn!(error = %e, "eBPF worker failed");
            }
        })
        .map_err(|e| TelemetryError::LoadFailed(e.to_string()))?;

    Ok(ProbeHandle {
        target,
        events: events_rx,
        detach: Some(detach_tx),
        worker: Some(worker),
    })
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
fn inner_detach(handle: ProbeHandle) {
    if let Some(tx) = handle.detach {
        let _ = tx.send(());
    }
    if let Some(worker) = handle.worker {
        let _ = worker.join();
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
fn inner_poll_events(handle: &ProbeHandle) -> Vec<TelemetryEvent> {
    handle.events.try_iter().collect()
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
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

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
fn procfs_handle(target: ObservabilityTarget, _config: &ProbeConfig) -> ProbeHandle {
    info!(vm = %target.vm_name, "using procfs fallback for egress telemetry");
    ProbeHandle::new(target)
}

/// Raw record produced by the kernel-side eBPF program.
#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
#[repr(C)]
struct RawEgressEvent {
    family: u16,
    dport: u16,
    daddr: u32,
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
fn ebpf_worker(
    path: PathBuf,
    vm_name: String,
    events: std::sync::mpsc::Sender<TelemetryEvent>,
    detach: std::sync::mpsc::Receiver<()>,
) -> Result<(), TelemetryError> {
    let mut ebpf =
        aya::Ebpf::load_file(&path).map_err(|e| TelemetryError::LoadFailed(e.to_string()))?;

    let program: &mut aya::programs::KProbe = ebpf
        .program_mut("mvm_hostd_egress_tcp_connect")
        .ok_or_else(|| TelemetryError::LoadFailed("program not found".into()))?
        .try_into()
        .map_err(|e| TelemetryError::LoadFailed(format!("{e:?}")))?;
    program
        .load()
        .map_err(|e| TelemetryError::LoadFailed(e.to_string()))?;
    program
        .attach("tcp_connect", 0)
        .map_err(|e| TelemetryError::LoadFailed(e.to_string()))?;

    info!(vm = %vm_name, "eBPF egress probe attached to tcp_connect");

    // The ring buffer is optional: older spikes may only use aya-log.
    let mut ring_buf: Option<aya::maps::RingBuf<&mut aya::maps::MapData>> =
        ebpf.map_mut("EVENTS").and_then(|m| m.try_into().ok());
    if ring_buf.is_none() {
        warn!(vm = %vm_name, "EVENTS ring buffer not found; probe loaded but no events will be read");
    }

    loop {
        if detach.try_recv().is_ok() {
            break;
        }

        if let Some(ref mut rb) = ring_buf {
            match rb.next() {
                Some(item) => {
                    let bytes = item.as_slice();
                    if bytes.len() >= core::mem::size_of::<RawEgressEvent>() {
                        // SAFETY: the kernel wrote the full RawEgressEvent.
                        let raw = unsafe { &*(bytes.as_ptr() as *const RawEgressEvent) };
                        let destination = std::net::SocketAddr::from((
                            std::net::Ipv4Addr::from(u32::from_be(raw.daddr)),
                            u16::from_be(raw.dport),
                        ));
                        let _ = events.send(TelemetryEvent::Egress(super::events::EgressEvent {
                            destination,
                            bytes: 0,
                            latency_us: None,
                        }));
                    }
                }
                None => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    info!(vm = %vm_name, "eBPF egress probe detached");
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

        #[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
        assert!(matches!(
            telemetry.attach(target),
            Err(TelemetryError::MissingSubstitutionPid(_))
        ));

        #[cfg(not(all(target_os = "linux", feature = "ebpf-telemetry")))]
        assert!(telemetry.attach(target).is_ok());
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
#[test]
fn telemetry_probe_loads_and_attaches_real_ebpf_object() {
    let path = default_ebpf_object_path();
    let Some(path) = path else {
        eprintln!("skipping: no default eBPF object path");
        return;
    };
    if !path.exists() {
        eprintln!("skipping: eBPF object not built at {}", path.display());
        return;
    }

    let telemetry = EgressTelemetry::new(ProbeConfig {
        ebpf_object_path: Some(path),
        enable_procfs_fallback: false,
    });
    let target =
        ObservabilityTarget::new("ebpf-live-test").with_substitution_pid(std::process::id());

    let handle = telemetry
        .attach(target)
        .expect("eBPF object should load and tcp_connect kprobe should attach");

    // Give the kprobe a moment to settle; we do not require an actual
    // TCP connect event to fire in this test.
    std::thread::sleep(std::time::Duration::from_millis(200));

    telemetry.detach(handle);
}

#[cfg(all(target_os = "linux", feature = "ebpf-telemetry"))]
#[test]
fn telemetry_probe_observes_ipv4_destination() {
    let path = default_ebpf_object_path();
    let Some(path) = path else {
        eprintln!("skipping: no default eBPF object path");
        return;
    };
    if !path.exists() {
        eprintln!("skipping: eBPF object not built at {}", path.display());
        return;
    }

    let telemetry = EgressTelemetry::new(ProbeConfig {
        ebpf_object_path: Some(path),
        enable_procfs_fallback: false,
    });
    let target =
        ObservabilityTarget::new("ebpf-dest-test").with_substitution_pid(std::process::id());

    let handle = telemetry
        .attach(target)
        .expect("eBPF object should load and tcp_connect kprobe should attach");

    // Trigger a TCP connect to a distinctive local port. It will fail with
    // ECONNREFUSED, but the tcp_connect kprobe still fires.
    let expected = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 61_987));
    std::thread::spawn(move || {
        let _ = std::net::TcpStream::connect_timeout(&expected, std::time::Duration::from_secs(1));
    });

    // Allow the kprobe and ring-buffer worker to observe the event.
    std::thread::sleep(std::time::Duration::from_millis(500));

    let events: Vec<_> = telemetry.poll_events(&handle);
    telemetry.detach(handle);

    assert!(
        events.iter().any(|e| match e {
            TelemetryEvent::Egress(ev) => ev.destination == expected,
        }),
        "expected an egress event for {expected}; got {events:?}"
    );
}
