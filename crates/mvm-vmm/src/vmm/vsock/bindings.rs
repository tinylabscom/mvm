//! Host-owned endpoint and activity bindings. These are runtime authority,
//! deliberately separate from the device's serializable guest state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Fresh host-owned paths supplied when a restored child reconnects its vsock
/// channels. These bindings are deliberately external to snapshot bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VsockHostBindings {
    /// Host agent RPC listener path.
    pub agent_socket: Option<PathBuf>,
    /// Host egress endpoint path.
    pub network_endpoint: Option<PathBuf>,
    /// Host broker endpoint path.
    pub broker_endpoint: Option<PathBuf>,
    /// Host view-only display frame sink path.
    pub display_endpoint: Option<PathBuf>,
    /// Host GPU endpoint path (the per-VM `mvm-gpu-endpoint` socket).
    pub gpu_endpoint: Option<PathBuf>,
    /// Additional host-dial listeners (telemetry and admitted console ports).
    pub console_sockets: Vec<(u32, PathBuf)>,
}

#[derive(Clone, Default)]
pub(super) struct VsockHostRuntimeConfig {
    pub(super) bindings: VsockHostBindings,
    pub(super) agent_activity: Option<Arc<AtomicUsize>>,
    pub(super) substitution_activity: Option<Arc<AtomicUsize>>,
    pub(super) broker_activity: Option<Arc<AtomicUsize>>,
    pub(super) display_activity: Option<Arc<AtomicUsize>>,
    pub(super) host_dial_activity: Option<Arc<AtomicUsize>>,
    pub(super) workload_exit_stop: Option<&'static AtomicBool>,
    pub(super) trusted_builder_egress: bool,
}

impl VsockHostBindings {
    pub(super) fn paths(&self) -> Vec<&Path> {
        self.agent_socket
            .iter()
            .map(PathBuf::as_path)
            .chain(self.network_endpoint.iter().map(PathBuf::as_path))
            .chain(self.broker_endpoint.iter().map(PathBuf::as_path))
            .chain(self.display_endpoint.iter().map(PathBuf::as_path))
            .chain(self.gpu_endpoint.iter().map(PathBuf::as_path))
            .chain(self.console_sockets.iter().map(|(_, path)| path.as_path()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_cover_each_host_owned_endpoint() {
        let bindings = VsockHostBindings {
            agent_socket: Some("agent.sock".into()),
            network_endpoint: Some("egress.sock".into()),
            broker_endpoint: Some("broker.sock".into()),
            display_endpoint: Some("display.sock".into()),
            gpu_endpoint: Some("gpu.sock".into()),
            console_sockets: vec![
                (6000, "console.sock".into()),
                (6001, "telemetry.sock".into()),
            ],
        };
        assert_eq!(
            bindings.paths(),
            [
                "agent.sock",
                "egress.sock",
                "broker.sock",
                "display.sock",
                "gpu.sock",
                "console.sock",
                "telemetry.sock",
            ]
            .map(Path::new)
        );
        assert!(VsockHostBindings::default().paths().is_empty());
    }
}
