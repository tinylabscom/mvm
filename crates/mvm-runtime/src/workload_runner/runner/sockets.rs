use std::path::{Path, PathBuf};

use mvm_agentd::vsock::BROKER_PORT;
use mvm_core::vm_backend::VmStartConfig;
use mvm_vmm::host::spec_map::{WorkloadSockets, console_data_sockets};

/// The standing host sockets a workload's vsock channels bind to, resolved
/// under its per-VM state dir. The egress gateway is the endpoint UDS the
/// spawner returns, not a state-dir path — it is the one gate off the box. A
/// deny-all, secret-free workload carries no egress path at all.
pub(super) struct StandingSockets {
    pub(super) agent: PathBuf,
    pub(super) exit: PathBuf,
    /// Host-services broker socket, resolved only for an admitted workload
    /// (`tenant_id.is_some()`). `None` for an unadmitted VM, which carries no
    /// broker channel at all. The one path threaded into both the spec and the
    /// `BrokerRegistrar::register` call so the relay target and bind path match.
    pub(super) broker: Option<PathBuf>,
    pub(super) console_log: PathBuf,
    /// Per-port UDS for the interactive console data range. Non-empty only when
    /// `VmStartConfig.dev_console` is true; empty for all sealed prod boots.
    pub(super) console_data: Vec<(u32, PathBuf)>,
}

impl StandingSockets {
    /// Bind these resolved sockets to `egress_uds` — the gating endpoint the
    /// guest's `EGRESS_PORT` relays to — yielding the channel description both
    /// start paths map through the shared vsock-port mapper. `None` is the
    /// explicit fail-closed shape for a deny-all, secret-free workload.
    pub(super) fn with_egress<'a>(&'a self, egress_uds: Option<&'a Path>) -> WorkloadSockets<'a> {
        WorkloadSockets {
            agent: &self.agent,
            egress_gateway: egress_uds,
            exit: &self.exit,
            broker: self.broker.as_deref(),
            console_data: self.console_data.clone(),
        }
    }
}

pub(super) fn standing_sockets(state_dir: &Path, config: &VmStartConfig) -> StandingSockets {
    StandingSockets {
        // Single source of truth shared with the host-side resolver so the
        // guest agent bridge can't drift out of the host's reach.
        agent: mvm_core::config::vm_inhouse_agent_socket_at(state_dir),
        exit: state_dir.join("workload.exit"),
        // Admitted-only: an unadmitted VM gets no broker channel, so a stray
        // guest BROKER_PORT dial stays ECONNREFUSED (fail-closed).
        broker: config
            .tenant_id
            .is_some()
            .then(|| mvm_core::config::vm_vsock_port_socket_at(state_dir, BROKER_PORT)),
        console_log: state_dir.join("console.log"),
        console_data: console_data_sockets(state_dir, config.dev_console),
    }
}
