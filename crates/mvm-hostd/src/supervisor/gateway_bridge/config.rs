//! Bridge configuration — the two [`BridgeEndpoints`] variants the
//! supervisor binaries construct, and the per-VM [`BridgeConfig`] the
//! bridge thread consumes.

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use mvm_core::plan::ExecutionPlan;
use mvm_core::policy::PolicyBundle;

use crate::supervisor::audit::AuditSigner;

/// Which backend the bridge is splicing for. The supervisor binary
/// constructs one of these per VM and hands it to
/// [`spawn_bridge_thread`].
pub enum BridgeEndpoints {
    /// Linux libkrun + passt. Both halves are SOCK_STREAM unix
    /// sockets owned by the supervisor; `tokio::io::copy_bidirectional`
    /// relays bytes between them.
    Passt {
        /// Parent half of the passt socketpair (faces passt).
        gateway_fd: OwnedFd,
        /// Supervisor half of an inner socketpair whose other
        /// half is plumbed into libkrun via
        /// `krun_add_net_unixstream_fd`.
        supervisor_fd: OwnedFd,
    },
    /// macOS libkrun + native gateway. SOCK_DGRAM datagram shuffle —
    /// the gateway creates its own listener at
    /// `gateway_socket_path`; bridge binds at
    /// `supervisor_listen_path` and libkrun connects to *that*.
    /// Bridge relays datagrams both directions.
    LibkrunNativeGateway {
        gateway_socket_path: PathBuf,
        supervisor_listen_path: PathBuf,
    },
}

/// Per-VM bridge config. The supervisor binary fills this from
/// the per-VM `SupervisorConfig` JSON it reads on stdin.
pub struct BridgeConfig {
    pub vm_name: String,
    pub plan: Arc<ExecutionPlan>,
    pub bundle: Option<Arc<PolicyBundle>>,
    /// Subscriber socket path (`~/.mvm/audit/gateway-<vm>.sock`).
    pub audit_socket: PathBuf,
    pub signer: Arc<dyn AuditSigner>,
    /// Host-allowlisted observers that fan-out each FlowEvent before
    /// chain signing. Empty `Vec` = no observers (only the always-on
    /// chain signer fires). The signer task wraps each observer call in
    /// `catch_unwind`; a panicking observer surfaces a `tracing::warn`
    /// and does not break sibling observers or the chain-signing path.
    ///
    /// `Pipeline::from_admitted` populates the list from the plan's
    /// resolved tenant policy bundle; callers without a bundle pass an
    /// empty vec (no observers fire).
    pub observers: Vec<Arc<dyn crate::supervisor::network::Observer>>,
    /// Bare egress policy for the **no-bundle** (transient/dev) path. When
    /// `cfg.bundle` is `None` and this is `Some`, the bridge derives the
    /// flow gate + DNS host allow-list directly from it (the libkrun
    /// analogue of Firecracker consuming `VmStartConfig.network_policy`),
    /// so a transient run enforces the same policy without a signed bundle.
    /// `None` (no bundle either) fails CLOSED to deny-all — never open.
    pub network_policy: Option<mvm_core::network_policy::NetworkPolicy>,
    /// Native-gateway flow-audit export to tail. `Some(<vm>/flow-audit.jsonl)`
    /// when the gateway is native `rvproxy run --config` (it writes its
    /// `FlowEvent` lifecycle there). The bridge spawns a follower that maps each
    /// record into a [`FlowEvent`] and feeds the **same** chain-signer the splice
    /// feeds — so rvproxy's native flow events become a source of the chain-signed
    /// audit. `None` for the native-gateway/passt path (the splice is the only
    /// source).
    pub native_flow_audit_path: Option<PathBuf>,
}
