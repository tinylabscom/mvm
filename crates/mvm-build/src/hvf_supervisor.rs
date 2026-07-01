//! Config contract for `mvm-hvf-supervisor` — the per-VM host process for the
//! raw HVF macOS backend. Lives here (below both `mvm-backend` and
//! `mvm-vm-host`) so the writer (`mvm_backend::hvf::HvfBackend`) and the reader
//! (the `mvm-hvf-supervisor` bin) share one definition — the same way the vz
//! `SupervisorConfig` does. The backend writes this as JSON on the supervisor's
//! stdin; the supervisor boots the guest and captures its console.
//!
//! `#[serde(deny_unknown_fields)]` keeps the host↔supervisor contract
//! fail-closed (strict-schema): an unexpected field is a hard parse error,
//! never a silently-ignored option.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Everything the supervisor needs to boot one guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfSupervisorConfig {
    /// arm64 `Image` to boot.
    pub kernel: PathBuf,
    /// Full kernel cmdline. `None` ⇒ the supervisor's built-in default (workload
    /// contract: `init=/init`). Set it to boot an image whose PID 1 differs — e.g.
    /// the builder rootfs, which boots the static `/sbin/mvm-host-vm-init`. The
    /// `MVM_HVF_BOOTARGS` env override still wins over this (dev hook).
    #[serde(default)]
    pub cmdline: Option<String>,
    /// Optional initramfs (cpio, gzip-or-raw).
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
    /// Optional virtio-blk backing image.
    #[serde(default)]
    pub disk: Option<PathBuf>,
    /// Attach a virtio-vsock device.
    #[serde(default)]
    pub vsock: bool,
    /// Where to write the captured guest console.
    pub console_log: PathBuf,
    /// Where to write this process's PID once booting starts (the backend polls
    /// for it to confirm launch, and reads it to stop/status the VM).
    pub pid_file: PathBuf,
    /// Where to persist the workload exit code (`<state>/workload.exit`, decimal)
    /// when the guest reports it over the workload-exit vsock port — the transient
    /// run-to-exit result the backend's `wait` reads.
    pub workload_exit: PathBuf,
    /// Run budget in seconds — a booting kernel never exits on its own, so the
    /// guest is forced out after this long. The backend sets it from the VM's
    /// requested lifetime.
    pub timeout_secs: u64,
    /// Per-VM host→guest agent RPC socket. The supervisor binds it so host clients
    /// (`machine invoke`) reach the guest agent over vsock. `None` ⇒ no agent
    /// listener (the supervisor falls back to the `MVM_HVF_AGENT_SOCKET` dev hook).
    /// Threading it here is the productionized path off that env hook.
    #[serde(default)]
    pub agent_socket: Option<PathBuf>,
    /// Per-VM substitution-endpoint socket. When set, the supervisor
    /// routes `EGRESS_PORT` to the `mvm-substitution-endpoint` bound here
    /// (WireRequest substitution; claims 10/12/13). `None` ⇒ the legacy raw-TCP
    /// egress path (no secret-bearing egress). The backend spawns the endpoint and
    /// sets this only when the admitted plan carries egress secrets.
    #[serde(default)]
    pub substitution_socket: Option<PathBuf>,
    /// Per-VM unified egress bridge UDS. When set, the supervisor wires
    /// `EGRESS_PORT` as a pure relay to it — the endpoint bound here gates
    /// (claim-10) and substitutes secrets, so `network_policy` is unused for this
    /// VM. `None` ⇒ the in-loop-gated paths (raw egress / gated substitution).
    #[serde(default)]
    pub egress_relay_socket: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_with_all_fields() {
        let cfg = HvfSupervisorConfig {
            kernel: "/k/Image".into(),
            cmdline: Some("console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init".into()),
            initramfs: Some("/k/initrd.cpio".into()),
            disk: Some("/k/disk.img".into()),
            vsock: true,
            console_log: "/state/console.log".into(),
            pid_file: "/state/hvf.pid".into(),
            workload_exit: "/state/workload.exit".into(),
            timeout_secs: 30,
            agent_socket: Some("/state/hvf-agent.sock".into()),
            substitution_socket: Some("/state/substitution-endpoint.sock".into()),
            egress_relay_socket: Some("/state/egress-bridge.sock".into()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(
            serde_json::from_str::<HvfSupervisorConfig>(&json).unwrap(),
            cfg
        );
    }

    #[test]
    fn socket_fields_default_to_none() {
        // Older configs (and non-secret VMs) omit the socket fields → None.
        let json = r#"{"kernel":"/k/Image","console_log":"/c.log","pid_file":"/p.pid","workload_exit":"/w.exit","timeout_secs":5}"#;
        let cfg: HvfSupervisorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.agent_socket, None);
        assert_eq!(cfg.substitution_socket, None);
        assert_eq!(cfg.egress_relay_socket, None);
    }

    #[test]
    fn optional_fields_default() {
        let json = r#"{"kernel":"/k/Image","console_log":"/c.log","pid_file":"/p.pid","workload_exit":"/w.exit","timeout_secs":5}"#;
        let cfg: HvfSupervisorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.cmdline, None);
        assert_eq!(cfg.initramfs, None);
        assert_eq!(cfg.disk, None);
        assert!(!cfg.vsock);
        assert_eq!(cfg.timeout_secs, 5);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields: a typo'd / unexpected field fails closed.
        let json = r#"{"kernel":"/k","console_log":"/c","pid_file":"/p","workload_exit":"/w","timeout_secs":1,"bogus":1}"#;
        assert!(serde_json::from_str::<HvfSupervisorConfig>(json).is_err());
    }
}
