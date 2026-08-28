//! Config contract for `mvm-hvf-supervisor` — the per-VM host process for the
//! raw HVF macOS backend. Lives here (below both `mvm-backend` and
//! `mvm-vm-host`) so the writer (`mvm_runtime::backends::hvf::HvfBackend`) and the reader
//! (the `mvm-hvf-supervisor` bin) share one definition — the same way libkrun's
//! `SupervisorConfig` does. The backend writes this as JSON on the supervisor's
//! stdin; the supervisor boots the guest and captures its console.
//!
//! `#[serde(deny_unknown_fields)]` keeps the host↔supervisor contract
//! fail-closed (strict-schema): an unexpected field is a hard parse error,
//! never a silently-ignored option.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One virtio-blk device attached to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfDisk {
    /// Host path to the backing image.
    pub path: PathBuf,
    /// Attach read-only — hypervisor-enforced: the device advertises
    /// `VIRTIO_BLK_F_RO` and rejects guest writes. A read-write disk persists
    /// guest writes back to the host file (e.g. the builder's nix-store).
    #[serde(default)]
    pub read_only: bool,
    /// Load the whole image into guest RAM and drop writes on exit, rather than
    /// serving it from the host file. For a writable rootfs whose mutations must
    /// not persist to a shared base image (the workload default). Ignored when
    /// `read_only` — a read-only disk is always served straight from the file.
    #[serde(default)]
    pub ephemeral: bool,
}

/// One read-only host directory served as a guest virtio-fs volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfVirtioFsShare {
    /// Host directory to serve.
    pub path: PathBuf,
    /// Guest-visible virtio-fs tag, for example `uvol0`.
    pub tag: String,
}

/// A host UDS the supervisor binds on behalf of one guest vsock port the guest
/// listens on and the host dials — a console data stream or a builder control
/// channel. Which ports appear is a policy decision made by the caller;
/// see `host::spec_map`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDialSocket {
    /// The vsock port the guest is listening on.
    pub guest_port: u32,
    /// Host UDS path the supervisor binds so a host client can connect.
    pub host_socket: PathBuf,
}

pub use crate::hvf_handoff::HvfHandoffRequest;

/// Filename for the optional supervisor-internal shutdown profile.
pub const SHUTDOWN_TIMING_FILE: &str = "shutdown-timing.json";

/// Supervisor-internal shutdown spans persisted before the live PID marker is
/// removed. Values are microseconds and contain no workload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfShutdownTimingRecord {
    /// Wire schema for strict consumers.
    pub schema_version: u32,
    /// From watchdog stop observation through vCPU run-loop return.
    pub watchdog_to_vcpu_exit_micros: u64,
    /// Watchdog thread join after vCPU return.
    pub watchdog_join_micros: u64,
    /// Event-driven host-I/O wake and thread join.
    pub io_thread_join_micros: u64,
    /// Hypervisor.framework vCPU destruction.
    pub vcpu_destroy_micros: u64,
    /// Hypervisor.framework VM destruction.
    pub vm_destroy_micros: u64,
    /// Captured console write and flush.
    pub console_write_micros: u64,
    /// Workload-exit marker write, or zero when no code was reported.
    pub workload_exit_write_micros: u64,
}

/// Resolve the timing record within one canonical VM state directory.
pub fn shutdown_timing_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join(SHUTDOWN_TIMING_FILE)
}

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
    /// Guest RAM in MiB. `0` (the default) ⇒ the supervisor's built-in default
    /// (512 MiB). A builder sets several GiB so `nix build` doesn't OOM.
    #[serde(default)]
    pub memory_mib: u32,
    /// Guest vCPUs. `0` (the default) ⇒ 1.
    ///
    /// The count has to reach *this* process because the supervisor is what
    /// calls `hv_vcpu_create`, and it also has to reach the device tree, which
    /// is built here: a guest cannot online a CPU the DTB does not describe,
    /// and describing one the VMM never creates hangs the boot waiting for a
    /// secondary that never arrives. Both readers take this one field so they
    /// cannot disagree.
    #[serde(default)]
    pub vcpus: u32,
    /// Optional initramfs (cpio, gzip-or-raw).
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
    /// virtio-blk devices in `/dev/vda`, `/dev/vdb`, … order. Empty ⇒ a disk-less
    /// (initramfs / freestanding) boot.
    #[serde(default)]
    pub disks: Vec<HvfDisk>,
    /// When set, serve this host directory (the unpacked+injected OCI tree) to the
    /// guest as a read-only **virtiofs root** — the Plan-223 dev-tier boot. No
    /// virtio-blk rootfs is attached; the default cmdline becomes
    /// `rootfstype=virtiofs root=mvmroot`.
    #[serde(default)]
    pub virtiofs_root: Option<PathBuf>,
    /// Read-only live host-directory shares mounted after the image root.
    #[serde(default)]
    pub virtiofs_shares: Vec<HvfVirtioFsShare>,
    /// Attach a virtio-vsock device.
    #[serde(default)]
    pub vsock: bool,
    /// Trusted-builder VM: relay egress without the per-workload byte-rate cap.
    /// A builder carries no untrusted workload and pulls multi-gigabyte
    /// substituter closures. Defaults false so a workload stays metered.
    #[serde(default)]
    pub trusted_builder_egress: bool,
    /// Where to write the captured guest console.
    pub console_log: PathBuf,
    /// Where to write this process's PID once booting starts (the backend polls
    /// for it to confirm launch, and reads it to stop/status the VM).
    pub pid_file: PathBuf,
    /// Where to persist the workload exit code (`<state>/workload.exit`, decimal)
    /// when the guest reports it over the workload-exit vsock port — the transient
    /// run-to-exit result the backend's `wait` reads.
    pub workload_exit: PathBuf,
    /// Marker written only after the vCPU has entered the pause hold. The
    /// backend waits for this marker before treating pause as complete.
    #[serde(default)]
    pub pause_state: Option<PathBuf>,
    /// Host-side request file used to ask a paused parent to serialize its
    /// in-process HVF state into the requested RAM file and sibling frame.
    #[serde(default)]
    pub snapshot_request: Option<PathBuf>,
    /// Fixed supervisor-owned raw RAM output for a parent snapshot.
    #[serde(default)]
    pub snapshot_ram: Option<PathBuf>,
    /// Fixed supervisor-owned vCPU/device frame output for a parent snapshot.
    #[serde(default)]
    pub snapshot_frame: Option<PathBuf>,
    /// Raw guest RAM backing file for a restored child. It is mapped private so
    /// child writes never modify the saved parent bytes.
    #[serde(default)]
    pub restore_ram: Option<PathBuf>,
    /// Complete HVF frame containing vCPU and deterministic device state.
    #[serde(default)]
    pub restore_frame: Option<PathBuf>,
    /// Run budget in seconds — a booting kernel never exits on its own, so the
    /// guest is forced out after this long. `0` means no backstop.
    ///
    /// This is **not** the plan's wall-clock bound and never has been: the
    /// workload path sets it from the `MVM_HVF_TIMEOUT` dev env var, which is
    /// unset in normal use. A plan's bound is enforced from [`Self::plan`],
    /// which is audited and exits `124`; this is an unaudited backstop against
    /// a guest that never reports its exit.
    pub timeout_secs: u64,
    /// The admitted `ExecutionPlan` envelope, when the launch carries one. The
    /// supervisor arms the plan's wall-clock bound from it, and refuses to boot
    /// a bounded workload whose kill it could not audit.
    #[serde(default)]
    pub plan: Option<serde_json::Value>,
    /// `~/.mvm/audit/` — where the chain-signed wall-clock kill entry lands.
    #[serde(default)]
    pub audit_dir: Option<PathBuf>,
    /// `~/.mvm/keys/host-signer.ed25519` — the key that chain is signed under.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,
    /// Per-VM host→guest agent RPC socket. The supervisor binds it so host clients
    /// (`machine invoke`) reach the guest agent over vsock. `None` ⇒ no agent
    /// listener (the supervisor falls back to the `MVM_HVF_AGENT_SOCKET` dev hook).
    /// Threading it here is the productionized path off that env hook.
    #[serde(default)]
    pub agent_socket: Option<PathBuf>,
    /// Per-VM substitution-endpoint socket. When set, the supervisor
    /// routes `EGRESS_PORT` to the `mvm-network-endpoint` bound here
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
    /// Per-VM host-services broker UDS. When set, the supervisor wires `BROKER_PORT`
    /// as a pure relay to it — the socket the per-tenant host-agent daemon bound for
    /// this VM — so a guest `host.audit.v1` call reaches the broker exactly as on the
    /// other backends. `None` ⇒ `BROKER_PORT` fails closed (no broker reachable).
    #[serde(default)]
    pub broker_socket: Option<PathBuf>,
    /// Explicit host-dial sockets: dev-only console channels plus any declared
    /// TCP ingress forward channels. An empty list binds no extra guest ports;
    /// sealed production boots therefore expose only explicitly admitted ingress.
    #[serde(default)]
    pub console_data_sockets: Vec<HostDialSocket>,
    /// Builder-tier control sockets: job dispatch and the resident daemon's
    /// typed channel, for a persistent builder VM. Empty for every workload —
    /// a guest that isn't the build engine serves neither port.
    #[serde(default)]
    pub builder_control_sockets: Vec<HostDialSocket>,
    /// Sidecar lock this supervisor must hold for its whole life, conferring
    /// the exclusive right to write the store image its guest attaches.
    ///
    /// Set only by the persistent builder, whose VM outlives the command that
    /// started it. An `flock` dies with the process holding it, so a
    /// CLI-held lock would be released the moment that command exits, leaving
    /// a running VM writing an image another builder is free to attach.
    /// Holding it here ties the lock to the process whose lifetime matches the
    /// VM's. `None` keeps the caller-held arrangement every one-shot path uses,
    /// which is correct there because the caller outlives the VM.
    #[serde(default)]
    pub exclusive_image_lock: Option<PathBuf>,
    /// Fixed supervisor-owned control socket for a live standby handoff.
    /// `None` disables this privileged path for ordinary VMs.
    #[serde(default)]
    pub handoff_socket: Option<PathBuf>,
    /// Trusted VM-state root from which child channel paths are derived.
    #[serde(default)]
    pub handoff_root: Option<PathBuf>,
    /// Hex-encoded host identity key used to authenticate handoff requests.
    #[serde(default)]
    pub handoff_verify_key: Option<String>,
    /// CPU share to enforce via the in-process HVF quota scheduler.
    /// `None` ⇒ no quota (the pre-Plan-327 path).
    #[serde(default)]
    pub cpu_millicores: Option<u32>,
    /// Where the supervisor should write the measured quota record on exit.
    /// `None` ⇒ no record is written.
    #[serde(default)]
    pub quota_record: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_with_all_fields() {
        let cfg = HvfSupervisorConfig {
            kernel: "/k/Image".into(),
            cmdline: Some("console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init".into()),
            memory_mib: 8192,
            vcpus: 1,
            initramfs: Some("/k/initrd.cpio".into()),
            disks: vec![
                HvfDisk {
                    path: "/k/rootfs.ext4".into(),
                    read_only: true,
                    ephemeral: false,
                },
                HvfDisk {
                    path: "/k/nix-store.img".into(),
                    read_only: false,
                    ephemeral: false,
                },
            ],
            virtiofs_root: None,
            virtiofs_shares: vec![],
            vsock: true,
            trusted_builder_egress: false,
            console_log: "/state/console.log".into(),
            pid_file: "/state/hvf.pid".into(),
            workload_exit: "/state/workload.exit".into(),
            pause_state: Some("/state/pause.state".into()),
            snapshot_request: Some("/state/snapshot.request".into()),
            snapshot_ram: Some("/state/snapshot.ram".into()),
            snapshot_frame: Some("/state/snapshot.frame".into()),
            restore_ram: None,
            restore_frame: None,
            timeout_secs: 30,
            plan: None,
            audit_dir: None,
            signing_key_path: None,
            agent_socket: Some("/state/hvf-agent.sock".into()),
            substitution_socket: Some("/state/substitution-endpoint.sock".into()),
            egress_relay_socket: Some("/state/egress-bridge.sock".into()),
            broker_socket: Some("/state/hvf-broker.sock".into()),
            console_data_sockets: vec![],
            builder_control_sockets: vec![],
            exclusive_image_lock: None,
            handoff_socket: Some("/state/handoff.sock".into()),
            handoff_root: Some("/state/vms".into()),
            handoff_verify_key: Some("11".repeat(32)),
            cpu_millicores: Some(500),
            quota_record: Some("/state/quota.json".into()),
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
        assert_eq!(cfg.broker_socket, None);
        assert_eq!(cfg.pause_state, None);
        assert_eq!(cfg.handoff_socket, None);
        assert_eq!(cfg.handoff_root, None);
        assert_eq!(cfg.handoff_verify_key, None);
        assert_eq!(cfg.cpu_millicores, None);
        assert_eq!(cfg.quota_record, None);
    }

    #[test]
    fn optional_fields_default() {
        let json = r#"{"kernel":"/k/Image","console_log":"/c.log","pid_file":"/p.pid","workload_exit":"/w.exit","timeout_secs":5}"#;
        let cfg: HvfSupervisorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.cmdline, None);
        assert_eq!(cfg.initramfs, None);
        assert!(cfg.disks.is_empty());
        assert!(!cfg.vsock);
        assert_eq!(cfg.timeout_secs, 5);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields: a typo'd / unexpected field fails closed.
        let json = r#"{"kernel":"/k","console_log":"/c","pid_file":"/p","workload_exit":"/w","timeout_secs":1,"bogus":1}"#;
        assert!(serde_json::from_str::<HvfSupervisorConfig>(json).is_err());
    }

    #[test]
    fn shutdown_timing_record_roundtrips_strictly() {
        let record = HvfShutdownTimingRecord {
            schema_version: 1,
            watchdog_to_vcpu_exit_micros: 1,
            watchdog_join_micros: 2,
            io_thread_join_micros: 3,
            vcpu_destroy_micros: 4,
            vm_destroy_micros: 5,
            console_write_micros: 6,
            workload_exit_write_micros: 7,
        };
        let json = serde_json::to_vec(&record).expect("serialize shutdown timing");
        assert_eq!(
            serde_json::from_slice::<HvfShutdownTimingRecord>(&json)
                .expect("parse shutdown timing"),
            record
        );
        let mut value = serde_json::to_value(record).expect("timing value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HvfShutdownTimingRecord>(value).is_err());
    }

    #[test]
    fn hvf_supervisor_console_data_sockets_roundtrip() {
        let cfg = HvfSupervisorConfig {
            kernel: "/k/Image".into(),
            cmdline: None,
            memory_mib: 0,
            vcpus: 1,
            initramfs: None,
            disks: vec![],
            virtiofs_root: None,
            virtiofs_shares: vec![],
            vsock: true,
            trusted_builder_egress: false,
            console_log: "/state/console.log".into(),
            pid_file: "/state/hvf.pid".into(),
            workload_exit: "/state/workload.exit".into(),
            pause_state: None,
            snapshot_request: None,
            snapshot_ram: None,
            snapshot_frame: None,
            restore_ram: None,
            restore_frame: None,
            timeout_secs: 30,
            plan: None,
            audit_dir: None,
            signing_key_path: None,
            agent_socket: None,
            substitution_socket: None,
            egress_relay_socket: None,
            broker_socket: None,
            builder_control_sockets: vec![],
            exclusive_image_lock: None,
            console_data_sockets: vec![
                HostDialSocket {
                    guest_port: 20001,
                    host_socket: "/state/vsock/vsock-20001.sock".into(),
                },
                HostDialSocket {
                    guest_port: 20002,
                    host_socket: "/state/vsock/vsock-20002.sock".into(),
                },
            ],
            handoff_socket: None,
            handoff_root: None,
            handoff_verify_key: None,
            cpu_millicores: None,
            quota_record: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: HvfSupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cfg);
        assert_eq!(decoded.console_data_sockets.len(), 2);
        assert_eq!(decoded.console_data_sockets[0].guest_port, 20001);
        assert_eq!(
            decoded.console_data_sockets[0].host_socket,
            PathBuf::from("/state/vsock/vsock-20001.sock")
        );
    }

    #[test]
    fn hvf_supervisor_console_data_sockets_defaults_to_empty() {
        // Configs without console_data_sockets (prod or pre-Task-2 configs) parse
        // to an empty vec — the serde(default) guarantee.
        let json = r#"{"kernel":"/k/Image","console_log":"/c.log","pid_file":"/p.pid","workload_exit":"/w.exit","timeout_secs":5}"#;
        let cfg: HvfSupervisorConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.console_data_sockets.is_empty());
    }

    #[test]
    fn handoff_signature_message_binds_channel_authority() {
        let base = HvfHandoffRequest::signing_message(42, "child", 0b0011);
        let other_pid = HvfHandoffRequest::signing_message(43, "child", 0b0011);
        let other_channels = HvfHandoffRequest::signing_message(42, "child", 0b0111);
        assert_ne!(base, other_pid);
        assert_ne!(base, other_channels);
    }
}
