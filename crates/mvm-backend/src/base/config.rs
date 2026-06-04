use serde::{Deserialize, Serialize};

/// Builder VM name. Carried over from the W7.2 Lima rename
/// (`mvm` → `mvm-builder`); ADR-013 / plan-60 retired Lima itself,
/// but the name still tags any future Linux builder VM (the
/// libkrun-as-Linux-builder follow-up in W7.x.2). The bridge
/// name `br-mvm`, log filter `RUST_LOG=mvm`, path `/var/lib/mvm/`,
/// OCI label `mvm`, and Apple Container guest hostname `mvm-dev`
/// are deliberately *not* this constant — they exist on every host
/// regardless of whether a builder VM is running.
pub const VM_NAME: &str = "mvm-builder";
pub const API_SOCKET: &str = "/tmp/firecracker.socket";
pub const TAP_DEV: &str = "tap0";
pub const TAP_IP: &str = "172.16.0.1";
pub const MASK_SHORT: &str = "/30";
pub const GUEST_IP: &str = "172.16.0.2";
pub const FC_MAC: &str = "06:00:AC:10:00:02";
/// Firecracker assets root. `~` expands against whichever shell
/// runs the script — on Linux+KVM that's the host user; on macOS
/// 26+ it's the Apple Container dev VM's user (commands route
/// through the guest-agent vsock channel). On hosts where neither
/// applies, the Firecracker backend isn't available — every script
/// that would write here fails at the binary-invocation step.
pub const MICROVM_DIR: &str = "~/microvm";

// --- Multi-VM bridge networking ---
pub const BRIDGE_DEV: &str = "br-mvm";
pub const BRIDGE_IP: &str = "172.16.0.1";
pub const BRIDGE_CIDR: &str = "172.16.0.1/24";
/// Per-VM state directory; resolves the same way as [`MICROVM_DIR`].
pub const VMS_DIR: &str = "~/microvm/vms";

/// Per-VM network + filesystem identity, derived from a slot index.
#[derive(Debug, Clone)]
pub struct VmSlot {
    pub name: String,
    pub index: u8,
    pub tap_dev: String,
    pub mac: String,
    pub guest_ip: String,
    pub vm_dir: String,
    pub api_socket: String,
}

impl VmSlot {
    /// Create a slot from a name and 0-based index.
    /// Index N → guest IP 172.16.0.{N+2}, TAP tap{N}.
    pub fn new(name: &str, index: u8) -> Self {
        let ip_octet = index + 2;
        Self {
            name: name.to_string(),
            index,
            tap_dev: format!("tap{}", index),
            mac: format!("06:00:AC:10:00:{:02x}", ip_octet),
            guest_ip: format!("172.16.0.{}", ip_octet),
            vm_dir: format!("{}/{}", VMS_DIR, name),
            api_socket: format!("{}/{}/fc.socket", VMS_DIR, name),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MvmState {
    pub kernel: String,
    pub rootfs: String,
    pub ssh_key: String,
    #[serde(default)]
    pub fc_pid: Option<u32>,
}

/// A host:guest port mapping for port forwarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortMapping {
    /// Port on the host that the user connects to.
    pub host: u16,
    /// Port inside the guest microVM.
    pub guest: u16,
}

/// Run mode info persisted at `~/microvm/.mvm-run-info` so `status` can
/// distinguish dev-mode VMs from flake-built VMs.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RunInfo {
    /// Schema version for forward-compatible migrations.
    #[serde(default)]
    pub schema_version: u32,
    /// "dev" or "flake"
    pub mode: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub flake_ref: Option<String>,
    #[serde(default)]
    pub guest_ip: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    pub guest_user: String,
    pub cpus: u32,
    pub memory: u32,
    /// Declared port mappings (host:guest). Used by `mvmctl forward` when
    /// no explicit port specs are given on the command line.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_non_empty() {
        assert!(!VM_NAME.is_empty());
        assert!(!mvm_core::config::fc_version().is_empty());
        assert!(!mvm_core::config::ARCH.is_empty());
        assert!(!API_SOCKET.is_empty());
        assert!(!TAP_DEV.is_empty());
        assert!(!TAP_IP.is_empty());
        assert!(!GUEST_IP.is_empty());
        assert!(!FC_MAC.is_empty());
        assert!(!BRIDGE_DEV.is_empty());
        assert!(!BRIDGE_IP.is_empty());
        assert!(!BRIDGE_CIDR.is_empty());
        assert!(!VMS_DIR.is_empty());
    }

    #[test]
    fn test_vm_slot_new_index_0() {
        let slot = VmSlot::new("gw", 0);
        assert_eq!(slot.name, "gw");
        assert_eq!(slot.index, 0);
        assert_eq!(slot.tap_dev, "tap0");
        assert_eq!(slot.mac, "06:00:AC:10:00:02");
        assert_eq!(slot.guest_ip, "172.16.0.2");
        assert!(slot.vm_dir.ends_with("/vms/gw"));
        assert!(slot.api_socket.ends_with("/vms/gw/fc.socket"));
    }

    #[test]
    fn test_vm_slot_new_index_1() {
        let slot = VmSlot::new("w1", 1);
        assert_eq!(slot.index, 1);
        assert_eq!(slot.tap_dev, "tap1");
        assert_eq!(slot.mac, "06:00:AC:10:00:03");
        assert_eq!(slot.guest_ip, "172.16.0.3");
    }

    #[test]
    fn test_vm_slot_new_index_10() {
        let slot = VmSlot::new("worker-10", 10);
        assert_eq!(slot.tap_dev, "tap10");
        assert_eq!(slot.mac, "06:00:AC:10:00:0c");
        assert_eq!(slot.guest_ip, "172.16.0.12");
    }

    #[test]
    fn test_fc_version_starts_with_v() {
        assert!(
            mvm_core::config::fc_version().starts_with('v'),
            "FC_VERSION should start with 'v'"
        );
    }

    #[test]
    fn test_ip_addresses_are_in_same_subnet() {
        // TAP_IP and GUEST_IP should share the 172.16.0.x prefix
        assert!(TAP_IP.starts_with("172.16.0."));
        assert!(GUEST_IP.starts_with("172.16.0."));
    }

    #[test]
    fn test_mvm_state_json_roundtrip() {
        let state = MvmState {
            kernel: "vmlinux-5.10.217".to_string(),
            rootfs: "ubuntu-24.04.ext4".to_string(),
            ssh_key: "ubuntu-24.04.id_rsa".to_string(),
            fc_pid: Some(12345),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: MvmState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.kernel, "vmlinux-5.10.217");
        assert_eq!(parsed.rootfs, "ubuntu-24.04.ext4");
        assert_eq!(parsed.ssh_key, "ubuntu-24.04.id_rsa");
        assert_eq!(parsed.fc_pid, Some(12345));
    }

    #[test]
    fn test_mvm_state_json_without_pid() {
        let json = r#"{"kernel":"k","rootfs":"r","ssh_key":"s"}"#;
        let state: MvmState = serde_json::from_str(json).unwrap();
        assert_eq!(state.fc_pid, None);
    }

    #[test]
    fn test_mvm_state_default() {
        let state = MvmState::default();
        assert!(state.kernel.is_empty());
        assert!(state.rootfs.is_empty());
        assert!(state.ssh_key.is_empty());
        assert_eq!(state.fc_pid, None);
    }

    #[test]
    fn test_port_mapping_serde_roundtrip() {
        let pm = PortMapping {
            host: 3333,
            guest: 3000,
        };
        let json = serde_json::to_string(&pm).unwrap();
        let parsed: PortMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pm);
    }

    #[test]
    fn test_run_info_json_roundtrip() {
        let info = RunInfo {
            schema_version: 1,
            mode: "flake".to_string(),
            name: Some("gw".to_string()),
            revision: Some("abc123".to_string()),
            flake_ref: Some("/home/user/project".to_string()),
            guest_ip: Some("172.16.0.2".to_string()),
            profile: Some("gateway".to_string()),
            guest_user: "root".to_string(),
            cpus: 4,
            memory: 2048,
            ports: vec![
                PortMapping {
                    host: 3333,
                    guest: 3000,
                },
                PortMapping {
                    host: 3334,
                    guest: 3002,
                },
            ],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: RunInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, "flake");
        assert_eq!(parsed.name.as_deref(), Some("gw"));
        assert_eq!(parsed.revision.as_deref(), Some("abc123"));
        assert_eq!(parsed.flake_ref.as_deref(), Some("/home/user/project"));
        assert_eq!(parsed.guest_ip.as_deref(), Some("172.16.0.2"));
        assert_eq!(parsed.profile.as_deref(), Some("gateway"));
        assert_eq!(parsed.guest_user, "root");
        assert_eq!(parsed.cpus, 4);
        assert_eq!(parsed.memory, 2048);
        assert_eq!(parsed.ports.len(), 2);
        assert_eq!(parsed.ports[0].host, 3333);
        assert_eq!(parsed.ports[0].guest, 3000);
    }

    #[test]
    fn test_run_info_default() {
        let info = RunInfo::default();
        assert!(info.mode.is_empty());
        assert!(info.name.is_none());
        assert!(info.revision.is_none());
        assert!(info.flake_ref.is_none());
        assert!(info.guest_ip.is_none());
        assert!(info.profile.is_none());
        assert!(info.guest_user.is_empty());
        assert_eq!(info.cpus, 0);
        assert_eq!(info.memory, 0);
        assert!(info.ports.is_empty());
    }

    #[test]
    fn test_run_info_minimal_json() {
        let json = r#"{"mode":"dev","guest_user":"mvm","cpus":2,"memory":1024}"#;
        let info: RunInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.mode, "dev");
        assert!(info.revision.is_none());
        assert!(info.flake_ref.is_none());
        assert!(
            info.ports.is_empty(),
            "missing ports field should default to empty vec"
        );
    }

    #[test]
    fn test_production_mode_disabled_by_default() {
        // Without env var set, should be false
        unsafe { std::env::remove_var("MVM_PRODUCTION") };
        assert!(!mvm_core::config::is_production_mode());
    }
}
