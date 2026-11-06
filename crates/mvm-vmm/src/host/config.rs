use serde::{Deserialize, Serialize};

/// Builder VM name. Carried over from the Lima rename
/// (`mvm` → `mvm-builder`); Lima itself is retired, but the name
/// still tags any future Linux builder VM (the libkrun-as-Linux-builder
/// follow-up). The bridge name `br-mvm`, log filter `RUST_LOG=mvm`,
/// path `/var/lib/mvm/`, OCI label `mvm`, and Apple Container guest
/// hostname `mvm-dev` are deliberately *not* this constant — they exist
/// on every host regardless of whether a builder VM is running.
pub const VM_NAME: &str = "mvm-builder";
/// Firecracker assets root. `~` expands against whichever shell
/// runs the script — on Linux+KVM that's the host user; on macOS
/// 26+ it's the Apple Container dev VM's user (commands route
/// through the guest-agent vsock channel). On hosts where neither
/// applies, the Firecracker backend isn't available — every script
/// that would write here fails at the binary-invocation step.
pub const MICROVM_DIR: &str = "~/microvm";

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
    /// Index N → guest IP at host octet N+2 in the dev subnet, TAP tap{N}.
    /// `vm_dir` / `api_socket` live in the per-VM directory under the
    /// single mvm root (`mvm_core::config::vms_dir()`), as absolute paths.
    pub fn new(name: &str, index: u8) -> Self {
        let ip_octet = index + 2;
        let vm_dir = mvm_core::config::vm_state_dir(name);
        Self {
            name: name.to_string(),
            index,
            tap_dev: format!("tap{}", index),
            mac: format!("06:00:AC:10:00:{:02x}", ip_octet),
            guest_ip: mvm_core::dev_network::default_guest_ip_for_index(index),
            api_socket: vm_dir.join("fc.socket").display().to_string(),
            vm_dir: vm_dir.display().to_string(),
        }
    }
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
    use mvm_core::util::test_env::TestEnv;

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
        let mut env = TestEnv::new();
        env.remove("MVM_PRODUCTION");
        assert!(!mvm_core::config::is_production_mode());
    }
}
