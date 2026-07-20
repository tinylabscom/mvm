use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// IPv4 prefix (first three octets) shared by every address in the built-in
/// dev subnet. Per-slot guest addresses append a host octet to this.
pub const DEFAULT_SUBNET_PREFIX: &str = "172.16.0";
/// The built-in dev subnet in CIDR notation.
pub const DEFAULT_SUBNET_CIDR: &str = "172.16.0.0/24";
/// Gateway (first usable) address of the built-in dev subnet.
pub const DEFAULT_GATEWAY_IP: &str = "172.16.0.1";
/// Gateway address of the built-in dev subnet in CIDR notation.
pub const DEFAULT_GATEWAY_CIDR: &str = "172.16.0.1/24";
/// Default guest address (network slot 0) of the built-in dev subnet.
pub const DEFAULT_GUEST_IP: &str = "172.16.0.2";

/// Per-slot guest IP in the built-in dev subnet. The host octet is `index + 2`
/// (slot 0 → `.2`), so the gateway (`.1`) is never handed to a guest.
pub fn default_guest_ip_for_index(index: u8) -> String {
    format!("{DEFAULT_SUBNET_PREFIX}.{}", index + 2)
}

/// A named dev-mode network with its own bridge and subnet.
///
/// Stored as JSON files in `{mvm_share_dir}/networks/<name>.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevNetwork {
    /// User-facing network name (e.g. "default", "isolated").
    pub name: String,
    /// Linux bridge device name (e.g. "br-mvm-default").
    pub bridge_name: String,
    /// Subnet CIDR (e.g. "172.16.0.0/24").
    pub subnet: String,
    /// Gateway IP — first usable address (e.g. "172.16.0.1").
    pub gateway: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

impl DevNetwork {
    /// The built-in default network, matching the legacy hardcoded bridge.
    pub fn default_network() -> Self {
        Self {
            name: "default".to_string(),
            bridge_name: "br-mvm".to_string(),
            subnet: DEFAULT_SUBNET_CIDR.to_string(),
            gateway: DEFAULT_GATEWAY_IP.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a new named network with an auto-assigned subnet.
    ///
    /// `slot` is a 1-based index used to derive a unique 172.16.X.0/24 subnet.
    /// Slot 0 is reserved for the default network.
    pub fn new(name: &str, slot: u8) -> Result<Self> {
        validate_network_name(name)?;
        if slot == 0 {
            bail!("slot 0 is reserved for the default network");
        }
        Ok(Self {
            name: name.to_string(),
            bridge_name: format!("br-mvm-{name}"),
            subnet: format!("172.16.{slot}.0/24"),
            gateway: format!("172.16.{slot}.1"),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// CIDR notation for the gateway (e.g. "172.16.0.1/24").
    pub fn gateway_cidr(&self) -> String {
        let prefix = self.subnet.split('/').nth(1).unwrap_or("24");
        format!("{}/{prefix}", self.gateway)
    }
}

/// Validate a network name: lowercase alphanumeric + hyphens, 1-63 chars.
pub fn validate_network_name(name: &str) -> Result<()> {
    crate::naming::validate_id(name, "network name")
}

/// Directory where network definitions are stored.
pub fn networks_dir() -> String {
    format!("{}/networks", crate::config::mvm_share_dir())
}

/// Path to a specific network definition file.
pub fn network_path(name: &str) -> String {
    format!("{}/{name}.json", networks_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_network() {
        let net = DevNetwork::default_network();
        assert_eq!(net.name, "default");
        assert_eq!(net.bridge_name, "br-mvm");
        assert_eq!(net.subnet, "172.16.0.0/24");
        assert_eq!(net.gateway, "172.16.0.1");
        assert!(!net.created_at.is_empty());
    }

    #[test]
    fn test_new_network() {
        let net = DevNetwork::new("isolated", 1).unwrap();
        assert_eq!(net.name, "isolated");
        assert_eq!(net.bridge_name, "br-mvm-isolated");
        assert_eq!(net.subnet, "172.16.1.0/24");
        assert_eq!(net.gateway, "172.16.1.1");
    }

    #[test]
    fn test_new_network_slot_0_rejected() {
        assert!(DevNetwork::new("bad", 0).is_err());
    }

    #[test]
    fn test_gateway_cidr() {
        let net = DevNetwork::default_network();
        assert_eq!(net.gateway_cidr(), "172.16.0.1/24");

        let net2 = DevNetwork::new("test", 5).unwrap();
        assert_eq!(net2.gateway_cidr(), "172.16.5.1/24");
    }

    #[test]
    fn test_serde_roundtrip() {
        let net = DevNetwork::new("mynet", 3).unwrap();
        let json = serde_json::to_string(&net).unwrap();
        let parsed: DevNetwork = serde_json::from_str(&json).unwrap();
        assert_eq!(net, parsed);
    }

    #[test]
    fn test_validate_network_name() {
        assert!(validate_network_name("default").is_ok());
        assert!(validate_network_name("my-net-1").is_ok());
        assert!(validate_network_name("").is_err());
        assert!(validate_network_name("UPPER").is_err());
        assert!(validate_network_name("-leading").is_err());
    }

    #[test]
    fn test_network_path() {
        let path = network_path("default");
        assert!(path.ends_with("/networks/default.json"));
    }

    #[test]
    fn default_consts_agree_with_default_network() {
        let net = DevNetwork::default_network();
        assert_eq!(net.subnet, DEFAULT_SUBNET_CIDR);
        assert_eq!(net.gateway, DEFAULT_GATEWAY_IP);
        assert_eq!(net.gateway_cidr(), DEFAULT_GATEWAY_CIDR);
    }

    #[test]
    fn default_guest_ip_for_index_matches_slot_zero_const() {
        assert_eq!(default_guest_ip_for_index(0), DEFAULT_GUEST_IP);
        assert_eq!(default_guest_ip_for_index(1), "172.16.0.3");
        assert_eq!(default_guest_ip_for_index(10), "172.16.0.12");
    }
}
