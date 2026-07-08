//! Guest-side transparent networking bridge configuration.
//!
//! This module is intentionally a dependency-light planning layer. It defines
//! the synthetic network shape and the ordered operations the Linux guest
//! bridge executor must perform, without pulling TUN, netlink, async runtimes,
//! or packet stacks into the default crate build.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Well-known guest-to-host vsock port for transparent networking.
///
/// The guest bridge opens this single stream to the host authority. DNS, TCP,
/// UDP, ICMP echo, TLS transforms, audit correlation, and plugin events all
/// multiplex over the protocol frames from [`crate::proto`].
pub const TRANSPARENT_NET_VSOCK_PORT: u32 = 5254;

pub const DEFAULT_TUN_NAME: &str = "mvmnet0";
pub const DEFAULT_GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const DEFAULT_HOST_GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub const DEFAULT_LINK_PREFIX: u8 = 30;
pub const DEFAULT_SYNTHETIC_POOL: Ipv4Cidr =
    Ipv4Cidr::new_unchecked(Ipv4Addr::new(198, 19, 0, 0), 16);
pub const DEFAULT_RESOLV_CONF: &str = "/etc/resolv.conf";
pub const DEFAULT_RESOLV_BACKUP: &str = "/run/mvm/resolv.conf.mvm-net.backup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestBridgeError {
    EmptyInterfaceName,
    InterfaceNameTooLong { name: String, max_bytes: usize },
    InvalidInterfaceName { name: String },
    InvalidPrefix { prefix: u8 },
    GatewayOutsideLink { gateway: Ipv4Addr, link: Ipv4Cidr },
    GuestAddressOutsideLink { address: Ipv4Addr, link: Ipv4Cidr },
    GatewayEqualsGuest { address: Ipv4Addr },
    ZeroVsockPort,
    EmptyPath { field: &'static str },
}

impl fmt::Display for GuestBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInterfaceName => write!(f, "interface name cannot be empty"),
            Self::InterfaceNameTooLong { name, max_bytes } => write!(
                f,
                "interface name {name:?} exceeds Linux interface limit of {max_bytes} bytes"
            ),
            Self::InvalidInterfaceName { name } => {
                write!(f, "interface name {name:?} contains unsupported characters")
            }
            Self::InvalidPrefix { prefix } => {
                write!(f, "IPv4 CIDR prefix {prefix} is outside 0..=32")
            }
            Self::GatewayOutsideLink { gateway, link } => {
                write!(f, "gateway {gateway} is outside bridge link {link}")
            }
            Self::GuestAddressOutsideLink { address, link } => {
                write!(f, "guest address {address} is outside bridge link {link}")
            }
            Self::GatewayEqualsGuest { address } => {
                write!(
                    f,
                    "gateway and guest address must differ, both were {address}"
                )
            }
            Self::ZeroVsockPort => write!(f, "transparent network vsock port cannot be zero"),
            Self::EmptyPath { field } => write!(f, "{field} path cannot be empty"),
        }
    }
}

impl std::error::Error for GuestBridgeError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName(String);

impl InterfaceName {
    const MAX_BYTES: usize = 15;

    pub fn new(name: impl Into<String>) -> Result<Self, GuestBridgeError> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(GuestBridgeError::EmptyInterfaceName);
        }
        if name.len() > Self::MAX_BYTES {
            return Err(GuestBridgeError::InterfaceNameTooLong {
                name,
                max_bytes: Self::MAX_BYTES,
            });
        }
        if !name.bytes().all(valid_interface_name_byte) {
            return Err(GuestBridgeError::InvalidInterfaceName { name });
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_interface_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self, GuestBridgeError> {
        if prefix > 32 {
            return Err(GuestBridgeError::InvalidPrefix { prefix });
        }
        Ok(Self {
            network: mask_addr(network, prefix),
            prefix,
        })
    }

    const fn new_unchecked(network: Ipv4Addr, prefix: u8) -> Self {
        Self { network, prefix }
    }

    pub const fn network(self) -> Ipv4Addr {
        self.network
    }

    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    pub fn contains(self, address: Ipv4Addr) -> bool {
        mask_addr(address, self.prefix) == self.network
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn mask_addr(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from(address);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits & mask)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBridgeConfig {
    tun_name: InterfaceName,
    guest_address: Ipv4Addr,
    host_gateway: Ipv4Addr,
    link: Ipv4Cidr,
    synthetic_pool: Ipv4Cidr,
    resolv_conf: PathBuf,
    resolv_backup: PathBuf,
    vsock_port: u32,
}

impl GuestBridgeConfig {
    pub fn builder() -> GuestBridgeConfigBuilder {
        GuestBridgeConfigBuilder::default()
    }

    pub fn tun_name(&self) -> &InterfaceName {
        &self.tun_name
    }

    pub const fn guest_address(&self) -> Ipv4Addr {
        self.guest_address
    }

    pub const fn host_gateway(&self) -> Ipv4Addr {
        self.host_gateway
    }

    pub const fn link(&self) -> Ipv4Cidr {
        self.link
    }

    pub const fn synthetic_pool(&self) -> Ipv4Cidr {
        self.synthetic_pool
    }

    pub fn resolv_conf(&self) -> &Path {
        &self.resolv_conf
    }

    pub fn resolv_backup(&self) -> &Path {
        &self.resolv_backup
    }

    pub const fn vsock_port(&self) -> u32 {
        self.vsock_port
    }

    pub fn operation_plan(&self) -> Vec<GuestBridgeOperation> {
        vec![
            GuestBridgeOperation::OpenTun {
                name: self.tun_name.clone(),
            },
            GuestBridgeOperation::AssignAddress {
                name: self.tun_name.clone(),
                address: self.guest_address,
                link: self.link,
            },
            GuestBridgeOperation::BringInterfaceUp {
                name: self.tun_name.clone(),
            },
            GuestBridgeOperation::InstallDefaultRoute {
                name: self.tun_name.clone(),
                gateway: self.host_gateway,
            },
            GuestBridgeOperation::WriteResolver {
                path: self.resolv_conf.clone(),
                backup_path: self.resolv_backup.clone(),
                nameserver: self.host_gateway,
            },
            GuestBridgeOperation::ConnectVsockAuthority {
                port: self.vsock_port,
            },
        ]
    }
}

impl Default for GuestBridgeConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default guest bridge config is valid")
    }
}

#[derive(Debug, Clone)]
pub struct GuestBridgeConfigBuilder {
    tun_name: String,
    guest_address: Ipv4Addr,
    host_gateway: Ipv4Addr,
    link: Ipv4Cidr,
    synthetic_pool: Ipv4Cidr,
    resolv_conf: PathBuf,
    resolv_backup: PathBuf,
    vsock_port: u32,
}

impl Default for GuestBridgeConfigBuilder {
    fn default() -> Self {
        Self {
            tun_name: DEFAULT_TUN_NAME.to_string(),
            guest_address: DEFAULT_GUEST_ADDRESS,
            host_gateway: DEFAULT_HOST_GATEWAY,
            link: Ipv4Cidr::new(DEFAULT_GUEST_ADDRESS, DEFAULT_LINK_PREFIX)
                .expect("default link prefix is valid"),
            synthetic_pool: DEFAULT_SYNTHETIC_POOL,
            resolv_conf: PathBuf::from(DEFAULT_RESOLV_CONF),
            resolv_backup: PathBuf::from(DEFAULT_RESOLV_BACKUP),
            vsock_port: TRANSPARENT_NET_VSOCK_PORT,
        }
    }
}

impl GuestBridgeConfigBuilder {
    pub fn tun_name(mut self, tun_name: impl Into<String>) -> Self {
        self.tun_name = tun_name.into();
        self
    }

    pub fn guest_address(mut self, guest_address: Ipv4Addr) -> Self {
        self.guest_address = guest_address;
        self
    }

    pub fn host_gateway(mut self, host_gateway: Ipv4Addr) -> Self {
        self.host_gateway = host_gateway;
        self
    }

    pub fn link(mut self, link: Ipv4Cidr) -> Self {
        self.link = link;
        self
    }

    pub fn synthetic_pool(mut self, synthetic_pool: Ipv4Cidr) -> Self {
        self.synthetic_pool = synthetic_pool;
        self
    }

    pub fn resolv_conf(mut self, resolv_conf: impl Into<PathBuf>) -> Self {
        self.resolv_conf = resolv_conf.into();
        self
    }

    pub fn resolv_backup(mut self, resolv_backup: impl Into<PathBuf>) -> Self {
        self.resolv_backup = resolv_backup.into();
        self
    }

    pub fn vsock_port(mut self, vsock_port: u32) -> Self {
        self.vsock_port = vsock_port;
        self
    }

    pub fn build(self) -> Result<GuestBridgeConfig, GuestBridgeError> {
        if self.vsock_port == 0 {
            return Err(GuestBridgeError::ZeroVsockPort);
        }
        if !self.link.contains(self.guest_address) {
            return Err(GuestBridgeError::GuestAddressOutsideLink {
                address: self.guest_address,
                link: self.link,
            });
        }
        if !self.link.contains(self.host_gateway) {
            return Err(GuestBridgeError::GatewayOutsideLink {
                gateway: self.host_gateway,
                link: self.link,
            });
        }
        if self.guest_address == self.host_gateway {
            return Err(GuestBridgeError::GatewayEqualsGuest {
                address: self.guest_address,
            });
        }
        if path_is_empty(&self.resolv_conf) {
            return Err(GuestBridgeError::EmptyPath {
                field: "resolv.conf",
            });
        }
        if path_is_empty(&self.resolv_backup) {
            return Err(GuestBridgeError::EmptyPath {
                field: "resolv.conf backup",
            });
        }
        Ok(GuestBridgeConfig {
            tun_name: InterfaceName::new(self.tun_name)?,
            guest_address: self.guest_address,
            host_gateway: self.host_gateway,
            link: self.link,
            synthetic_pool: self.synthetic_pool,
            resolv_conf: self.resolv_conf,
            resolv_backup: self.resolv_backup,
            vsock_port: self.vsock_port,
        })
    }
}

fn path_is_empty(path: &Path) -> bool {
    path.as_os_str().is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestBridgeOperation {
    OpenTun {
        name: InterfaceName,
    },
    AssignAddress {
        name: InterfaceName,
        address: Ipv4Addr,
        link: Ipv4Cidr,
    },
    BringInterfaceUp {
        name: InterfaceName,
    },
    InstallDefaultRoute {
        name: InterfaceName,
        gateway: Ipv4Addr,
    },
    WriteResolver {
        path: PathBuf,
        backup_path: PathBuf,
        nameserver: Ipv4Addr,
    },
    ConnectVsockAuthority {
        port: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_rfc2544_synthetic_and_vsock_only() {
        let cfg = GuestBridgeConfig::default();
        assert_eq!(cfg.tun_name().as_str(), DEFAULT_TUN_NAME);
        assert_eq!(cfg.guest_address(), Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(cfg.host_gateway(), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(cfg.link().to_string(), "198.18.0.0/30");
        assert_eq!(cfg.synthetic_pool().to_string(), "198.19.0.0/16");
        assert_eq!(cfg.vsock_port(), TRANSPARENT_NET_VSOCK_PORT);
    }

    #[test]
    fn operation_plan_orders_network_before_vsock() {
        let cfg = GuestBridgeConfig::default();
        let plan = cfg.operation_plan();
        assert_eq!(plan.len(), 6);
        assert!(matches!(plan[0], GuestBridgeOperation::OpenTun { .. }));
        assert!(matches!(
            plan[1],
            GuestBridgeOperation::AssignAddress { .. }
        ));
        assert!(matches!(
            plan[2],
            GuestBridgeOperation::BringInterfaceUp { .. }
        ));
        assert!(matches!(
            plan[3],
            GuestBridgeOperation::InstallDefaultRoute { .. }
        ));
        assert!(matches!(
            plan[4],
            GuestBridgeOperation::WriteResolver { .. }
        ));
        assert!(matches!(
            plan[5],
            GuestBridgeOperation::ConnectVsockAuthority {
                port: TRANSPARENT_NET_VSOCK_PORT
            }
        ));
    }

    #[test]
    fn interface_name_validation_matches_linux_safe_subset() {
        assert_eq!(
            InterfaceName::new("mvm-net_0").unwrap().as_str(),
            "mvm-net_0"
        );
        assert!(matches!(
            InterfaceName::new(" "),
            Err(GuestBridgeError::EmptyInterfaceName)
        ));
        assert!(matches!(
            InterfaceName::new("bad/name"),
            Err(GuestBridgeError::InvalidInterfaceName { .. })
        ));
        assert!(matches!(
            InterfaceName::new("a".repeat(16)),
            Err(GuestBridgeError::InterfaceNameTooLong { .. })
        ));
    }

    #[test]
    fn cidr_masks_network_and_checks_membership() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(198, 18, 0, 2), 30).unwrap();
        assert_eq!(cidr.network(), Ipv4Addr::new(198, 18, 0, 0));
        assert!(cidr.contains(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(cidr.contains(Ipv4Addr::new(198, 18, 0, 2)));
        assert!(!cidr.contains(Ipv4Addr::new(198, 18, 0, 4)));
        assert!(matches!(
            Ipv4Cidr::new(Ipv4Addr::new(198, 18, 0, 0), 33),
            Err(GuestBridgeError::InvalidPrefix { prefix: 33 })
        ));
    }

    #[test]
    fn builder_rejects_inconsistent_networks() {
        let link = Ipv4Cidr::new(Ipv4Addr::new(198, 18, 0, 0), 30).unwrap();
        assert!(matches!(
            GuestBridgeConfig::builder()
                .link(link)
                .guest_address(Ipv4Addr::new(198, 18, 0, 4))
                .build(),
            Err(GuestBridgeError::GuestAddressOutsideLink { .. })
        ));
        assert!(matches!(
            GuestBridgeConfig::builder()
                .link(link)
                .host_gateway(Ipv4Addr::new(198, 18, 0, 4))
                .build(),
            Err(GuestBridgeError::GatewayOutsideLink { .. })
        ));
        assert!(matches!(
            GuestBridgeConfig::builder()
                .guest_address(Ipv4Addr::new(198, 18, 0, 1))
                .host_gateway(Ipv4Addr::new(198, 18, 0, 1))
                .build(),
            Err(GuestBridgeError::GatewayEqualsGuest { .. })
        ));
    }

    #[test]
    fn builder_rejects_zero_port_and_empty_paths() {
        assert!(matches!(
            GuestBridgeConfig::builder().vsock_port(0).build(),
            Err(GuestBridgeError::ZeroVsockPort)
        ));
        assert!(matches!(
            GuestBridgeConfig::builder().resolv_conf("").build(),
            Err(GuestBridgeError::EmptyPath {
                field: "resolv.conf"
            })
        ));
        assert!(matches!(
            GuestBridgeConfig::builder().resolv_backup("").build(),
            Err(GuestBridgeError::EmptyPath {
                field: "resolv.conf backup"
            })
        ));
    }
}
