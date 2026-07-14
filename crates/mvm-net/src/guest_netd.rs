//! Entry-point support for the Linux guest transparent networking daemon.
//!
//! The binary wrapper stays tiny; this module owns manual argument/env parsing
//! so the guest daemon does not pull a CLI framework into the runtime closure.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::guest::{GuestBridgeConfig, GuestBridgeError, Ipv4Cidr};
use crate::guest_linux::{
    LinuxGuestBridgeRunError, LinuxGuestBridgeRunnerConfig, run_linux_guest_bridge,
};
use crate::guest_pump::{GuestPumpError, GuestPumpLoopConfig, GuestPumpRunStats};
use crate::wire_json::{JsonWireConfig, JsonWireError};

pub const ENV_TUN_NAME: &str = "MVM_NET_TUN_NAME";
pub const ENV_GUEST_ADDRESS: &str = "MVM_NET_GUEST_ADDRESS";
pub const ENV_HOST_GATEWAY: &str = "MVM_NET_HOST_GATEWAY";
pub const ENV_LINK_CIDR: &str = "MVM_NET_LINK_CIDR";
pub const ENV_SYNTHETIC_POOL_CIDR: &str = "MVM_NET_SYNTHETIC_POOL_CIDR";
pub const ENV_RESOLV_CONF: &str = "MVM_NET_RESOLV_CONF";
pub const ENV_RESOLV_BACKUP: &str = "MVM_NET_RESOLV_BACKUP";
pub const ENV_VSOCK_PORT: &str = "MVM_NET_VSOCK_PORT";
pub const ENV_MAX_TUN_PACKET_BYTES: &str = "MVM_NET_MAX_TUN_PACKET_BYTES";
pub const ENV_MAX_AUTHORITY_MESSAGES_PER_TICK: &str = "MVM_NET_MAX_AUTHORITY_MESSAGES_PER_TICK";
pub const ENV_MAX_WIRE_FRAME_BYTES: &str = "MVM_NET_MAX_WIRE_FRAME_BYTES";
pub const ENV_IDLE_POLL_TIMEOUT_MILLIS: &str = "MVM_NET_IDLE_POLL_TIMEOUT_MILLIS";
pub const ENV_WRITE_POLL_TIMEOUT_MILLIS: &str = "MVM_NET_WRITE_POLL_TIMEOUT_MILLIS";

const USAGE: &str = "\
mvm-guest-netd [OPTIONS]

Guest transparent networking daemon. It configures the Linux TUN bridge and
pumps guest packets over the host vsock networking authority.

Options:
  --tun-name NAME
  --guest-address IPV4
  --host-gateway IPV4
  --link-cidr IPV4/PREFIX
  --synthetic-pool-cidr IPV4/PREFIX
  --resolv-conf PATH
  --resolv-backup PATH
  --vsock-port PORT
  --max-tun-packet-bytes BYTES
  --max-authority-messages-per-tick COUNT
  --max-wire-frame-bytes BYTES
  --idle-poll-timeout-ms MILLIS
  --write-poll-timeout-ms MILLIS
  -h, --help

Environment:
  MVM_NET_TUN_NAME
  MVM_NET_GUEST_ADDRESS
  MVM_NET_HOST_GATEWAY
  MVM_NET_LINK_CIDR
  MVM_NET_SYNTHETIC_POOL_CIDR
  MVM_NET_RESOLV_CONF
  MVM_NET_RESOLV_BACKUP
  MVM_NET_VSOCK_PORT
  MVM_NET_MAX_TUN_PACKET_BYTES
  MVM_NET_MAX_AUTHORITY_MESSAGES_PER_TICK
  MVM_NET_MAX_WIRE_FRAME_BYTES
  MVM_NET_IDLE_POLL_TIMEOUT_MILLIS
  MVM_NET_WRITE_POLL_TIMEOUT_MILLIS

Command-line options override environment values.
";

#[derive(Debug)]
pub enum GuestNetdError {
    HelpRequested,
    UnknownArgument(String),
    MissingValue(String),
    InvalidValue {
        field: &'static str,
        value: String,
        reason: String,
    },
    BridgeConfig(GuestBridgeError),
    PumpConfig(GuestPumpError),
    WireConfig(JsonWireError),
    RunnerConfig(LinuxGuestBridgeRunError),
    Runtime(LinuxGuestBridgeRunError),
}

impl fmt::Display for GuestNetdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested => write!(f, "{USAGE}"),
            Self::UnknownArgument(arg) => write!(f, "unknown argument {arg:?}"),
            Self::MissingValue(arg) => write!(f, "missing value for {arg}"),
            Self::InvalidValue {
                field,
                value,
                reason,
            } => write!(f, "invalid value {value:?} for {field}: {reason}"),
            Self::BridgeConfig(err) => write!(f, "invalid bridge config: {err}"),
            Self::PumpConfig(err) => write!(f, "invalid pump config: {err}"),
            Self::WireConfig(err) => write!(f, "invalid wire config: {err}"),
            Self::RunnerConfig(err) => write!(f, "invalid runner config: {err}"),
            Self::Runtime(err) => write!(f, "guest network daemon failed: {err}"),
        }
    }
}

impl std::error::Error for GuestNetdError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestNetdConfig {
    bridge_config: GuestBridgeConfig,
    runner_config: LinuxGuestBridgeRunnerConfig,
}

impl GuestNetdConfig {
    pub fn bridge_config(&self) -> &GuestBridgeConfig {
        &self.bridge_config
    }

    pub fn runner_config(&self) -> &LinuxGuestBridgeRunnerConfig {
        &self.runner_config
    }
}

pub fn usage() -> &'static str {
    USAGE
}

pub fn config_from_args_and_env<Args, Arg, Env, Key, Value>(
    args: Args,
    env: Env,
) -> Result<GuestNetdConfig, GuestNetdError>
where
    Args: IntoIterator<Item = Arg>,
    Arg: Into<String>,
    Env: IntoIterator<Item = (Key, Value)>,
    Key: AsRef<str>,
    Value: Into<String>,
{
    let mut options = GuestNetdOptions::default();
    for (key, value) in env {
        if let Some(option) = GuestNetdOption::from_env(key.as_ref()) {
            options.apply(option, value.into())?;
        }
    }
    options.apply_args(args)?;
    options.build()
}

pub fn run_guest_netd(config: GuestNetdConfig) -> Result<GuestPumpRunStats, GuestNetdError> {
    run_linux_guest_bridge(&config.bridge_config, config.runner_config)
        .map_err(GuestNetdError::Runtime)
}

#[derive(Debug, Default)]
struct GuestNetdOptions {
    tun_name: Option<String>,
    guest_address: Option<Ipv4Addr>,
    host_gateway: Option<Ipv4Addr>,
    link: Option<Ipv4Cidr>,
    synthetic_pool: Option<Ipv4Cidr>,
    resolv_conf: Option<PathBuf>,
    resolv_backup: Option<PathBuf>,
    vsock_port: Option<u32>,
    max_tun_packet_bytes: Option<usize>,
    max_authority_messages_per_tick: Option<usize>,
    max_wire_frame_bytes: Option<usize>,
    idle_poll_timeout_millis: Option<i32>,
    write_poll_timeout_millis: Option<i32>,
}

impl GuestNetdOptions {
    fn apply_args<Args, Arg>(&mut self, args: Args) -> Result<(), GuestNetdError>
    where
        Args: IntoIterator<Item = Arg>,
        Arg: Into<String>,
    {
        let mut args = args.into_iter().map(Into::into).peekable();
        while let Some(arg) = args.next() {
            if arg == "-h" || arg == "--help" {
                return Err(GuestNetdError::HelpRequested);
            }
            let (flag, value) = split_arg_value(arg, &mut args)?;
            let option = GuestNetdOption::from_flag(&flag)
                .ok_or_else(|| GuestNetdError::UnknownArgument(flag.clone()))?;
            self.apply(option, value)?;
        }
        Ok(())
    }

    fn apply(&mut self, option: GuestNetdOption, value: String) -> Result<(), GuestNetdError> {
        match option {
            GuestNetdOption::TunName => self.tun_name = Some(value),
            GuestNetdOption::GuestAddress => {
                self.guest_address = Some(parse_ipv4(option.field(), &value)?);
            }
            GuestNetdOption::HostGateway => {
                self.host_gateway = Some(parse_ipv4(option.field(), &value)?);
            }
            GuestNetdOption::LinkCidr => {
                self.link = Some(parse_cidr(option.field(), &value)?);
            }
            GuestNetdOption::SyntheticPoolCidr => {
                self.synthetic_pool = Some(parse_cidr(option.field(), &value)?);
            }
            GuestNetdOption::ResolvConf => self.resolv_conf = Some(PathBuf::from(value)),
            GuestNetdOption::ResolvBackup => self.resolv_backup = Some(PathBuf::from(value)),
            GuestNetdOption::VsockPort => {
                self.vsock_port = Some(parse_u32(option.field(), &value)?);
            }
            GuestNetdOption::MaxTunPacketBytes => {
                self.max_tun_packet_bytes = Some(parse_usize(option.field(), &value)?);
            }
            GuestNetdOption::MaxAuthorityMessagesPerTick => {
                self.max_authority_messages_per_tick = Some(parse_usize(option.field(), &value)?);
            }
            GuestNetdOption::MaxWireFrameBytes => {
                self.max_wire_frame_bytes = Some(parse_usize(option.field(), &value)?);
            }
            GuestNetdOption::IdlePollTimeoutMillis => {
                self.idle_poll_timeout_millis = Some(parse_i32(option.field(), &value)?);
            }
            GuestNetdOption::WritePollTimeoutMillis => {
                self.write_poll_timeout_millis = Some(parse_i32(option.field(), &value)?);
            }
        }
        Ok(())
    }

    fn build(self) -> Result<GuestNetdConfig, GuestNetdError> {
        let mut bridge_builder = GuestBridgeConfig::builder();
        if let Some(value) = self.tun_name {
            bridge_builder = bridge_builder.tun_name(value);
        }
        if let Some(value) = self.guest_address {
            bridge_builder = bridge_builder.guest_address(value);
        }
        if let Some(value) = self.host_gateway {
            bridge_builder = bridge_builder.host_gateway(value);
        }
        if let Some(value) = self.link {
            bridge_builder = bridge_builder.link(value);
        }
        if let Some(value) = self.synthetic_pool {
            bridge_builder = bridge_builder.synthetic_pool(value);
        }
        if let Some(value) = self.resolv_conf {
            bridge_builder = bridge_builder.resolv_conf(value);
        }
        if let Some(value) = self.resolv_backup {
            bridge_builder = bridge_builder.resolv_backup(value);
        }
        if let Some(value) = self.vsock_port {
            bridge_builder = bridge_builder.vsock_port(value);
        }
        let bridge_config = bridge_builder
            .build()
            .map_err(GuestNetdError::BridgeConfig)?;

        let mut pump_builder = GuestPumpLoopConfig::builder();
        if let Some(value) = self.max_tun_packet_bytes {
            pump_builder = pump_builder.max_tun_packet_bytes(value);
        }
        if let Some(value) = self.max_authority_messages_per_tick {
            pump_builder = pump_builder.max_authority_messages_per_tick(value);
        }
        let pump_loop_config = pump_builder.build().map_err(GuestNetdError::PumpConfig)?;

        let mut wire_builder = JsonWireConfig::builder();
        if let Some(value) = self.max_wire_frame_bytes {
            wire_builder = wire_builder.max_frame_bytes(value);
        }
        let json_wire_config = wire_builder.build().map_err(GuestNetdError::WireConfig)?;

        let mut runner_builder = LinuxGuestBridgeRunnerConfig::builder()
            .pump_loop_config(pump_loop_config)
            .json_wire_config(json_wire_config);
        if let Some(value) = self.idle_poll_timeout_millis {
            runner_builder = runner_builder.idle_poll_timeout_millis(value);
        }
        if let Some(value) = self.write_poll_timeout_millis {
            runner_builder = runner_builder.write_poll_timeout_millis(value);
        }
        let runner_config = runner_builder
            .build()
            .map_err(GuestNetdError::RunnerConfig)?;

        Ok(GuestNetdConfig {
            bridge_config,
            runner_config,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum GuestNetdOption {
    TunName,
    GuestAddress,
    HostGateway,
    LinkCidr,
    SyntheticPoolCidr,
    ResolvConf,
    ResolvBackup,
    VsockPort,
    MaxTunPacketBytes,
    MaxAuthorityMessagesPerTick,
    MaxWireFrameBytes,
    IdlePollTimeoutMillis,
    WritePollTimeoutMillis,
}

impl GuestNetdOption {
    fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "--tun-name" => Some(Self::TunName),
            "--guest-address" => Some(Self::GuestAddress),
            "--host-gateway" => Some(Self::HostGateway),
            "--link-cidr" => Some(Self::LinkCidr),
            "--synthetic-pool-cidr" => Some(Self::SyntheticPoolCidr),
            "--resolv-conf" => Some(Self::ResolvConf),
            "--resolv-backup" => Some(Self::ResolvBackup),
            "--vsock-port" => Some(Self::VsockPort),
            "--max-tun-packet-bytes" => Some(Self::MaxTunPacketBytes),
            "--max-authority-messages-per-tick" => Some(Self::MaxAuthorityMessagesPerTick),
            "--max-wire-frame-bytes" => Some(Self::MaxWireFrameBytes),
            "--idle-poll-timeout-ms" => Some(Self::IdlePollTimeoutMillis),
            "--write-poll-timeout-ms" => Some(Self::WritePollTimeoutMillis),
            _ => None,
        }
    }

    fn from_env(key: &str) -> Option<Self> {
        match key {
            ENV_TUN_NAME => Some(Self::TunName),
            ENV_GUEST_ADDRESS => Some(Self::GuestAddress),
            ENV_HOST_GATEWAY => Some(Self::HostGateway),
            ENV_LINK_CIDR => Some(Self::LinkCidr),
            ENV_SYNTHETIC_POOL_CIDR => Some(Self::SyntheticPoolCidr),
            ENV_RESOLV_CONF => Some(Self::ResolvConf),
            ENV_RESOLV_BACKUP => Some(Self::ResolvBackup),
            ENV_VSOCK_PORT => Some(Self::VsockPort),
            ENV_MAX_TUN_PACKET_BYTES => Some(Self::MaxTunPacketBytes),
            ENV_MAX_AUTHORITY_MESSAGES_PER_TICK => Some(Self::MaxAuthorityMessagesPerTick),
            ENV_MAX_WIRE_FRAME_BYTES => Some(Self::MaxWireFrameBytes),
            ENV_IDLE_POLL_TIMEOUT_MILLIS => Some(Self::IdlePollTimeoutMillis),
            ENV_WRITE_POLL_TIMEOUT_MILLIS => Some(Self::WritePollTimeoutMillis),
            _ => None,
        }
    }

    const fn field(self) -> &'static str {
        match self {
            Self::TunName => "tun-name",
            Self::GuestAddress => "guest-address",
            Self::HostGateway => "host-gateway",
            Self::LinkCidr => "link-cidr",
            Self::SyntheticPoolCidr => "synthetic-pool-cidr",
            Self::ResolvConf => "resolv-conf",
            Self::ResolvBackup => "resolv-backup",
            Self::VsockPort => "vsock-port",
            Self::MaxTunPacketBytes => "max-tun-packet-bytes",
            Self::MaxAuthorityMessagesPerTick => "max-authority-messages-per-tick",
            Self::MaxWireFrameBytes => "max-wire-frame-bytes",
            Self::IdlePollTimeoutMillis => "idle-poll-timeout-ms",
            Self::WritePollTimeoutMillis => "write-poll-timeout-ms",
        }
    }
}

fn split_arg_value<Args>(
    arg: String,
    args: &mut std::iter::Peekable<Args>,
) -> Result<(String, String), GuestNetdError>
where
    Args: Iterator<Item = String>,
{
    if !arg.starts_with("--") {
        return Err(GuestNetdError::UnknownArgument(arg));
    }
    if let Some((flag, value)) = arg.split_once('=') {
        return Ok((flag.to_string(), value.to_string()));
    }
    let value = args
        .next()
        .ok_or_else(|| GuestNetdError::MissingValue(arg.clone()))?;
    if value.starts_with("--") {
        return Err(GuestNetdError::MissingValue(arg));
    }
    Ok((arg, value))
}

fn parse_ipv4(field: &'static str, value: &str) -> Result<Ipv4Addr, GuestNetdError> {
    value
        .parse()
        .map_err(|err: std::net::AddrParseError| invalid_value(field, value, err))
}

fn parse_cidr(field: &'static str, value: &str) -> Result<Ipv4Cidr, GuestNetdError> {
    let (network, prefix) = value
        .split_once('/')
        .ok_or_else(|| invalid_value(field, value, "expected IPV4/PREFIX"))?;
    let network = parse_ipv4(field, network)?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| invalid_value(field, value, err))?;
    Ipv4Cidr::new(network, prefix).map_err(GuestNetdError::BridgeConfig)
}

fn parse_u32(field: &'static str, value: &str) -> Result<u32, GuestNetdError> {
    value
        .parse()
        .map_err(|err: std::num::ParseIntError| invalid_value(field, value, err))
}

fn parse_usize(field: &'static str, value: &str) -> Result<usize, GuestNetdError> {
    value
        .parse()
        .map_err(|err: std::num::ParseIntError| invalid_value(field, value, err))
}

fn parse_i32(field: &'static str, value: &str) -> Result<i32, GuestNetdError> {
    value
        .parse()
        .map_err(|err: std::num::ParseIntError| invalid_value(field, value, err))
}

fn invalid_value(field: &'static str, value: &str, reason: impl fmt::Display) -> GuestNetdError {
    GuestNetdError::InvalidValue {
        field,
        value: value.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &[&str], env: &[(&str, &str)]) -> Result<GuestNetdConfig, GuestNetdError> {
        config_from_args_and_env(args.iter().copied(), env.iter().copied())
    }

    #[test]
    fn empty_sources_use_secure_defaults() {
        let config = config(&[], &[]).unwrap();

        assert_eq!(config.bridge_config().tun_name().as_str(), "mvmnet0");
        assert_eq!(config.bridge_config().vsock_port(), 5254);
        assert_eq!(
            config.runner_config().idle_poll_timeout_millis(),
            crate::guest_linux::DEFAULT_GUEST_RUNNER_POLL_TIMEOUT_MILLIS
        );
    }

    #[test]
    fn env_values_build_bridge_and_runner_config() {
        let config = config(
            &[],
            &[
                (ENV_TUN_NAME, "mvmnet1"),
                (ENV_GUEST_ADDRESS, "198.18.0.2"),
                (ENV_HOST_GATEWAY, "198.18.0.1"),
                (ENV_LINK_CIDR, "198.18.0.0/30"),
                (ENV_SYNTHETIC_POOL_CIDR, "198.19.0.0/16"),
                (ENV_RESOLV_CONF, "/run/mvm/resolv.conf"),
                (ENV_RESOLV_BACKUP, "/run/mvm/resolv.conf.backup"),
                (ENV_VSOCK_PORT, "6000"),
                (ENV_MAX_TUN_PACKET_BYTES, "4096"),
                (ENV_MAX_AUTHORITY_MESSAGES_PER_TICK, "8"),
                (ENV_MAX_WIRE_FRAME_BYTES, "8192"),
                (ENV_IDLE_POLL_TIMEOUT_MILLIS, "250"),
                (ENV_WRITE_POLL_TIMEOUT_MILLIS, "125"),
            ],
        )
        .unwrap();

        assert_eq!(config.bridge_config().tun_name().as_str(), "mvmnet1");
        assert_eq!(config.bridge_config().vsock_port(), 6000);
        assert_eq!(
            config
                .runner_config()
                .pump_loop_config()
                .max_tun_packet_bytes(),
            4096
        );
        assert_eq!(
            config
                .runner_config()
                .pump_loop_config()
                .max_authority_messages_per_tick(),
            8
        );
        assert_eq!(
            config.runner_config().json_wire_config().max_frame_bytes(),
            8192
        );
        assert_eq!(config.runner_config().idle_poll_timeout_millis(), 250);
        assert_eq!(config.runner_config().write_poll_timeout_millis(), 125);
    }

    #[test]
    fn oversized_poll_timeout_values_fail_at_runner_config_admission() {
        let oversized = (crate::guest_linux::MAX_GUEST_RUNNER_POLL_TIMEOUT_MILLIS + 1).to_string();
        let err = config(&["--idle-poll-timeout-ms", oversized.as_str()], &[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid runner config: invalid guest bridge runner config: idle_poll_timeout_millis exceeds the hard maximum"
        );

        let err = config(&["--write-poll-timeout-ms", oversized.as_str()], &[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid runner config: invalid guest bridge runner config: write_poll_timeout_millis exceeds the hard maximum"
        );
    }

    #[test]
    fn args_override_environment_values() {
        let config = config(
            &["--tun-name", "arg0", "--vsock-port=7000"],
            &[(ENV_TUN_NAME, "env0"), (ENV_VSOCK_PORT, "6000")],
        )
        .unwrap();

        assert_eq!(config.bridge_config().tun_name().as_str(), "arg0");
        assert_eq!(config.bridge_config().vsock_port(), 7000);
    }

    #[test]
    fn parser_reports_help_unknown_missing_and_invalid_values() {
        assert!(matches!(
            config(&["--help"], &[]),
            Err(GuestNetdError::HelpRequested)
        ));
        assert!(matches!(
            config(&["--unknown", "value"], &[]),
            Err(GuestNetdError::UnknownArgument(arg)) if arg == "--unknown"
        ));
        assert!(matches!(
            config(&["--vsock-port"], &[]),
            Err(GuestNetdError::MissingValue(arg)) if arg == "--vsock-port"
        ));
        assert!(matches!(
            config(&["--vsock-port", "--tun-name"], &[]),
            Err(GuestNetdError::MissingValue(arg)) if arg == "--vsock-port"
        ));
        assert!(matches!(
            config(&["--link-cidr", "not-a-cidr"], &[]),
            Err(GuestNetdError::InvalidValue {
                field: "link-cidr",
                ..
            })
        ));
    }

    #[test]
    fn invalid_builder_values_surface_as_config_errors() {
        assert!(matches!(
            config(&["--max-tun-packet-bytes", "0"], &[]),
            Err(GuestNetdError::PumpConfig(_))
        ));
        assert!(matches!(
            config(&["--max-wire-frame-bytes", "0"], &[]),
            Err(GuestNetdError::WireConfig(_))
        ));
        assert!(matches!(
            config(
                &[&format!(
                    "--max-wire-frame-bytes={}",
                    crate::wire_json::MAX_JSON_WIRE_FRAME_BYTES + 1
                )],
                &[]
            ),
            Err(GuestNetdError::WireConfig(_))
        ));
        assert!(matches!(
            config(
                &[&format!(
                    "--max-authority-messages-per-tick={}",
                    crate::guest_pump::MAX_AUTHORITY_MESSAGES_PER_TICK + 1
                )],
                &[]
            ),
            Err(GuestNetdError::PumpConfig(_))
        ));
        assert!(matches!(
            config(&["--idle-poll-timeout-ms", "0"], &[]),
            Err(GuestNetdError::RunnerConfig(_))
        ));
    }
}
