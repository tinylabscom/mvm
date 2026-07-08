//! Host transparent networking daemon entry-point support.
//!
//! The binary wrapper stays tiny. This module owns JSON config loading, manual
//! argument/env parsing, structured audit emission, and binding the host
//! authority to stdio-framed protocol streams.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::host::{HostAuditEvent, HostAuditSink, HostAuthority, HostTcpConnector};
use crate::host::{MvmCoreNetworkPolicy, StdTcpConnector};
use crate::host_runner::{
    HostAuthorityWire, HostRunnerConfig, HostRunnerError, HostRunnerStats, SplitJsonHostWire,
    run_host_authority_until_blocked,
};
use crate::wire_json::{JsonWireConfig, JsonWireError, LengthPrefixedJsonAuthority};

pub const ENV_CONFIG: &str = "MVM_NET_HOST_CONFIG";
pub const ENV_LISTEN_UDS: &str = "MVM_NET_HOST_LISTEN_UDS";

const USAGE: &str = "\
mvm-host-netd [OPTIONS]

Host transparent networking authority. It either accepts one Unix-domain
socket connection or reads length-prefixed JSON mvm-net frames from stdin,
writes length-prefixed responses to the peer/stdout, and emits structured
JSON audit events to stderr.

Options:
  --config PATH       JSON host-netd config file
  --listen-uds PATH   Bind PATH and accept one authority stream
  -h, --help

Environment:
  MVM_NET_HOST_CONFIG
  MVM_NET_HOST_LISTEN_UDS

Command-line options override environment values.
";

#[derive(Debug)]
pub enum HostNetdError {
    HelpRequested,
    UnknownArgument(String),
    MissingValue(String),
    MissingConfigPath,
    Io {
        context: &'static str,
        source: io::Error,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
    Config(&'static str),
    Runner(HostRunnerError),
    WireConfig(JsonWireError),
    PolicyProjection(mvm_core::policy::projection::ProjectionError),
}

impl fmt::Display for HostNetdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested => write!(f, "{USAGE}"),
            Self::UnknownArgument(arg) => write!(f, "unknown argument {arg:?}"),
            Self::MissingValue(arg) => write!(f, "missing value for {arg}"),
            Self::MissingConfigPath => write!(f, "missing host netd config path"),
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Json { context, source } => write!(f, "{context}: {source}"),
            Self::Config(reason) => write!(f, "invalid host netd config: {reason}"),
            Self::Runner(err) => write!(f, "{err}"),
            Self::WireConfig(err) => write!(f, "invalid wire config: {err}"),
            Self::PolicyProjection(err) => write!(f, "invalid network policy projection: {err}"),
        }
    }
}

impl std::error::Error for HostNetdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Runner(err) => Some(err),
            Self::WireConfig(err) => Some(err),
            Self::PolicyProjection(err) => Some(err),
            Self::HelpRequested
            | Self::UnknownArgument(_)
            | Self::MissingValue(_)
            | Self::MissingConfigPath
            | Self::Config(_) => None,
        }
    }
}

impl From<HostRunnerError> for HostNetdError {
    fn from(value: HostRunnerError) -> Self {
        Self::Runner(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNetdLaunchConfig {
    config_path: PathBuf,
    listen_uds: Option<PathBuf>,
}

impl HostNetdLaunchConfig {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            listen_uds: None,
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn listen_uds(&self) -> Option<&Path> {
        self.listen_uds.as_deref()
    }

    fn with_listen_uds(mut self, listen_uds: impl Into<PathBuf>) -> Self {
        self.listen_uds = Some(listen_uds.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNetdConfig {
    network_policy: mvm_core::policy::network_policy::NetworkPolicy,
    dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry,
    now: String,
    runner_config: HostRunnerConfig,
    wire_config: JsonWireConfig,
}

impl HostNetdConfig {
    pub fn builder() -> HostNetdConfigBuilder {
        HostNetdConfigBuilder::default()
    }

    pub fn network_policy(&self) -> &mvm_core::policy::network_policy::NetworkPolicy {
        &self.network_policy
    }

    pub fn dns_pins(&self) -> &mvm_core::policy::dns_pin::DnsPinRegistry {
        &self.dns_pins
    }

    pub fn now(&self) -> &str {
        &self.now
    }

    pub fn runner_config(&self) -> &HostRunnerConfig {
        &self.runner_config
    }

    pub fn wire_config(&self) -> &JsonWireConfig {
        &self.wire_config
    }

    fn policy_adapter(&self) -> Result<MvmCoreNetworkPolicy, HostNetdError> {
        MvmCoreNetworkPolicy::from_network_policy(
            &self.network_policy,
            self.dns_pins.clone(),
            &self.now,
        )
        .map_err(HostNetdError::PolicyProjection)
    }
}

#[derive(Debug, Default, Clone)]
pub struct HostNetdConfigBuilder {
    network_policy: Option<mvm_core::policy::network_policy::NetworkPolicy>,
    dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry,
    now: Option<String>,
    max_messages_per_run: Option<usize>,
    max_wire_frame_bytes: Option<usize>,
}

impl HostNetdConfigBuilder {
    pub fn network_policy(
        mut self,
        network_policy: mvm_core::policy::network_policy::NetworkPolicy,
    ) -> Self {
        self.network_policy = Some(network_policy);
        self
    }

    pub fn dns_pins(mut self, dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry) -> Self {
        self.dns_pins = dns_pins;
        self
    }

    pub fn now(mut self, now: impl Into<String>) -> Self {
        self.now = Some(now.into());
        self
    }

    pub fn max_messages_per_run(mut self, max_messages_per_run: usize) -> Self {
        self.max_messages_per_run = Some(max_messages_per_run);
        self
    }

    pub fn max_wire_frame_bytes(mut self, max_wire_frame_bytes: usize) -> Self {
        self.max_wire_frame_bytes = Some(max_wire_frame_bytes);
        self
    }

    pub fn build(self) -> Result<HostNetdConfig, HostNetdError> {
        let network_policy = self
            .network_policy
            .ok_or(HostNetdError::Config("network_policy is required"))?;
        let now = self.now.ok_or(HostNetdError::Config("now is required"))?;
        if now.trim().is_empty() {
            return Err(HostNetdError::Config("now must not be empty"));
        }
        let mut runner_builder = HostRunnerConfig::builder();
        if let Some(value) = self.max_messages_per_run {
            runner_builder = runner_builder.max_messages_per_run(value);
        }
        let mut wire_builder = JsonWireConfig::builder();
        if let Some(value) = self.max_wire_frame_bytes {
            wire_builder = wire_builder.max_frame_bytes(value);
        }
        Ok(HostNetdConfig {
            network_policy,
            dns_pins: self.dns_pins,
            now,
            runner_config: runner_builder.build()?,
            wire_config: wire_builder.build().map_err(HostNetdError::WireConfig)?,
        })
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNetdConfigFile {
    network_policy: mvm_core::policy::network_policy::NetworkPolicy,
    #[serde(default)]
    dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry,
    now: String,
    #[serde(default)]
    max_messages_per_run: Option<usize>,
    #[serde(default)]
    max_wire_frame_bytes: Option<usize>,
}

impl HostNetdConfigFile {
    fn into_config(self) -> Result<HostNetdConfig, HostNetdError> {
        let mut builder = HostNetdConfig::builder()
            .network_policy(self.network_policy)
            .dns_pins(self.dns_pins)
            .now(self.now);
        if let Some(value) = self.max_messages_per_run {
            builder = builder.max_messages_per_run(value);
        }
        if let Some(value) = self.max_wire_frame_bytes {
            builder = builder.max_wire_frame_bytes(value);
        }
        builder.build()
    }
}

pub fn usage() -> &'static str {
    USAGE
}

pub fn launch_config_from_args_and_env<Args, Arg, Env, Key, Value>(
    args: Args,
    env: Env,
) -> Result<HostNetdLaunchConfig, HostNetdError>
where
    Args: IntoIterator<Item = Arg>,
    Arg: Into<String>,
    Env: IntoIterator<Item = (Key, Value)>,
    Key: AsRef<str>,
    Value: Into<String>,
{
    let mut config_path = None;
    let mut listen_uds = None;
    for (key, value) in env {
        match key.as_ref() {
            ENV_CONFIG => config_path = Some(PathBuf::from(value.into())),
            ENV_LISTEN_UDS => listen_uds = Some(PathBuf::from(value.into())),
            _ => {}
        }
    }

    let mut args = args.into_iter().map(Into::into).peekable();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Err(HostNetdError::HelpRequested);
        }
        let value = if let Some((flag, value)) = arg.split_once('=') {
            match flag {
                "--config" | "--listen-uds" => value.to_string(),
                _ => return Err(HostNetdError::UnknownArgument(flag.to_string())),
            }
        } else if arg == "--config" || arg == "--listen-uds" {
            args.next()
                .ok_or_else(|| HostNetdError::MissingValue(arg.clone()))?
        } else {
            return Err(HostNetdError::UnknownArgument(arg));
        };
        if arg.starts_with("--listen-uds") {
            listen_uds = Some(PathBuf::from(value));
        } else {
            config_path = Some(PathBuf::from(value));
        }
    }

    let config = match config_path {
        Some(path) if !path.as_os_str().is_empty() => Ok(HostNetdLaunchConfig::new(path)),
        Some(_) | None => Err(HostNetdError::MissingConfigPath),
    }?;
    match listen_uds {
        Some(path) if !path.as_os_str().is_empty() => Ok(config.with_listen_uds(path)),
        Some(_) => Err(HostNetdError::Config("listen-uds path must not be empty")),
        None => Ok(config),
    }
}

pub fn load_config_file(path: &Path) -> Result<HostNetdConfig, HostNetdError> {
    let contents = std::fs::read_to_string(path).map_err(|source| HostNetdError::Io {
        context: "failed to read host netd config",
        source,
    })?;
    config_from_json_str(&contents)
}

pub fn config_from_json_str(contents: &str) -> Result<HostNetdConfig, HostNetdError> {
    let config: HostNetdConfigFile =
        serde_json::from_str(contents).map_err(|source| HostNetdError::Json {
            context: "failed to decode host netd config",
            source,
        })?;
    config.into_config()
}

pub fn run_host_netd_stdio(config: &HostNetdConfig) -> Result<HostRunnerStats, HostNetdError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_host_netd_on_stdio_parts(
        config,
        stdin.lock(),
        stdout.lock(),
        JsonLineAuditSink::new(stderr.lock()),
    )
}

pub fn run_host_netd_listen_uds(
    config: &HostNetdConfig,
    path: &Path,
) -> Result<HostRunnerStats, HostNetdError> {
    let stderr = io::stderr();
    run_host_netd_listen_uds_with_audit(config, path, JsonLineAuditSink::new(stderr.lock()))
}

pub fn run_host_netd_listen_uds_with_audit<A>(
    config: &HostNetdConfig,
    path: &Path,
    audit: A,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
{
    if path.as_os_str().is_empty() {
        return Err(HostNetdError::Config("listen-uds path must not be empty"));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|source| HostNetdError::Io {
            context: "failed to create host netd socket directory",
            source,
        })?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(HostNetdError::Io {
                context: "failed to remove stale host netd socket",
                source,
            });
        }
    }
    let listener = UnixListener::bind(path).map_err(|source| HostNetdError::Io {
        context: "failed to bind host netd socket",
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| HostNetdError::Io {
                context: "failed to chmod host netd socket",
                source,
            },
        )?;
    }
    let (stream, _) = listener.accept().map_err(|source| HostNetdError::Io {
        context: "failed to accept host netd socket",
        source,
    })?;
    run_host_netd_on_stream(config, stream, audit)
}

pub fn run_host_netd_on_stream<A>(
    config: &HostNetdConfig,
    stream: UnixStream,
    audit: A,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
{
    let mut wire = LengthPrefixedJsonAuthority::with_config(stream, config.wire_config().clone());
    run_host_netd_with_wire(config, audit, StdTcpConnector::new(), &mut wire)
}

pub fn run_host_netd_on_stdio_parts<R, W, A>(
    config: &HostNetdConfig,
    reader: R,
    writer: W,
    audit: A,
) -> Result<HostRunnerStats, HostNetdError>
where
    R: Read,
    W: Write,
    A: HostAuditSink,
{
    let mut wire = SplitJsonHostWire::with_config(reader, writer, config.wire_config().clone());
    run_host_netd_with_wire(config, audit, StdTcpConnector::new(), &mut wire)
}

pub fn run_host_netd_with_wire<A, T, W>(
    config: &HostNetdConfig,
    audit: A,
    tcp: T,
    wire: &mut W,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
    T: HostTcpConnector,
    W: HostAuthorityWire,
{
    let policy = config.policy_adapter()?;
    let mut authority = HostAuthority::new(policy, audit, tcp);
    run_host_authority_until_blocked(&mut authority, wire, config.runner_config())
        .map_err(HostNetdError::Runner)
}

#[derive(Debug)]
pub enum JsonLineAuditError {
    Io(io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for JsonLineAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "audit I/O failed: {err}"),
            Self::Json(err) => write!(f, "audit JSON encode failed: {err}"),
        }
    }
}

impl std::error::Error for JsonLineAuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
        }
    }
}

impl From<io::Error> for JsonLineAuditError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for JsonLineAuditError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug)]
pub struct JsonLineAuditSink<W> {
    writer: W,
}

impl<W> JsonLineAuditSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> HostAuditSink for JsonLineAuditSink<W>
where
    W: Write,
{
    type Error = JsonLineAuditError;

    fn record(&mut self, event: HostAuditEvent) -> Result<(), Self::Error> {
        serde_json::to_writer(&mut self.writer, &event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::host::{NoopHostAuditSink, RefusingTcpConnector};
    use crate::host_runner::{HostRunnerOutcome, HostRunnerStats};
    use crate::proto::{Capability, EndpointRole, Hello, NetMessage};
    use crate::wire_json::{JsonWireRead, LengthPrefixedJsonAuthority};

    const NOW: &str = "2030-01-01T00:00:00Z";

    fn deny_all_config() -> HostNetdConfig {
        HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .build()
            .unwrap()
    }

    #[test]
    fn launch_config_prefers_cli_path_over_env_path() {
        let config = launch_config_from_args_and_env(
            ["--config", "/tmp/cli.json"],
            [
                (ENV_CONFIG, "/tmp/env.json"),
                (ENV_LISTEN_UDS, "/tmp/env.sock"),
            ],
        )
        .unwrap();

        assert_eq!(config.config_path(), Path::new("/tmp/cli.json"));
        assert_eq!(config.listen_uds(), Some(Path::new("/tmp/env.sock")));
    }

    #[test]
    fn launch_config_prefers_cli_listen_socket_over_env_socket() {
        let config = launch_config_from_args_and_env(
            ["--config=/tmp/cfg.json", "--listen-uds", "/tmp/cli.sock"],
            [(ENV_LISTEN_UDS, "/tmp/env.sock")],
        )
        .unwrap();

        assert_eq!(config.listen_uds(), Some(Path::new("/tmp/cli.sock")));
    }

    #[test]
    fn launch_config_rejects_empty_path() {
        let err =
            launch_config_from_args_and_env(["--config="], std::iter::empty::<(&str, &str)>())
                .unwrap_err();

        assert!(matches!(err, HostNetdError::MissingConfigPath));
    }

    #[test]
    fn config_json_rejects_unknown_fields() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "extra": true
            }"#,
        )
        .unwrap_err();

        assert!(matches!(err, HostNetdError::Json { .. }));
    }

    #[test]
    fn config_builder_rejects_zero_frame_bound() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_wire_frame_bytes(0)
            .build()
            .unwrap_err();

        assert!(matches!(err, HostNetdError::WireConfig(_)));
    }

    #[test]
    fn host_netd_stdio_processes_hello_and_writes_structured_audit() {
        let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        encoded
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();

        let mut output = Cursor::new(Vec::new());
        let mut audit = Vec::new();
        let stats = run_host_netd_on_stdio_parts(
            &deny_all_config(),
            Cursor::new(encoded.into_inner().into_inner()),
            &mut output,
            JsonLineAuditSink::new(&mut audit),
        )
        .unwrap();

        assert_eq!(
            stats,
            HostRunnerStats {
                messages_read: 1,
                messages_written: 1,
                outcome: HostRunnerOutcome::Closed,
            }
        );
        let mut decoded = LengthPrefixedJsonAuthority::new(Cursor::new(output.into_inner()));
        assert!(matches!(
            decoded.read_message().unwrap(),
            JsonWireRead::Message(NetMessage::HelloAck(_))
        ));
        let audit_line = std::str::from_utf8(&audit).unwrap();
        let audit_json: serde_json::Value = serde_json::from_str(audit_line.trim()).unwrap();
        assert_eq!(audit_json["event"], "handshake_accepted");
        assert_eq!(audit_json["guest_capabilities"][0], "Dns");
    }

    #[test]
    fn host_netd_listen_uds_accepts_one_authority_stream() {
        let dir = std::env::temp_dir().join(format!(
            "mvm-netd-listen-{}-{}",
            std::process::id(),
            unique_test_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("netd.sock");
        let config = deny_all_config();
        let server_socket = socket.clone();
        let server = std::thread::spawn(move || {
            let mut audit = Vec::new();
            let stats = run_host_netd_listen_uds_with_audit(
                &config,
                &server_socket,
                JsonLineAuditSink::new(&mut audit),
            )
            .unwrap();
            (stats, audit)
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "host netd socket was not bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let mut client = LengthPrefixedJsonAuthority::new(
            UnixStream::connect(&socket).expect("connect to host netd socket"),
        );
        client
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();
        assert!(matches!(
            client.read_message().unwrap(),
            JsonWireRead::Message(NetMessage::HelloAck(_))
        ));
        drop(client);

        let (stats, audit) = server.join().unwrap();
        assert_eq!(stats.messages_read, 1);
        assert_eq!(stats.messages_written, 1);
        let audit_line = std::str::from_utf8(&audit).unwrap();
        let audit_json: serde_json::Value = serde_json::from_str(audit_line.trim()).unwrap();
        assert_eq!(audit_json["event"], "handshake_accepted");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn host_netd_wire_runner_uses_configured_policy_adapter() {
        let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        encoded
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();
        let input = Cursor::new(encoded.into_inner().into_inner());
        let output = Cursor::new(Vec::new());
        let mut wire = SplitJsonHostWire::new(input, output);

        let stats = run_host_netd_with_wire(
            &deny_all_config(),
            NoopHostAuditSink,
            RefusingTcpConnector,
            &mut wire,
        )
        .unwrap();

        assert_eq!(stats.messages_read, 1);
        assert_eq!(stats.messages_written, 1);
    }

    fn unique_test_suffix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed).to_string()
    }
}
