//! Host authority wire runner.
//!
//! The runner is intentionally generic over the stream source. Backend-specific
//! code owns accepting or dialing the per-VM transport; this module owns reading
//! `mvm-net` messages, applying the host authority, and writing responses.

use std::fmt;
use std::io::{Read, Write};

use crate::host::{
    HostAuditSink, HostAuthority, HostAuthorityError, HostNetworkPolicy, HostTcpConnector,
};
use crate::proto::NetMessage;
use crate::wire_json::{JsonWireError, JsonWireRead, LengthPrefixedJsonAuthority};

pub const DEFAULT_MAX_HOST_MESSAGES_PER_RUN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRunnerError {
    InvalidConfig(&'static str),
    Authority(HostAuthorityError),
    Wire(String),
}

impl fmt::Display for HostRunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid host runner config: {reason}"),
            Self::Authority(err) => write!(f, "{err}"),
            Self::Wire(err) => write!(f, "host authority wire failed: {err}"),
        }
    }
}

impl std::error::Error for HostRunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(err) => Some(err),
            Self::InvalidConfig(_) | Self::Wire(_) => None,
        }
    }
}

impl From<HostAuthorityError> for HostRunnerError {
    fn from(value: HostAuthorityError) -> Self {
        Self::Authority(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRunnerConfig {
    max_messages_per_run: usize,
}

impl HostRunnerConfig {
    pub fn builder() -> HostRunnerConfigBuilder {
        HostRunnerConfigBuilder::default()
    }

    pub const fn max_messages_per_run(&self) -> usize {
        self.max_messages_per_run
    }
}

impl Default for HostRunnerConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default host runner config is valid")
    }
}

#[derive(Debug, Clone)]
pub struct HostRunnerConfigBuilder {
    max_messages_per_run: usize,
}

impl Default for HostRunnerConfigBuilder {
    fn default() -> Self {
        Self {
            max_messages_per_run: DEFAULT_MAX_HOST_MESSAGES_PER_RUN,
        }
    }
}

impl HostRunnerConfigBuilder {
    pub fn max_messages_per_run(mut self, max_messages_per_run: usize) -> Self {
        self.max_messages_per_run = max_messages_per_run;
        self
    }

    pub fn build(self) -> Result<HostRunnerConfig, HostRunnerError> {
        if self.max_messages_per_run == 0 {
            return Err(HostRunnerError::InvalidConfig(
                "max_messages_per_run must be non-zero",
            ));
        }
        Ok(HostRunnerConfig {
            max_messages_per_run: self.max_messages_per_run,
        })
    }
}

pub trait HostAuthorityWire {
    type Error: fmt::Display;

    fn receive_message(&mut self) -> Result<HostAuthorityRead, Self::Error>;

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAuthorityRead {
    Message(NetMessage),
    WouldBlock,
    Closed,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HostRunnerOutcome {
    WouldBlock,
    Closed,
    MaxMessages,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HostRunnerStats {
    pub messages_read: usize,
    pub messages_written: usize,
    pub outcome: HostRunnerOutcome,
}

impl HostRunnerStats {
    const fn new(outcome: HostRunnerOutcome) -> Self {
        Self {
            messages_read: 0,
            messages_written: 0,
            outcome,
        }
    }
}

pub fn run_host_authority_until_blocked<P, A, T, W>(
    authority: &mut HostAuthority<P, A, T>,
    wire: &mut W,
    config: &HostRunnerConfig,
) -> Result<HostRunnerStats, HostRunnerError>
where
    P: HostNetworkPolicy,
    A: HostAuditSink,
    T: HostTcpConnector,
    W: HostAuthorityWire,
{
    let mut stats = HostRunnerStats::new(HostRunnerOutcome::WouldBlock);
    loop {
        if stats.messages_read >= config.max_messages_per_run() {
            stats.outcome = HostRunnerOutcome::MaxMessages;
            return Ok(stats);
        }
        match wire
            .receive_message()
            .map_err(|err| HostRunnerError::Wire(err.to_string()))?
        {
            HostAuthorityRead::Message(message) => {
                stats.messages_read += 1;
                let responses = authority.handle_message(message)?;
                for response in responses {
                    wire.send_message(response)
                        .map_err(|err| HostRunnerError::Wire(err.to_string()))?;
                    stats.messages_written += 1;
                }
            }
            HostAuthorityRead::WouldBlock => {
                stats.outcome = HostRunnerOutcome::WouldBlock;
                return Ok(stats);
            }
            HostAuthorityRead::Closed => {
                stats.outcome = HostRunnerOutcome::Closed;
                return Ok(stats);
            }
        }
    }
}

impl<T> HostAuthorityWire for LengthPrefixedJsonAuthority<T>
where
    T: Read + Write,
{
    type Error = JsonWireError;

    fn receive_message(&mut self) -> Result<HostAuthorityRead, Self::Error> {
        match self.read_message()? {
            JsonWireRead::Message(message) => Ok(HostAuthorityRead::Message(message)),
            JsonWireRead::WouldBlock => Ok(HostAuthorityRead::WouldBlock),
            JsonWireRead::Closed => Ok(HostAuthorityRead::Closed),
        }
    }

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
        self.write_message(message)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::host::{
        AllowAllHostPolicy, DenyAllHostPolicy, HostAuditEvent, NoopHostAuditSink,
        RefusingTcpConnector,
    };
    use crate::proto::{
        Capability, DnsName, DnsQuery, DnsRecordType, EndpointRole, FlowId, Hello, NetMessage,
        OpenTcp, Target,
    };

    #[derive(Debug, Default)]
    struct MemoryWire {
        reads: VecDeque<HostAuthorityRead>,
        writes: Vec<NetMessage>,
    }

    impl MemoryWire {
        fn with_reads(reads: impl IntoIterator<Item = HostAuthorityRead>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                writes: Vec::new(),
            }
        }
    }

    impl HostAuthorityWire for MemoryWire {
        type Error = &'static str;

        fn receive_message(&mut self) -> Result<HostAuthorityRead, Self::Error> {
            Ok(self.reads.pop_front().unwrap_or(HostAuthorityRead::Closed))
        }

        fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
            self.writes.push(message);
            Ok(())
        }
    }

    #[test]
    fn runner_processes_messages_until_would_block() {
        let mut authority =
            HostAuthority::new(AllowAllHostPolicy, NoopHostAuditSink, RefusingTcpConnector);
        let query = DnsQuery {
            query_id: crate::proto::QueryId::new(1).unwrap(),
            name: DnsName::new("example.com").unwrap(),
            record_type: DnsRecordType::A,
        };
        let mut wire = MemoryWire::with_reads([
            HostAuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            ))),
            HostAuthorityRead::Message(NetMessage::DnsQuery(query)),
            HostAuthorityRead::WouldBlock,
        ]);

        let stats = run_host_authority_until_blocked(
            &mut authority,
            &mut wire,
            &HostRunnerConfig::default(),
        )
        .unwrap();

        assert_eq!(
            stats,
            HostRunnerStats {
                messages_read: 2,
                messages_written: 2,
                outcome: HostRunnerOutcome::WouldBlock,
            }
        );
        assert!(matches!(wire.writes[0], NetMessage::HelloAck(_)));
        assert!(matches!(wire.writes[1], NetMessage::DnsResponse(_)));
    }

    #[test]
    fn runner_stops_at_configured_message_budget() {
        let mut authority =
            HostAuthority::new(AllowAllHostPolicy, NoopHostAuditSink, RefusingTcpConnector);
        let mut wire = MemoryWire::with_reads([
            HostAuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            ))),
            HostAuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Tcp],
            ))),
        ]);
        let config = HostRunnerConfig::builder()
            .max_messages_per_run(1)
            .build()
            .unwrap();

        let stats = run_host_authority_until_blocked(&mut authority, &mut wire, &config).unwrap();

        assert_eq!(
            stats,
            HostRunnerStats {
                messages_read: 1,
                messages_written: 1,
                outcome: HostRunnerOutcome::MaxMessages,
            }
        );
    }

    #[test]
    fn runner_surfaces_authority_errors_before_writing_responses() {
        let mut authority =
            HostAuthority::new(DenyAllHostPolicy, FailingAudit, RefusingTcpConnector);
        let open = OpenTcp::new(
            FlowId::new(9).unwrap(),
            Target::new("example.com", 443).unwrap(),
        );
        let mut wire =
            MemoryWire::with_reads([HostAuthorityRead::Message(NetMessage::OpenTcp(open))]);

        let err = run_host_authority_until_blocked(
            &mut authority,
            &mut wire,
            &HostRunnerConfig::default(),
        )
        .unwrap_err();

        assert!(matches!(err, HostRunnerError::Authority(_)));
        assert!(wire.writes.is_empty());
    }

    #[test]
    fn runner_config_rejects_zero_budget() {
        assert!(matches!(
            HostRunnerConfig::builder().max_messages_per_run(0).build(),
            Err(HostRunnerError::InvalidConfig(_))
        ));
    }

    #[derive(Debug, Default)]
    struct FailingAudit;

    impl crate::host::HostAuditSink for FailingAudit {
        type Error = &'static str;

        fn record(&mut self, _event: HostAuditEvent) -> Result<(), Self::Error> {
            Err("audit unavailable")
        }
    }

    #[test]
    fn length_prefixed_json_authority_implements_host_wire() {
        let mut source = LengthPrefixedJsonAuthority::new(std::io::Cursor::new(Vec::new()));
        source
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();
        source.inner_mut().set_position(0);

        assert!(matches!(
            HostAuthorityWire::receive_message(&mut source).unwrap(),
            HostAuthorityRead::Message(NetMessage::Hello(_))
        ));
    }
}
