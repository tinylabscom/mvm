//! Length-prefixed JSON framing for the mvm-net protocol.
//!
//! This is an opt-in, dependency-light wire adapter for early guest/authority
//! integration. It owns frame bounds and partial-read state, while the caller
//! remains responsible for readiness, scheduling, and write backpressure.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};

#[cfg(feature = "guest")]
use crate::guest_pump::{AuthorityRead, GuestAuthority, GuestAuthorityReceiver};
use crate::proto::NetMessage;

pub const DEFAULT_MAX_JSON_WIRE_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum JsonWireError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidConfig(&'static str),
    FrameTooLarge { bytes: usize, max: usize },
    InvalidFrameLength { bytes: usize, max: usize },
    UnexpectedEof { context: &'static str },
}

impl fmt::Display for JsonWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "json wire I/O failed: {err}"),
            Self::Json(err) => write!(f, "json wire decode failed: {err}"),
            Self::InvalidConfig(reason) => write!(f, "invalid json wire config: {reason}"),
            Self::FrameTooLarge { bytes, max } => {
                write!(f, "json wire frame is {bytes} bytes; maximum is {max}")
            }
            Self::InvalidFrameLength { bytes, max } => {
                write!(
                    f,
                    "json wire frame declared {bytes} bytes; maximum is {max}"
                )
            }
            Self::UnexpectedEof { context } => {
                write!(f, "json wire stream closed while reading {context}")
            }
        }
    }
}

impl std::error::Error for JsonWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::InvalidConfig(_)
            | Self::FrameTooLarge { .. }
            | Self::InvalidFrameLength { .. }
            | Self::UnexpectedEof { .. } => None,
        }
    }
}

impl From<io::Error> for JsonWireError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for JsonWireError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonWireConfig {
    max_frame_bytes: usize,
}

impl JsonWireConfig {
    pub fn builder() -> JsonWireConfigBuilder {
        JsonWireConfigBuilder::default()
    }

    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

impl Default for JsonWireConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_JSON_WIRE_FRAME_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonWireConfigBuilder {
    max_frame_bytes: usize,
}

impl Default for JsonWireConfigBuilder {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_JSON_WIRE_FRAME_BYTES,
        }
    }
}

impl JsonWireConfigBuilder {
    pub fn max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    pub fn build(self) -> Result<JsonWireConfig, JsonWireError> {
        if self.max_frame_bytes == 0 {
            return Err(JsonWireError::InvalidConfig(
                "max_frame_bytes must be non-zero",
            ));
        }
        if self.max_frame_bytes > u32::MAX as usize {
            return Err(JsonWireError::InvalidConfig(
                "max_frame_bytes must fit in a 32-bit frame length",
            ));
        }
        Ok(JsonWireConfig {
            max_frame_bytes: self.max_frame_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonWireRead {
    Message(NetMessage),
    WouldBlock,
    Closed,
}

#[derive(Debug)]
pub struct LengthPrefixedJsonAuthority<T> {
    inner: T,
    config: JsonWireConfig,
    read_state: ReadState,
}

impl<T> LengthPrefixedJsonAuthority<T> {
    pub fn new(inner: T) -> Self {
        Self::with_config(inner, JsonWireConfig::default())
    }

    pub fn with_config(inner: T, config: JsonWireConfig) -> Self {
        Self {
            inner,
            config,
            read_state: ReadState::prefix(),
        }
    }

    pub fn config(&self) -> &JsonWireConfig {
        &self.config
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> LengthPrefixedJsonAuthority<T>
where
    T: Write,
{
    pub fn write_message(&mut self, message: NetMessage) -> Result<(), JsonWireError> {
        let body = serde_json::to_vec(&message)?;
        if body.len() > self.config.max_frame_bytes {
            return Err(JsonWireError::FrameTooLarge {
                bytes: body.len(),
                max: self.config.max_frame_bytes,
            });
        }
        let len = u32::try_from(body.len()).map_err(|_| JsonWireError::FrameTooLarge {
            bytes: body.len(),
            max: self.config.max_frame_bytes,
        })?;
        self.inner.write_all(&len.to_be_bytes())?;
        self.inner.write_all(&body)?;
        self.inner.flush()?;
        Ok(())
    }
}

impl<T> LengthPrefixedJsonAuthority<T>
where
    T: Read,
{
    pub fn read_message(&mut self) -> Result<JsonWireRead, JsonWireError> {
        loop {
            let state = std::mem::replace(&mut self.read_state, ReadState::prefix());
            match state {
                ReadState::Prefix {
                    mut bytes,
                    mut read,
                } => {
                    match read_to_buffer(&mut self.inner, &mut bytes, &mut read, "frame length")? {
                        ReadStatus::Complete => {
                            let body_len = u32::from_be_bytes(bytes) as usize;
                            if body_len == 0 || body_len > self.config.max_frame_bytes {
                                return Err(JsonWireError::InvalidFrameLength {
                                    bytes: body_len,
                                    max: self.config.max_frame_bytes,
                                });
                            }
                            self.read_state = ReadState::Body {
                                bytes: vec![0; body_len],
                                read: 0,
                            };
                        }
                        ReadStatus::WouldBlock => {
                            self.read_state = ReadState::Prefix { bytes, read };
                            return Ok(JsonWireRead::WouldBlock);
                        }
                        ReadStatus::Closed => return Ok(JsonWireRead::Closed),
                    }
                }
                ReadState::Body {
                    mut bytes,
                    mut read,
                } => match read_to_buffer(&mut self.inner, &mut bytes, &mut read, "frame body")? {
                    ReadStatus::Complete => {
                        self.read_state = ReadState::prefix();
                        let message = serde_json::from_slice(&bytes)?;
                        return Ok(JsonWireRead::Message(message));
                    }
                    ReadStatus::WouldBlock => {
                        self.read_state = ReadState::Body { bytes, read };
                        return Ok(JsonWireRead::WouldBlock);
                    }
                    ReadStatus::Closed => {
                        return Err(JsonWireError::UnexpectedEof {
                            context: "frame body",
                        });
                    }
                },
            }
        }
    }
}

#[cfg(feature = "guest")]
impl<T> GuestAuthority for LengthPrefixedJsonAuthority<T>
where
    T: Write,
{
    type Error = JsonWireError;

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
        self.write_message(message)
    }
}

#[cfg(feature = "guest")]
impl<T> GuestAuthorityReceiver for LengthPrefixedJsonAuthority<T>
where
    T: Read + Write,
{
    fn receive_message(&mut self) -> Result<AuthorityRead, Self::Error> {
        match self.read_message()? {
            JsonWireRead::Message(message) => Ok(AuthorityRead::Message(message)),
            JsonWireRead::WouldBlock => Ok(AuthorityRead::WouldBlock),
            JsonWireRead::Closed => Ok(AuthorityRead::Closed),
        }
    }
}

#[derive(Debug)]
enum ReadState {
    Prefix { bytes: [u8; 4], read: usize },
    Body { bytes: Vec<u8>, read: usize },
}

impl ReadState {
    const fn prefix() -> Self {
        Self::Prefix {
            bytes: [0; 4],
            read: 0,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ReadStatus {
    Complete,
    WouldBlock,
    Closed,
}

fn read_to_buffer<R>(
    reader: &mut R,
    target: &mut [u8],
    read: &mut usize,
    context: &'static str,
) -> Result<ReadStatus, JsonWireError>
where
    R: Read,
{
    while *read < target.len() {
        match reader.read(&mut target[*read..]) {
            Ok(0) => {
                if *read == 0 {
                    return Ok(ReadStatus::Closed);
                }
                return Err(JsonWireError::UnexpectedEof { context });
            }
            Ok(bytes) => {
                *read += bytes;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(ReadStatus::WouldBlock),
            Err(err) => return Err(JsonWireError::Io(err)),
        }
    }
    Ok(ReadStatus::Complete)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Cursor;

    use super::*;
    use crate::proto::{EndpointRole, Hello};

    fn hello_message() -> NetMessage {
        NetMessage::Hello(Hello::new(EndpointRole::Guest, Vec::new()))
    }

    fn encoded_frame(message: NetMessage) -> Vec<u8> {
        let mut authority = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        authority.write_message(message).unwrap();
        authority.into_inner().into_inner()
    }

    #[test]
    fn framed_json_round_trips_message() {
        let message = hello_message();
        let mut authority = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));

        authority.write_message(message.clone()).unwrap();
        authority.inner_mut().set_position(0);

        assert_eq!(
            authority.read_message().unwrap(),
            JsonWireRead::Message(message)
        );
    }

    #[test]
    fn framed_json_preserves_partial_prefix_across_would_block() {
        let frame = encoded_frame(hello_message());
        let mut reader = ScriptedIo::new([
            ReadStep::Bytes(frame[..2].to_vec()),
            ReadStep::WouldBlock,
            ReadStep::Bytes(frame[2..].to_vec()),
        ]);
        let mut authority = LengthPrefixedJsonAuthority::new(&mut reader);

        assert_eq!(authority.read_message().unwrap(), JsonWireRead::WouldBlock);
        assert!(matches!(
            authority.read_message().unwrap(),
            JsonWireRead::Message(NetMessage::Hello(_))
        ));
    }

    #[test]
    fn framed_json_rejects_oversized_outbound_message() {
        let config = JsonWireConfig::builder()
            .max_frame_bytes(8)
            .build()
            .unwrap();
        let mut authority =
            LengthPrefixedJsonAuthority::with_config(Cursor::new(Vec::new()), config);

        assert!(matches!(
            authority.write_message(hello_message()),
            Err(JsonWireError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn framed_json_rejects_oversized_inbound_length_before_allocation() {
        let config = JsonWireConfig::builder()
            .max_frame_bytes(8)
            .build()
            .unwrap();
        let input = Cursor::new(64u32.to_be_bytes().to_vec());
        let mut authority = LengthPrefixedJsonAuthority::with_config(input, config);

        assert!(matches!(
            authority.read_message(),
            Err(JsonWireError::InvalidFrameLength { bytes: 64, max: 8 })
        ));
    }

    #[test]
    fn framed_json_reports_empty_stream_closed() {
        let mut authority = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));

        assert_eq!(authority.read_message().unwrap(), JsonWireRead::Closed);
    }

    #[test]
    fn config_rejects_unbounded_frame_size() {
        assert!(matches!(
            JsonWireConfig::builder().max_frame_bytes(0).build(),
            Err(JsonWireError::InvalidConfig(_))
        ));
        assert!(matches!(
            JsonWireConfig::builder()
                .max_frame_bytes(u32::MAX as usize + 1)
                .build(),
            Err(JsonWireError::InvalidConfig(_))
        ));
    }

    #[cfg(feature = "guest")]
    #[test]
    fn framed_json_implements_guest_authority_traits() {
        let message = hello_message();
        let mut authority = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));

        authority.send_message(message.clone()).unwrap();
        authority.inner_mut().set_position(0);

        assert_eq!(
            authority.receive_message().unwrap(),
            AuthorityRead::Message(message)
        );
    }

    #[derive(Debug)]
    enum ReadStep {
        Bytes(Vec<u8>),
        WouldBlock,
    }

    #[derive(Debug)]
    struct ScriptedIo {
        reads: VecDeque<ReadStep>,
        written: Vec<u8>,
    }

    impl ScriptedIo {
        fn new(reads: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                written: Vec::new(),
            }
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                Some(ReadStep::Bytes(bytes)) => {
                    let copied = bytes.len().min(buffer.len());
                    buffer[..copied].copy_from_slice(&bytes[..copied]);
                    if copied < bytes.len() {
                        self.reads
                            .push_front(ReadStep::Bytes(bytes[copied..].to_vec()));
                    }
                    Ok(copied)
                }
                Some(ReadStep::WouldBlock) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                None => Ok(0),
            }
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
