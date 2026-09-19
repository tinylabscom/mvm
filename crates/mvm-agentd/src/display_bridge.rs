//! View-only CDP screencast bridge.
//!
//! The bridge constructs the four CDP messages it needs itself. Nothing read
//! from the host is ever forwarded to Chrome, so this is not a raw DevTools
//! tunnel: a caller cannot turn the display path into `Runtime.evaluate`,
//! cookie mutation, request interception, or input dispatch.

use std::io::{self, BufRead, Write};

use base64::Engine as _;
use mvm_contract::stream::{DisplayFrame, DisplayFrameError, DisplayMime};
use serde_json::{Value, json};
use thiserror::Error;

const PAGE_ENABLE_ID: u64 = 1;
const START_SCREENCAST_ID: u64 = 2;
const FIRST_ACK_ID: u64 = 3;
const MAX_CDP_MESSAGE_BYTES: usize = 3 * 1024 * 1024;

/// The only CDP methods this bridge can issue.
pub const ALLOWED_CDP_METHODS: &[&str] = &[
    CdpMethod::Enable.as_str(),
    CdpMethod::StartScreencast.as_str(),
    CdpMethod::ScreencastFrameAck.as_str(),
    CdpMethod::StopScreencast.as_str(),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CdpMethod {
    Enable,
    StartScreencast,
    ScreencastFrameAck,
    StopScreencast,
}

impl CdpMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "Page.enable",
            Self::StartScreencast => "Page.startScreencast",
            Self::ScreencastFrameAck => "Page.screencastFrameAck",
            Self::StopScreencast => "Page.stopScreencast",
        }
    }
}

/// A parsed frame and the fixed acknowledgement Chrome expects for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgedFrame {
    pub frame: DisplayFrame,
    pub acknowledgement: Vec<u8>,
}

/// Stateful method filter for one screencast session.
#[derive(Debug)]
pub struct CdpScreencastBridge {
    step_id: Option<String>,
    next_ack_id: u64,
}

impl CdpScreencastBridge {
    #[must_use]
    pub fn new(step_id: Option<String>) -> Self {
        Self {
            step_id,
            next_ack_id: FIRST_ACK_ID,
        }
    }

    /// Fixed setup messages for a JPEG screencast. The caller writes these to
    /// Chrome's remote-debugging pipe; no arbitrary method enters here.
    pub fn setup_messages() -> [Vec<u8>; 2] {
        [
            encode_cdp(PAGE_ENABLE_ID, CdpMethod::Enable, json!({})),
            encode_cdp(
                START_SCREENCAST_ID,
                CdpMethod::StartScreencast,
                json!({"format": "jpeg", "quality": 75, "everyNthFrame": 1}),
            ),
        ]
    }

    /// Extract only `Page.screencastFrame` events. Command responses and other
    /// Chrome-originated events are discarded and never reach either output.
    pub fn handle_message(&mut self, encoded: &[u8]) -> Result<Option<BridgedFrame>, BridgeError> {
        let message: Value = serde_json::from_slice(encoded).map_err(BridgeError::InvalidCdp)?;
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Ok(None);
        };
        if method != "Page.screencastFrame" {
            return Ok(None);
        }
        let params = message
            .get("params")
            .ok_or(BridgeError::MissingField("params"))?;
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_u64)
            .ok_or(BridgeError::MissingField("sessionId"))?;
        let data = params
            .get("data")
            .and_then(Value::as_str)
            .ok_or(BridgeError::MissingField("data"))?;
        let metadata = params
            .get("metadata")
            .ok_or(BridgeError::MissingField("metadata"))?;
        let width = dimension(metadata, "deviceWidth")?;
        let height = dimension(metadata, "deviceHeight")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(BridgeError::InvalidBase64)?;
        let frame = DisplayFrame {
            step_id: self.step_id.clone(),
            mime: DisplayMime::Jpeg,
            width,
            height,
            bytes,
        };
        // Encode once here to run the shared bounds and shape validation
        // before anything reaches the host transport.
        frame.encode().map_err(BridgeError::InvalidFrame)?;
        let acknowledgement = encode_cdp(
            self.next_ack_id,
            CdpMethod::ScreencastFrameAck,
            json!({"sessionId": session_id}),
        );
        self.next_ack_id = self.next_ack_id.saturating_add(1);
        Ok(Some(BridgedFrame {
            frame,
            acknowledgement,
        }))
    }
}

/// Write one length-prefixed frame to the host-only display transport.
pub fn write_frame(mut writer: impl Write, frame: &DisplayFrame) -> Result<(), BridgeError> {
    let encoded = frame.encode().map_err(BridgeError::InvalidFrame)?;
    let length = u32::try_from(encoded.len()).map_err(|_| BridgeError::FrameTooLarge)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    Ok(())
}

/// Run one fixed-method screencast session over Chrome's NUL-framed remote
/// debugging pipe and the guest-to-host display stream.
///
/// The host side is write-only here. Commands sent to Chrome are constructed
/// locally and cannot be supplied by the host, which is the boundary that
/// keeps the display stream from becoming a raw debugging tunnel.
pub fn bridge_session(
    mut cdp_reader: impl BufRead,
    mut cdp_writer: impl Write,
    mut host_writer: impl Write,
    step_id: Option<String>,
) -> Result<(), BridgeError> {
    for setup in CdpScreencastBridge::setup_messages() {
        write_cdp(&mut cdp_writer, &setup)?;
    }
    let mut bridge = CdpScreencastBridge::new(step_id);
    loop {
        let mut message = Vec::new();
        let limit = u64::try_from(MAX_CDP_MESSAGE_BYTES + 1).expect("CDP limit fits u64");
        let read = std::io::Read::take(&mut cdp_reader, limit).read_until(0, &mut message)?;
        if read == 0 {
            return Ok(());
        }
        if message.len() > MAX_CDP_MESSAGE_BYTES {
            return Err(BridgeError::CdpMessageTooLarge);
        }
        if message.last() != Some(&0) {
            return Err(BridgeError::TruncatedCdpMessage);
        }
        message.pop();
        if let Some(bridged) = bridge.handle_message(&message)? {
            write_frame(&mut host_writer, &bridged.frame)?;
            write_cdp(&mut cdp_writer, &bridged.acknowledgement)?;
        }
    }
}

fn write_cdp(writer: &mut impl Write, message: &[u8]) -> Result<(), BridgeError> {
    writer.write_all(message)?;
    writer.write_all(&[0])?;
    writer.flush()?;
    Ok(())
}

fn dimension(metadata: &Value, field: &'static str) -> Result<u32, BridgeError> {
    let value = metadata
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BridgeError::MissingField(field))?;
    u32::try_from(value).map_err(|_| BridgeError::InvalidDimension(field))
}

fn encode_cdp(id: u64, method: CdpMethod, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"id": id, "method": method.as_str(), "params": params}))
        .expect("fixed CDP command serializes")
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid CDP message: {0}")]
    InvalidCdp(serde_json::Error),
    #[error("CDP screencast event is missing {0}")]
    MissingField(&'static str),
    #[error("CDP screencast event has an invalid {0}")]
    InvalidDimension(&'static str),
    #[error("CDP screencast frame is not valid base64: {0}")]
    InvalidBase64(base64::DecodeError),
    #[error("CDP screencast frame is invalid: {0}")]
    InvalidFrame(DisplayFrameError),
    #[error("CDP screencast frame exceeds the transport length")]
    FrameTooLarge,
    #[error("CDP message exceeds the bridge byte limit")]
    CdpMessageTooLarge,
    #[error("CDP pipe ended in the middle of a message")]
    TruncatedCdpMessage,
    #[error("writing display frame: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(method: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "method": method,
            "params": {
                "sessionId": 9,
                "data": base64::engine::general_purpose::STANDARD.encode([1, 2, 3]),
                "metadata": {"deviceWidth": 800, "deviceHeight": 600}
            }
        }))
        .unwrap()
    }

    #[test]
    fn the_bridge_issues_only_the_fixed_method_allow_list() {
        for encoded in CdpScreencastBridge::setup_messages() {
            let command: Value = serde_json::from_slice(&encoded).unwrap();
            let method = command["method"].as_str().unwrap();
            assert!(ALLOWED_CDP_METHODS.contains(&method));
        }
    }

    #[test]
    fn a_non_frame_cdp_message_is_discarded_instead_of_forwarded() {
        let mut bridge = CdpScreencastBridge::new(None);
        assert_eq!(
            bridge.handle_message(&event("Runtime.evaluate")).unwrap(),
            None
        );
    }

    #[test]
    fn a_screencast_frame_is_bounded_and_bound_to_the_agent_step() {
        let mut bridge = CdpScreencastBridge::new(Some("agent-step-3".into()));
        let bridged = bridge
            .handle_message(&event("Page.screencastFrame"))
            .unwrap()
            .expect("frame event");
        assert_eq!(bridged.frame.step_id.as_deref(), Some("agent-step-3"));
        assert_eq!(bridged.frame.bytes, [1, 2, 3]);
        let ack: Value = serde_json::from_slice(&bridged.acknowledgement).unwrap();
        assert_eq!(ack["method"], "Page.screencastFrameAck");
        assert_eq!(ack["params"]["sessionId"], 9);
    }

    #[test]
    fn host_wire_is_one_length_prefixed_frame() {
        let mut bridge = CdpScreencastBridge::new(None);
        let frame = bridge
            .handle_message(&event("Page.screencastFrame"))
            .unwrap()
            .unwrap()
            .frame;
        let mut wire = Vec::new();
        write_frame(&mut wire, &frame).unwrap();
        let length = usize::try_from(u32::from_be_bytes(wire[..4].try_into().unwrap())).unwrap();
        assert_eq!(length, wire.len() - 4);
        assert_eq!(DisplayFrame::decode(&wire[4..]).unwrap(), frame);
    }

    #[test]
    fn a_pipe_session_constructs_setup_and_ack_messages_and_only_writes_frames_hostward() {
        let mut input = event("Page.screencastFrame");
        input.push(0);
        let mut cdp_output = Vec::new();
        let mut host_output = Vec::new();
        bridge_session(
            std::io::Cursor::new(input),
            &mut cdp_output,
            &mut host_output,
            Some("step-pipe".into()),
        )
        .unwrap();

        let commands = cdp_output
            .split(|byte| *byte == 0)
            .filter(|message| !message.is_empty())
            .map(|message| serde_json::from_slice::<Value>(message).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0]["method"], "Page.enable");
        assert_eq!(commands[1]["method"], "Page.startScreencast");
        assert_eq!(commands[2]["method"], "Page.screencastFrameAck");
        let length =
            usize::try_from(u32::from_be_bytes(host_output[..4].try_into().unwrap())).unwrap();
        let frame = DisplayFrame::decode(&host_output[4..4 + length]).unwrap();
        assert_eq!(frame.step_id.as_deref(), Some("step-pipe"));
    }

    #[test]
    fn an_unterminated_cdp_message_is_bounded_before_allocation_can_grow() {
        let oversized = vec![b'x'; MAX_CDP_MESSAGE_BYTES + 1];
        let error = bridge_session(
            std::io::Cursor::new(oversized),
            Vec::new(),
            Vec::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(error, BridgeError::CdpMessageTooLarge));
    }
}
