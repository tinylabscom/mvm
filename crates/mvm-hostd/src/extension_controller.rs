//! Blocking stream adapter for the generic optional-extension controller frame.
//!
//! This module owns transport only. It never interprets a campaign, selects a
//! binary, or grants authority. A concrete controller receives bounded payload
//! bytes and must parse its own versioned typed contract before doing work.

use std::io::{ErrorKind, Read, Write};

use anyhow::{Context, Result};
use mvm_contract::protocol::extension_controller::{
    DEFAULT_MAX_PAYLOAD_BYTES, ExtensionFrame, ExtensionFrameError, ExtensionMessageKind,
    ExtensionSequenceValidator, HEADER_BYTES, decode_extension_frame, encode_extension_frame,
};

/// Narrow behavior hosted behind a generic extension-controller stream.
pub trait ExtensionControllerHandler {
    /// Strict `mvm.extension.descriptor/v1` JSON bytes.
    fn descriptor(&self) -> Result<Vec<u8>>;
    /// Execute one typed request. Implementations parse and validate before any
    /// effect and return a typed response document.
    fn start(&self, payload: &[u8]) -> Result<Vec<u8>>;
    /// Bind separately supplied operator authority to a later typed request.
    /// Implementations that do not expose sessions refuse by default.
    fn open_session(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("extension controller does not accept operator sessions")
    }
    /// Cancel the exact active request. The payload must itself be a bounded,
    /// identity-only contract understood by the extension.
    fn cancel(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

/// Serve one controller stream until shutdown or clean EOF.
pub fn serve_extension_controller(
    reader: &mut impl Read,
    writer: &mut impl Write,
    maximum_payload_bytes: usize,
    handler: &dyn ExtensionControllerHandler,
) -> Result<()> {
    let maximum = maximum_payload_bytes.min(DEFAULT_MAX_PAYLOAD_BYTES);
    let mut incoming = ExtensionSequenceValidator::default();
    let mut response_sequence = 1u64;
    loop {
        let frame = match read_extension_frame(reader, maximum) {
            Ok(frame) => frame,
            Err(StreamFrameError::Io(error)) if error.kind() == ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        incoming
            .observe(frame.sequence)
            .context("validating extension-controller request sequence")?;
        let (kind, payload, stop) = match frame.kind {
            ExtensionMessageKind::Hello | ExtensionMessageKind::Describe => {
                (ExtensionMessageKind::Describe, handler.descriptor(), false)
            }
            ExtensionMessageKind::Start => (
                ExtensionMessageKind::Complete,
                handler.start(&frame.payload),
                false,
            ),
            ExtensionMessageKind::OpenSession => (
                ExtensionMessageKind::Complete,
                handler.open_session(&frame.payload),
                false,
            ),
            ExtensionMessageKind::Cancel => (
                ExtensionMessageKind::Complete,
                handler.cancel(&frame.payload),
                false,
            ),
            ExtensionMessageKind::Shutdown => (
                ExtensionMessageKind::Complete,
                Ok(br#"{"status":"shutdown"}"#.to_vec()),
                true,
            ),
            ExtensionMessageKind::ValidateConfig
            | ExtensionMessageKind::Plan
            | ExtensionMessageKind::Progress
            | ExtensionMessageKind::Observation
            | ExtensionMessageKind::Finding
            | ExtensionMessageKind::ArtifactReady
            | ExtensionMessageKind::Complete
            | ExtensionMessageKind::Error => (
                ExtensionMessageKind::Error,
                Err(anyhow::anyhow!("unsupported controller message")),
                false,
            ),
        };
        let (kind, payload) = match payload {
            Ok(payload) => (kind, payload),
            Err(error) => (
                ExtensionMessageKind::Error,
                serde_json::to_vec(&ControllerErrorResponse {
                    error: sanitize_error(&error),
                })
                .context("encoding extension-controller error")?,
            ),
        };
        write_extension_frame(
            writer,
            &ExtensionFrame {
                kind,
                sequence: response_sequence,
                payload,
            },
            maximum,
        )?;
        response_sequence = response_sequence.saturating_add(1);
        if stop {
            return Ok(());
        }
    }
}

#[derive(serde::Serialize)]
struct ControllerErrorResponse {
    error: String,
}

fn sanitize_error(error: &anyhow::Error) -> String {
    let message = error.to_string();
    let bounded: String = message
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect();
    if bounded.is_empty() {
        "extension controller refused request".to_string()
    } else {
        bounded
    }
}

#[derive(Debug, thiserror::Error)]
enum StreamFrameError {
    #[error("extension-controller I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] ExtensionFrameError),
}

fn read_extension_frame(
    reader: &mut impl Read,
    maximum: usize,
) -> Result<ExtensionFrame, StreamFrameError> {
    let mut header = [0u8; HEADER_BYTES];
    reader.read_exact(&mut header)?;
    let announced = usize::try_from(u32::from_be_bytes(
        header[16..20]
            .try_into()
            .expect("fixed-width payload length slice"),
    ))
    .expect("u32 fits in usize on supported hosts");
    if announced > maximum {
        return Err(ExtensionFrameError::PayloadTooLarge { announced, maximum }.into());
    }
    let mut encoded = Vec::with_capacity(HEADER_BYTES.saturating_add(announced));
    encoded.extend_from_slice(&header);
    encoded.resize(HEADER_BYTES.saturating_add(announced), 0);
    reader.read_exact(&mut encoded[HEADER_BYTES..])?;
    let (frame, consumed) = decode_extension_frame(&encoded, maximum)?;
    if consumed != encoded.len() {
        return Err(ExtensionFrameError::DigestMismatch.into());
    }
    Ok(frame)
}

fn write_extension_frame(
    writer: &mut impl Write,
    frame: &ExtensionFrame,
    maximum: usize,
) -> Result<(), StreamFrameError> {
    let encoded = encode_extension_frame(frame, maximum)?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TypedFixture;

    impl ExtensionControllerHandler for TypedFixture {
        fn descriptor(&self) -> Result<Vec<u8>> {
            Ok(br#"{"schema":"mvm.extension.descriptor/v1","id":"org.example.fixture"}"#.to_vec())
        }

        fn start(&self, payload: &[u8]) -> Result<Vec<u8>> {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                schema: String,
                request_id: String,
            }
            let request: Request = serde_json::from_slice(payload)?;
            if request.schema != "example.request/v1" {
                anyhow::bail!("unsupported typed request schema");
            }
            Ok(serde_json::to_vec(&serde_json::json!({
                "schema": "example.response/v1",
                "request_id": request.request_id
            }))?)
        }

        fn cancel(&self, payload: &[u8]) -> Result<Vec<u8>> {
            if payload != br#"{"request_id":"request-1"}"# {
                anyhow::bail!("cancellation identity mismatch");
            }
            Ok(br#"{"status":"canceled"}"#.to_vec())
        }
    }

    fn request(kind: ExtensionMessageKind, sequence: u64, payload: &[u8]) -> Vec<u8> {
        encode_extension_frame(
            &ExtensionFrame {
                kind,
                sequence,
                payload: payload.to_vec(),
            },
            4096,
        )
        .expect("encode request")
    }

    #[test]
    fn sibling_compatible_stream_describes_starts_and_shuts_down() {
        let mut input = request(ExtensionMessageKind::Hello, 1, &[]);
        input.extend(request(
            ExtensionMessageKind::Start,
            2,
            br#"{"schema":"example.request/v1","request_id":"request-1"}"#,
        ));
        input.extend(request(ExtensionMessageKind::Shutdown, 3, &[]));
        let mut output = Vec::new();
        serve_extension_controller(&mut Cursor::new(input), &mut output, 4096, &TypedFixture)
            .expect("serve");

        let (describe, first) = decode_extension_frame(&output, 4096).expect("describe");
        assert_eq!(describe.kind, ExtensionMessageKind::Describe);
        assert_eq!(describe.sequence, 1);
        let (complete, second) = decode_extension_frame(&output[first..], 4096).expect("complete");
        assert_eq!(complete.kind, ExtensionMessageKind::Complete);
        assert_eq!(complete.sequence, 2);
        assert!(
            String::from_utf8(complete.payload)
                .expect("UTF-8")
                .contains("request-1")
        );
        let (shutdown, third) =
            decode_extension_frame(&output[first + second..], 4096).expect("shutdown");
        assert_eq!(shutdown.kind, ExtensionMessageKind::Complete);
        assert_eq!(first + second + third, output.len());
    }

    #[test]
    fn malformed_typed_request_is_a_bounded_error_and_replay_fails_closed() {
        let input = request(
            ExtensionMessageKind::Start,
            1,
            br#"{"schema":"example.request/v1","request_id":"request-1","command":"sh"}"#,
        );
        let mut output = Vec::new();
        serve_extension_controller(&mut Cursor::new(input), &mut output, 4096, &TypedFixture)
            .expect("typed refusal is a protocol response");
        let (error, _) = decode_extension_frame(&output, 4096).expect("error");
        assert_eq!(error.kind, ExtensionMessageKind::Error);
        assert!(error.payload.len() <= 1024);

        let mut replay = request(ExtensionMessageKind::Hello, 2, &[]);
        replay.extend(request(ExtensionMessageKind::Hello, 2, &[]));
        let failure = serve_extension_controller(
            &mut Cursor::new(replay),
            &mut Vec::new(),
            4096,
            &TypedFixture,
        )
        .expect_err("replayed sequence");
        assert!(failure.to_string().contains("sequence"));
    }

    #[test]
    fn announced_oversize_is_rejected_before_payload_read() {
        let mut encoded = request(ExtensionMessageKind::Start, 1, b"small");
        encoded[16..20].copy_from_slice(&4096_u32.to_be_bytes());
        let error = serve_extension_controller(
            &mut Cursor::new(encoded),
            &mut Vec::new(),
            32,
            &TypedFixture,
        )
        .expect_err("oversize");
        assert!(error.to_string().contains("too large"));
    }
}
