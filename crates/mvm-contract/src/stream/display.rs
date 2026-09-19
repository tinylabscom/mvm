//! View-only display frames and the signed-plan grant that exposes their
//! guest-to-host transport.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::plan::execution_plan::ExecutionPlan;
use crate::protocol::broker::ServiceId;

/// The plan service token that authorizes view-only display frames.
pub const DISPLAY_VIEW_GRANT_SERVICE: &str = "host.display.view.v1";

/// Guest-to-host vsock port used only by the display-frame bridge.
///
/// 5254 is telemetry, so display uses the next unprivileged port. The host
/// exposes this port only when the signed plan carries
/// [`DISPLAY_VIEW_GRANT_SERVICE`].
pub const DISPLAY_FRAME_PORT: u32 = 5255;

/// Largest encoded image body accepted from the guest.
pub const MAX_DISPLAY_FRAME_BYTES: usize = 2 * 1024 * 1024;

const MAX_STEP_ID_BYTES: usize = 256;
const DISPLAY_FRAME_VERSION: u8 = 1;
const DISPLAY_FRAME_PREFIX: u8 = 0x05;
const HEADER_BYTES: usize = 16;

/// Largest complete encoded frame accepted on the guest-to-host transport.
pub const MAX_ENCODED_DISPLAY_FRAME_BYTES: usize =
    HEADER_BYTES + MAX_STEP_ID_BYTES + MAX_DISPLAY_FRAME_BYTES;

/// Image encoding accepted from the screencast bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DisplayMime {
    Jpeg = 1,
    Png = 2,
}

impl DisplayMime {
    fn from_wire(value: u8) -> Result<Self, DisplayFrameError> {
        match value {
            1 => Ok(Self::Jpeg),
            2 => Ok(Self::Png),
            other => Err(DisplayFrameError::UnknownMime(other)),
        }
    }
}

/// One guest-to-host screencast frame, optionally bound to an agent step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DisplayFrame {
    pub step_id: Option<String>,
    pub mime: DisplayMime,
    pub width: u32,
    pub height: u32,
    pub bytes: Vec<u8>,
}

impl DisplayFrame {
    /// Encode a bounded binary frame without JSON-expanding the image bytes.
    pub fn encode(&self) -> Result<Vec<u8>, DisplayFrameError> {
        self.validate()?;
        let step = self.step_id.as_deref().unwrap_or_default().as_bytes();
        let step_len = u16::try_from(step.len()).map_err(|_| DisplayFrameError::StepTooLong)?;
        let body_len = u32::try_from(self.bytes.len()).map_err(|_| DisplayFrameError::TooLarge)?;
        let mut encoded = Vec::with_capacity(HEADER_BYTES + step.len() + self.bytes.len());
        encoded.push(DISPLAY_FRAME_VERSION);
        encoded.push(self.mime as u8);
        encoded.extend_from_slice(&step_len.to_be_bytes());
        encoded.extend_from_slice(&self.width.to_be_bytes());
        encoded.extend_from_slice(&self.height.to_be_bytes());
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(step);
        encoded.extend_from_slice(&self.bytes);
        Ok(encoded)
    }

    /// Decode one complete binary frame and reject trailing or oversized data.
    pub fn decode(encoded: &[u8]) -> Result<Self, DisplayFrameError> {
        let header = encoded
            .get(..HEADER_BYTES)
            .ok_or(DisplayFrameError::Truncated)?;
        if header[0] != DISPLAY_FRAME_VERSION {
            return Err(DisplayFrameError::UnsupportedVersion(header[0]));
        }
        let mime = DisplayMime::from_wire(header[1])?;
        let step_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let width = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let height = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        let body_len = usize::try_from(u32::from_be_bytes([
            header[12], header[13], header[14], header[15],
        ]))
        .map_err(|_| DisplayFrameError::TooLarge)?;
        if step_len > MAX_STEP_ID_BYTES || body_len > MAX_DISPLAY_FRAME_BYTES {
            return Err(if step_len > MAX_STEP_ID_BYTES {
                DisplayFrameError::StepTooLong
            } else {
                DisplayFrameError::TooLarge
            });
        }
        let expected = HEADER_BYTES
            .checked_add(step_len)
            .and_then(|size| size.checked_add(body_len))
            .ok_or(DisplayFrameError::TooLarge)?;
        if encoded.len() != expected {
            return Err(DisplayFrameError::LengthMismatch);
        }
        let step_end = HEADER_BYTES + step_len;
        let step_id = if step_len == 0 {
            None
        } else {
            Some(
                core::str::from_utf8(&encoded[HEADER_BYTES..step_end])
                    .map_err(|_| DisplayFrameError::InvalidStepId)?
                    .into(),
            )
        };
        let frame = Self {
            step_id,
            mime,
            width,
            height,
            bytes: encoded[step_end..].to_vec(),
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Domain-separated digest recorded by the stream chain.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([DISPLAY_FRAME_PREFIX]);
        hasher.update([self.mime as u8]);
        hasher.update(self.width.to_be_bytes());
        hasher.update(self.height.to_be_bytes());
        let step = self.step_id.as_deref().unwrap_or_default().as_bytes();
        hasher.update(u64::try_from(step.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(step);
        hasher.update(
            u64::try_from(self.bytes.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }

    fn validate(&self) -> Result<(), DisplayFrameError> {
        if self.width == 0 || self.height == 0 {
            return Err(DisplayFrameError::EmptyDimensions);
        }
        if self.bytes.is_empty() {
            return Err(DisplayFrameError::EmptyBody);
        }
        if self.bytes.len() > MAX_DISPLAY_FRAME_BYTES {
            return Err(DisplayFrameError::TooLarge);
        }
        if self.step_id.as_ref().is_some_and(|step| {
            step.is_empty() || step.len() > MAX_STEP_ID_BYTES || step.chars().any(char::is_control)
        }) {
            return Err(DisplayFrameError::InvalidStepId);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DisplayFrameError {
    #[error("display frame is truncated")]
    Truncated,
    #[error("display frame uses unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("display frame uses unknown image encoding {0}")]
    UnknownMime(u8),
    #[error("display frame length does not match its header")]
    LengthMismatch,
    #[error("display frame exceeds the byte limit")]
    TooLarge,
    #[error("display frame step id exceeds the byte limit")]
    StepTooLong,
    #[error("display frame step id is invalid")]
    InvalidStepId,
    #[error("display frame dimensions must be non-zero")]
    EmptyDimensions,
    #[error("display frame body must not be empty")]
    EmptyBody,
}

#[must_use]
pub fn grants_display_view_for(services: &[ServiceId]) -> bool {
    services
        .iter()
        .any(|service| service.as_str() == DISPLAY_VIEW_GRANT_SERVICE)
}

#[must_use]
pub fn grants_display_view(plan: &ExecutionPlan) -> bool {
    grants_display_view_for(&plan.services)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::plan::execution_plan::minimal_plan;
    use crate::stream::input::grants_input;

    fn sample() -> DisplayFrame {
        DisplayFrame {
            step_id: Some("step-7".into()),
            mime: DisplayMime::Jpeg,
            width: 1280,
            height: 720,
            bytes: vec![0xff, 0xd8, 0xff, 0xd9],
        }
    }

    #[test]
    fn frame_binary_round_trip_preserves_image_bytes() {
        let frame = sample();
        let encoded = frame.encode().expect("frame encodes");
        assert_eq!(DisplayFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn frame_json_round_trip_preserves_every_field() {
        let frame = sample();
        let encoded = serde_json::to_string(&frame).expect("frame serializes");
        let decoded: DisplayFrame = serde_json::from_str(&encoded).expect("frame deserializes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn frame_digest_covers_step_metadata_and_body() {
        let base = sample().digest();
        let mut changed = sample();
        changed.step_id = Some("step-8".into());
        assert_ne!(changed.digest(), base);
        changed = sample();
        changed.bytes.push(0);
        assert_ne!(changed.digest(), base);

        let mut first = sample();
        first.step_id = Some("a".into());
        first.bytes = vec![b'b', b'c'];
        let mut second = sample();
        second.step_id = Some("ab".into());
        second.bytes = vec![b'c'];
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn oversized_or_trailing_frames_are_refused() {
        let mut oversized = sample();
        oversized.bytes = vec![0; MAX_DISPLAY_FRAME_BYTES + 1];
        assert_eq!(oversized.encode(), Err(DisplayFrameError::TooLarge));

        let mut trailing = sample().encode().unwrap();
        trailing.push(0);
        assert_eq!(
            DisplayFrame::decode(&trailing),
            Err(DisplayFrameError::LengthMismatch)
        );
    }

    #[test]
    fn display_view_grant_opens_no_input_route() {
        let mut plan = minimal_plan();
        plan.services =
            vec![ServiceId::parse(DISPLAY_VIEW_GRANT_SERVICE).expect("display grant parses")];
        assert!(grants_display_view(&plan));
        assert!(!grants_input(&plan));
    }
}
