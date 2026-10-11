//! Caller-visible output, distinct from redacted audit records and telemetry.

use mvm_contract::stream::StreamKind;

/// One chunk on the guest's original channel. These are protocol result bytes,
/// not diagnostics: callers must not redact or reinterpret them as telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownChunk {
    pub kind: StreamKind,
    pub body: Vec<u8>,
    pub recorded: RecordedCopy,
}

/// How the independently recorded copy differs from the caller's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedCopy {
    NotRecorded,
    Identical,
    Masked { rules_fired: Vec<&'static str> },
    Withheld { reason: String },
}

impl ShownChunk {
    pub(super) fn from_capture(chunk: mvm_hostd::stream::ShownChunk) -> Self {
        let recorded = match chunk.recorded {
            mvm_hostd::stream::RecordedCopy::NotRecorded => RecordedCopy::NotRecorded,
            mvm_hostd::stream::RecordedCopy::Identical => RecordedCopy::Identical,
            mvm_hostd::stream::RecordedCopy::Masked { rules_fired } => {
                RecordedCopy::Masked { rules_fired }
            }
            mvm_hostd::stream::RecordedCopy::Withheld { reason } => {
                RecordedCopy::Withheld { reason }
            }
        };
        Self {
            kind: chunk.kind,
            body: chunk.body,
            recorded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withheld_record_keeps_guest_channel_and_protocol_bytes() {
        let body = vec![0, 255, b'\n'];
        let shown = ShownChunk::from_capture(mvm_hostd::stream::ShownChunk {
            kind: StreamKind::Stderr,
            body: body.clone(),
            recorded: mvm_hostd::stream::RecordedCopy::Withheld {
                reason: "detector unavailable".into(),
            },
        });
        assert_eq!(shown.kind, StreamKind::Stderr);
        assert_eq!(shown.body, body);
        assert!(matches!(shown.recorded, RecordedCopy::Withheld { .. }));
    }
}
