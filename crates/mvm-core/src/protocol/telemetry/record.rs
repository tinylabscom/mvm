use std::{io, num::NonZeroU32, num::NonZeroU64};

use serde::{Deserialize, Serialize};

use super::{
    MAX_RECORD_BYTES, MAX_RECORD_DEPTH, ProducerEpoch, RecordBody, RecordError, SourceKind,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Format {
    #[serde(rename = "mvm.telemetry.v1")]
    V1,
}

/// One validated observation. VM/tenant/boot identity is deliberately absent:
/// the host stamps it from the authenticated connection's runtime registration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryRecord {
    format: Format,
    epoch: ProducerEpoch,
    producer: NonZeroU32,
    sequence: NonZeroU64,
    monotonic_ns: u64,
    source: SourceKind,
    body: RecordBody,
}

impl TelemetryRecord {
    /// Start construction with no implicit producer identity or record body.
    pub fn builder() -> TelemetryRecordBuilder {
        TelemetryRecordBuilder::default()
    }
    /// Producer incarnation (not authoritative VM identity).
    pub fn epoch(&self) -> ProducerEpoch {
        self.epoch
    }
    /// Local producer number, scoped to its epoch and host registration.
    pub fn producer(&self) -> u32 {
        self.producer.get()
    }
    /// Monotonic producer sequence including attempts shed before delivery.
    pub fn sequence(&self) -> u64 {
        self.sequence.get()
    }
    /// Guest monotonic timestamp, not trusted wall time.
    pub fn monotonic_ns(&self) -> u64 {
        self.monotonic_ns
    }
    /// Declared source, still subject to host registration/policy.
    pub fn source(&self) -> SourceKind {
        self.source
    }
    /// Borrow the closed record body.
    pub fn body(&self) -> &RecordBody {
        &self.body
    }

    /// Worker-side encoding with a bounded output allocation. Not a producer API.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut output = BoundedOutput(Vec::new());
        serde_json::to_writer(&mut output, self).map_err(|_| RecordError::Capacity)?;
        Ok(output.0)
    }

    /// Decode one size-bounded record, discarding parser errors that may quote data.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::Capacity);
        }
        check_depth(bytes)?;
        serde_json::from_slice(bytes).map_err(|_| RecordError::Invalid)
    }
}

// Check nesting before serde's tagged-enum buffering can allocate unknown values.
// JSON syntax and UTF-8 validity remain the deserializer's responsibility.
fn check_depth(bytes: &[u8]) -> Result<(), RecordError> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_RECORD_DEPTH {
                        return Err(RecordError::Capacity);
                    }
                }
                b']' | b'}' => depth = depth.checked_sub(1).ok_or(RecordError::Invalid)?,
                _ => {}
            }
        }
    }
    Ok(())
}

struct BoundedOutput(Vec<u8>);
impl io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Builder for an observation; all identity fields and the body are required.
#[derive(Debug, Default)]
pub struct TelemetryRecordBuilder {
    epoch: Option<ProducerEpoch>,
    producer: Option<NonZeroU32>,
    sequence: Option<NonZeroU64>,
    monotonic_ns: u64,
    source: Option<SourceKind>,
    body: Option<RecordBody>,
}
impl TelemetryRecordBuilder {
    /// Set the fresh process/restore incarnation.
    pub fn epoch(mut self, value: ProducerEpoch) -> Self {
        self.epoch = Some(value);
        self
    }
    /// Set the nonzero producer number assigned within the epoch.
    pub fn producer(mut self, value: u32) -> Self {
        self.producer = NonZeroU32::new(value);
        self
    }
    /// Set the nonzero attempt sequence, never a transport ACK counter.
    pub fn sequence(mut self, value: u64) -> Self {
        self.sequence = NonZeroU64::new(value);
        self
    }
    /// Set elapsed monotonic nanoseconds since the producer epoch began.
    pub fn monotonic_ns(mut self, value: u64) -> Self {
        self.monotonic_ns = value;
        self
    }
    /// Set the declared source class.
    pub fn source(mut self, value: SourceKind) -> Self {
        self.source = Some(value);
        self
    }
    /// Set the signal body.
    pub fn body(mut self, value: RecordBody) -> Self {
        self.body = Some(value);
        self
    }
    /// Refuse incomplete identities or a missing body.
    pub fn build(self) -> Result<TelemetryRecord, RecordError> {
        Ok(TelemetryRecord {
            format: Format::V1,
            epoch: self.epoch.ok_or(RecordError::Identity)?,
            producer: self.producer.ok_or(RecordError::Identity)?,
            sequence: self.sequence.ok_or(RecordError::Identity)?,
            monotonic_ns: self.monotonic_ns,
            source: self.source.ok_or(RecordError::Identity)?,
            body: self.body.ok_or(RecordError::Invalid)?,
        })
    }
}
