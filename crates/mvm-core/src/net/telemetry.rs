//! Dedicated, authenticated telemetry transport for worker threads.
//!
//! These operations perform bounded allocations and blocking I/O. They must not
//! run in a tracing callback or on a control/exit/audit connection. The supervisor
//! supplies I/O deadlines and binds the expected guest key to its VM generation;
//! record payloads never choose that identity. Queue admission is a separate layer.

use std::io::{Read, Write};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::protocol::telemetry::{MAX_RECORD_BYTES, RecordError, TelemetryRecord};

use super::session::{Session, SessionError, read_sealed_frame, write_sealed_frame};

pub mod outbox;

const SESSION_PREFIX: &str = "mvm.telemetry.v1.";
// Binary metadata is length-bounded (three u8 strings, u16 signature), with a
// fixed Ed25519 signature and GCM tag. This leaves room for the legal envelope.
const MAX_SEALED_BYTES: usize = MAX_RECORD_BYTES + 1024;

/// Payload-free failures; underlying parsers can quote hostile input so their
/// error strings are deliberately not retained as sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    /// Handshake failed or the peer did not match the pinned identity/service.
    #[error("telemetry peer authentication failed")]
    Authentication,
    /// Invalid, oversized or unauthenticated frame. The connection is terminal.
    #[error("telemetry frame rejected; reconnect required")]
    Rejected,
    /// An I/O failure or peer hangup leaves delivery of the tail unknown.
    #[error("telemetry transport failed; delivery tail unknown")]
    Transport,
    /// Calls on a failed connection never continue its sequence or framing state.
    #[error("telemetry connection is closed")]
    Closed,
    /// Locally invalid records do not spend a transport sequence number.
    #[error(transparent)]
    Record(#[from] RecordError),
}

/// Guest worker's one-way sender. Emission never waits for application ACKs.
/// The worker can wait for socket I/O, so producers must hand off non-waitingly.
pub struct TelemetrySender {
    session: Option<Session>,
}

impl TelemetrySender {
    /// Authenticate the pinned host using the shared cryptographic handshake.
    pub fn connect<S: Read + Write>(
        stream: &mut S,
        guest_key: SigningKey,
        host_anchor: &VerifyingKey,
    ) -> Result<Self, TelemetryError> {
        let (session, id) = Session::guest(stream, guest_key, host_anchor)
            .map_err(|_| TelemetryError::Authentication)?;
        if !id.starts_with(SESSION_PREFIX) {
            return Err(TelemetryError::Authentication);
        }
        Ok(Self {
            session: Some(session),
        })
    }

    /// Encrypt/sign one bounded record and send without reading an ACK.
    /// A partial write invalidates the session; never retry a spent sequence.
    pub fn send(
        &mut self,
        stream: &mut impl Write,
        record: &TelemetryRecord,
    ) -> Result<(), TelemetryError> {
        if self.session.is_none() {
            return Err(TelemetryError::Closed);
        }
        let prepared = outbox::PreparedRecord::new(record)?;
        self.send_prepared(stream, &prepared)
    }

    /// Worker-only send of a validated, prepared record; no decode/re-encode.
    pub fn send_prepared(
        &mut self,
        stream: &mut impl Write,
        record: &outbox::PreparedRecord,
    ) -> Result<(), TelemetryError> {
        let mut session = self.session.take().ok_or(TelemetryError::Closed)?;
        let frame = session
            .seal(record.bytes())
            .map_err(|_| TelemetryError::Rejected)?;
        write_sealed_frame(stream, &frame).map_err(|_| TelemetryError::Transport)?;
        self.session = Some(session);
        Ok(())
    }

    /// Worker-only: send at most one queued record. A stalled write owns no queue
    /// lock, and loss counters survive a failed write. The runtime owns readiness,
    /// I/O deadlines and cancellation; emitting threads never call this method.
    pub fn send_next(
        &mut self,
        stream: &mut impl Write,
        queue: &outbox::Outbox,
    ) -> Result<bool, TelemetryError> {
        if self.session.is_none() {
            return Err(TelemetryError::Closed);
        }
        let Some(record) = queue.take()? else {
            return Ok(false);
        };
        if let Err(error) = self.send_prepared(stream, &record) {
            queue.failed_transport(&record);
            return Err(error);
        }
        Ok(true)
    }
}

/// Host worker receiver, bound to an externally registered guest key.
/// No constructor accepts an already-open, potentially wrong-role session.
pub struct TelemetryReceiver {
    session: Option<Session>,
}

impl TelemetryReceiver {
    /// Establish a fresh session and pin the guest identity before any ingestion.
    /// The expected key must come from runtime registration, never guest data.
    pub fn connect<S: Read + Write>(
        stream: &mut S,
        host_key: SigningKey,
        expected_guest: &VerifyingKey,
    ) -> Result<Self, TelemetryError> {
        let id = format!("{SESSION_PREFIX}{}", uuid::Uuid::new_v4());
        let (session, peer) =
            Session::host(stream, &id, host_key).map_err(|_| TelemetryError::Authentication)?;
        if &peer != expected_guest {
            return Err(TelemetryError::Authentication);
        }
        Ok(Self {
            session: Some(session),
        })
    }

    /// Read one encrypted record with a frame ceiling checked before allocation.
    /// Any failure is terminal, including partial reads and invalid record bodies.
    pub fn receive(&mut self, stream: &mut impl Read) -> Result<TelemetryRecord, TelemetryError> {
        let mut session = self.session.take().ok_or(TelemetryError::Closed)?;
        let frame = read_sealed_frame(stream, MAX_SEALED_BYTES).map_err(|error| {
            if matches!(error, SessionError::Io(_)) {
                TelemetryError::Transport
            } else {
                TelemetryError::Rejected
            }
        })?;
        let plaintext = session.open(&frame).map_err(|_| TelemetryError::Rejected)?;
        let record = TelemetryRecord::decode(&plaintext).map_err(|_| TelemetryError::Rejected)?;
        self.session = Some(session);
        Ok(record)
    }
}

#[cfg(all(test, unix))]
mod tests;
