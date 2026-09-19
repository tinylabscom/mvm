//! Bounded, non-waiting handoff between prepared records and a transport worker.
//!
//! Preparation is an allocating adapter operation, not a tracing callback API.
//! Once prepared, admission only copies bounded bytes with one `try_lock` attempt.
//! Runtime source adapters still need bounded capture before this boundary.

use std::{
    fmt,
    sync::{
        Mutex, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use crate::protocol::telemetry::{MAX_RECORD_BYTES, RecordError, TelemetryRecord};

/// One validated, canonical wire record. Construction may allocate; admission
/// borrows it, so neither rejection nor success destroys caller-owned storage.
pub struct PreparedRecord {
    bytes: Vec<u8>,
}

impl PreparedRecord {
    /// Apply source policy before preparing a record. Structural validation alone
    /// is not a redaction policy. Call outside latency-sensitive callbacks.
    pub fn new(record: &TelemetryRecord) -> Result<Self, RecordError> {
        Ok(Self {
            bytes: record.encode()?,
        })
    }

    /// Encoded size, excluding the encrypted transport envelope.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Valid records are never empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for PreparedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedRecord")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}

/// Outcome of one admission attempt. Rejected records remain caller-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Offer {
    /// Copied into owned queue storage, not acknowledged by the host.
    Queued,
    /// Record or byte capacity exhausted.
    Full,
    /// Another thread owns the queue. No lock wait or retry was attempted.
    Contended,
    /// Supervisor closed admission. Existing records may still be drained.
    Closed,
    /// A poisoned queue cannot be trusted.
    Unavailable,
}

/// Cumulative loss/failure evidence, not an acknowledgement or a delivery claim.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LossCount {
    /// Records rejected at this stage, or uncertain writes for transport evidence.
    pub records: u64,
    /// Canonical plaintext bytes, not encrypted frame bytes.
    pub bytes: u64,
}

/// Independent cumulative counters remain available even when the queue is full
/// or locked. Concurrent snapshots are approximate across fields; after producers
/// and the transport worker stop, they are exact unless `counts_overflowed` is
/// true. Reading never resets
/// them, so a failed loss-summary send cannot erase local accounting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LossSnapshot {
    /// Queue count/byte exhaustion.
    pub capacity: LossCount,
    /// Non-waiting admission lost to contention.
    pub contention: LossCount,
    /// Closed or poisoned queue.
    pub unavailable: LossCount,
    /// Popped records whose write failed: attempted bytes/records, not a claim
    /// that the host received none of them. See `transport_tail_unknown`.
    pub transport: LossCount,
    /// At least one counter wrapped; counts are incomplete, never silently exact.
    pub counts_overflowed: bool,
    /// Partial transport writes leave the delivered tail unknowable.
    pub transport_tail_unknown: bool,
    /// A poisoned queue may contain records that can no longer be drained.
    pub queue_tail_unknown: bool,
}

#[derive(Default)]
struct Counters {
    records: AtomicU64,
    bytes: AtomicU64,
}

impl Counters {
    fn add(&self, bytes: usize, overflow: &AtomicBool) {
        // Single atomic operations, not CAS retry loops. All callers supply a
        // validated record length, so conversion is bounded on every platform.
        let bytes = u64::try_from(bytes).expect("telemetry record length fits u64");
        let records_before = self.records.fetch_add(1, Ordering::Relaxed);
        let bytes_before = self.bytes.fetch_add(bytes, Ordering::Relaxed);
        if records_before == u64::MAX || bytes_before > u64::MAX - bytes {
            overflow.store(true, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> LossCount {
        LossCount {
            records: self.records.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

struct Slot {
    bytes: [u8; MAX_RECORD_BYTES],
    len: usize,
}

struct State {
    slots: Box<[Slot]>,
    head: usize,
    len: usize,
    bytes: usize,
}

/// Fixed-storage queue for one supervised telemetry worker. Construction reserves
/// at most 256 × 32 KiB plus slot metadata; records cannot bring excess `Vec`
/// capacity into the queue. Byte admission may be stricter than reserved storage.
///
/// `offer` does no allocation, deallocation, formatting, I/O, blocking lock,
/// notification or retry. Worker readiness must be wired by the runtime owner;
/// this type does not introduce a polling thread or a teardown join.
pub struct Outbox {
    state: Mutex<State>,
    closed: AtomicBool,
    byte_limit: usize,
    capacity: Counters,
    contention: Counters,
    unavailable: Counters,
    transport: Counters,
    overflow: AtomicBool,
    transport_tail_unknown: AtomicBool,
    queue_tail_unknown: AtomicBool,
}

impl Outbox {
    /// Reserve bounded storage before exposing the queue to producers.
    /// Reject zero limits, more than 256 slots, or a byte limit beyond storage.
    pub fn new(records: usize, bytes: usize) -> Result<Self, RecordError> {
        if !(1..=256).contains(&records) || bytes == 0 || bytes > records * MAX_RECORD_BYTES {
            return Err(RecordError::Capacity);
        }
        let slots = (0..records)
            .map(|_| Slot {
                bytes: [0; MAX_RECORD_BYTES],
                len: 0,
            })
            .collect();
        let state = Mutex::new(State {
            slots,
            head: 0,
            len: 0,
            bytes: 0,
        });
        // Some platforms lazily allocate their native mutex on its first lock.
        // Pay that cost during setup, before any producer can call try_lock.
        drop(state.lock().map_err(|_| RecordError::Invalid)?);
        Ok(Self {
            state,
            closed: AtomicBool::new(false),
            byte_limit: bytes,
            capacity: Counters::default(),
            contention: Counters::default(),
            unavailable: Counters::default(),
            transport: Counters::default(),
            overflow: AtomicBool::new(false),
            transport_tail_unknown: AtomicBool::new(false),
            queue_tail_unknown: AtomicBool::new(false),
        })
    }

    /// Make exactly one admission attempt. Caller identity/sequence and source
    /// policy are established before preparation; this queue never rewrites them.
    pub fn offer(&self, record: &PreparedRecord) -> Offer {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                self.contention.add(record.len(), &self.overflow);
                return Offer::Contended;
            }
            Err(TryLockError::Poisoned(_)) => {
                self.queue_tail_unknown.store(true, Ordering::Relaxed);
                self.unavailable.add(record.len(), &self.overflow);
                return Offer::Unavailable;
            }
        };
        if self.closed.load(Ordering::Acquire) {
            self.unavailable.add(record.len(), &self.overflow);
            return Offer::Closed;
        }
        if state.len == state.slots.len() || record.len() > self.byte_limit - state.bytes {
            self.capacity.add(record.len(), &self.overflow);
            return Offer::Full;
        }
        let index = (state.head + state.len) % state.slots.len();
        let slot = &mut state.slots[index];
        slot.bytes[..record.len()].copy_from_slice(record.bytes());
        slot.len = record.len();
        state.bytes += record.len();
        state.len += 1;
        Offer::Queued
    }

    /// Worker-only pop. Allocates an owned bounded record and releases the queue
    /// lock before any crypto or I/O. Poison is a terminal worker error.
    pub(super) fn take(&self) -> Result<Option<PreparedRecord>, RecordError> {
        let mut state = self.state.lock().map_err(|_| {
            self.queue_tail_unknown.store(true, Ordering::Relaxed);
            RecordError::Invalid
        })?;
        if state.len == 0 {
            return Ok(None);
        }
        let head = state.head;
        let slot = &mut state.slots[head];
        let record = PreparedRecord {
            bytes: slot.bytes[..slot.len].to_vec(),
        };
        slot.bytes[..slot.len].fill(0);
        slot.len = 0;
        state.bytes -= record.len();
        state.len -= 1;
        state.head = (head + 1) % state.slots.len();
        Ok(Some(record))
    }

    /// Close admission without a lock, flush, worker join or socket access.
    /// Offers already past the closed check can finish; their records remain
    /// drainable. The owner schedules cancellation independently of this flag.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Read cumulative loss evidence without queue locks or destructive drains.
    pub fn losses(&self) -> LossSnapshot {
        LossSnapshot {
            capacity: self.capacity.snapshot(),
            contention: self.contention.snapshot(),
            unavailable: self.unavailable.snapshot(),
            transport: self.transport.snapshot(),
            counts_overflowed: self.overflow.load(Ordering::Relaxed),
            transport_tail_unknown: self.transport_tail_unknown.load(Ordering::Relaxed),
            queue_tail_unknown: self.queue_tail_unknown.load(Ordering::Relaxed),
        }
    }

    pub(super) fn failed_transport(&self, record: &PreparedRecord) {
        self.transport.add(record.len(), &self.overflow);
        self.transport_tail_unknown.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
