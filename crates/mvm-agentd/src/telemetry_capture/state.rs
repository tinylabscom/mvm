//! Process-wide capture identity and per-producer accounting.
//!
//! One epoch and one monotonic origin are minted at construction and shared by
//! every producer in the process; sessions restate them, they never remint per
//! session. Rotation replaces both together, so `monotonic_ns` always means
//! elapsed time since the current epoch began.

use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use mvm_core::net::telemetry::outbox::Outbox;
use mvm_core::protocol::telemetry::{ProducerEpoch, RecordError, SourceKind};

use super::emit::ShedReason;

/// Fixed guest producer table. Host-side gap detection keys on these numbers,
/// so each is assigned here once and never reused for another source. Only
/// agent diagnostics has a wired caller in this module; the stdio producers
/// are reserved for the pipe-capture adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerId {
    /// Guest-agent diagnostics emitted through the `tracing` facade.
    AgentDiagnostics,
    /// Workload stdout chunks (reserved, no producer wired here).
    Stdout,
    /// Workload stderr chunks (reserved, no producer wired here).
    Stderr,
}

impl ProducerId {
    /// Nonzero wire producer number, scoped to the process epoch.
    pub fn number(self) -> u32 {
        match self {
            Self::AgentDiagnostics => 1,
            Self::Stdout => 2,
            Self::Stderr => 3,
        }
    }

    /// Default declared source class for this producer. The host still checks
    /// the declared source against its own registration.
    pub fn default_source(self) -> SourceKind {
        match self {
            Self::AgentDiagnostics => SourceKind::GuestAgent,
            Self::Stdout | Self::Stderr => SourceKind::Stdio,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::AgentDiagnostics => 0,
            Self::Stdout => 1,
            Self::Stderr => 2,
        }
    }
}

const PRODUCER_COUNT: usize = 3;

/// Copyable records/bytes pair from one cumulative loss counter.
///
/// `bytes` counts canonical encoded bytes where the record was encoded before
/// it shed, and truncated-away bytes for truncation; a record refused before
/// encoding contributes zero bytes because none exist to count.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LossTally {
    /// Records (or, for truncation, affected values) lost at this stage.
    pub records: u64,
    /// Known lost bytes; zero when the loss happened before encoding.
    pub bytes: u64,
}

#[derive(Default)]
struct LossCell {
    records: AtomicU64,
    bytes: AtomicU64,
}

impl LossCell {
    fn add(&self, records: u64, bytes: u64) {
        self.records.fetch_add(records, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn snapshot(&self) -> LossTally {
        LossTally {
            records: self.records.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

/// Cumulative per-producer evidence. The shared outbox's own counters are
/// queue-global, so these are what attribute loss to a source. Concurrent
/// snapshots are approximate across fields; reading never resets anything.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SourceLosses {
    /// Emission attempts, including every shed one. This equals the last
    /// sequence number spent, which is what host-side gap detection needs.
    pub attempts: u64,
    /// Queue record/byte capacity exhaustion.
    pub capacity: LossTally,
    /// Non-waiting admission lost to a held queue lock.
    pub contention: LossTally,
    /// Closed or poisoned queue, or an unreadable epoch during rotation.
    pub unavailable: LossTally,
    /// Records refused before admission (oversize or unbuildable).
    pub rejected: LossTally,
    /// Values truncated or dropped by bounded field capture.
    pub truncated: LossTally,
}

#[derive(Default)]
struct SourceCounters {
    sequence: AtomicU64,
    capacity: LossCell,
    contention: LossCell,
    unavailable: LossCell,
    rejected: LossCell,
    truncated: LossCell,
}

struct EpochState {
    epoch: ProducerEpoch,
    origin: Instant,
}

/// Shared capture core: one process-wide epoch and monotonic origin, one
/// shared bounded outbox for every source, and per-producer attempt and shed
/// accounting. Producers only ever make non-waiting calls through it; the
/// draining cadence belongs to the transport worker that owns the outbox.
pub struct CaptureState {
    epoch: RwLock<EpochState>,
    outbox: Arc<Outbox>,
    counters: [SourceCounters; PRODUCER_COUNT],
}

impl CaptureState {
    /// Mint the process epoch and monotonic origin over one shared queue.
    /// Fails only if the runtime RNG returns the reserved all-zero epoch.
    pub fn new(outbox: Arc<Outbox>) -> Result<Self, RecordError> {
        Ok(Self {
            epoch: RwLock::new(mint_epoch()?),
            outbox,
            counters: Default::default(),
        })
    }

    /// Replace the epoch and its monotonic origin for a generation change
    /// (for example after restore). Sessions restate the current epoch; only
    /// this hook remints it. Emissions racing the swap shed with counted loss
    /// instead of waiting for it.
    pub fn rotate_epoch(&self) -> Result<(), RecordError> {
        let fresh = mint_epoch()?;
        let mut state = self.epoch.write().map_err(|_| RecordError::Invalid)?;
        *state = fresh;
        Ok(())
    }

    /// Snapshot one producer's cumulative attempt and loss evidence.
    pub fn losses(&self, producer: ProducerId) -> SourceLosses {
        let counters = &self.counters[producer.index()];
        SourceLosses {
            attempts: counters.sequence.load(Ordering::Relaxed),
            capacity: counters.capacity.snapshot(),
            contention: counters.contention.snapshot(),
            unavailable: counters.unavailable.snapshot(),
            rejected: counters.rejected.snapshot(),
            truncated: counters.truncated.snapshot(),
        }
    }

    /// Count values a bounded capture path truncated or dropped. Callers pass
    /// the number of affected values and the bytes known to be lost.
    pub fn record_truncation(&self, producer: ProducerId, values: u64, bytes: u64) {
        if values > 0 || bytes > 0 {
            self.counters[producer.index()].truncated.add(values, bytes);
        }
    }

    /// Spend the next attempt sequence number. Every attempt spends one,
    /// shed or delivered, so host-side gap detection stays truthful.
    pub(super) fn next_sequence(&self, producer: ProducerId) -> u64 {
        self.counters[producer.index()]
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Read the current epoch and elapsed nanoseconds without waiting.
    /// `None` means a rotation holds the lock (or poisoned it); the caller
    /// sheds with counted loss rather than blocking an instrumented path.
    pub(super) fn identity_now(&self) -> Option<(ProducerEpoch, u64)> {
        let state = self.epoch.try_read().ok()?;
        let elapsed = u64::try_from(state.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Some((state.epoch, elapsed))
    }

    pub(super) fn count_shed(&self, producer: ProducerId, reason: ShedReason, bytes: u64) {
        let counters = &self.counters[producer.index()];
        let cell = match reason {
            ShedReason::Capacity => &counters.capacity,
            ShedReason::Contention => &counters.contention,
            ShedReason::Unavailable => &counters.unavailable,
            ShedReason::Rejected => &counters.rejected,
        };
        cell.add(1, bytes);
    }

    pub(super) fn outbox(&self) -> &Outbox {
        &self.outbox
    }
}

fn mint_epoch() -> Result<EpochState, RecordError> {
    // The workspace RNG is the same cryptographically seeded generator the
    // guest's key-material paths use; the all-zero value is reserved invalid.
    let epoch = ProducerEpoch::new(rand::random::<[u8; 16]>())?;
    Ok(EpochState {
        epoch,
        origin: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_numbers_and_sources_follow_the_fixed_table() {
        for (producer, number, source) in [
            (ProducerId::AgentDiagnostics, 1, SourceKind::GuestAgent),
            (ProducerId::Stdout, 2, SourceKind::Stdio),
            (ProducerId::Stderr, 3, SourceKind::Stdio),
        ] {
            assert_eq!(producer.number(), number);
            assert_eq!(producer.default_source(), source);
        }
    }

    #[test]
    fn sequences_are_per_producer_and_start_at_one() {
        let outbox = Arc::new(Outbox::new(4, 4 * 32 * 1024).unwrap());
        let state = CaptureState::new(outbox).unwrap();
        assert_eq!(state.next_sequence(ProducerId::AgentDiagnostics), 1);
        assert_eq!(state.next_sequence(ProducerId::AgentDiagnostics), 2);
        assert_eq!(state.next_sequence(ProducerId::Stdout), 1);
        assert_eq!(state.losses(ProducerId::AgentDiagnostics).attempts, 2);
        assert_eq!(state.losses(ProducerId::Stdout).attempts, 1);
        assert_eq!(state.losses(ProducerId::Stderr).attempts, 0);
    }

    #[test]
    fn truncation_accounting_is_per_producer_and_skips_empty_reports() {
        let outbox = Arc::new(Outbox::new(1, 32 * 1024).unwrap());
        let state = CaptureState::new(outbox).unwrap();
        state.record_truncation(ProducerId::AgentDiagnostics, 2, 100);
        state.record_truncation(ProducerId::AgentDiagnostics, 0, 0);
        let losses = state.losses(ProducerId::AgentDiagnostics);
        assert_eq!(
            losses.truncated,
            LossTally {
                records: 2,
                bytes: 100
            }
        );
        assert_eq!(
            state.losses(ProducerId::Stdout).truncated,
            LossTally::default()
        );
    }
}
