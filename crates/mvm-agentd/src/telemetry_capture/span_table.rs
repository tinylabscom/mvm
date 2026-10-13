//! Fixed-capacity active-span table behind the capture subscriber.
//!
//! Every slot is preallocated when the table is built and nothing grows
//! afterwards, so the number of spans capture tracks at once is a constant.
//! No operation here waits: a slot's lifecycle is one packed atomic word
//! changed only by compare-and-swap, a slot another thread is mid-way through
//! claiming is skipped rather than awaited, and there is no lock at all.
//!
//! A tracing span id names a slot *at a generation*. Every claim bumps the
//! slot's generation, so an id kept past its span's close can never alias the
//! span that reused the slot: every lookup compares generations first.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};

use mvm_core::trace_context::{SpanId, TraceContext, TraceId};

/// Slots in the table the guest agent installs.
pub(super) const DEFAULT_SPAN_SLOTS: usize = 256;

/// Low 31 bits of a slot word: outstanding references (handles) to the span.
const REFS_MASK: u64 = 0x7FFF_FFFF;
/// Bit 31: claimed and being written; not yet visible as a live span.
const RESERVED: u64 = 1 << 31;

/// A span id whose low half is zero never names a slot. Spans capture could
/// not track — the table was full, or the epoch was mid-rotation — all share
/// it, so later callbacks recognise them and produce nothing for them.
pub(super) const UNTRACKED_SPAN: u64 = 1 << 32;

fn pack(generation: u32, low: u64) -> u64 {
    (u64::from(generation) << 32) | low
}

fn generation_of(word: u64) -> u32 {
    (word >> 32) as u32
}

fn refs_of(word: u64) -> u64 {
    word & REFS_MASK
}

fn is_reserved(word: u64) -> bool {
    word & RESERVED != 0
}

/// One slot at one generation: what a tracked tracing span id encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SlotRef {
    index: u32,
    generation: u32,
}

impl SlotRef {
    /// Nonzero tracing id bits: generation in the high half, index plus one
    /// in the low half.
    pub(super) fn id_bits(self) -> u64 {
        pack(self.generation, u64::from(self.index) + 1)
    }

    /// Decode id bits for a table of `slots`; `None` for the untracked id or
    /// anything naming no slot.
    pub(super) fn from_id_bits(bits: u64, slots: usize) -> Option<Self> {
        let low = bits & 0xFFFF_FFFF;
        if low == 0 || low > slots as u64 {
            return None;
        }
        Some(Self {
            index: (low - 1) as u32,
            generation: generation_of(bits),
        })
    }
}

/// What dropping one reference did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Release {
    /// The id named no live span (closed, reused or never tracked).
    Stale,
    /// Other references remain; the span is still open.
    Retained,
    /// That was the last reference: the slot is free again.
    Closed {
        /// The span that closed.
        context: TraceContext,
        /// Whether an `error` field was recorded on it.
        failed: bool,
    },
}

#[derive(Default)]
struct Slot {
    /// Generation (high 32 bits), reserved flag, reference count.
    word: AtomicU64,
    trace_high: AtomicU64,
    trace_low: AtomicU64,
    span: AtomicU64,
    failed: AtomicBool,
}

/// The preallocated table. See the module documentation.
pub(super) struct SpanTable {
    slots: Box<[Slot]>,
    /// Where the next claim starts scanning, so claims spread over the table
    /// instead of all contending for its first free slot.
    cursor: AtomicUsize,
}

impl SpanTable {
    /// Preallocate `slots` slots (at least one).
    pub(super) fn with_slots(slots: usize) -> Self {
        let slots = slots.max(1);
        Self {
            slots: (0..slots).map(|_| Slot::default()).collect(),
            cursor: AtomicUsize::new(0),
        }
    }

    pub(super) fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Claim a free slot for `context`, holding one reference. One pass over
    /// the table at most; a slot another thread is changing is skipped, never
    /// awaited. `None` means no slot was free on this pass.
    pub(super) fn open(&self, context: TraceContext) -> Option<SlotRef> {
        let count = self.slots.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        (0..count).find_map(|step| self.try_claim((start + step) % count, context))
    }

    fn try_claim(&self, index: usize, context: TraceContext) -> Option<SlotRef> {
        let slot = &self.slots[index];
        let word = slot.word.load(Ordering::Acquire);
        if refs_of(word) != 0 || is_reserved(word) {
            return None;
        }
        let generation = generation_of(word).wrapping_add(1);
        slot.word
            .compare_exchange(
                word,
                pack(generation, RESERVED),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .ok()?;
        // Writer half of the sequence lock `context` reads under: the claim
        // above is the "being written" mark, the release below publishes.
        fence(Ordering::Release);
        let trace = context.trace_id.0;
        slot.trace_high.store(
            u64::from_be_bytes(trace[..8].try_into().unwrap_or_default()),
            Ordering::Relaxed,
        );
        slot.trace_low.store(
            u64::from_be_bytes(trace[8..].try_into().unwrap_or_default()),
            Ordering::Relaxed,
        );
        slot.span
            .store(u64::from_be_bytes(context.span_id.0), Ordering::Relaxed);
        slot.failed.store(false, Ordering::Relaxed);
        slot.word.store(pack(generation, 1), Ordering::Release);
        Some(SlotRef {
            index: index as u32,
            generation,
        })
    }

    fn live(&self, slot: SlotRef) -> Option<(&Slot, u64)> {
        let entry = self.slots.get(slot.index as usize)?;
        let word = entry.word.load(Ordering::Acquire);
        let live =
            generation_of(word) == slot.generation && !is_reserved(word) && refs_of(word) > 0;
        live.then_some((entry, word))
    }

    /// The live span's context, or `None` for a stale or untracked slot.
    pub(super) fn context(&self, slot: SlotRef) -> Option<TraceContext> {
        let (entry, _) = self.live(slot)?;
        let context = read_context(entry);
        // Reader half of the sequence lock: the context is only trusted if
        // the slot was not reclaimed while it was read. Reference counts may
        // move meanwhile; the ids change only under a new generation.
        fence(Ordering::Acquire);
        let after = entry.word.load(Ordering::Relaxed);
        (generation_of(after) == slot.generation && !is_reserved(after)).then_some(context)
    }

    /// Mark the live span failed; its close then reports an error outcome.
    pub(super) fn mark_failed(&self, slot: SlotRef) {
        if let Some((entry, _)) = self.live(slot) {
            entry.failed.store(true, Ordering::Relaxed);
        }
    }

    /// Add a reference to a live span. `false` for a stale id.
    ///
    /// A count that reaches the field's ceiling stays there: the span is then
    /// pinned open and its slot is never reclaimed, which costs one slot and
    /// cannot close a span early.
    pub(super) fn retain(&self, slot: SlotRef) -> bool {
        loop {
            let Some((entry, word)) = self.live(slot) else {
                return false;
            };
            if refs_of(word) == REFS_MASK {
                return true;
            }
            // Lock-free: a failed exchange means another thread changed the
            // word, so the retry observes progress rather than waiting on it.
            if entry
                .word
                .compare_exchange(word, word + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Drop one reference; the last one frees the slot.
    pub(super) fn release(&self, slot: SlotRef) -> Release {
        loop {
            let Some((entry, word)) = self.live(slot) else {
                return Release::Stale;
            };
            let refs = refs_of(word);
            if refs == REFS_MASK {
                return Release::Retained;
            }
            if refs > 1 {
                if entry
                    .word
                    .compare_exchange(word, word - 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return Release::Retained;
                }
                continue;
            }
            // The last reference is this caller's, so nothing can reclaim the
            // slot before the exchange below: the context read is stable.
            let context = read_context(entry);
            let failed = entry.failed.load(Ordering::Relaxed);
            if entry
                .word
                .compare_exchange(
                    word,
                    pack(slot.generation, 0),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Release::Closed { context, failed };
            }
        }
    }

    /// Live spans right now; for tests and diagnostics.
    #[cfg(test)]
    pub(super) fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| refs_of(slot.word.load(Ordering::Acquire)) > 0)
            .count()
    }
}

fn read_context(slot: &Slot) -> TraceContext {
    let mut trace = [0u8; 16];
    trace[..8].copy_from_slice(&slot.trace_high.load(Ordering::Relaxed).to_be_bytes());
    trace[8..].copy_from_slice(&slot.trace_low.load(Ordering::Relaxed).to_be_bytes());
    TraceContext::new(
        TraceId(trace),
        SpanId(slot.span.load(Ordering::Relaxed).to_be_bytes()),
    )
}

/// Mints nonzero trace and span ids without an RNG call: the producer epoch
/// is already a fresh random value per process incarnation, and a counter
/// makes every id within it distinct. Drawing from the system RNG here could
/// block in early boot, before the kernel's generator is seeded, which no
/// instrumented callback may do.
#[derive(Default)]
pub(super) struct IdSource {
    counter: AtomicU64,
}

impl IdSource {
    /// A fresh span context: a child of `parent`'s trace, or a new trace.
    pub(super) fn mint(&self, epoch: [u8; 16], parent: Option<TraceId>) -> TraceContext {
        let high = u64::from_be_bytes(epoch[..8].try_into().unwrap_or_default());
        let low = u64::from_be_bytes(epoch[8..].try_into().unwrap_or_default());
        loop {
            let n = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            // `mix` is a bijection, so distinct counters give distinct ids;
            // exactly one counter value maps to the reserved zero, skipped.
            let span = mix(high ^ low ^ n);
            if span == 0 {
                continue;
            }
            let trace_id = parent.unwrap_or_else(|| {
                let mut trace = [0u8; 16];
                trace[..8].copy_from_slice(&(high ^ mix(n)).to_be_bytes());
                // Injective in `n`, so roots within one epoch never share a
                // trace; the epoch half separates incarnations.
                trace[8..].copy_from_slice(&low.wrapping_add(n).to_be_bytes());
                TraceId(trace)
            });
            if trace_id.0 == [0; 16] {
                continue;
            }
            return TraceContext::new(trace_id, SpanId(span.to_be_bytes()));
        }
    }
}

/// The SplitMix64 finalizer: a bijection on `u64` that scatters counters.
fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn context(n: u8) -> TraceContext {
        TraceContext::new(TraceId([n; 16]), SpanId([n; 8]))
    }

    #[test]
    fn a_claimed_slot_reads_back_its_context_and_frees_on_the_last_release() {
        let table = SpanTable::with_slots(2);
        let slot = table.open(context(7)).unwrap();
        assert_eq!(table.context(slot), Some(context(7)));
        assert!(table.retain(slot));
        assert_eq!(table.release(slot), Release::Retained);
        assert_eq!(table.live_count(), 1);
        assert_eq!(
            table.release(slot),
            Release::Closed {
                context: context(7),
                failed: false
            }
        );
        assert_eq!(table.live_count(), 0);
        assert_eq!(table.context(slot), None);
    }

    #[test]
    fn an_id_kept_past_its_close_never_aliases_the_slots_next_span() {
        let table = SpanTable::with_slots(1);
        let first = table.open(context(1)).unwrap();
        assert!(matches!(table.release(first), Release::Closed { .. }));
        let second = table.open(context(2)).unwrap();
        assert_ne!(first.id_bits(), second.id_bits());
        assert_eq!(table.context(first), None);
        assert!(!table.retain(first));
        assert_eq!(table.release(first), Release::Stale);
        assert_eq!(table.context(second), Some(context(2)));
    }

    #[test]
    fn a_full_table_refuses_a_claim_instead_of_growing() {
        let table = SpanTable::with_slots(2);
        assert!(table.open(context(1)).is_some());
        assert!(table.open(context(2)).is_some());
        assert!(table.open(context(3)).is_none());
        assert_eq!(table.capacity(), 2);
    }

    #[test]
    fn a_failure_mark_is_reported_at_close_and_cleared_on_reuse() {
        let table = SpanTable::with_slots(1);
        let slot = table.open(context(1)).unwrap();
        table.mark_failed(slot);
        assert_eq!(
            table.release(slot),
            Release::Closed {
                context: context(1),
                failed: true
            }
        );
        let next = table.open(context(2)).unwrap();
        assert!(matches!(
            table.release(next),
            Release::Closed { failed: false, .. }
        ));
    }

    #[test]
    fn id_bits_round_trip_and_the_untracked_id_names_no_slot() {
        let slot = SlotRef {
            index: 3,
            generation: 9,
        };
        assert_eq!(SlotRef::from_id_bits(slot.id_bits(), 4), Some(slot));
        assert_eq!(SlotRef::from_id_bits(slot.id_bits(), 3), None);
        assert_eq!(SlotRef::from_id_bits(UNTRACKED_SPAN, 4), None);
        assert_ne!(slot.id_bits(), 0);
    }

    #[test]
    fn minted_ids_are_nonzero_distinct_and_children_keep_their_trace() {
        let ids = IdSource::default();
        let epoch = [0x5a; 16];
        let mut spans = HashSet::new();
        let mut traces = HashSet::new();
        for _ in 0..10_000 {
            let context = ids.mint(epoch, None);
            assert_ne!(context.span_id.0, [0; 8]);
            assert_ne!(context.trace_id.0, [0; 16]);
            assert!(spans.insert(context.span_id));
            assert!(traces.insert(context.trace_id));
        }
        let root = ids.mint(epoch, None);
        let child = ids.mint(epoch, Some(root.trace_id));
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
    }
}
