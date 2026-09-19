//! Allocation regression for the prepared-record admission boundary.
//! Preparation and queue construction intentionally happen outside measurement.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use mvm_core::{
    net::telemetry::outbox::{Offer, Outbox, PreparedRecord},
    protocol::telemetry::{
        CoverageState, MAX_RECORD_BYTES, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    allocations: usize,
    reallocations: usize,
    deallocations: usize,
}

thread_local! {
    // Const, destructor-free TLS avoids allocating during allocator observation.
    static MEASUREMENT: Cell<Option<Counts>> = const { Cell::new(None) };
}

fn count(update: impl FnOnce(&mut Counts)) {
    let _ = MEASUREMENT.try_with(|measurement| {
        if let Some(mut counts) = measurement.get() {
            update(&mut counts);
            measurement.set(Some(counts));
        }
    });
}

struct ObservedSystem;

// SAFETY: every operation forwards the caller's unchanged allocation contract
// to System. Observation touches only destructor-free thread-local counters;
// it never changes, dereferences, retains or frees an allocation itself.
unsafe impl GlobalAlloc for ObservedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(|c| c.allocations += 1);
        // SAFETY: GlobalAlloc's caller supplies a valid, nonzero layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(|c| c.allocations += 1);
        // SAFETY: the layout and zero-initialization contract are unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(|c| c.reallocations += 1);
        // SAFETY: ptr/layout identify a live System allocation and the caller
        // supplies the required nonzero new size; nothing is altered here.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(|c| c.deallocations += 1);
        // SAFETY: ptr/layout are forwarded exactly once to their allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedSystem = ObservedSystem;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, Counts) {
    MEASUREMENT.with(|m| m.set(Some(Counts::default())));
    let result = operation();
    let counts = MEASUREMENT.with(|m| m.replace(None).unwrap());
    (result, counts)
}

#[test]
fn first_offer_full_offer_loss_read_and_close_do_not_allocate_or_free() {
    let record = TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).unwrap())
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state: CoverageState::Started,
            code: "allocation-witness".try_into().unwrap(),
        })
        .build()
        .unwrap();
    let record = PreparedRecord::new(&record).unwrap();
    let queue = Outbox::new(1, MAX_RECORD_BYTES).unwrap();

    let (offer, counts) = measured(|| queue.offer(&record));
    assert_eq!(offer, Offer::Queued);
    assert_eq!(counts, Counts::default(), "cold first offer");
    let (offer, counts) = measured(|| queue.offer(&record));
    assert_eq!(offer, Offer::Full);
    assert_eq!(counts, Counts::default(), "full queue");
    let (losses, counts) = measured(|| queue.losses());
    assert_eq!(losses.capacity.records, 1);
    assert_eq!(counts, Counts::default(), "loss observation");
    let ((), counts) = measured(|| queue.close());
    assert_eq!(counts, Counts::default(), "admission close");
    let (offer, counts) = measured(|| queue.offer(&record));
    assert_eq!(offer, Offer::Closed);
    assert_eq!(counts, Counts::default(), "closed queue");
}

#[test]
fn fresh_producer_threads_do_not_initialize_or_allocate_queue_storage() {
    let record = TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).unwrap())
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state: CoverageState::Started,
            code: "thread-allocation-witness".try_into().unwrap(),
        })
        .build()
        .unwrap();
    let record = std::sync::Arc::new(PreparedRecord::new(&record).unwrap());
    let queue = std::sync::Arc::new(Outbox::new(2, 2 * MAX_RECORD_BYTES).unwrap());
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let queue = std::sync::Arc::clone(&queue);
            let record = std::sync::Arc::clone(&record);
            std::thread::spawn(move || measured(|| queue.offer(&record)))
        })
        .collect();
    let mut contended = 0;
    for producer in threads {
        let (result, counts) = producer.join().unwrap();
        assert_eq!(counts, Counts::default(), "fresh producer thread");
        assert!(matches!(result, Offer::Queued | Offer::Contended));
        if result == Offer::Contended {
            contended += 1;
        }
    }
    assert!(
        contended < 2,
        "at least one producer must own the queue lock"
    );
    assert_eq!(queue.losses().contention.records, contended);
}
