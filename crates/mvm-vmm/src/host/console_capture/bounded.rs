//! Bounded, lossy handoff from a synchronous UART to its capture owner.
//!
//! No storage or encryption runs on the producer. Successful writes mean
//! accepted by this lossy sink, not persisted; the owner must record loss.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

/// Maximum work and copied bytes in one `write` call.
pub const CHUNK_BYTES: usize = 512;
/// Fixed queue capacity: 128 KiB of payload, allocated before guest execution.
const QUEUE_CHUNKS: usize = 256;

/// A fixed-size message; neither sending nor receiving allocates its payload.
pub struct Chunk {
    bytes: [u8; CHUNK_BYTES],
    len: usize,
}

impl Chunk {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

/// Monotonic producer counters. Read after producer drop for a coherent total.
/// Only the uniquely owned, non-cloneable producer writes these counters;
/// consumers can neither reset nor mutate them, including during rotation.
#[derive(Default)]
pub struct Counters {
    accepted_bytes: AtomicU64,
    accepted_chunks: AtomicU64,
    dropped_bytes: AtomicU64,
    dropped_chunks: AtomicU64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub accepted_bytes: u64,
    pub accepted_chunks: u64,
    pub dropped_bytes: u64,
    pub dropped_chunks: u64,
}

impl Snapshot {
    /// At saturation the totals are lower bounds, not proof of completeness.
    /// A sealing owner must mark capture incomplete if this returns true.
    pub fn is_saturated(&self) -> bool {
        [
            self.accepted_bytes,
            self.accepted_chunks,
            self.dropped_bytes,
            self.dropped_chunks,
        ]
        .contains(&u64::MAX)
    }
}

impl Counters {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            accepted_bytes: self.accepted_bytes.load(Ordering::Relaxed),
            accepted_chunks: self.accepted_chunks.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            dropped_chunks: self.dropped_chunks.load(Ordering::Relaxed),
        }
    }
}

/// A nonblocking `Write` endpoint. Full and disconnected queues consume and
/// explicitly count loss rather than asking the UART to retry or abandon it.
pub struct Producer {
    sender: SyncSender<Chunk>,
    counters: Arc<Counters>,
    totals: Snapshot,
}

pub struct Consumer {
    pub receiver: Receiver<Chunk>,
    pub counters: Arc<Counters>,
}

pub fn channel() -> (Producer, Consumer) {
    channel_with_capacity(QUEUE_CHUNKS)
}

fn channel_with_capacity(capacity: usize) -> (Producer, Consumer) {
    let (sender, receiver) = mpsc::sync_channel(capacity);
    let counters = Arc::new(Counters::default());
    (
        Producer {
            sender,
            counters: Arc::clone(&counters),
            totals: Snapshot::default(),
        },
        Consumer { receiver, counters },
    )
}

impl Write for Producer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = bytes.len().min(CHUNK_BYTES);
        if len == 0 {
            return Ok(0);
        }
        let mut chunk = Chunk {
            bytes: [0; CHUNK_BYTES],
            len,
        };
        chunk.bytes[..len].copy_from_slice(&bytes[..len]);
        // There is one producer, so saturating locally then publishing avoids
        // wrapping totals without a compare-exchange retry loop on the vCPU.
        match self.sender.try_send(chunk) {
            Ok(()) => {
                self.totals.accepted_chunks = self.totals.accepted_chunks.saturating_add(1);
                self.totals.accepted_bytes = self.totals.accepted_bytes.saturating_add(len as u64);
                self.counters
                    .accepted_chunks
                    .store(self.totals.accepted_chunks, Ordering::Relaxed);
                self.counters
                    .accepted_bytes
                    .store(self.totals.accepted_bytes, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.totals.dropped_chunks = self.totals.dropped_chunks.saturating_add(1);
                self.totals.dropped_bytes = self.totals.dropped_bytes.saturating_add(len as u64);
                self.counters
                    .dropped_chunks
                    .store(self.totals.dropped_chunks, Ordering::Relaxed);
                self.counters
                    .dropped_bytes
                    .store(self.totals.dropped_bytes, Ordering::Relaxed);
            }
        }
        Ok(len)
    }

    /// A producer flush never waits for a consumer or claims storage durability.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn uart_handoff_keeps_a_partial_final_line() {
        use crate::vmm::device::{MmioDevice, Pl011};
        let (producer, consumer) = channel();
        let mut uart = Pl011::new(0);
        uart.stream_to(Box::new(producer));
        for byte in b"synthetic console marker" {
            uart.write(0, u64::from(*byte), 1);
        }
        drop(uart);
        assert_eq!(
            consumer.receiver.recv().unwrap().as_bytes(),
            b"synthetic console marker"
        );
        assert!(consumer.receiver.recv().is_err());
        assert_eq!(consumer.counters.snapshot().dropped_bytes, 0);
    }

    #[test]
    fn error_unwind_flushes_the_uart_before_owner_drain() {
        use crate::vmm::device::{MmioDevice, Pl011};
        let (producer, consumer) = channel();
        let result = std::panic::catch_unwind(move || {
            let mut uart = Pl011::new(0);
            uart.stream_to(Box::new(producer));
            for byte in b"partial" {
                uart.write(0, u64::from(*byte), 1);
            }
            panic!("synthetic shutdown failure");
        });
        assert!(result.is_err());
        assert_eq!(consumer.receiver.recv().unwrap().as_bytes(), b"partial");
        assert!(consumer.receiver.recv().is_err());
    }

    #[test]
    fn totals_saturate_without_wraparound_or_payload_diagnostics() {
        let (mut producer, consumer) = channel_with_capacity(1);
        producer.totals.accepted_bytes = u64::MAX;
        producer.totals.accepted_chunks = u64::MAX;
        producer.totals.dropped_bytes = u64::MAX;
        producer.totals.dropped_chunks = u64::MAX;
        producer.write_all(b"sensitive marker").unwrap();
        producer.write_all(b"sensitive marker").unwrap();
        let counts = consumer.counters.snapshot();
        assert_eq!(counts.accepted_bytes, u64::MAX);
        assert_eq!(counts.accepted_chunks, u64::MAX);
        assert_eq!(counts.dropped_bytes, u64::MAX);
        assert_eq!(counts.dropped_chunks, u64::MAX);
        assert!(counts.is_saturated());
        assert!(!format!("{counts:?}").contains("sensitive marker"));
    }

    #[test]
    fn full_queue_recovers_without_disabling_the_sink() {
        let (mut producer, consumer) = channel_with_capacity(1);
        producer.write_all(b"first").unwrap();
        producer.write_all(b"shed").unwrap();
        assert_eq!(consumer.receiver.recv().unwrap().as_bytes(), b"first");
        producer.write_all(b"last").unwrap();
        assert_eq!(consumer.receiver.recv().unwrap().as_bytes(), b"last");
        assert_eq!(consumer.counters.snapshot().dropped_bytes, 4);
        assert_eq!(consumer.counters.snapshot().accepted_bytes, 9);
    }

    #[test]
    fn partial_writes_bound_work_and_preserve_bytes() {
        let (mut producer, consumer) = channel_with_capacity(2);
        let bytes = [42; CHUNK_BYTES + 3];
        assert_eq!(producer.write(&bytes).unwrap(), CHUNK_BYTES);
        producer.write_all(&bytes[CHUNK_BYTES..]).unwrap();
        assert_eq!(producer.write(&[]).unwrap(), 0);
        producer.flush().unwrap();
        drop(producer);
        let received: Vec<_> = consumer.receiver.iter().collect();
        assert_eq!(received[0].as_bytes(), &bytes[..CHUNK_BYTES]);
        assert_eq!(received[1].as_bytes(), &bytes[CHUNK_BYTES..]);
        assert_eq!(
            consumer.counters.snapshot(),
            Snapshot {
                accepted_bytes: (CHUNK_BYTES + 3) as u64,
                accepted_chunks: 2,
                ..Snapshot::default()
            }
        );
    }

    #[test]
    fn stalled_full_and_disconnected_consumers_never_hold_the_producer() {
        let (mut producer, consumer) = channel_with_capacity(1);
        let counters = Arc::clone(&consumer.counters);
        let (done_tx, done_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            producer.write_all(b"first").unwrap();
            producer.write_all(&[7; CHUNK_BYTES * 1000]).unwrap();
            producer.flush().unwrap();
            done_tx.send(producer).unwrap();
        });
        // Keep the receiver alive and do not drain it until the producer finishes.
        let mut producer = done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        writer.join().unwrap();
        assert_eq!(consumer.receiver.recv().unwrap().as_bytes(), b"first");
        drop(consumer);
        producer.write_all(b"disconnected").unwrap();
        drop(producer);
        assert_eq!(
            counters.snapshot(),
            Snapshot {
                accepted_bytes: 5,
                accepted_chunks: 1,
                dropped_bytes: (CHUNK_BYTES * 1000 + 12) as u64,
                dropped_chunks: 1001,
            }
        );
    }
}
