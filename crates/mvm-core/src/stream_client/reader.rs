//! [`StreamReader`]: the one trait every stream consumer reads through, and
//! [`FramedStreamReader`], the implementation over a broker connection.

use std::collections::VecDeque;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::{fmt, io};

use mvm_protocol::stream::{ChainError, StreamRecord, verify_chain_from};

use crate::config;
use crate::transcript::GapMarker;

use super::opts::StreamOpts;
use super::wire::{MAX_BATCH_PAYLOAD_BYTES, StreamBatch, read_batch};

/// Largest frame a reader will accept. A broker caps one batch's payload at
/// [`crate::stream_client::MAX_BATCH_PAYLOAD_BYTES`] and JSON-encodes each byte as a small integer
/// plus a separator, so a legitimate frame lands well inside this; the
/// remaining headroom covers per-record metadata for a batch of tiny writes.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// JSON renders each payload byte as up to four characters. If the frame cap
/// ever stopped covering that expansion, a legitimate full-size batch would be
/// refused as hostile — so the relation is checked at compile time, not left
/// to whoever next edits one of the two numbers.
const _: () = assert!(MAX_BATCH_PAYLOAD_BYTES * 4 < MAX_FRAME_BYTES);

/// Why a consumer could not read the next record.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// No broker is serving this microVM's stream.
    #[error("no output stream for microVM `{vm}` at {}: {source}", path.display())]
    Connect {
        /// The microVM the consumer asked for.
        vm: String,
        /// The socket that was dialled.
        path: PathBuf,
        /// The underlying connect failure.
        #[source]
        source: io::Error,
    },
    /// The connection failed, or a frame was malformed.
    #[error("stream transport failed: {0}")]
    Transport(#[from] io::Error),
    /// The delivered window is not an unbroken chain from its anchor.
    ///
    /// Surfaced rather than truncated: a consumer that stopped early on a
    /// break would render tampering as the end of output.
    #[error("stream window failed chain verification: {0}")]
    Chain(#[from] ChainError),
}

/// A verified, filtered source of one microVM's output records.
///
/// `next_record` returns records in sequence order and `None` once the
/// stream is done — end of output for a non-following reader, producer gone
/// for a following one. Chain verification has already happened: a record
/// handed out here was part of a window that verified against its anchor.
pub trait StreamReader {
    /// The next record, or `None` when this reader is finished.
    fn next_record(&mut self) -> Result<Option<StreamRecord>, StreamError>;
}

/// A [`StreamReader`] over any framed byte source — a broker socket in
/// production, an in-memory buffer under test.
///
/// Holds the running anchor across batches: after a verified window, the next
/// window chains from the hash of the last record this reader saw, which it
/// computes itself rather than trusting the broker to repeat. The broker's
/// anchor is used only where the reader has none of its own — the first
/// window, and the window after a loss, which is exactly the case the
/// reader cannot reconstruct because the linking record was evicted.
pub struct FramedStreamReader<R> {
    source: R,
    opts: StreamOpts,
    pending: VecDeque<StreamRecord>,
    anchor: Option<[u8; 32]>,
    gap: Option<GapMarker>,
    finished: bool,
}

impl<R: Read> FramedStreamReader<R> {
    /// Read `source` under `opts`.
    pub fn new(source: R, opts: StreamOpts) -> Self {
        Self {
            source,
            opts,
            pending: VecDeque::new(),
            anchor: None,
            gap: None,
            finished: false,
        }
    }

    /// What this reader has lost to the broker's retention ring so far, or
    /// `None` if it has kept up. Cumulative, so a consumer polls it to
    /// notice new loss.
    pub fn gap(&self) -> Option<GapMarker> {
        self.gap
    }

    /// Pull one batch and stage the records this consumer asked for.
    fn fetch(&mut self) -> Result<(), StreamError> {
        let Some(batch) = read_batch(&mut self.source, MAX_FRAME_BYTES)? else {
            self.finished = true;
            return Ok(());
        };
        self.absorb(batch)
    }

    /// Verify the window, then filter it. Never the other way round: a
    /// filter removes records from the middle of a window, so verifying
    /// afterwards would check a chain the broker never sent.
    fn absorb(&mut self, batch: StreamBatch) -> Result<(), StreamError> {
        let lost_records = batch.gap != self.gap;
        self.gap = batch.gap;
        if lost_records || self.anchor.is_none() {
            self.anchor = Some(batch.anchor);
        }
        let anchor = self
            .anchor
            .expect("the branch above sets an anchor whenever there was none");

        if !batch.records.is_empty() {
            verify_chain_from(&batch.records, anchor)?;
            let last = batch
                .records
                .last()
                .expect("the emptiness check above guarantees a last record");
            self.anchor = Some(last.hash());
        }

        if batch.caught_up && !self.opts.follow {
            self.finished = true;
        }
        for record in batch.records {
            if self.opts.accepts(&record) {
                self.pending.push_back(record);
            }
        }
        Ok(())
    }
}

impl<R: Read> StreamReader for FramedStreamReader<R> {
    fn next_record(&mut self) -> Result<Option<StreamRecord>, StreamError> {
        loop {
            if let Some(record) = self.pending.pop_front() {
                return Ok(Some(record));
            }
            if self.finished {
                return Ok(None);
            }
            self.fetch()?;
        }
    }
}

impl<R> fmt::Debug for FramedStreamReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately payload-free: a stream reader's buffered records are
        // workload output, and a `Debug` that prints them turns any log line
        // into a second copy of the stream.
        f.debug_struct("FramedStreamReader")
            .field("opts", &self.opts)
            .field("pending", &self.pending.len())
            .field("gap", &self.gap)
            .field("finished", &self.finished)
            .finish()
    }
}

/// Connect to the broker serving `vm`'s output.
pub fn connect_stream(vm: &str, opts: StreamOpts) -> Result<Box<dyn StreamReader>, StreamError> {
    let path = config::vm_stream_socket(vm);
    dial(&path, vm, opts)
}

/// Connect to a broker at an explicit socket path, for a caller that already
/// resolved it (a test fixture, or a state dir it holds directly).
pub fn connect_stream_at(
    path: &Path,
    opts: StreamOpts,
) -> Result<Box<dyn StreamReader>, StreamError> {
    let label = path.display().to_string();
    dial(path, &label, opts)
}

fn dial(path: &Path, vm: &str, opts: StreamOpts) -> Result<Box<dyn StreamReader>, StreamError> {
    let socket = UnixStream::connect(path).map_err(|source| StreamError::Connect {
        vm: vm.to_string(),
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Box::new(FramedStreamReader::new(socket, opts)))
}

#[cfg(test)]
mod tests {
    use super::super::opts::KindFilter;
    use super::super::wire::write_batch;
    use super::*;
    use mvm_protocol::stream::{StreamKind, StreamSource};

    /// A real chain: each record's `prev_hash` is its predecessor's hash, so
    /// verification is evidence rather than a restatement of the bytes.
    fn chained(from: u64, count: u64, anchor: [u8; 32]) -> Vec<StreamRecord> {
        let mut prev = anchor;
        let mut out = Vec::new();
        for seq in from..from + count {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: if seq % 3 == 1 {
                    StreamKind::Stderr
                } else {
                    StreamKind::Stdout
                },
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: format!("line-{seq}").into_bytes(),
            };
            prev = record.hash();
            out.push(record);
        }
        out
    }

    fn framed(batches: &[StreamBatch]) -> Vec<u8> {
        let mut buf = Vec::new();
        for batch in batches {
            write_batch(&mut buf, batch).expect("write batch");
        }
        buf
    }

    fn batch(records: Vec<StreamRecord>, anchor: [u8; 32]) -> StreamBatch {
        StreamBatch {
            anchor,
            records,
            gap: None,
            caught_up: true,
        }
    }

    fn drain(reader: &mut dyn StreamReader) -> Vec<StreamRecord> {
        let mut out = Vec::new();
        while let Some(record) = reader.next_record().expect("reader must not fail") {
            out.push(record);
        }
        out
    }

    #[test]
    fn from_seq_resumes_at_the_requested_sequence() {
        let records = chained(0, 8, [0u8; 32]);
        let bytes = framed(&[batch(records, [0u8; 32])]);
        let opts = StreamOpts::builder().from_seq(5).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);

        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5, 6, 7]);
    }

    #[test]
    fn follow_false_terminates_at_the_last_record() {
        // A second batch is on the wire; a non-following reader must stop at
        // the first caught-up marker rather than draining the whole source.
        let first = chained(0, 3, [0u8; 32]);
        let anchor_after = first.last().expect("three records").hash();
        let second = chained(3, 3, anchor_after);
        let bytes = framed(&[batch(first, [0u8; 32]), batch(second, anchor_after)]);

        let mut reader = FramedStreamReader::new(bytes.as_slice(), StreamOpts::default());
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![0, 1, 2],
            "a non-following reader stops caught up"
        );
    }

    #[test]
    fn follow_true_keeps_reading_past_the_caught_up_marker() {
        let first = chained(0, 3, [0u8; 32]);
        let anchor_after = first.last().expect("three records").hash();
        let second = chained(3, 3, anchor_after);
        let bytes = framed(&[batch(first, [0u8; 32]), batch(second, anchor_after)]);

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_kind_filter_excludes_non_matching_kinds() {
        let records = chained(0, 9, [0u8; 32]);
        let bytes = framed(&[batch(records, [0u8; 32])]);
        let opts = StreamOpts::builder()
            .kinds(KindFilter::only(StreamKind::Stderr))
            .build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);

        let got = drain(&mut reader);
        assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 4, 7]);
        assert!(got.iter().all(|r| r.kind == StreamKind::Stderr));
    }

    #[test]
    fn filtering_never_weakens_verification() {
        // The excluded record is the tampered one. If the reader filtered
        // before verifying, this window would pass and the consumer would
        // see a clean stdout stream over a broken chain.
        let mut records = chained(0, 6, [0u8; 32]);
        records[1].payload = b"tampered".to_vec();
        let bytes = framed(&[batch(records, [0u8; 32])]);
        let opts = StreamOpts::builder()
            .kinds(KindFilter::only(StreamKind::Stdout))
            .build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);

        assert!(matches!(
            reader.next_record(),
            Err(StreamError::Chain(ChainError::HashMismatch { .. }))
        ));
    }

    #[test]
    fn a_broken_chain_is_an_error_not_a_silent_truncation() {
        let mut records = chained(0, 6, [0u8; 32]);
        records.remove(3);
        let bytes = framed(&[batch(records, [0u8; 32])]);
        let mut reader = FramedStreamReader::new(bytes.as_slice(), StreamOpts::default());

        let err = reader
            .next_record()
            .expect_err("a gap must not read as the end");
        assert!(
            matches!(err, StreamError::Chain(ChainError::SeqGap { .. })),
            "{err}"
        );
    }

    #[test]
    fn a_pruned_window_verifies_without_the_caller_naming_an_anchor() {
        // The consumer never sees an anchor: it asks for records and the
        // reader checks the mid-stream window against the hash the broker
        // kept for the record it evicted.
        let full = chained(0, 10, [0u8; 32]);
        let anchor = full[4].hash();
        let survivors = full[5..].to_vec();
        let bytes = framed(&[StreamBatch {
            anchor,
            records: survivors,
            gap: Some(GapMarker {
                after_seq: 4,
                dropped_chunks: 5,
                dropped_bytes: 30,
            }),
            caught_up: true,
        }]);

        let mut reader = FramedStreamReader::new(bytes.as_slice(), StreamOpts::default());
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5, 6, 7, 8, 9]);
        assert_eq!(
            reader.gap().map(|g| g.after_seq),
            Some(4),
            "the loss stays visible to the consumer"
        );
    }

    #[test]
    fn a_wrong_anchor_on_a_pruned_window_is_rejected() {
        let full = chained(0, 10, [0u8; 32]);
        let bytes = framed(&[StreamBatch {
            anchor: [0x5a; 32],
            records: full[5..].to_vec(),
            gap: Some(GapMarker {
                after_seq: 4,
                dropped_chunks: 5,
                dropped_bytes: 30,
            }),
            caught_up: true,
        }]);
        let mut reader = FramedStreamReader::new(bytes.as_slice(), StreamOpts::default());
        assert!(matches!(
            reader.next_record(),
            Err(StreamError::Chain(ChainError::HashMismatch { seq: 5 }))
        ));
    }

    #[test]
    fn a_loss_between_batches_re_anchors_instead_of_reading_as_tampering() {
        // The reader's running anchor is stale the moment records are
        // evicted. Without re-anchoring on the moved gap, this window is
        // indistinguishable from a tampered one.
        let full = chained(0, 12, [0u8; 32]);
        let first = full[..3].to_vec();
        let after_first = full[2].hash();
        let bytes = framed(&[
            StreamBatch {
                anchor: [0u8; 32],
                records: first,
                gap: None,
                caught_up: true,
            },
            StreamBatch {
                anchor: full[7].hash(),
                records: full[8..].to_vec(),
                gap: Some(GapMarker {
                    after_seq: 7,
                    dropped_chunks: 5,
                    dropped_bytes: 40,
                }),
                caught_up: true,
            },
        ]);
        assert_ne!(after_first, full[7].hash());

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 8, 9, 10, 11]);
    }

    #[test]
    fn consecutive_batches_chain_from_the_readers_own_hash_not_a_repeated_anchor() {
        // The second batch's anchor field is deliberately wrong. With no
        // reported loss the reader must use the hash it computed from the
        // record it already verified, so the broker cannot re-anchor a
        // continuing stream onto a value of its choosing.
        let full = chained(0, 6, [0u8; 32]);
        let bytes = framed(&[
            StreamBatch {
                anchor: [0u8; 32],
                records: full[..3].to_vec(),
                gap: None,
                caught_up: true,
            },
            StreamBatch {
                anchor: [0xee; 32],
                records: full[3..].to_vec(),
                gap: None,
                caught_up: true,
            },
        ]);
        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn an_empty_caught_up_batch_ends_a_non_following_read() {
        let bytes = framed(&[batch(Vec::new(), [0u8; 32])]);
        let mut reader = FramedStreamReader::new(bytes.as_slice(), StreamOpts::default());
        assert_eq!(reader.next_record().expect("no error"), None);
    }

    #[test]
    fn end_of_connection_ends_a_following_read() {
        let bytes = framed(&[StreamBatch {
            anchor: [0u8; 32],
            records: chained(0, 2, [0u8; 32]),
            gap: None,
            caught_up: false,
        }]);
        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        assert_eq!(drain(&mut reader).len(), 2);
    }

    #[test]
    fn connect_to_a_missing_socket_names_the_vm() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.sock");
        let Err(err) = connect_stream_at(&path, StreamOpts::default()) else {
            panic!("connecting to an absent socket must fail");
        };
        assert!(matches!(err, StreamError::Connect { .. }), "{err}");
        assert!(err.to_string().contains("absent.sock"), "{err}");
    }

    #[test]
    fn debug_never_prints_buffered_payload_bytes() {
        let bytes = framed(&[batch(chained(0, 3, [0u8; 32]), [0u8; 32])]);
        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        reader.fetch().expect("fetch");
        let rendered = format!("{reader:?}");
        assert!(!rendered.contains("line-0"), "{rendered}");
        assert!(rendered.contains("pending: 3"), "{rendered}");
    }
}
