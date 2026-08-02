//! [`StreamReader`]: the one trait every stream consumer reads through, and
//! [`FramedStreamReader`], the implementation over a broker connection.

use std::collections::VecDeque;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::{fmt, io};

use mvm_protocol::stream::{ChainError, StreamRecord, verify_chain_from};

use crate::config;
use crate::transcript::{Direction, GapMarker, TranscriptError};

use super::console::ConsoleUnsupported;
use super::opts::StreamOpts;
use super::wire::{MAX_FRAME_BYTES, StreamBatch, read_batch};

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
    /// No source answered: no broker is serving this microVM, it has no
    /// durable transcript, and no console capture exists for it either.
    #[error(
        "no output capture for microVM `{vm}`: no live broker at {}, no transcript at {}, \
         and no console capture at {}",
        socket.display(),
        transcript.display(),
        console.display()
    )]
    NoCapture {
        /// The microVM the consumer asked for.
        vm: String,
        /// The broker socket that was dialled.
        socket: PathBuf,
        /// The capture directory that was looked in.
        transcript: PathBuf,
        /// The console capture that was looked for.
        console: PathBuf,
    },
    /// The durable transcript exists but could not be verified or decrypted.
    ///
    /// Distinct from "no history": an unreadable capture reported as an empty
    /// one would hide the tamper the sealed root exists to catch.
    #[error("output transcript for microVM `{vm}` at {}: {source}", dir.display())]
    Transcript {
        /// The microVM the consumer asked for.
        vm: String,
        /// The capture directory.
        dir: PathBuf,
        /// Why the capture could not be read.
        #[source]
        source: TranscriptError,
    },
    /// The console capture is the only source this microVM has, and the
    /// request asks it for something a console log cannot supply.
    ///
    /// Refused rather than quietly ignored. Applying the filter would return
    /// nothing and hide the only output the VM has; ignoring it would return
    /// the whole merged console under a flag that says it was narrowed, and
    /// the note explaining that goes to stderr where a script reading stdout
    /// never sees it. Refusing is the only answer that cannot mislead.
    #[error(
        "microVM `{vm}` has no output capture; its console log at {} is one unlabelled stream \
         merging stdout and stderr, so {unsupported} cannot be honoured — drop it to read the \
         whole console",
        console.display()
    )]
    ConsoleCannotFilter {
        /// The microVM the consumer asked for.
        vm: String,
        /// The console capture that is the only source.
        console: PathBuf,
        /// What the console cannot supply.
        unsupported: ConsoleUnsupported,
    },
    /// The transcript at this location captures network frames, not workload
    /// output — an operator-armed forensic capture pointed at by mistake.
    #[error(
        "transcript at {} captures network traffic, not workload output (chunk {seq} is {direction:?})",
        dir.display()
    )]
    NotOutputTranscript {
        /// The capture directory.
        dir: PathBuf,
        /// The offending chunk.
        seq: u64,
        /// The direction it recorded.
        direction: Direction,
    },
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

    /// What this reader has lost, or `None` if it has kept up.
    ///
    /// On the trait rather than only on the concrete reader because a
    /// consumer holds a `Box<dyn StreamReader>`: a loss it cannot see is a
    /// loss it renders as a clean, complete log. Defaults to `None` for a
    /// source that cannot drop records (a durable transcript reports its
    /// incompleteness through its manifest instead).
    fn gap(&self) -> Option<GapMarker> {
        None
    }
}

/// A [`StreamReader`] over any framed byte source — a broker socket in
/// production, an in-memory buffer under test.
///
/// Holds the running anchor across batches: after a verified window, the next
/// window chains from the hash of the last record this reader saw, which it
/// computes itself rather than trusting the broker to repeat. The broker's
/// anchor is used only where the reader has none of its own — the first
/// window, and the first batch reporting a *new* loss, which is exactly the
/// case the reader cannot reconstruct because the linking record was evicted.
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
        let anchor = match self.new_loss(batch.gap) {
            // The record that linked this window to the last one was
            // evicted, so the running anchor is stale and the broker's is
            // the only value that can close the window.
            Some(reported) => {
                self.gap = Some(reported);
                batch.anchor
            }
            None => self.anchor.unwrap_or(batch.anchor),
        };
        self.anchor = Some(anchor);

        if let Some(last) = batch.records.last() {
            verify_chain_from(&batch.records, anchor)?;
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

    /// The marker on a batch, if it reports loss this reader has not already
    /// folded in — which is exactly when the broker's anchor is worth taking.
    ///
    /// Strictly advancing, for one reason: a window big enough to split
    /// arrives as several frames and the marker rides the first of them, so
    /// treating a later frame's absent marker as recovery would drop a loss
    /// the consumer is owed and then read the *next* window's repeat of it as
    /// a fresh one — re-anchoring a caught-up reader onto a hash from
    /// hundreds of records back, which surfaces as tampering. Narrowing when
    /// the broker's anchor is taken also narrows the blast radius of a *buggy*
    /// broker: a stale marker beside a wrong anchor moves nothing.
    ///
    /// It is not a defence against a hostile one, and must not be read as
    /// such. The gate compares only `after_seq`, and `verify_chain_from` never
    /// cross-checks the anchor against the sequence numbers delivered beside
    /// it, so a broker that raises `after_seq` on every window keeps full
    /// re-anchoring control. That is by design: a malicious host is outside
    /// the threat model — it owns the hypervisor, the transcript, and the
    /// signing keys, so a client-side rule here could not constrain it anyway.
    fn new_loss(&self, reported: Option<GapMarker>) -> Option<GapMarker> {
        let reported = reported?;
        match self.gap {
            Some(seen) if reported.after_seq <= seen.after_seq => None,
            _ => Some(reported),
        }
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

    /// What this reader has lost to the broker's retention ring so far.
    /// Cumulative and monotone in `after_seq`, so a consumer polls it to
    /// notice new loss and never sees loss un-report itself — a batch arriving
    /// without a marker means "nothing new since", not "recovered".
    fn gap(&self) -> Option<GapMarker> {
        self.gap
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
    fn a_split_window_does_not_erase_the_loss_it_reported() {
        // A window too big for one frame arrives as several, and the marker
        // rides the first. If a later frame's absent marker cleared the
        // reader's, the next window's repeat of the same marker would read as
        // a fresh loss and re-anchor a caught-up reader onto a stale hash.
        let full = chained(0, 12, [0u8; 32]);
        let gap = GapMarker {
            after_seq: 3,
            dropped_chunks: 4,
            dropped_bytes: 40,
        };
        let bytes = framed(&[
            // Window one, split in two: survivors 4..6 then 7..9.
            StreamBatch {
                anchor: full[3].hash(),
                records: full[4..7].to_vec(),
                gap: Some(gap),
                caught_up: false,
            },
            StreamBatch {
                anchor: full[6].hash(),
                records: full[7..10].to_vec(),
                gap: None,
                caught_up: true,
            },
            // Window two: no new loss, so the same cumulative marker rides
            // again — over a queue anchor that has not moved since the loss.
            StreamBatch {
                anchor: full[3].hash(),
                records: full[10..].to_vec(),
                gap: Some(gap),
                caught_up: true,
            },
        ]);

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![4, 5, 6, 7, 8, 9, 10, 11]);
        assert_eq!(
            reader.gap(),
            Some(gap),
            "the loss stays reported across the split"
        );
    }

    #[test]
    fn a_repeated_gap_cannot_re_anchor_a_continuing_stream() {
        // The anchor is the one value taken from the broker on trust, so it
        // is taken only when the marker advances. Re-sending an old marker
        // beside an anchor of the broker's choosing must not move the reader.
        let full = chained(0, 8, [0u8; 32]);
        let gap = GapMarker {
            after_seq: 1,
            dropped_chunks: 2,
            dropped_bytes: 20,
        };
        let bytes = framed(&[
            StreamBatch {
                anchor: full[1].hash(),
                records: full[2..5].to_vec(),
                gap: Some(gap),
                caught_up: true,
            },
            StreamBatch {
                anchor: [0xee; 32],
                records: full[5..].to_vec(),
                gap: Some(gap),
                caught_up: true,
            },
        ]);

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn a_gap_that_did_not_advance_never_moves_the_reader_backwards() {
        let full = chained(0, 8, [0u8; 32]);
        let far = GapMarker {
            after_seq: 4,
            dropped_chunks: 5,
            dropped_bytes: 50,
        };
        let stale = GapMarker {
            after_seq: 1,
            dropped_chunks: 2,
            dropped_bytes: 20,
        };
        let bytes = framed(&[
            StreamBatch {
                anchor: full[4].hash(),
                records: full[5..7].to_vec(),
                gap: Some(far),
                caught_up: true,
            },
            StreamBatch {
                anchor: full[1].hash(),
                records: full[7..].to_vec(),
                gap: Some(stale),
                caught_up: true,
            },
        ]);

        let opts = StreamOpts::builder().follow(true).build();
        let mut reader = FramedStreamReader::new(bytes.as_slice(), opts);
        let seqs: Vec<u64> = drain(&mut reader).iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5, 6, 7]);
        assert_eq!(reader.gap(), Some(far), "loss never un-reports itself");
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
