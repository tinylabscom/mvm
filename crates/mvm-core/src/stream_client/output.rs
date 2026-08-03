//! One VM's output as a consumer reads it: durable history first, then
//! whatever the broker is still producing.
//!
//! [`StreamReader`] alone does not satisfy "capturable while it runs **and**
//! when it exits", for two reasons that are properties of the broker rather
//! than bugs in it:
//!
//! - A subscription attaches at the **live head**. Everything already
//!   produced is in the durable transcript, not in the follower's queue, so a
//!   non-following read of an idle VM returns nothing.
//! - An exited VM has **no broker**. Connecting fails, and that is the whole
//!   after-exit half of the requirement.
//!
//! So a consumer reads through [`VmOutputStream`], which resolves three
//! sources and reports which of them answered: the broker, the durable
//! transcript, and — only when neither of those does — the console capture the
//! backend writes for every VM.
//!
//! **Dial before reading history.** The order narrows, but does not close, the
//! window between the two sources. Dialling first means the transcript read
//! happens under an already-queued connection, so most of what lands during it
//! is also delivered live; the resulting duplicates are suppressed by sequence
//! number. It is not a proof of no omission, and must not be read as one: the
//! broker subscribes on its own accept thread some time after `connect`
//! returns, and a record ingested inside *that* gap is in the transcript
//! snapshot taken before it and in no follower's queue. Closing it properly
//! needs the broker to state a follower's start sequence on the wire, which
//! this side cannot synthesise. Until then the residual window is one accept
//! tick wide, and it is a window of omission.
//!
//! **Durable history is only as current as the last seal.** The manifest is
//! written when a capture seals, so a VM whose capture has not sealed since it
//! started has nothing here to splice. This reader takes whatever manifest
//! exists; keeping one current is the writing side's job.
//!
//! **Where the two halves meet is checked for a hole.** A durable half that
//! stops at the last seal and a live half that starts where the follower
//! attached can leave a run of sequence numbers in neither source, and
//! rendering them adjacently would present a partial log as a complete one —
//! the exact failure the splice exists to avoid.
//! [`VmOutputStream::splice_gap`] reports it. Only an unnarrowed request can
//! tell a hole from its own filter, so a channel selection or a resume point
//! disables the check rather than reporting distances the caller created.
//!
//! **A source that answered is not the same as a source that matched.** A
//! transcript that verifies clean and holds nothing the request asked for is
//! *present*; treating it as absent would discard it, fall through to the
//! console, and report "no output capture" over a healthy capture. Presence
//! decides [`StreamAvailability`]; why a present capture replayed nothing is
//! reported separately through [`EmptyHistory`].
//!
//! **An integrity mechanism per source, and no claim beyond it.** Live records
//! are hash-chained and verified against their anchor by the reader that
//! produced them. Durable records are covered by the transcript's sealed
//! Merkle root and their own ciphertext digests, checked by
//! `verify_sealed_root` + `verify_chunks` before a byte is decrypted. Console
//! records carry neither, and say so through [`RecordOrigin::Console`].
//! Neither proof is reconstructible from another source's storage, so neither
//! is asserted over records it does not cover.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use mvm_protocol::stream::{StreamKind, StreamRecord, StreamSource};

use crate::config;
use crate::crypto::aead;
use crate::transcript::{
    self, Direction, GapMarker, MANIFEST_FILENAME, TranscriptError, TranscriptManifest,
};

use super::console::{ConsoleTail, ConsoleUnsupported};
use super::opts::{KindFilter, StreamOpts};
use super::reader::{StreamError, StreamReader, connect_stream_at};

/// Where an [`OutputRecord`] came from, and what that source is able to say
/// about it.
///
/// Not a cosmetic label. The durable transcript records a chunk's channel and
/// its order and nothing else — no producing process, no capture stamp — so a
/// history record cannot carry the fields a live one does. Naming the origin
/// is how that shows up in the type instead of as an invented `Entrypoint` and
/// a fabricated timestamp on a record the chain never covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOrigin {
    /// Delivered by the broker and chain-verified against its anchor.
    Live {
        /// Which process produced it.
        source: StreamSource,
        /// Host wall-clock at capture, nanoseconds since the Unix epoch.
        host_unix_nanos: u64,
    },
    /// Recovered from the VM's durable transcript, verified against the
    /// capture's sealed root.
    Durable,
    /// Read straight off the VM's console capture file. The fallback source:
    /// no channel separation (the guest writes both streams to one console),
    /// no hash chain, and chunk boundaries that are read boundaries.
    Console,
}

/// One unit of a workload's output, from whichever source could supply it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRecord {
    /// Position in the producing source's sequence.
    pub seq: u64,
    /// Which channel the bytes came out of.
    pub kind: StreamKind,
    /// Which source supplied the record.
    pub origin: RecordOrigin,
    /// The captured bytes, verbatim.
    pub payload: Vec<u8>,
}

impl OutputRecord {
    fn from_live(record: StreamRecord) -> Self {
        Self {
            seq: record.seq,
            kind: record.kind,
            origin: RecordOrigin::Live {
                source: record.source,
                host_unix_nanos: record.host_unix_nanos,
            },
            payload: record.payload,
        }
    }
}

/// How much of a capture is missing, and from which end.
///
/// Both ends matter and they mean different things: `refused` is a lost
/// **tail** (the store stopped taking chunks), `evicted` is a lost **head**
/// (ring retention dropped the oldest to keep the newest). A consumer shown
/// neither reads a partial capture as the whole of a quiet workload's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncation {
    /// Chunks the store would not take, off the tail.
    pub refused_chunks: u64,
    /// Plaintext bytes in those chunks.
    pub refused_bytes: u64,
    /// Chunks ring retention dropped, off the head.
    pub evicted_chunks: u64,
    /// Plaintext bytes in those chunks.
    pub evicted_bytes: u64,
    /// Whether the counts above are a floor rather than the whole shortfall,
    /// because the manifest was rebuilt by a process that did not own the
    /// capture. A run started detached and stopped later is the ordinary way
    /// to get one, and the four counts cannot see what the departed process
    /// dropped on its way out.
    pub adopted: bool,
}

impl Truncation {
    /// The manifest's shortfall, or `None` when the capture is whole.
    fn of(manifest: &TranscriptManifest) -> Option<Self> {
        manifest.is_truncated().then_some(Self {
            refused_chunks: manifest.refused_chunks,
            refused_bytes: manifest.refused_bytes,
            evicted_chunks: manifest.evicted_chunks,
            evicted_bytes: manifest.evicted_bytes,
            adopted: manifest.adopted,
        })
    }
}

/// A hole between the newest record the durable half supplied and the oldest
/// one the live half did.
///
/// The manifest is written when a capture seals, so the durable half stops at
/// the last seal while the live half starts wherever the follower attached.
/// Everything between the two is in neither source. A consumer shown the two
/// halves adjacently reads a partial log as a complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceGap {
    /// The newest sequence the durable half supplied.
    pub after_seq: u64,
    /// The oldest sequence the live half supplied.
    pub before_seq: u64,
}

impl SpliceGap {
    /// How many sequence numbers fall in the hole.
    pub fn missing(self) -> u64 {
        self.before_seq
            .saturating_sub(self.after_seq)
            .saturating_sub(1)
    }
}

/// Why the durable half handed over no records, when it handed over none.
///
/// All three shapes render as an empty replay and they mean different things:
/// a capture with nothing in it, a capture the request filtered out entirely,
/// and a request that asked for no replay. Only the last is something the
/// operator chose, so a consumer that cannot tell them apart either stays
/// silent about a capture it threw away or nags about one it was told to skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyHistory {
    /// The transcript sealed with no chunks in it.
    CaptureEmpty,
    /// The transcript holds records and the request's filter matched none.
    FilteredOut,
    /// The request asked for zero replayed records.
    NotRequested,
}

/// Which sources answered for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAvailability {
    /// A broker is serving live output and a durable transcript supplied
    /// history — the normal case for a running workload.
    LiveAndHistory,
    /// A broker is serving, but nothing durable exists yet: a VM that has
    /// just booted, or one whose capture is not persisted.
    LiveOnly,
    /// No broker. Everything came off the durable transcript — the after-exit
    /// read.
    HistoryOnly,
    /// Neither the broker nor a transcript answered, so the console capture is
    /// all there is: no channel separation and no hash chain.
    ConsoleOnly,
}

impl StreamAvailability {
    /// Whether a broker answered, i.e. whether the records are chain-verified
    /// and separated by channel.
    pub fn is_live(self) -> bool {
        matches!(self, Self::LiveAndHistory | Self::LiveOnly)
    }
}

/// What a consumer is asking a VM for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputRequest {
    /// Which records qualify, and whether to keep reading past the live head.
    pub opts: StreamOpts,
    /// Keep only the last N *qualifying* history records. `None` reads the
    /// whole transcript. Applied after filtering, so `-n 50 --stream stderr`
    /// means fifty stderr records rather than whatever stderr survives in the
    /// last fifty of everything.
    pub history_tail: Option<usize>,
    /// Start a console fallback this many bytes before the file's end. Bytes
    /// rather than records because the console has no record boundaries to
    /// count. `None` reads it whole.
    pub console_tail_bytes: Option<u64>,
}

/// Everything needed to find one VM's output sources.
///
/// Split from [`open_vm_output`] so a test drives the real resolution against
/// temp dirs rather than a second, test-only code path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLocator {
    /// The VM's name, for error messages a user can act on.
    pub vm: String,
    /// The broker's per-VM socket.
    pub socket: PathBuf,
    /// The durable capture directory.
    pub transcript_dir: PathBuf,
    /// The backend's write-only console capture, the fallback source.
    pub console_log: PathBuf,
    /// Where the host KEK that unwraps the capture's data key lives.
    pub keys_dir: PathBuf,
}

impl OutputLocator {
    /// Resolve a VM's sources through the shared path helpers, so the reader
    /// and whatever writes the capture cannot drift on a location.
    pub fn for_vm(vm: &str) -> Self {
        Self {
            vm: vm.to_string(),
            socket: config::vm_stream_socket(vm),
            transcript_dir: config::vm_stream_transcript_dir(vm),
            console_log: config::vm_console_log(vm),
            keys_dir: config::mvm_keys_dir(),
        }
    }
}

/// The source a [`VmOutputStream`] draws continuing records from once its
/// staged history is spent.
enum Tail {
    /// The broker, over its per-VM socket.
    Broker(Box<dyn StreamReader>),
    /// The console capture on disk. Only ever chosen when neither other source
    /// answered — a running broker already republishes these bytes, so reading
    /// the file beside it would double every line.
    Console(ConsoleTail),
}

/// A VM's output: durable history spliced ahead of whatever is still coming.
pub struct VmOutputStream {
    history: VecDeque<OutputRecord>,
    tail: Option<Tail>,
    availability: StreamAvailability,
    truncation: Option<Truncation>,
    /// Why a transcript that answered replayed nothing, when one did and it
    /// did not.
    empty_history: Option<EmptyHistory>,
    /// Highest history sequence handed out, for live de-duplication.
    history_high_water: Option<u64>,
    /// Whether a distance between the two halves would be attributable to the
    /// splice rather than to the request's own filter.
    splice_detectable: bool,
    /// Whether a live record has been handed out, so the hole is measured
    /// against the first one and not re-measured after.
    saw_live: bool,
    splice_gap: Option<SpliceGap>,
}

impl VmOutputStream {
    /// Which sources answered.
    pub fn availability(&self) -> StreamAvailability {
        self.availability
    }

    /// What the durable capture is missing, if anything.
    pub fn truncation(&self) -> Option<Truncation> {
        self.truncation
    }

    /// History records still staged, before any live record is read.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Why the durable half replayed nothing, or `None` when it replayed
    /// something or no transcript answered at all.
    ///
    /// The difference between "this VM captured nothing" and "this VM
    /// captured plenty, none of it on the channel you asked for". Both show
    /// zero records; only one of them is about the capture.
    pub fn empty_history(&self) -> Option<EmptyHistory> {
        self.empty_history
    }

    /// The hole where the durable half meets the live one, if the splice left
    /// one.
    ///
    /// Poll it as records are read, like [`Self::gap`]: it cannot be known
    /// until the first live record arrives, which is after `availability()`
    /// and the whole staged history have already been reported.
    pub fn splice_gap(&self) -> Option<SpliceGap> {
        self.splice_gap
    }

    /// What the live follower has lost to the broker's retention ring.
    ///
    /// Poll this *as records are read*, not only at the end: the marker
    /// arrives with the batch that reports it, and a follower that never
    /// returns has no end at which to check.
    pub fn gap(&self) -> Option<GapMarker> {
        match self.tail.as_ref() {
            Some(Tail::Broker(live)) => live.gap(),
            Some(Tail::Console(_)) | None => None,
        }
    }

    /// The next record, history first, then whatever is still arriving.
    ///
    /// Live records at or below the highest history sequence are suppressed:
    /// they are the overlap the attach-then-read order deliberately creates.
    ///
    /// The two sequence spaces coincide as long as every ingested record
    /// reaches the store, because both are issued 0-based and in step. A
    /// persist failure consumes a broker sequence and not a transcript one, so
    /// after N failures the durable numbering trails the live one by N and the
    /// suppression window is short by that much. That direction is the one to
    /// be wrong in: the transcript sequence can only ever lag, never lead, so
    /// the failure mode is a repeated line rather than a swallowed one.
    ///
    /// Suppression does not apply to a console tail, whose sequence numbers
    /// count read chunks and share nothing with either of the others.
    ///
    /// The first live record that survives suppression is also where the two
    /// halves are measured against each other: if it does not follow the last
    /// history record, [`Self::splice_gap`] records the hole.
    pub fn next_output(&mut self) -> Result<Option<OutputRecord>, StreamError> {
        if let Some(record) = self.history.pop_front() {
            self.history_high_water = Some(record.seq);
            return Ok(Some(record));
        }
        match self.tail.as_mut() {
            None => Ok(None),
            Some(Tail::Console(console)) => Ok(console.next_record()?),
            Some(Tail::Broker(live)) => {
                let high_water = self.history_high_water;
                loop {
                    let Some(record) = live.next_record()? else {
                        return Ok(None);
                    };
                    if high_water.is_some_and(|high| record.seq <= high) {
                        continue;
                    }
                    if !self.saw_live {
                        self.saw_live = true;
                        self.splice_gap =
                            detect_splice_gap(self.splice_detectable, high_water, record.seq);
                    }
                    return Ok(Some(OutputRecord::from_live(record)));
                }
            }
        }
    }
}

/// The hole between the two halves, or `None` when they meet, when there is
/// no durable half to meet, or when the request itself explains the distance.
fn detect_splice_gap(
    detectable: bool,
    after_seq: Option<u64>,
    first_live_seq: u64,
) -> Option<SpliceGap> {
    if !detectable {
        return None;
    }
    let after_seq = after_seq?;
    (first_live_seq > after_seq.saturating_add(1)).then_some(SpliceGap {
        after_seq,
        before_seq: first_live_seq,
    })
}

/// Whether a distance between the durable and live halves could be attributed
/// to the splice at all.
///
/// Both sources number densely across channels, so under an unnarrowed
/// request a missing sequence number is a missing record. Under a channel
/// filter or a resume point it is not: the reader drops non-matching records
/// before a consumer sees them, so `…, 4, 9, …` is the ordinary shape of a
/// stderr-only read over a mostly-stdout run. Claiming a hole there would cry
/// wolf on every narrowed read, which is worse than the silence it replaces.
fn splice_detectable(opts: &StreamOpts) -> bool {
    opts.kinds == KindFilter::all() && opts.from_seq.is_none()
}

/// Open a VM's output stream through the shared path helpers.
pub fn open_vm_output(vm: &str, request: OutputRequest) -> Result<VmOutputStream, StreamError> {
    open_vm_output_at(&OutputLocator::for_vm(vm), request)
}

/// Open a VM's output stream from explicitly-resolved locations.
///
/// Fails only when *no* source answers. A live broker with no transcript, a
/// transcript with no broker, and a console capture with neither are all
/// ordinary shapes, each reported through [`VmOutputStream::availability`]
/// rather than as an error.
pub fn open_vm_output_at(
    locator: &OutputLocator,
    request: OutputRequest,
) -> Result<VmOutputStream, StreamError> {
    // Attach before reading history: see the module docs on the ordering and
    // on the residual window it does not close.
    let live = connect_broker(locator, request.opts)?;
    let history = read_history(locator, request)?;

    // Presence, never the surviving record count. A capture that verifies
    // clean and matched nothing is still a capture: counting it absent would
    // throw it away, fall through to the console, and announce "no output
    // capture" over a transcript sitting right there.
    let present = history.is_some();
    let (records, truncation, empty_history) = history.map_or_else(
        || (VecDeque::new(), None, None),
        |history| (history.records, history.truncation, history.empty),
    );
    let (tail, availability) = resolve_tail(locator, request, live, present)?;
    Ok(VmOutputStream {
        history: records,
        tail,
        availability,
        truncation,
        empty_history,
        history_high_water: None,
        splice_detectable: splice_detectable(&request.opts),
        saw_live: false,
        splice_gap: None,
    })
}

/// Which source continues the read once staged history is spent, and which
/// sources answered at all.
fn resolve_tail(
    locator: &OutputLocator,
    request: OutputRequest,
    live: Option<Box<dyn StreamReader>>,
    history_present: bool,
) -> Result<(Option<Tail>, StreamAvailability), StreamError> {
    Ok(match (live, history_present) {
        (Some(live), true) => (Some(Tail::Broker(live)), StreamAvailability::LiveAndHistory),
        (Some(live), false) => (Some(Tail::Broker(live)), StreamAvailability::LiveOnly),
        (None, true) => (None, StreamAvailability::HistoryOnly),
        (None, false) => (
            Some(Tail::Console(open_console(locator, request)?)),
            StreamAvailability::ConsoleOnly,
        ),
    })
}

/// Dial the broker, distinguishing "no broker here" from "could not dial".
///
/// Only an absent or unattended socket means the VM has no live stream.
/// Anything else — a permission refusal on the 0600 socket, a path the kernel
/// will not take — is a real failure whose cause the caller must see, not one
/// to be re-reported downstream as "this VM has no output".
fn connect_broker(
    locator: &OutputLocator,
    opts: StreamOpts,
) -> Result<Option<Box<dyn StreamReader>>, StreamError> {
    match connect_stream_at(&locator.socket, opts) {
        Ok(reader) => Ok(Some(reader)),
        Err(StreamError::Connect { source, .. })
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

/// Fall back to the console capture, or report that the VM has no output at
/// all — or that the console cannot answer what was asked.
///
/// "Nothing anywhere" outranks "the fallback cannot filter", so the existence
/// check comes first: a user whose VM has no capture at all needs to hear
/// that, not advice about a flag.
fn open_console(
    locator: &OutputLocator,
    request: OutputRequest,
) -> Result<ConsoleTail, StreamError> {
    let exists = locator
        .console_log
        .try_exists()
        .map_err(|source| StreamError::Transcript {
            vm: locator.vm.clone(),
            dir: locator.console_log.clone(),
            source: TranscriptError::Io {
                file: locator.console_log.display().to_string(),
                msg: source.to_string(),
            },
        })?;
    if !exists {
        return Err(StreamError::NoCapture {
            vm: locator.vm.clone(),
            socket: locator.socket.clone(),
            transcript: locator.transcript_dir.clone(),
            console: locator.console_log.clone(),
        });
    }
    if let Some(unsupported) = ConsoleUnsupported::of(&request.opts) {
        return Err(StreamError::ConsoleCannotFilter {
            vm: locator.vm.clone(),
            console: locator.console_log.clone(),
            unsupported,
        });
    }
    let mut console = ConsoleTail::open(&locator.console_log, request.opts.follow);
    if let Some(tail) = request.console_tail_bytes {
        // Best effort: a stat that fails leaves the reader at the start, which
        // shows more than asked rather than less.
        let _ = console.seek_to_last(tail);
    }
    Ok(console)
}

/// The durable half, decoded and filtered.
struct History {
    records: VecDeque<OutputRecord>,
    truncation: Option<Truncation>,
    /// Why `records` is empty, when it is.
    empty: Option<EmptyHistory>,
}

/// Read, verify, and decrypt the VM's transcript, or `Ok(None)` when it has
/// none.
///
/// `Ok(None)` means **no transcript**, and nothing else. A capture that
/// exists and yields no matching record still returns `Some`, with
/// [`History::empty`] saying why — the distinction the caller keys
/// availability off.
///
/// An *absent* capture is not an error; an unreadable one is. A manifest that
/// exists but does not parse, does not verify, or cannot be decrypted is
/// evidence of a problem with the capture, and reporting it as "no history"
/// would hide exactly the case the sealed root exists to catch. That is also
/// why the existence check is `try_exists` and not `exists`: the latter folds
/// every error — a permission refusal on the capture dir above all — into
/// `false`, which is the fail-open reading this function exists to refuse.
fn read_history(
    locator: &OutputLocator,
    request: OutputRequest,
) -> Result<Option<History>, StreamError> {
    let manifest_path = locator.transcript_dir.join(MANIFEST_FILENAME);
    let exists = manifest_path.try_exists().map_err(|e| {
        transcript_error(
            locator,
            TranscriptError::Io {
                file: MANIFEST_FILENAME.to_string(),
                msg: e.to_string(),
            },
        )
    })?;
    if !exists {
        return Ok(None);
    }
    let Some(manifest) = load_manifest(locator, &manifest_path)? else {
        return Ok(None);
    };
    let key = unwrap_capture_key(locator, &manifest)?;
    let chunks = transcript::export_chunks(&manifest, &locator.transcript_dir, &key)
        .map_err(|source| transcript_error(locator, source))?;

    let total_chunks = chunks.len();
    let mut records = VecDeque::new();
    for chunk in chunks {
        let kind =
            output_kind(chunk.direction).ok_or_else(|| StreamError::NotOutputTranscript {
                dir: locator.transcript_dir.clone(),
                seq: chunk.seq,
                direction: chunk.direction,
            })?;
        if !qualifies(&request.opts, chunk.seq, kind) {
            continue;
        }
        records.push_back(OutputRecord {
            seq: chunk.seq,
            kind,
            origin: RecordOrigin::Durable,
            payload: chunk.plaintext,
        });
    }
    let empty = classify_empty(total_chunks, records.len(), request.history_tail);
    if let Some(tail) = request.history_tail {
        // From the front, so the newest record always survives and the live
        // half still splices onto the record immediately before it.
        while records.len() > tail {
            records.pop_front();
        }
    }
    Ok(Some(History {
        truncation: Truncation::of(&manifest),
        records,
        empty,
    }))
}

/// Why a present capture will replay nothing, or `None` when it will replay
/// something.
///
/// Decided **before** the tail trim: "the filter matched none" and "the
/// request asked for none" are only distinguishable there.
fn classify_empty(
    total_chunks: usize,
    matched: usize,
    tail: Option<usize>,
) -> Option<EmptyHistory> {
    if total_chunks == 0 {
        return Some(EmptyHistory::CaptureEmpty);
    }
    if matched == 0 {
        return Some(EmptyHistory::FilteredOut);
    }
    (tail == Some(0)).then_some(EmptyHistory::NotRequested)
}

/// Read the manifest, or report that there is no usable one.
///
/// The two failures here are not the same failure and must not be reported
/// the same way. An **I/O** error — a permission refusal above all — is about
/// the reader's access to the capture and has to surface: swallowing it would
/// print "no output capture" over a transcript that is sitting right there.
/// A **parse** error is about the file's contents, and the overwhelmingly
/// likely cause is a manifest written by a process that died partway through
/// it. Hard-erroring on that costs the operator the console fallback at the
/// exact moment the host crashed, which is when they most need to see
/// something. So a manifest that does not parse degrades to "no durable
/// half", loudly, and the read continues to whatever else can answer.
///
/// A manifest that *parses* and then fails verification is the opposite case
/// and still fails closed — that is the signal the sealed root exists to
/// give, and it is handled by the caller's verify, not here.
fn load_manifest(
    locator: &OutputLocator,
    path: &Path,
) -> Result<Option<TranscriptManifest>, StreamError> {
    let bytes = std::fs::read(path).map_err(|e| {
        transcript_error(
            locator,
            TranscriptError::Io {
                file: MANIFEST_FILENAME.to_string(),
                msg: e.to_string(),
            },
        )
    })?;
    match serde_json::from_slice(&bytes) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) => {
            tracing::warn!(
                vm = %locator.vm,
                path = %path.display(),
                error = %error,
                "capture manifest does not parse and is being ignored; it was most likely \
                 written by a process that did not survive writing it"
            );
            Ok(None)
        }
    }
}

/// Recover the per-capture data key from under the host KEK.
///
/// Load-only. A read path that *minted* a KEK would turn a missing-key
/// problem into a permanent one — every existing capture was sealed under the
/// old key — and would race the writing side for which random key wins. An
/// absent KEK is reported as what it is.
fn unwrap_capture_key(
    locator: &OutputLocator,
    manifest: &TranscriptManifest,
) -> Result<aead::Key, StreamError> {
    let kek_io = |msg: String| {
        transcript_error(
            locator,
            TranscriptError::Io {
                file: transcript::TRANSCRIPT_KEK_FILENAME.to_string(),
                msg,
            },
        )
    };
    let kek = transcript::load_kek(&locator.keys_dir)
        .map_err(|e| kek_io(e.to_string()))?
        .ok_or_else(|| {
            kek_io(format!(
                "not found under {} — the capture cannot be opened without it",
                locator.keys_dir.display()
            ))
        })?;
    transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64)
        .map_err(|source| transcript_error(locator, source))
}

fn transcript_error(locator: &OutputLocator, source: TranscriptError) -> StreamError {
    StreamError::Transcript {
        vm: locator.vm.clone(),
        dir: locator.transcript_dir.clone(),
        source,
    }
}

/// The output channel a capture direction names, or `None` for the network
/// directions a workload-output transcript never contains.
fn output_kind(direction: Direction) -> Option<StreamKind> {
    match direction {
        Direction::Stdout => Some(StreamKind::Stdout),
        Direction::Stderr => Some(StreamKind::Stderr),
        Direction::Trace => Some(StreamKind::Trace),
        Direction::Egress | Direction::Ingress => None,
    }
}

/// The same two filters [`StreamOpts::accepts`] applies, over a history record
/// that has no [`StreamRecord`] to hand.
fn qualifies(opts: &StreamOpts, seq: u64, kind: StreamKind) -> bool {
    opts.from_seq.is_none_or(|from| seq >= from) && opts.kinds.matches(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::{
        CaptureBinding, CaptureBounds, RetentionPolicy, TranscriptWriter, TranscriptWriterConfig,
    };
    use std::path::Path;

    use super::super::opts::KindFilter;
    use super::super::wire::{StreamBatch, write_batch};

    fn bounds() -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: 8 << 20,
            max_chunks: 4096,
        }
    }

    /// Write a real capture the way the broker will: a data key wrapped under
    /// a real KEK in a real keys dir, chunks encrypted through the real
    /// writer, and a sealed manifest on disk. Nothing here is a stand-in, so a
    /// verification regression in the read path fails these tests.
    fn seal_capture(
        root: &Path,
        chunks: &[(Direction, &[u8])],
        retention: RetentionPolicy,
        capture_bounds: CaptureBounds,
    ) -> OutputLocator {
        let keys_dir = root.join("keys");
        let dir = root.join("stream");
        std::fs::create_dir_all(&keys_dir).expect("keys dir");
        std::fs::create_dir_all(&dir).expect("capture dir");

        let kek = transcript::load_or_init_kek(&keys_dir).expect("kek");
        let data_key = aead::Key::from_bytes([0x33; 32]);
        let wrapped = transcript::wrap_data_key(&kek, &data_key);
        let mut writer = TranscriptWriter::new(
            &dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: "capture-vm".to_string(),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: "vm".to_string(),
                    session_id: None,
                },
                bounds: capture_bounds,
                retention,
                created_unix_secs: 0,
                recipient: "transcript-kek".to_string(),
                wrapped_data_key_b64: wrapped,
            },
        );
        for (direction, bytes) in chunks {
            // Under `FailClosed` a refusal is the point of the fixture, so a
            // failed push is recorded in the manifest rather than asserted on.
            let _ = writer.push(*direction, bytes);
        }
        let manifest = writer.seal();
        std::fs::write(
            dir.join(MANIFEST_FILENAME),
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");

        OutputLocator {
            vm: "vm".to_string(),
            socket: root.join("absent.sock"),
            transcript_dir: dir,
            console_log: root.join("absent-console.log"),
            keys_dir,
        }
    }

    fn stdout_capture(root: &Path, lines: &[&str]) -> OutputLocator {
        let owned: Vec<(Direction, &[u8])> = lines
            .iter()
            .map(|l| (Direction::Stdout, l.as_bytes()))
            .collect();
        seal_capture(root, &owned, RetentionPolicy::Ring, bounds())
    }

    fn drain(stream: &mut VmOutputStream) -> Vec<OutputRecord> {
        let mut out = Vec::new();
        while let Some(record) = stream.next_output().expect("stream must not fail") {
            out.push(record);
        }
        out
    }

    fn payloads(records: &[OutputRecord]) -> Vec<String> {
        records
            .iter()
            .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
            .collect()
    }

    /// A live chain of `count` records starting at `from`, framed on the wire
    /// the way a broker sends them.
    fn framed_live(from: u64, count: u64) -> Vec<u8> {
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        for seq in 0..from + count {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: format!("live-{seq}").into_bytes(),
            };
            prev = record.hash();
            records.push(record);
        }
        let anchor = if from == 0 {
            [0u8; 32]
        } else {
            records[(from - 1) as usize].hash()
        };
        let mut buf = Vec::new();
        write_batch(
            &mut buf,
            &StreamBatch {
                anchor,
                records: records.split_off(from as usize),
                gap: None,
                caught_up: true,
            },
        )
        .expect("frame");
        buf
    }

    #[test]
    fn an_exited_vm_with_no_broker_still_reads_its_whole_history() {
        // The after-exit half of the requirement: no socket exists anywhere
        // near this fixture, and the output still comes back.
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one", "two", "three"]);

        let mut stream =
            open_vm_output_at(&locator, OutputRequest::default()).expect("open history only");
        assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
        let got = drain(&mut stream);
        assert_eq!(payloads(&got), vec!["one", "two", "three"]);
        assert!(got.iter().all(|r| r.origin == RecordOrigin::Durable));
    }

    /// A real listening socket that hands one follower `frames` and hangs up.
    ///
    /// Drives the socket half of the resolution — the branch that decides
    /// whether a VM is live — through the same `connect_stream_at` the
    /// production path takes, rather than reaching past it into the struct.
    /// The broker's own behaviour is exercised against a real broker in
    /// `mvm-hostd`'s serve tests; what is under test here is the splice.
    struct FakeBroker {
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeBroker {
        fn serve(path: &Path, frames: Vec<u8>) -> Self {
            use std::io::Write as _;
            let listener = std::os::unix::net::UnixListener::bind(path).expect("bind");
            let thread = std::thread::spawn(move || {
                if let Ok((mut socket, _)) = listener.accept() {
                    let _ = socket.write_all(&frames);
                    let _ = socket.flush();
                }
            });
            Self {
                thread: Some(thread),
            }
        }
    }

    impl Drop for FakeBroker {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// `locator` pointed at a socket this fake broker is serving.
    fn live_locator(
        root: &Path,
        mut locator: OutputLocator,
        frames: Vec<u8>,
    ) -> (OutputLocator, FakeBroker) {
        let socket = root.join("s.sock");
        let broker = FakeBroker::serve(&socket, frames);
        locator.socket = socket;
        (locator, broker)
    }

    #[test]
    fn an_idle_vm_returns_history_rather_than_the_empty_live_head() {
        // A broker attaches a follower at the live head, so without the splice
        // an idle VM's `logs` is silent however much it has already printed.
        let root = tempfile::tempdir().expect("tempdir");
        let capture = stdout_capture(root.path(), &["printed", "earlier"]);
        // An empty, caught-up live window: exactly what a fresh subscription
        // to an idle broker delivers.
        let (locator, _broker) = live_locator(root.path(), capture, framed_live(0, 0));

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.availability(), StreamAvailability::LiveAndHistory);
        assert_eq!(payloads(&drain(&mut stream)), vec!["printed", "earlier"]);
    }

    #[test]
    fn live_records_the_history_already_carried_are_not_printed_twice() {
        // Dialling before reading the transcript means the overlap window is
        // delivered by both sources. Suppressing by sequence is what keeps the
        // order-of-operations choice from costing duplicate output.
        let root = tempfile::tempdir().expect("tempdir");
        let capture = stdout_capture(root.path(), &["live-0", "live-1", "live-2"]);
        let (locator, _broker) = live_locator(root.path(), capture, framed_live(0, 5));

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(
            payloads(&drain(&mut stream)),
            vec!["live-0", "live-1", "live-2", "live-3", "live-4"],
            "the overlap is printed once, and nothing after it is lost"
        );
    }

    #[test]
    fn a_chain_break_on_the_live_half_is_an_error_not_the_end_of_history() {
        // History already flowed, so the tempting failure is to treat the
        // broken live window as "that's all there was".
        let root = tempfile::tempdir().expect("tempdir");
        let capture = stdout_capture(root.path(), &["done"]);
        let mut frames = framed_live(0, 4);
        // Corrupt the last frame's payload bytes: the chain no longer closes.
        let len = frames.len();
        frames[len - 8..].fill(b'!');
        let (locator, _broker) = live_locator(root.path(), capture, frames);

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert!(stream.next_output().expect("history first").is_some());
        let err = stream
            .next_output()
            .expect_err("a broken live chain must not read as the end");
        assert!(
            matches!(err, StreamError::Chain(_) | StreamError::Transport(_)),
            "{err}"
        );
    }

    #[test]
    fn a_live_broker_with_no_transcript_is_live_only_not_a_failure() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = OutputLocator {
            vm: "vm".to_string(),
            socket: root.path().join("s.sock"),
            transcript_dir: root.path().join("no-capture"),
            console_log: root.path().join("no-console.log"),
            keys_dir: root.path().join("keys"),
        };
        let _broker = FakeBroker::serve(&locator.socket, framed_live(0, 2));

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.availability(), StreamAvailability::LiveOnly);
        assert_eq!(payloads(&drain(&mut stream)), vec!["live-0", "live-1"]);
    }

    #[test]
    fn a_truncated_capture_reports_which_end_it_lost() {
        // A window that verifies clean while being a window is the exact
        // artifact this reports on: without it, a partial log reads as whole.
        let root = tempfile::tempdir().expect("tempdir");
        let chunks: Vec<(Direction, &[u8])> =
            (0..8).map(|_| (Direction::Stdout, &b"xxxx"[..])).collect();
        let locator = seal_capture(
            root.path(),
            &chunks,
            RetentionPolicy::FailClosed,
            CaptureBounds {
                max_duration_secs: u64::MAX,
                max_bytes: 1 << 20,
                max_chunks: 3,
            },
        );

        let stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        let truncation = stream.truncation().expect("the capture lost its tail");
        assert_eq!(truncation.refused_chunks, 5);
        assert_eq!(truncation.refused_bytes, 20);
        assert_eq!(truncation.evicted_chunks, 0);
    }

    #[test]
    fn a_whole_capture_reports_no_truncation() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["all", "of", "it"]);
        let stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.truncation(), None);
    }

    #[test]
    fn a_kind_filter_narrows_history_too() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = seal_capture(
            root.path(),
            &[
                (Direction::Stdout, b"out-0"),
                (Direction::Stderr, b"err-1"),
                (Direction::Stdout, b"out-2"),
                (Direction::Stderr, b"err-3"),
            ],
            RetentionPolicy::Ring,
            bounds(),
        );

        let request = OutputRequest {
            opts: StreamOpts::builder()
                .kinds(KindFilter::only(StreamKind::Stderr))
                .build(),
            history_tail: None,
            ..Default::default()
        };
        let mut stream = open_vm_output_at(&locator, request).expect("open");
        let got = drain(&mut stream);
        assert_eq!(payloads(&got), vec!["err-1", "err-3"]);
        assert!(got.iter().all(|r| r.kind == StreamKind::Stderr));
    }

    #[test]
    fn from_seq_drops_the_history_prefix() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["a", "b", "c", "d"]);
        let request = OutputRequest {
            opts: StreamOpts::builder().from_seq(2).build(),
            history_tail: None,
            ..Default::default()
        };
        let mut stream = open_vm_output_at(&locator, request).expect("open");
        assert_eq!(payloads(&drain(&mut stream)), vec!["c", "d"]);
    }

    #[test]
    fn the_tail_keeps_the_newest_qualifying_records() {
        // `-n` after the filter, not before: fifty stderr lines, rather than
        // whatever stderr happens to survive in the last fifty of everything.
        let root = tempfile::tempdir().expect("tempdir");
        let locator = seal_capture(
            root.path(),
            &[
                (Direction::Stderr, b"err-0"),
                (Direction::Stdout, b"out-1"),
                (Direction::Stdout, b"out-2"),
                (Direction::Stderr, b"err-3"),
                (Direction::Stderr, b"err-4"),
            ],
            RetentionPolicy::Ring,
            bounds(),
        );
        let request = OutputRequest {
            opts: StreamOpts::builder()
                .kinds(KindFilter::only(StreamKind::Stderr))
                .build(),
            history_tail: Some(2),
            ..Default::default()
        };
        let mut stream = open_vm_output_at(&locator, request).expect("open");
        assert_eq!(payloads(&drain(&mut stream)), vec!["err-3", "err-4"]);
    }

    fn empty_locator(root: &Path) -> OutputLocator {
        OutputLocator {
            vm: "ghost".to_string(),
            socket: root.join("absent.sock"),
            transcript_dir: root.join("no-such-capture"),
            console_log: root.join("no-console.log"),
            keys_dir: root.join("keys"),
        }
    }

    #[test]
    fn a_vm_with_no_source_at_all_names_itself_and_every_place_looked() {
        let root = tempfile::tempdir().expect("tempdir");
        let Err(err) = open_vm_output_at(&empty_locator(root.path()), OutputRequest::default())
        else {
            panic!("a VM with no capture at all must not open");
        };
        assert!(matches!(err, StreamError::NoCapture { .. }), "{err}");
        let rendered = err.to_string();
        assert!(rendered.contains("ghost"), "{rendered}");
        assert!(rendered.contains("no-such-capture"), "{rendered}");
        assert!(rendered.contains("no-console.log"), "{rendered}");
    }

    #[test]
    fn a_vm_with_only_a_console_capture_still_shows_its_output() {
        // Every workload backend writes this file before boot, and until the
        // broker is wired it is the only source a real VM has. Refusing here
        // would leave `logs` showing nothing at all on every host.
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = empty_locator(root.path());
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"kernel boot\nworkload said hi\n")
            .expect("console capture");

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.availability(), StreamAvailability::ConsoleOnly);
        let got = drain(&mut stream);
        assert_eq!(payloads(&got), vec!["kernel boot\nworkload said hi\n"]);
        assert!(
            got.iter().all(|r| r.origin == RecordOrigin::Console),
            "a console record must not pass itself off as a verified one"
        );
    }

    #[test]
    fn the_console_fallback_is_not_used_beside_a_transcript() {
        // The broker's own console follower already republishes these bytes,
        // so reading the file beside a real source would double every line.
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = stdout_capture(root.path(), &["from-transcript"]);
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"from-console").expect("console capture");

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
        assert_eq!(payloads(&drain(&mut stream)), vec!["from-transcript"]);
    }

    #[test]
    fn the_console_tail_starts_near_the_end_when_one_is_asked_for() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = empty_locator(root.path());
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"old noise, lots of it. NEWEST").expect("capture");

        let request = OutputRequest {
            console_tail_bytes: Some(6),
            ..Default::default()
        };
        let mut stream = open_vm_output_at(&locator, request).expect("open");
        assert_eq!(payloads(&drain(&mut stream)), vec!["NEWEST"]);
    }

    #[test]
    fn a_tampered_capture_refuses_rather_than_reading_as_no_history() {
        // Reporting a broken transcript as "nothing here" would hide exactly
        // the case the sealed root exists to catch.
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one", "two"]);
        let manifest_path = locator.transcript_dir.join(MANIFEST_FILENAME);
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let mut manifest: TranscriptManifest = serde_json::from_str(&raw).expect("parse");
        manifest.chunks[0].sha256_hex = "0".repeat(64);
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize"),
        )
        .expect("write manifest");

        let Err(err) = open_vm_output_at(&locator, OutputRequest::default()) else {
            panic!("a tampered manifest must not open clean");
        };
        assert!(matches!(err, StreamError::Transcript { .. }), "{err}");
    }

    #[test]
    fn a_manifest_torn_by_a_dying_writer_degrades_to_the_console_rather_than_erroring() {
        // A half-written manifest is what a host crash leaves behind, which is
        // precisely when the operator needs whatever output survived. Refusing
        // the whole read over it hides the console capture sitting beside it.
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = stdout_capture(root.path(), &["one", "two"]);
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"what the guest managed to say")
            .expect("console capture");

        let manifest_path = locator.transcript_dir.join(MANIFEST_FILENAME);
        let whole = std::fs::read(&manifest_path).expect("read manifest");
        std::fs::write(&manifest_path, &whole[..whole.len() / 2]).expect("tear the manifest");

        let mut stream = open_vm_output_at(&locator, OutputRequest::default())
            .expect("a torn manifest must not fail the read");
        assert_eq!(stream.availability(), StreamAvailability::ConsoleOnly);
        assert_eq!(
            payloads(&drain(&mut stream)),
            vec!["what the guest managed to say"]
        );
    }

    #[test]
    fn an_unreadable_manifest_still_fails_rather_than_degrading() {
        // The degrade is for contents, never for access: a manifest the reader
        // cannot open is a problem with the reader's view of the capture, and
        // announcing "no capture" over it is the fail-open this refuses.
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one"]);
        let manifest_path = locator.transcript_dir.join(MANIFEST_FILENAME);
        std::fs::remove_file(&manifest_path).expect("remove the manifest file");
        // A directory where the manifest should be: present to `try_exists`,
        // an I/O error to `read`.
        std::fs::create_dir(&manifest_path).expect("stand a directory in its place");

        let Err(err) = open_vm_output_at(&locator, OutputRequest::default()) else {
            panic!("a manifest that cannot be read must not be reported as absent");
        };
        assert!(matches!(err, StreamError::Transcript { .. }), "{err}");
    }

    #[test]
    fn an_adopted_capture_reports_that_its_shortfall_is_only_a_floor() {
        // A manifest rebuilt without the writer that produced it cannot know
        // what that writer dropped on its way out. Reading it as whole is the
        // one outcome the flag exists to prevent.
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one", "two"]);
        let manifest_path = locator.transcript_dir.join(MANIFEST_FILENAME);
        let raw = std::fs::read(&manifest_path).expect("read manifest");
        let mut manifest: TranscriptManifest = serde_json::from_slice(&raw).expect("parse");
        manifest.adopted = true;
        manifest.sealed_root_hex =
            transcript::sealed_root_hex(&manifest).expect("reseal the adopted manifest");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize"),
        )
        .expect("write manifest");

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        let truncation = stream
            .truncation()
            .expect("an adopted capture is never reported as whole");
        assert!(truncation.adopted);
        assert_eq!(truncation.refused_chunks, 0);
        assert_eq!(payloads(&drain(&mut stream)), vec!["one", "two"]);
    }

    #[test]
    fn a_network_capture_is_refused_as_the_wrong_kind_of_transcript() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = seal_capture(
            root.path(),
            &[(Direction::Egress, b"GET / HTTP/1.1")],
            RetentionPolicy::Ring,
            bounds(),
        );
        let Err(err) = open_vm_output_at(&locator, OutputRequest::default()) else {
            panic!("an egress capture is not workload output");
        };
        assert!(
            matches!(err, StreamError::NotOutputTranscript { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_capture_whose_key_cannot_be_unwrapped_fails_closed() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = stdout_capture(root.path(), &["secret"]);
        // A foreign KEK: present, but not the one the capture was sealed under.
        let other_keys = root.path().join("other-keys");
        std::fs::create_dir_all(&other_keys).expect("other keys dir");
        transcript::load_or_init_kek(&other_keys).expect("foreign kek");
        locator.keys_dir = other_keys;

        let Err(err) = open_vm_output_at(&locator, OutputRequest::default()) else {
            panic!("a foreign KEK must not decrypt the capture");
        };
        assert!(matches!(err, StreamError::Transcript { .. }), "{err}");
    }

    #[test]
    fn a_missing_kek_is_reported_rather_than_minted() {
        // Minting one from a read path would seal every later capture under a
        // key a diagnostic command invented, and permanently orphan this one.
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = stdout_capture(root.path(), &["secret"]);
        let bare_keys = root.path().join("bare-keys");
        std::fs::create_dir_all(&bare_keys).expect("bare keys dir");
        locator.keys_dir = bare_keys.clone();

        let Err(err) = open_vm_output_at(&locator, OutputRequest::default()) else {
            panic!("a capture cannot be opened without its KEK");
        };
        assert!(matches!(err, StreamError::Transcript { .. }), "{err}");
        assert!(
            !bare_keys.join(transcript::TRANSCRIPT_KEK_FILENAME).exists(),
            "a read must not create key material"
        );
    }

    #[test]
    fn history_only_availability_reports_not_live() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["done"]);
        let stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert!(!stream.availability().is_live());
        assert_eq!(stream.history_len(), 1);
    }

    /// `request` narrowed to one channel, and nothing else.
    fn only(kind: StreamKind) -> OutputRequest {
        OutputRequest {
            opts: StreamOpts::builder().kinds(KindFilter::only(kind)).build(),
            ..Default::default()
        }
    }

    #[test]
    fn a_capture_that_matched_nothing_is_present_not_missing() {
        // Keying availability off surviving records rather than the
        // transcript's existence turns a stdout-only run read as stderr into
        // "this VM has no output capture" — over a capture that verified
        // clean two lines earlier.
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one", "two"]);

        let mut stream =
            open_vm_output_at(&locator, only(StreamKind::Stderr)).expect("a capture is present");
        assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
        assert_eq!(stream.empty_history(), Some(EmptyHistory::FilteredOut));
        assert!(drain(&mut stream).is_empty());
    }

    #[test]
    fn a_capture_that_matched_nothing_does_not_fall_through_to_the_console() {
        // The console holds the whole merged run. Discarding a filtered
        // transcript and dumping that instead answers a narrowed question
        // with everything, under a note claiming there was no capture.
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = stdout_capture(root.path(), &["one"]);
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"WHOLE MERGED CONSOLE").expect("console capture");

        let mut stream = open_vm_output_at(&locator, only(StreamKind::Stderr)).expect("open");
        assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
        assert!(
            drain(&mut stream).is_empty(),
            "the console must not stand in for a filtered transcript"
        );
    }

    #[test]
    fn an_empty_capture_says_it_is_empty_rather_than_absent() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = seal_capture(root.path(), &[], RetentionPolicy::Ring, bounds());
        let stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
        assert_eq!(stream.empty_history(), Some(EmptyHistory::CaptureEmpty));
    }

    #[test]
    fn asking_for_no_replay_is_not_mistaken_for_an_unmatched_filter() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one", "two"]);
        let request = OutputRequest {
            history_tail: Some(0),
            ..Default::default()
        };
        let mut stream = open_vm_output_at(&locator, request).expect("open");
        assert_eq!(stream.empty_history(), Some(EmptyHistory::NotRequested));
        assert!(drain(&mut stream).is_empty());
    }

    #[test]
    fn a_capture_that_replayed_something_reports_no_emptiness() {
        let root = tempfile::tempdir().expect("tempdir");
        let locator = stdout_capture(root.path(), &["one"]);
        let stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(stream.empty_history(), None);
    }

    #[test]
    fn emptiness_is_classified_before_the_tail_trim() {
        assert_eq!(classify_empty(0, 0, None), Some(EmptyHistory::CaptureEmpty));
        assert_eq!(classify_empty(4, 0, None), Some(EmptyHistory::FilteredOut));
        assert_eq!(
            classify_empty(4, 2, Some(0)),
            Some(EmptyHistory::NotRequested)
        );
        assert_eq!(classify_empty(4, 2, Some(1)), None);
        assert_eq!(classify_empty(4, 4, None), None);
        assert_eq!(
            classify_empty(0, 0, Some(0)),
            Some(EmptyHistory::CaptureEmpty),
            "an empty capture is the truer statement than an unasked-for replay"
        );
    }

    #[test]
    fn a_console_only_read_refuses_a_channel_it_cannot_separate() {
        // The console interleaves both channels with no labels. Answering
        // `stderr` with the whole merged log is a lie a script reading stdout
        // cannot detect, and answering it with nothing hides the only output
        // the VM has. Neither is acceptable, so neither is what happens.
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = empty_locator(root.path());
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"out and err, interleaved").expect("capture");

        let Err(err) = open_vm_output_at(&locator, only(StreamKind::Stderr)) else {
            panic!("a console log cannot honour a channel selection");
        };
        assert!(
            matches!(
                err,
                StreamError::ConsoleCannotFilter {
                    unsupported: ConsoleUnsupported::ChannelSelection,
                    ..
                }
            ),
            "{err}"
        );
        let rendered = err.to_string();
        assert!(rendered.contains("console.log"), "{rendered}");
        assert!(rendered.contains("merging stdout and stderr"), "{rendered}");
    }

    #[test]
    fn a_console_only_read_refuses_a_resume_point_from_another_sequence_space() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut locator = empty_locator(root.path());
        locator.console_log = root.path().join("console.log");
        std::fs::write(&locator.console_log, b"chunked by read, not by record").expect("capture");

        let request = OutputRequest {
            opts: StreamOpts::builder().from_seq(5).build(),
            ..Default::default()
        };
        let Err(err) = open_vm_output_at(&locator, request) else {
            panic!("console sequence numbers share nothing with a broker's");
        };
        assert!(
            matches!(
                err,
                StreamError::ConsoleCannotFilter {
                    unsupported: ConsoleUnsupported::ResumePoint,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn no_source_at_all_outranks_a_filter_the_console_could_not_have_honoured() {
        // "Nothing anywhere" is the more actionable of the two, so it wins.
        let root = tempfile::tempdir().expect("tempdir");
        let Err(err) = open_vm_output_at(&empty_locator(root.path()), only(StreamKind::Trace))
        else {
            panic!("a VM with no capture at all must not open");
        };
        assert!(matches!(err, StreamError::NoCapture { .. }), "{err}");
    }

    #[test]
    fn a_hole_between_the_sealed_history_and_the_live_head_is_reported() {
        // The manifest is written at seal, so a running VM's recorded half
        // stops well before a follower attaches. Rendering seq 0..2 straight
        // into seq 7 shows a partial log as the whole run.
        let root = tempfile::tempdir().expect("tempdir");
        let capture = stdout_capture(root.path(), &["h-0", "h-1", "h-2"]);
        let (locator, _broker) = live_locator(root.path(), capture, framed_live(7, 2));

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(
            payloads(&drain(&mut stream)),
            vec!["h-0", "h-1", "h-2", "live-7", "live-8"]
        );
        let splice = stream.splice_gap().expect("the two halves do not meet");
        assert_eq!(splice.after_seq, 2);
        assert_eq!(splice.before_seq, 7);
        assert_eq!(splice.missing(), 4);
    }

    #[test]
    fn halves_that_meet_report_no_hole() {
        let root = tempfile::tempdir().expect("tempdir");
        let capture = stdout_capture(root.path(), &["h-0", "h-1", "h-2"]);
        let (locator, _broker) = live_locator(root.path(), capture, framed_live(3, 2));

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        assert_eq!(
            payloads(&drain(&mut stream)),
            vec!["h-0", "h-1", "h-2", "live-3", "live-4"]
        );
        assert_eq!(stream.splice_gap(), None, "seq 3 follows seq 2");
    }

    #[test]
    fn an_overlap_the_dedup_suppressed_is_not_a_hole() {
        let root = tempfile::tempdir().expect("tempdir");
        let capture = stdout_capture(root.path(), &["live-0", "live-1", "live-2"]);
        let (locator, _broker) = live_locator(root.path(), capture, framed_live(0, 5));

        let mut stream = open_vm_output_at(&locator, OutputRequest::default()).expect("open");
        let _ = drain(&mut stream);
        assert_eq!(stream.splice_gap(), None);
    }

    #[test]
    fn a_narrowed_read_does_not_claim_a_hole_its_own_filter_created() {
        // Under a channel filter the reader drops records before the consumer
        // sees them, so a jump in sequence numbers is the ordinary shape of
        // the request. Reporting one would warn on every narrowed read.
        let root = tempfile::tempdir().expect("tempdir");
        let capture = seal_capture(
            root.path(),
            &[
                (Direction::Stdout, b"h-0"),
                (Direction::Stderr, b"h-1"),
                (Direction::Stdout, b"h-2"),
            ],
            RetentionPolicy::Ring,
            bounds(),
        );
        let (locator, _broker) = live_locator(root.path(), capture, framed_live(5, 2));

        let mut stream =
            open_vm_output_at(&locator, only(StreamKind::Stdout)).expect("open narrowed");
        assert_eq!(
            payloads(&drain(&mut stream)),
            vec!["h-0", "h-2", "live-5", "live-6"]
        );
        assert_eq!(
            stream.splice_gap(),
            None,
            "the distance is the filter's, not the splice's"
        );
    }

    #[test]
    fn a_hole_is_measured_only_against_the_first_live_record() {
        assert_eq!(detect_splice_gap(true, Some(4), 5), None, "adjacent");
        assert_eq!(
            detect_splice_gap(true, Some(4), 6),
            Some(SpliceGap {
                after_seq: 4,
                before_seq: 6
            }),
            "one missing"
        );
        assert_eq!(detect_splice_gap(true, None, 900), None, "no durable half");
        assert_eq!(detect_splice_gap(false, Some(4), 900), None, "narrowed");
        assert_eq!(
            detect_splice_gap(true, Some(0), 0),
            None,
            "a suppressed overlap never reaches this check, and would not be a hole"
        );
    }

    #[test]
    fn only_an_unnarrowed_request_can_attribute_a_hole_to_the_splice() {
        assert!(splice_detectable(&StreamOpts::default()));
        assert!(!splice_detectable(
            &StreamOpts::builder()
                .kinds(KindFilter::only(StreamKind::Stdout))
                .build()
        ));
        assert!(!splice_detectable(
            &StreamOpts::builder().from_seq(1).build()
        ));
        assert!(
            splice_detectable(&StreamOpts::builder().follow(true).build()),
            "following changes nothing about how densely records are numbered"
        );
    }
}
