//! The console capture, read directly off the host filesystem.
//!
//! The coarsest of a VM's output sources and the only one that exists on a VM
//! whose broker never ran: a single write-only file every workload backend
//! opens before boot. It is a **fallback**, used only when neither the broker
//! nor a durable transcript answers — when a broker is running, its own
//! console follower already republishes these bytes, and reading the file
//! again beside it would double every line.
//!
//! What this is **not** is the path it replaces. The retired `mvmctl logs`
//! reached the same file by shelling `tail -f` through a `LinuxEnv`
//! indirection that, on the one tier where the indirection was not a no-op,
//! had nothing left to dispatch to. This opens a host file. No subprocess, no
//! builder VM, no guest.
//!
//! **Read-only, always.** The console has no host input fd by design — a
//! sealed production guest must never gain one — and nothing here adds one.
//!
//! Two honest limitations, both surfaced rather than papered over:
//!
//! - **No channel separation.** The guest writes stdout and stderr to one
//!   console, so every record is reported as [`StreamKind::Stdout`] under
//!   [`RecordOrigin::Console`]. A consumer that needs the split needs the
//!   broker.
//! - **No record boundaries.** Chunking is by read, so a record is "whatever
//!   had arrived at that tick", not a line and not a write.
//!
//! Neither is papered over by guessing. A request this source cannot answer
//! is named through [`ConsoleUnsupported`] and refused by the resolver, rather
//! than answered with everything under a flag that says it was narrowed.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mvm_protocol::stream::StreamKind;

use super::opts::{KindFilter, StreamOpts};
use super::output::{OutputRecord, RecordOrigin};

/// What a console-only read was asked for that a console log cannot supply.
///
/// A console log is one interleaved byte stream with no channel labels and a
/// sequence space of its own, so a request that narrows by channel or resumes
/// at a sequence has no honest answer here. Both of the tempting answers are
/// wrong in the same way: returning everything hands back bytes the caller
/// excluded, and returning nothing hides the only output the VM has. Naming
/// what cannot be supplied lets the caller decide, and — unlike a warning on
/// stderr — cannot be missed by a script reading stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleUnsupported {
    /// A channel narrower than every kind. The guest writes stdout and stderr
    /// to one console with nothing left to tell them apart.
    ChannelSelection,
    /// A resume point. Console sequence numbers count read chunks and share
    /// nothing with the broker's or the transcript's numbering, so honouring
    /// one would drop console output for an unrelated reason.
    ResumePoint,
}

impl ConsoleUnsupported {
    /// What `opts` asks a console log for that it cannot give, if anything.
    ///
    /// Channel first: it is the one a person types.
    pub fn of(opts: &StreamOpts) -> Option<Self> {
        if opts.kinds != KindFilter::all() {
            return Some(Self::ChannelSelection);
        }
        opts.from_seq.map(|_| Self::ResumePoint)
    }
}

impl std::fmt::Display for ConsoleUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ChannelSelection => "a channel selection",
            Self::ResumePoint => "a resume point",
        })
    }
}

/// Largest read per tick. Bounds one tick's allocation even when the file grew
/// a lot between polls; the remainder is picked up by the next tick, which
/// does not sleep while a tick made progress.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// How often a following reader re-checks the file for appended bytes. Matches
/// the host-side console follower's cadence, so switching between them does
/// not change how live the output feels.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Reads a VM's console capture as output records.
pub struct ConsoleTail {
    path: PathBuf,
    file: Option<File>,
    offset: u64,
    seq: u64,
    follow: bool,
}

impl ConsoleTail {
    /// Read `path` from its start. `follow` keeps polling for appended bytes
    /// once the end is reached, instead of finishing.
    pub fn open(path: &Path, follow: bool) -> Self {
        Self {
            path: path.to_path_buf(),
            file: None,
            offset: 0,
            seq: 0,
            follow,
        }
    }

    /// Skip to `bytes` before the current end, so a bounded read starts near
    /// the newest output rather than replaying a long-running VM's whole boot.
    ///
    /// Byte-based because the console has no record boundaries to count.
    pub fn seek_to_last(&mut self, bytes: u64) -> io::Result<()> {
        let len = std::fs::metadata(&self.path)?.len();
        self.offset = len.saturating_sub(bytes);
        Ok(())
    }

    /// Position at the start of the last `lines` newline-delimited lines.
    ///
    /// `--lines` is a line-oriented request, and a byte estimate answers it
    /// only approximately — a short line count under-trims and returns more
    /// than was asked for. The console is the one source where honouring it
    /// exactly is safe: it is the unchained, unredacted fallback, so moving
    /// the start to a line boundary re-frames nothing the chain covers.
    pub fn seek_to_last_lines(&mut self, lines: usize) -> io::Result<()> {
        let contents = std::fs::read(&self.path)?;
        if lines == 0 {
            self.offset = contents.len() as u64;
            return Ok(());
        }
        // Step over one trailing newline so a file ending in `\n` does not
        // spend a line on the empty remainder after it.
        let mut i = contents.len();
        if i > 0 && contents[i - 1] == b'\n' {
            i -= 1;
        }
        let mut seen = 0usize;
        while i > 0 {
            if contents[i - 1] == b'\n' {
                seen += 1;
                if seen == lines {
                    break;
                }
            }
            i -= 1;
        }
        self.offset = i as u64;
        Ok(())
    }

    /// The next chunk of console output, or `None` when a non-following reader
    /// reaches the end.
    pub fn next_record(&mut self) -> io::Result<Option<OutputRecord>> {
        loop {
            if let Some(payload) = self.read_tick()? {
                let record = OutputRecord {
                    seq: self.seq,
                    kind: StreamKind::Stdout,
                    origin: RecordOrigin::Console,
                    payload,
                };
                self.seq = self.seq.saturating_add(1);
                return Ok(Some(record));
            }
            if !self.follow {
                return Ok(None);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// One poll: whatever is readable past the held offset, if anything.
    ///
    /// The file is reopened whenever it is not yet held, so a reader that
    /// attached before the backend created it picks it up rather than
    /// reporting an empty capture forever.
    fn read_tick(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.file.is_none() {
            match File::open(&self.path) {
                Ok(file) => self.file = Some(file),
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(err),
            }
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(None);
        };
        file.seek(SeekFrom::Start(self.offset))?;
        let mut buf = vec![0u8; READ_CHUNK_BYTES];
        let read = file.read(&mut buf)?;
        if read == 0 {
            return Ok(None);
        }
        buf.truncate(read);
        self.offset = self.offset.saturating_add(read as u64);
        Ok(Some(buf))
    }
}

impl std::fmt::Debug for ConsoleTail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Payload-free, for the same reason the framed reader's is: a `Debug`
        // that printed buffered bytes would turn any log line into a second
        // copy of the workload's output.
        f.debug_struct("ConsoleTail")
            .field("path", &self.path)
            .field("offset", &self.offset)
            .field("seq", &self.seq)
            .field("follow", &self.follow)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open capture");
        file.write_all(bytes).expect("append");
    }

    fn drain(tail: &mut ConsoleTail) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(record) = tail.next_record().expect("read must not fail") {
            out.extend_from_slice(&record.payload);
        }
        out
    }

    #[test]
    fn a_capture_file_reads_back_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"boot\nrunning\n");

        let mut tail = ConsoleTail::open(&path, false);
        assert_eq!(drain(&mut tail), b"boot\nrunning\n");
    }

    #[test]
    fn every_record_declares_itself_console_sourced() {
        // The console cannot separate stdout from stderr, so a consumer must
        // be able to see that its channel label is a default, not a fact.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"merged");

        let mut tail = ConsoleTail::open(&path, false);
        let record = tail.next_record().expect("read").expect("a record");
        assert_eq!(record.origin, RecordOrigin::Console);
        assert_eq!(record.kind, StreamKind::Stdout);
    }

    #[test]
    fn a_missing_capture_is_an_empty_read_not_an_error() {
        // A VM whose backend has not opened the file yet is not a failure.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut tail = ConsoleTail::open(&dir.path().join("absent.log"), false);
        assert_eq!(tail.next_record().expect("no error"), None);
    }

    #[test]
    fn a_capture_created_after_the_reader_attached_is_picked_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        let mut tail = ConsoleTail::open(&path, false);
        assert_eq!(tail.next_record().expect("no error"), None);

        write(&path, b"late boot");
        assert_eq!(drain(&mut tail), b"late boot");
    }

    #[test]
    fn a_non_following_reader_stops_at_the_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"done");
        let mut tail = ConsoleTail::open(&path, false);
        assert_eq!(drain(&mut tail), b"done");
        assert_eq!(tail.next_record().expect("no error"), None);
    }

    #[test]
    fn a_following_reader_picks_up_bytes_appended_after_it_caught_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"first");
        let mut tail = ConsoleTail::open(&path, true);
        assert_eq!(
            tail.next_record().expect("read").expect("a record").payload,
            b"first"
        );

        let appender = {
            let path = path.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                write(&path, b"second");
            })
        };
        assert_eq!(
            tail.next_record().expect("read").expect("a record").payload,
            b"second"
        );
        appender.join().expect("appender");
    }

    #[test]
    fn seeking_to_the_last_bytes_skips_a_long_boot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"aaaaaaaaaaaaaaaaaaaanewest");

        let mut tail = ConsoleTail::open(&path, false);
        tail.seek_to_last(6).expect("seek");
        assert_eq!(drain(&mut tail), b"newest");
    }

    #[test]
    fn seeking_past_the_whole_file_keeps_all_of_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"short");

        let mut tail = ConsoleTail::open(&path, false);
        tail.seek_to_last(9_000).expect("seek");
        assert_eq!(drain(&mut tail), b"short");
    }

    #[test]
    fn sequence_numbers_advance_across_chunks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, &vec![b'x'; READ_CHUNK_BYTES + 16]);

        let mut tail = ConsoleTail::open(&path, false);
        let mut seqs = Vec::new();
        while let Some(record) = tail.next_record().expect("read") {
            seqs.push(record.seq);
        }
        assert_eq!(seqs, vec![0, 1], "an over-chunk read splits and numbers");
    }

    #[test]
    fn debug_never_prints_captured_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("console.log");
        write(&path, b"secret-console-bytes");
        let mut tail = ConsoleTail::open(&path, false);
        let _ = tail.next_record().expect("read");
        let rendered = format!("{tail:?}");
        assert!(!rendered.contains("secret-console-bytes"), "{rendered}");
    }
}
