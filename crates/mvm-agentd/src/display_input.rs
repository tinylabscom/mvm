//! Delivery of admitted display input to the guest's display bridge.
//!
//! The host's display input gate decides whether input may move: the signed
//! grant, the attended tier, the single-writer lease, the ordering, and the
//! audit record. What reaches this module is a frame that gate already
//! accepted. The agent's job is only to hand it to the bridge that owns the
//! browser's debugging pipe, and it does that through one FIFO:
//!
//! - **The agent creates it, the bridge reads it.** Neither side listens on
//!   anything. The FIFO is created on the first delivery, mode `0604`, so the
//!   agent is its only writer; the bridge, started with `--input`, opens it for
//!   reading. A guest with no `--input` bridge has a FIFO nobody reads, and a
//!   delivery into it is refused rather than queued.
//! - **No reader, no delivery.** The write end is opened non-blocking, which
//!   fails with `ENXIO` when no bridge holds the read end. That is reported as
//!   [`DisplayDeliveryRefusal::NoBridge`] and nothing is buffered.
//! - **A frame is one line.** Each frame is written as a newline, its compact
//!   JSON, and a newline. A frame cut short by the write deadline leaves an
//!   unterminated line that the next frame's leading newline closes, so the
//!   reader drops that one frame and stays in step.
//! - **Repeats are answered, not replayed.** A host whose call failed after the
//!   bridge already took the frame offers it again under the same `seq`. The
//!   desk answers a repeat of the last delivered `seq` without writing it
//!   twice.
//!
//! Anything typed through this path is inside the guest, which belongs to the
//! workload: the workload drives the browser the bridge feeds. That is the
//! limit the attended grant exists to make explicit, not something this module
//! can hide.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use mvm_contract::stream::DisplayInputFrame;

use crate::vsock::{DisplayDeliveryRefusal, DisplayInputResult};

/// The FIFO between the agent and the display bridge.
pub const DISPLAY_INPUT_FIFO: &str = "/run/mvm/display-input";

/// Largest encoded frame the agent writes or the bridge reads.
///
/// A paste is bounded at 64 KiB by its grant; JSON escaping can multiply that
/// several times for control characters, and everything else in a frame is
/// small.
pub const MAX_ENCODED_DISPLAY_INPUT_FRAME_BYTES: usize = 512 * 1024;

/// How long one delivery may wait on a bridge that is not reading.
const WRITE_DEADLINE: Duration = Duration::from_secs(2);

/// Bound live-input latency independently of the FIFO startup retry interval.
const INPUT_IDLE_BACKOFF: Duration = Duration::from_millis(5);

const FIFO_MODE: u32 = 0o604;

/// Encode one frame as the line the bridge reads.
///
/// # Errors
/// The frame does not serialize, or its encoding exceeds
/// [`MAX_ENCODED_DISPLAY_INPUT_FRAME_BYTES`].
pub fn encode_frame(frame: &DisplayInputFrame) -> io::Result<Vec<u8>> {
    let json =
        serde_json::to_vec(frame).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    if json.len() > MAX_ENCODED_DISPLAY_INPUT_FRAME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "display input frame exceeds the encoded byte limit",
        ));
    }
    let mut line = Vec::with_capacity(json.len() + 2);
    line.push(b'\n');
    line.extend_from_slice(&json);
    line.push(b'\n');
    Ok(line)
}

/// Read the next well-formed frame, skipping blank lines and lines that do not
/// decode. `Ok(None)` is end of input.
///
/// # Errors
/// Only I/O errors from `reader`. A malformed or oversized line is skipped, so
/// one truncated frame cannot stop the frames after it.
pub fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<DisplayInputFrame>> {
    loop {
        let mut line = Vec::new();
        let limit = u64::try_from(MAX_ENCODED_DISPLAY_INPUT_FRAME_BYTES + 2).unwrap_or(u64::MAX);
        let read = reader.by_ref().take(limit).read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') {
            // Oversized: discard the rest of this line before continuing.
            if u64::try_from(read).unwrap_or(u64::MAX) >= limit {
                let mut rest = Vec::new();
                reader.read_until(b'\n', &mut rest)?;
                continue;
            }
            // End of input mid-line: a frame cut short by its writer.
            return Ok(None);
        }
        line.pop();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<DisplayInputFrame>(&line) {
            Ok(frame) if frame.validate().is_ok() => return Ok(Some(frame)),
            Ok(_) | Err(_) => {
                tracing::warn!("display bridge dropped a malformed input frame");
            }
        }
    }
}

/// The agent's side of the FIFO. One per guest, because one guest is one
/// workload.
pub struct DisplayInputDesk;

static LAST_DELIVERED: Mutex<Option<u64>> = Mutex::new(None);

impl DisplayInputDesk {
    /// Hand one admitted frame to the display bridge.
    #[must_use]
    pub fn deliver(frame: &DisplayInputFrame) -> DisplayInputResult {
        Self::deliver_at(Path::new(DISPLAY_INPUT_FIFO), frame)
    }

    /// [`deliver`](Self::deliver) through an explicit FIFO path.
    #[must_use]
    pub fn deliver_at(fifo: &Path, frame: &DisplayInputFrame) -> DisplayInputResult {
        let mut last = LAST_DELIVERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(previous) = *last {
            if frame.seq == previous {
                return DisplayInputResult::Accepted;
            }
            if frame.seq < previous {
                return refused(
                    DisplayDeliveryRefusal::OutOfOrder,
                    format!("seq {} does not advance past {previous}", frame.seq),
                );
            }
        }
        if let Err(error) = frame.validate() {
            return refused(DisplayDeliveryRefusal::Malformed, error.to_string());
        }
        let line = match encode_frame(frame) {
            Ok(line) => line,
            Err(error) => return refused(DisplayDeliveryRefusal::Malformed, error.to_string()),
        };
        if let Err(error) = ensure_fifo(fifo) {
            return refused(DisplayDeliveryRefusal::NoBridge, error.to_string());
        }
        let mut writer = match open_writer(fifo) {
            Ok(writer) => writer,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                return refused(
                    DisplayDeliveryRefusal::NoBridge,
                    "no display bridge is reading input; start it with --input".to_string(),
                );
            }
            Err(error) => return refused(DisplayDeliveryRefusal::NoBridge, error.to_string()),
        };
        match write_with_deadline(&mut writer, &line, WRITE_DEADLINE) {
            Ok(()) => {
                *last = Some(frame.seq);
                DisplayInputResult::Accepted
            }
            Err(error) => refused(DisplayDeliveryRefusal::Busy, error.to_string()),
        }
    }

    /// Forget the delivery sequence — for tests that share the process.
    #[cfg(test)]
    pub(crate) fn reset_for_test() {
        *LAST_DELIVERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

fn refused(kind: DisplayDeliveryRefusal, message: String) -> DisplayInputResult {
    DisplayInputResult::Refused { kind, message }
}

/// Create the FIFO if it is absent, and refuse a path that is anything but a
/// FIFO this process owns. `lstat` rather than `stat`, so a symlink planted in
/// its place is refused rather than followed.
fn ensure_fifo(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => return check_fifo(&metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
    // SAFETY: `c_path` is a valid NUL-terminated path that outlives the call,
    // and `mkfifo` reads it without retaining it.
    let created = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if created != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(FIFO_MODE))?;
    check_fifo(&std::fs::symlink_metadata(path)?)
}

fn check_fifo(metadata: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.file_type().is_fifo() {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "the display input path exists and is not a FIFO",
        ));
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "the display input FIFO belongs to another user",
        ));
    }
    Ok(())
}

fn open_writer(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

/// Write all of `bytes` to a non-blocking FIFO, waiting at most `deadline` for
/// a reader that has fallen behind.
fn write_with_deadline(writer: &mut File, mut bytes: &[u8], deadline: Duration) -> io::Result<()> {
    let start = Instant::now();
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "the display bridge stopped reading",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if start.elapsed() >= deadline {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "the display bridge did not read the frame in time",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Open the FIFO for reading, waiting for the agent to create it. Blocks until
/// a writer opens the other end, which is the agent delivering a frame.
///
/// # Errors
/// The path exists and is not a FIFO, or opening it fails.
pub fn open_reader(path: &Path, poll: Duration) -> io::Result<File> {
    loop {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_fifo() => {
                return OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path);
            }
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "the display input path exists and is not a FIFO",
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => std::thread::sleep(poll),
            Err(error) => return Err(error),
        }
    }
}

/// The bridge's read side of the FIFO, held open between deliveries.
///
/// The agent opens the FIFO for each delivery and closes it after, which the
/// reader sees as end of input. Keep the reader alive across that EOF: closing
/// it could break a writer that opened just after the EOF was observed.
pub struct FifoInput {
    path: std::path::PathBuf,
    startup_poll: Duration,
    file: Option<File>,
}

impl FifoInput {
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>, startup_poll: Duration) -> Self {
        Self {
            path: path.into(),
            startup_poll,
            file: None,
        }
    }

    fn wait_after_eof(&mut self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        // Reconcile externally owned path replacement, but never close a live
        // reader merely because the per-delivery writer disconnected.
        let current = self.file.as_ref().expect("EOF requires an open FIFO");
        let held = current.metadata()?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(path) if path.dev() == held.dev() && path.ino() == held.ino() => {}
            Ok(_) => self.file = None,
            Err(error) if error.kind() == ErrorKind::NotFound => self.file = None,
            Err(error) => return Err(error),
        }
        // EOF stays readable to poll/select while no writer exists. A short
        // backoff avoids spinning without imposing startup retry latency on
        // keyboard/pointer input. At idle this costs at most 200 wakes/second.
        std::thread::sleep(INPUT_IDLE_BACKOFF);
        Ok(())
    }
}

impl Read for FifoInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let file = match self.file.as_mut() {
                Some(file) => file,
                None => self
                    .file
                    .insert(open_reader(&self.path, self.startup_poll)?),
            };
            match file.read(buf) {
                Ok(0) => self.wait_after_eof()?,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;
    use std::sync::mpsc;

    use mvm_contract::stream::{DisplayInputEvent, PointerButton};

    use super::*;

    /// Serializes the tests that share the desk's sequence.
    static DESK: Mutex<()> = Mutex::new(());

    fn frame(seq: u64) -> DisplayInputFrame {
        DisplayInputFrame {
            seq,
            events: vec![DisplayInputEvent::PointerButton {
                x: 1,
                y: 2,
                button: PointerButton::Left,
                pressed: true,
            }],
        }
    }

    #[test]
    fn a_frame_is_one_line_and_reads_back() {
        let line = encode_frame(&frame(4)).unwrap();
        assert_eq!(line.first(), Some(&b'\n'));
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 2);
        let mut reader = BufReader::new(&line[..]);
        assert_eq!(read_frame(&mut reader).unwrap(), Some(frame(4)));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn a_truncated_frame_costs_only_itself() {
        let whole = encode_frame(&frame(1)).unwrap();
        let mut stream = whole[..whole.len() / 2].to_vec();
        stream.extend_from_slice(&encode_frame(&frame(2)).unwrap());
        stream.extend_from_slice(b"\n{\"seq\":3,\"events\":[{\"kind\":\"evaluate\"}]}\n");
        stream.extend_from_slice(&encode_frame(&frame(4)).unwrap());
        let mut reader = BufReader::new(&stream[..]);
        assert_eq!(read_frame(&mut reader).unwrap(), Some(frame(2)));
        assert_eq!(read_frame(&mut reader).unwrap(), Some(frame(4)));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn no_bridge_means_no_delivery() {
        let _desk = DESK.lock().unwrap_or_else(PoisonError::into_inner);
        DisplayInputDesk::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("display-input");
        let result = DisplayInputDesk::deliver_at(&fifo, &frame(0));
        assert!(
            matches!(
                result,
                DisplayInputResult::Refused {
                    kind: DisplayDeliveryRefusal::NoBridge,
                    ..
                }
            ),
            "{result:?}"
        );
        let mode = std::fs::metadata(&fifo).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, FIFO_MODE);
    }

    #[test]
    fn a_planted_file_is_refused_rather_than_written() {
        let _desk = DESK.lock().unwrap_or_else(PoisonError::into_inner);
        DisplayInputDesk::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("display-input");
        std::fs::write(&fifo, b"keep me").unwrap();
        assert!(matches!(
            DisplayInputDesk::deliver_at(&fifo, &frame(0)),
            DisplayInputResult::Refused { .. }
        ));
        assert_eq!(std::fs::read(&fifo).unwrap(), b"keep me");
    }

    fn input_at_eof(path: &Path) -> FifoInput {
        ensure_fifo(path).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
            .unwrap();
        assert_eq!(file.read(&mut [0]).unwrap(), 0);
        let mut input = FifoInput::new(path, Duration::from_millis(1));
        input.file = Some(file);
        input
    }

    #[test]
    fn eof_does_not_disconnect_a_writer_that_already_opened() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("display-input");
        let mut input = input_at_eof(&fifo);

        // Force the failing interleaving without relying on thread scheduling:
        // observe EOF, open the next writer, then handle the previous EOF.
        let mut writer = open_writer(&fifo).unwrap();
        input.wait_after_eof().unwrap();
        let line = encode_frame(&frame(2)).unwrap();
        write_with_deadline(&mut writer, &line, WRITE_DEADLINE).unwrap();
        drop(writer);
        assert_eq!(
            read_frame(&mut BufReader::new(&mut input)).unwrap(),
            Some(frame(2))
        );

        drop(input);
        assert_eq!(
            open_writer(&fifo).unwrap_err().raw_os_error(),
            Some(libc::ENXIO)
        );
    }

    #[test]
    fn eof_releases_an_unlinked_or_replaced_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("display-input");
        let mut input = input_at_eof(&fifo);
        std::fs::remove_file(&fifo).unwrap();
        input.wait_after_eof().unwrap();
        assert!(input.file.is_none(), "an unlinked FIFO must be released");

        let mut input = input_at_eof(&fifo);
        std::fs::rename(&fifo, dir.path().join("old-input")).unwrap();
        ensure_fifo(&fifo).unwrap();
        input.wait_after_eof().unwrap();
        assert!(input.file.is_none(), "a replaced FIFO must be reopened");
    }

    #[test]
    fn live_input_does_not_wait_for_the_startup_poll_interval() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("display-input");
        let mut input = FifoInput::new(&fifo, Duration::from_millis(250));
        input.file = input_at_eof(&fifo).file;

        // Queue the next delivery just after observing EOF, so handling that
        // EOF must not impose the bridge's much slower startup interval.
        let mut writer = open_writer(&fifo).unwrap();
        let started = Instant::now();
        write_with_deadline(
            &mut writer,
            &encode_frame(&frame(2)).unwrap(),
            WRITE_DEADLINE,
        )
        .unwrap();
        drop(writer);
        input.wait_after_eof().unwrap();
        assert_eq!(
            read_frame(&mut BufReader::new(&mut input)).unwrap(),
            Some(frame(2))
        );
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "live delivery inherited the startup interval: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_reading_bridge_receives_frames_in_order_and_repeats_are_not_replayed() {
        let _desk = DESK.lock().unwrap_or_else(PoisonError::into_inner);
        DisplayInputDesk::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("display-input");
        assert!(matches!(
            DisplayInputDesk::deliver_at(&fifo, &frame(0)),
            DisplayInputResult::Refused { .. }
        ));

        let (sent, received) = mpsc::channel();
        let reader_path = fifo.clone();
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(FifoInput::new(reader_path, Duration::from_millis(5)));
            while let Some(frame) = read_frame(&mut reader).unwrap() {
                sent.send(frame.seq).unwrap();
                if frame.seq == 3 {
                    return;
                }
            }
        });

        let deliver = |seq| {
            let start = Instant::now();
            loop {
                match DisplayInputDesk::deliver_at(&fifo, &frame(seq)) {
                    DisplayInputResult::Accepted => return,
                    DisplayInputResult::Refused {
                        kind: DisplayDeliveryRefusal::NoBridge,
                        ..
                    } if start.elapsed() < Duration::from_secs(5) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    other => panic!("delivery of {seq} failed: {other:?}"),
                }
            }
        };
        deliver(1);
        deliver(2);
        deliver(2);
        assert!(matches!(
            DisplayInputDesk::deliver_at(&fifo, &frame(1)),
            DisplayInputResult::Refused {
                kind: DisplayDeliveryRefusal::OutOfOrder,
                ..
            }
        ));
        let first = received.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((first, second), (1, 2));
        assert!(
            matches!(
                received.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "a repeated seq must not be written twice"
        );
        deliver(3);
        assert_eq!(received.recv_timeout(Duration::from_secs(5)).unwrap(), 3);
        reader.join().unwrap();
    }
}
