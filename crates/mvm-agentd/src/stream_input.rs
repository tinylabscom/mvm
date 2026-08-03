//! Delivery of admitted input bytes into a running workload's stdin.
//!
//! The one-shot path writes the whole payload once and drops the pipe
//! immediately (`entrypoint::execute`), so EOF is implicit in "there was never
//! going to be more". Continuous input has no such moment: bytes keep arriving
//! for as long as a writer holds the lease, and nothing in the byte stream says
//! where it ends. Three properties carry that difference.
//!
//! - **EOF is explicit and it really closes the fd.** [`InputSink::close`] is
//!   the only thing that ends the stream, and it ends it by dropping the
//!   `ChildStdin` — a flag, a zero-length write or a sentinel byte would leave
//!   a `cat`-shaped workload blocked on a `read` that never returns. Closing
//!   the fd is the signal; there is no second mechanism.
//! - **Delivery order is acceptance order.** Frames are written in the order
//!   they were offered, never re-sorted by [`InputFrame::seq`]. The host gate
//!   scans for secret material across frame boundaries by concatenating what it
//!   accepted, in that order, so a sink that re-sorted could reassemble inside
//!   the guest a secret the gate saw as non-contiguous. The gate holds up its
//!   end by refusing any frame whose `seq` does not advance; this side holds up
//!   its end by not reordering, and neither can drift from what was scanned.
//! - **A child that is not reading cannot stall anything else.** A pipe holds
//!   a page or two, so a `write` into a wedged stdin blocks — and blocking on
//!   the caller's thread would park whichever loop it shares. Writes therefore
//!   happen on this sink's own thread, fed by a channel, and the enqueue side
//!   never waits on the child. What the channel must not do is grow without
//!   bound in a guest with a fixed memory budget, so a queue past
//!   [`MAX_PENDING_INPUT_BYTES`] is refused rather than accepted: backpressure
//!   the writer can see, instead of memory it cannot.

use std::io::{self, Write};
use std::process::ChildStdin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

use mvm_protocol::stream::input::InputFrame;
use zeroize::Zeroize;

/// Bytes that may sit queued for a workload that is not reading its stdin.
///
/// Matches the one-shot payload cap (`CallCaps::stdin_max`), because it bounds
/// the same thing: how much undelivered input the agent will hold on a
/// workload's behalf. Generous enough that a writer streaming at any sane rate
/// never sees it, small enough that a workload which stopped reading costs the
/// guest a megabyte rather than everything it has.
pub const MAX_PENDING_INPUT_BYTES: usize = 1024 * 1024;

/// The writing half of one workload's stdin.
///
/// Owns the `ChildStdin` for the life of the stream — the `Child` must not
/// still hold it, or the fd stays open past [`close`](InputSink::close) and the
/// EOF never lands.
pub struct InputSink {
    tx: Sender<Vec<u8>>,
    pending: Arc<AtomicUsize>,
}

impl InputSink {
    /// Take ownership of a spawned child's stdin and start delivering to it.
    #[must_use]
    pub fn new(stdin: ChildStdin) -> Self {
        let (tx, rx) = mpsc::channel();
        let pending = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&pending);
        std::thread::spawn(move || write_until_closed(stdin, &rx, &counted));
        Self { tx, pending }
    }

    /// Queue one admitted frame's payload for the workload.
    ///
    /// Returns as soon as the bytes are queued; it does not wait for the child
    /// to read them. `WouldBlock` means the queue is at its budget and the
    /// caller should offer the frame again later; `BrokenPipe` means the
    /// workload's stdin is gone and offering it again will not help.
    ///
    /// Frames are delivered in call order. Callers must offer them in the order
    /// the gate accepted them, which is also `seq` order — see the module docs
    /// for why the two must not be allowed to differ.
    pub fn write_frame(&mut self, frame: InputFrame) -> io::Result<()> {
        self.enqueue(frame.payload)
    }

    /// Queue bytes the gate withheld and released at close.
    ///
    /// Separate from [`write_frame`](Self::write_frame) because these bytes
    /// carry no `seq` of their own: the gate holds back a tail that is still a
    /// live prefix of a known secret and releases it when closing proves it was
    /// only ever a prefix. They belong immediately after the highest frame the
    /// gate accepted, which is where calling this before `close` puts them.
    pub fn deliver_tail(&mut self, tail: &[u8]) -> io::Result<()> {
        self.enqueue(tail.to_vec())
    }

    /// Bytes queued for the workload but not yet written to its pipe.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// End the input stream: deliver what is queued, then close the fd.
    ///
    /// Dropping the sender is what the writer thread reads as end-of-stream. It
    /// finishes the queue first — a channel hands over everything buffered
    /// before it reports the disconnect — and then drops the `ChildStdin`, and
    /// that fd close *is* the EOF. Bytes handed to
    /// [`deliver_tail`](Self::deliver_tail) therefore land ahead of it rather
    /// than being lost to the close.
    ///
    /// Deliberately does not wait for the writer to drain. A workload that
    /// stopped reading its stdin would make that wait as long as the workload
    /// itself, and closing input is not a reason to block the agent for the
    /// rest of a call. The fd is closed by the thread that owns it, whenever
    /// the last queued byte lands or the child goes away first.
    pub fn close(self) {
        drop(self);
    }

    fn enqueue(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let queued = self.pending.load(Ordering::Relaxed);
        if queued.saturating_add(bytes.len()) > MAX_PENDING_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("workload input queue is full ({queued} bytes undelivered)"),
            ));
        }
        let len = bytes.len();
        self.pending.fetch_add(len, Ordering::Relaxed);
        self.tx.send(bytes).map_err(|_| {
            self.pending.fetch_sub(len, Ordering::Relaxed);
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the workload is no longer reading its stdin",
            )
        })
    }
}

/// Write queued bytes to the workload until the stream ends, then close the fd.
///
/// Runs on its own thread precisely so the blocking `write_all` here is the
/// only thing a full pipe can stall.
fn write_until_closed(mut stdin: ChildStdin, rx: &Receiver<Vec<u8>>, pending: &AtomicUsize) {
    while let Ok(mut bytes) = rx.recv() {
        let delivered = stdin.write_all(&bytes);
        pending.fetch_sub(bytes.len(), Ordering::Relaxed);
        // Delivered input does not linger on the guest heap, mirroring the
        // hygiene the host gate applies to the same bytes on its side.
        bytes.zeroize();
        if delivered.is_err() {
            // The workload closed its stdin or died. Nothing queued behind
            // this will ever be delivered, so drop it out of the accounting:
            // a caller that kept seeing a full queue would retry forever
            // instead of learning the pipe is gone.
            while let Ok(mut undelivered) = rx.try_recv() {
                pending.fetch_sub(undelivered.len(), Ordering::Relaxed);
                undelivered.zeroize();
            }
            break;
        }
    }
    // Dropping `stdin` closes the write end, and that close is the EOF a
    // read-to-EOF workload has been waiting for.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn frame(seq: u64, payload: &[u8]) -> InputFrame {
        InputFrame {
            seq,
            payload: payload.to_vec(),
        }
    }

    /// A child shaped like a workload: stdin piped, stdout piped.
    fn spawn(program: &str, args: &[&str]) -> std::process::Child {
        Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child")
    }

    #[test]
    fn close_input_delivers_eof_so_a_read_to_end_child_terminates() {
        // Without an explicit EOF this hangs forever — the trap this test exists for.
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn cat");
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(InputFrame {
            seq: 0,
            payload: b"hi".to_vec(),
        })
        .expect("write");
        sink.close();
        let status = child.wait().expect("cat must exit after EOF");
        assert!(status.success());
    }

    #[test]
    fn bytes_arrive_in_acceptance_order_not_seq_order() {
        // A sink that re-sorted by `seq` would emit "secondfirst" here — and a
        // secret split across two frames would reassemble in the guest that the
        // gate scanned as two separate, harmless halves.
        let mut child = spawn("/bin/cat", &[]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(frame(9, b"first"))
            .expect("first accepted");
        sink.write_frame(frame(3, b"second"))
            .expect("second accepted");
        sink.close();
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"firstsecond");
    }

    #[test]
    fn a_tail_withheld_at_the_gate_is_delivered_before_eof() {
        // The gate holds back a tail that is still a live prefix of a known
        // secret and releases it at close. Those bytes are the caller's last
        // ones; closing must ship them, not swallow them.
        let mut child = spawn("/bin/cat", &[]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(frame(0, b"he")).expect("frame accepted");
        sink.deliver_tail(b"llo").expect("tail accepted");
        sink.close();
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"hello");
    }

    #[test]
    fn a_child_that_never_reads_stalls_neither_delivery_nor_its_own_output() {
        let mut child = spawn("/bin/sh", &["-c", "echo ready; echo more; sleep 5"]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        let mut out = BufReader::new(child.stdout.take().expect("piped stdout"));

        let mut first = String::new();
        out.read_line(&mut first).expect("child output flows");
        assert_eq!(first.trim_end(), "ready");

        // Far more than a pipe buffer holds, into a child that will never read
        // a byte of it. If delivery waited on the child this loop would not
        // return, so the absence of a hang is the assertion.
        for seq in 0..8 {
            sink.write_frame(frame(seq, &vec![b'x'; 64 * 1024]))
                .expect("delivery never waits on the workload");
        }

        // And the wedged input path leaves the output path exactly where it was.
        let mut second = String::new();
        out.read_line(&mut second)
            .expect("child output still flows past a wedged stdin");
        assert_eq!(second.trim_end(), "more");

        sink.close();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn input_past_the_queue_budget_is_refused_rather_than_queued() {
        let mut child = spawn("/bin/sh", &["-c", "sleep 5"]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));

        // Four times the budget, into a child that reads none of it. The pipe
        // absorbs a page or two and the rest has nowhere to go.
        let mut refusal = None;
        for seq in 0..64 {
            if let Err(e) = sink.write_frame(frame(seq, &vec![b'x'; 64 * 1024])) {
                refusal = Some(e);
                break;
            }
        }
        let refusal = refusal.expect("an unread queue must stop growing at its budget");
        assert_eq!(refusal.kind(), io::ErrorKind::WouldBlock);
        assert!(sink.queued_bytes() <= MAX_PENDING_INPUT_BYTES);

        sink.close();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_sink_whose_workload_died_reports_the_broken_pipe() {
        let mut child = spawn("/bin/sh", &["-c", "exit 0"]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut drained = Vec::new();
        let _ = stdout.read_to_end(&mut drained);
        child.wait().expect("reap the child");

        // The writer learns the pipe is gone by writing into it, so the first
        // offer may still be accepted; what must not happen is that every
        // subsequent one is.
        let mut last = Ok(());
        for seq in 0..200 {
            last = sink.write_frame(frame(seq, b"x"));
            if last.is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let err = last.expect_err("a sink with no workload behind it must say so");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn an_empty_frame_is_accepted_without_reaching_the_workload() {
        // A zero-length write into a pipe is a no-op, not an EOF. Delivering it
        // would be harmless; refusing it would make a legal frame an error.
        let mut child = spawn("/bin/cat", &[]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(frame(0, b""))
            .expect("empty frame accepted");
        assert_eq!(sink.queued_bytes(), 0);
        sink.close();
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert!(out.stdout.is_empty());
    }
}
