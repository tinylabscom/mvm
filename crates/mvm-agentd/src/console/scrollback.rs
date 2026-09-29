//! Bounded scrollback for a console session with no attached client.
//!
//! The shell keeps running when its client goes away, so its output has to go
//! somewhere. It goes here: a fixed-capacity byte ring that keeps the most
//! recent [`SCROLLBACK_CAP_BYTES`] and discards the oldest, replayed to the
//! next client that attaches.

use std::collections::VecDeque;

/// How much console output a session retains for replay on reattach.
///
/// One mebibyte is several thousand screens of ordinary shell output, and it
/// is guest memory held for the whole life of a detached session, so it stays
/// at the bottom of the range rather than the top.
pub const SCROLLBACK_CAP_BYTES: usize = 1024 * 1024;

const _: () = assert!(
    SCROLLBACK_CAP_BYTES >= 1024 * 1024 && SCROLLBACK_CAP_BYTES <= 8 * 1024 * 1024,
    "the console scrollback cap must stay between 1 MiB and 8 MiB"
);

/// How far into a wrapped ring the replay looks for a line boundary to start
/// at. A wrapped ring's first byte is wherever the discard happened to land,
/// which can be the middle of a UTF-8 sequence or a terminal escape; starting
/// the replay at the next newline avoids painting that fragment. Bounded so a
/// session that never prints a newline still replays everything it has.
const REPLAY_ALIGN_WINDOW: usize = 4096;

/// A fixed-capacity FIFO of console output bytes.
#[derive(Debug)]
pub struct ScrollbackRing {
    buf: VecDeque<u8>,
    cap: usize,
    discarded: u64,
}

impl ScrollbackRing {
    /// An empty ring holding at most `cap` bytes. A zero cap is raised to one
    /// so the ring is always able to hold the last byte written.
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            buf: VecDeque::with_capacity(cap.min(64 * 1024)),
            cap,
            discarded: 0,
        }
    }

    /// Append `bytes`, discarding the oldest retained bytes past the cap.
    pub fn push(&mut self, bytes: &[u8]) {
        // A single write larger than the whole ring keeps only its tail; there
        // is no point copying bytes in just to discard them.
        let keep = if bytes.len() > self.cap {
            self.discarded += (bytes.len() - self.cap) as u64;
            &bytes[bytes.len() - self.cap..]
        } else {
            bytes
        };
        let overflow = (self.buf.len() + keep.len()).saturating_sub(self.cap);
        if overflow > 0 {
            self.buf.drain(..overflow);
            self.discarded += overflow as u64;
        }
        self.buf.extend(keep);
    }

    /// Bytes currently retained.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing is retained.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The capacity this ring was built with.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Total bytes discarded to stay under the cap.
    pub fn discarded(&self) -> u64 {
        self.discarded
    }

    /// The bytes to replay to a client that attaches now.
    ///
    /// A ring that never wrapped replays verbatim. A wrapped one starts just
    /// past its first newline when there is one within
    /// [`REPLAY_ALIGN_WINDOW`], for the reason given on that constant.
    pub fn replay(&self) -> Vec<u8> {
        let skip = if self.discarded == 0 {
            0
        } else {
            self.buf
                .iter()
                .take(REPLAY_ALIGN_WINDOW)
                .position(|&b| b == b'\n')
                .map_or(0, |newline| newline + 1)
        };
        self.buf.iter().skip(skip).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ring_under_its_cap_replays_everything_verbatim() {
        let mut ring = ScrollbackRing::new(16);
        ring.push(b"abc");
        ring.push(b"def");
        assert_eq!(ring.replay(), b"abcdef");
        assert_eq!(ring.len(), 6);
        assert_eq!(ring.discarded(), 0);
    }

    #[test]
    fn wraparound_keeps_the_most_recent_bytes_and_counts_the_rest() {
        let mut ring = ScrollbackRing::new(8);
        ring.push(b"0123456");
        ring.push(b"789ab");
        assert_eq!(ring.len(), 8, "the ring never exceeds its cap");
        assert_eq!(ring.discarded(), 4);
        // No newline to align on, so the replay is the whole retained tail.
        assert_eq!(ring.replay(), b"456789ab");
    }

    #[test]
    fn a_single_write_larger_than_the_cap_keeps_only_its_tail() {
        let mut ring = ScrollbackRing::new(4);
        ring.push(b"xy");
        ring.push(b"0123456789");
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.replay(), b"6789");
        assert_eq!(ring.discarded(), 8, "2 old bytes plus 6 of the new write");
    }

    #[test]
    fn a_wrapped_replay_starts_at_a_line_boundary() {
        let mut ring = ScrollbackRing::new(12);
        ring.push(b"first line\nsecond\n");
        // Retained: "line\nsecond\n" — the leading fragment is dropped.
        assert_eq!(ring.replay(), b"second\n");
    }

    #[test]
    fn an_unwrapped_replay_never_drops_a_leading_fragment() {
        let mut ring = ScrollbackRing::new(64);
        ring.push(b"prompt$ ls\nfile\n");
        assert_eq!(ring.replay(), b"prompt$ ls\nfile\n");
    }

    #[test]
    fn the_production_cap_is_what_a_session_is_built_with() {
        let ring = ScrollbackRing::new(SCROLLBACK_CAP_BYTES);
        assert_eq!(ring.capacity(), SCROLLBACK_CAP_BYTES);
        assert!(ring.is_empty());
    }

    #[test]
    fn a_sustained_stream_stays_bounded() {
        let mut ring = ScrollbackRing::new(1000);
        let chunk = [b'x'; 333];
        for _ in 0..100 {
            ring.push(&chunk);
        }
        assert_eq!(ring.len(), 1000);
        assert_eq!(ring.discarded(), 33_300 - 1000);
    }
}
