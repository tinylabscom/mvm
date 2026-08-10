//! Response and its streaming body.
//!
//! The byte cap is a property of the body reader, not of each call site. In the
//! reqwest-based code every caller wrote its own `while let Some(chunk)` loop
//! with a hand-rolled running total, which is the sort of thing that is correct
//! in five places and wrong in the sixth.

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, StatusCode};
use tokio::io::AsyncReadExt;

use crate::conn::Stream;
use crate::error::{Error, Result};
use crate::parse::{BodyLength, ChunkStep, next_chunk};

/// Read granularity from the socket.
const READ_CHUNK: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) enum BodyState {
    Done,
    Fixed { remaining: u64 },
    Chunked { finished: bool },
    UntilClose,
}

/// An HTTP response whose body has not been read yet.
#[derive(Debug)]
pub struct Response {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) stream: Stream,
    /// Bytes already read from the socket that belong to the body.
    pub(crate) buf: BytesMut,
    pub(crate) state: BodyState,
    /// Hard ceiling on total decoded body bytes, if any.
    pub(crate) max_bytes: Option<u64>,
    pub(crate) read_total: u64,
}

impl Response {
    pub(crate) fn new(
        status: StatusCode,
        headers: HeaderMap,
        stream: Stream,
        buf: BytesMut,
        body_length: BodyLength,
        max_bytes: Option<u64>,
    ) -> Self {
        let state = match body_length {
            BodyLength::None => BodyState::Done,
            BodyLength::Fixed(n) => {
                if n == 0 {
                    BodyState::Done
                } else {
                    BodyState::Fixed { remaining: n }
                }
            }
            BodyLength::Chunked => BodyState::Chunked { finished: false },
            BodyLength::UntilClose => BodyState::UntilClose,
        };
        Self {
            status,
            headers,
            stream,
            buf,
            state,
            max_bytes,
            read_total: 0,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The declared `Content-Length`, when the response carried one.
    pub fn content_length(&self) -> Option<u64> {
        match self.state {
            BodyState::Fixed { remaining } => Some(remaining.saturating_add(self.read_total)),
            BodyState::Done if self.read_total > 0 => Some(self.read_total),
            _ => None,
        }
    }

    /// Next piece of the decoded body, or `None` at end of body.
    ///
    /// The cap is enforced **before** a chunk is handed back, so a caller that
    /// simply accumulates whatever it receives cannot exceed it.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        loop {
            match self.state {
                BodyState::Done => return Ok(None),
                BodyState::Fixed { remaining } => {
                    if remaining == 0 {
                        self.state = BodyState::Done;
                        return Ok(None);
                    }
                    if self.buf.is_empty() && self.fill().await? == 0 {
                        return Err(Error::IncompleteBody { remaining });
                    }
                    let take = remaining.min(self.buf.len() as u64) as usize;
                    let out = self.buf.split_to(take).freeze();
                    self.state = BodyState::Fixed {
                        remaining: remaining - take as u64,
                    };
                    self.account(out.len())?;
                    return Ok(Some(out));
                }
                BodyState::UntilClose => {
                    if self.buf.is_empty() && self.fill().await? == 0 {
                        self.state = BodyState::Done;
                        return Ok(None);
                    }
                    let out = self.buf.split().freeze();
                    self.account(out.len())?;
                    return Ok(Some(out));
                }
                BodyState::Chunked { finished } => {
                    if finished {
                        self.state = BodyState::Done;
                        return Ok(None);
                    }
                    match next_chunk(&self.buf)? {
                        ChunkStep::Data {
                            start,
                            len,
                            consumed,
                        } => {
                            let out = Bytes::copy_from_slice(&self.buf[start..start + len]);
                            let _ = self.buf.split_to(consumed);
                            self.account(out.len())?;
                            return Ok(Some(out));
                        }
                        ChunkStep::End { consumed } => {
                            let _ = self.buf.split_to(consumed);
                            self.state = BodyState::Done;
                            return Ok(None);
                        }
                        ChunkStep::Incomplete => {
                            if self.fill().await? == 0 {
                                return Err(Error::IncompleteBody { remaining: 0 });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Drain the whole body, subject to the cap.
    pub async fn bytes(mut self) -> Result<Bytes> {
        let mut out = BytesMut::new();
        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Drain the whole body as UTF-8.
    pub async fn text(self) -> Result<String> {
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::NotUtf8)
    }

    /// Drain and deserialize the body as JSON.
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Count `n` decoded bytes against the cap, refusing once it is exceeded.
    fn account(&mut self, n: usize) -> Result<()> {
        self.read_total = self.read_total.saturating_add(n as u64);
        if let Some(limit) = self.max_bytes
            && self.read_total > limit
        {
            return Err(Error::BodyTooLarge { limit });
        }
        Ok(())
    }

    /// Read more bytes from the socket into `buf`. Returns bytes read; 0 means
    /// the peer closed.
    async fn fill(&mut self) -> Result<usize> {
        // Bound the buffer even for a chunked body whose size line never
        // arrives, mirroring the head-size guard.
        if self.buf.len() > crate::parse::MAX_HEAD_BYTES.saturating_mul(4) {
            return Err(Error::BodyTooLarge {
                limit: self.max_bytes.unwrap_or(u64::MAX),
            });
        }
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let n = self.stream.read(&mut self.buf[start..]).await?;
        self.buf.truncate(start + n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    // The body reader is driven end-to-end against real sockets in
    // `tests/client.rs`, which is where framing behaviour belongs. This unit
    // pins only the cap boundary, which is pure arithmetic.

    /// Mirrors `Response::account`.
    fn account(total: &mut u64, n: u64, limit: Option<u64>) -> Result<(), u64> {
        *total = total.saturating_add(n);
        match limit {
            Some(l) if *total > l => Err(l),
            _ => Ok(()),
        }
    }

    #[test]
    fn a_body_exactly_at_the_cap_is_allowed() {
        let mut t = 0;
        assert!(account(&mut t, 10, Some(10)).is_ok());
    }

    #[test]
    fn one_byte_past_the_cap_is_refused() {
        let mut t = 0;
        assert_eq!(account(&mut t, 11, Some(10)), Err(10));
    }

    #[test]
    fn the_cap_is_cumulative_across_chunks_not_per_chunk() {
        let mut t = 0;
        assert!(account(&mut t, 6, Some(10)).is_ok());
        assert_eq!(account(&mut t, 6, Some(10)), Err(10));
    }

    #[test]
    fn no_cap_admits_everything_without_overflowing() {
        let mut t = 0;
        assert!(account(&mut t, u64::MAX, None).is_ok());
        assert!(account(&mut t, u64::MAX, None).is_ok());
    }
}
