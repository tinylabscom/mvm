//! Read a microVM's captured output: [`connect_stream`], [`StreamOpts`], and
//! the [`StreamReader`] everything downstream consumes.
//!
//! ```no_run
//! use mvm_client::stream::{KindFilter, StreamOpts, connect_stream};
//! use mvm_protocol::stream::StreamKind;
//!
//! let opts = StreamOpts::builder()
//!     .follow(true)
//!     .kinds(KindFilter::only(StreamKind::Stderr))
//!     .build();
//! let mut reader = connect_stream("my-vm", opts)?;
//! while let Some(record) = reader.next_record()? {
//!     println!("{}", String::from_utf8_lossy(&record.payload));
//! }
//! # Ok::<(), mvm_client::stream::StreamError>(())
//! ```
//!
//! Records arrive already verified: a window that did not chain from its
//! anchor surfaces as [`StreamError::Chain`] rather than a short read, so a
//! consumer that ignores nothing still cannot mistake tampering for the end
//! of output. Anchors never appear in this API — the reader tracks them.
//!
//! The implementation lives in `mvm-core` and is re-exported here. That is
//! the same split the `MvmClient` facade already uses, and it is what lets
//! `mvm-sdk` (which sits *below* `mvm-hostd`, which this crate depends on)
//! expose the identical reader without a dependency cycle. Callers depend on
//! `mvm-client` and never name the lower crate.

pub use mvm_core::stream_client::{
    FramedStreamReader, KindFilter, MAX_BATCH_PAYLOAD_BYTES, MAX_FRAME_BYTES, StreamBatch,
    StreamError, StreamOpts, StreamOptsBuilder, StreamReader, connect_stream, connect_stream_at,
    read_batch, write_batch,
};

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_protocol::stream::StreamKind;

    #[test]
    fn the_facade_builds_the_same_opts_the_core_does() {
        let opts = StreamOpts::builder()
            .follow(true)
            .from_seq(7)
            .kinds(KindFilter::only(StreamKind::Trace))
            .build();
        assert_eq!(
            opts,
            mvm_core::stream_client::StreamOpts {
                follow: true,
                from_seq: Some(7),
                kinds: mvm_core::stream_client::KindFilter::only(StreamKind::Trace),
            }
        );
    }

    #[test]
    fn connecting_to_an_unserved_vm_names_it_rather_than_hanging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let Err(err) = connect_stream_at(&dir.path().join("nope.sock"), StreamOpts::default())
        else {
            panic!("there is no server on that path");
        };
        assert!(matches!(err, StreamError::Connect { .. }), "{err}");
    }
}
