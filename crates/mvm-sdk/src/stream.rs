//! Read a running workload's output from a program, without shelling out.
//!
//! Every other machine operation in this SDK goes through
//! [`crate::machine`], which builds an `mvmctl machine ...` argv and runs it
//! — deliberately, so OCI pull, admission, and audit stay owned by the one
//! admitted-boot path. Reading output is different in kind: it is a long-lived
//! byte stream, not a command, and a subprocess boundary would mean parsing
//! the CLI's rendering back into records and losing the hash chain that makes
//! them checkable. So this one reads the broker socket directly.
//!
//! It is the same reader `mvm-client` exposes, not a second implementation —
//! both re-export `mvm-core`'s. This crate cannot depend on `mvm-client`
//! (that would close the cycle `mvm-client` → `mvm-hostd` → `mvm-sdk`), which
//! is exactly why the reader lives below both.
//!
//! ```no_run
//! use mvm_sdk::stream::{KindFilter, StreamKind, StreamOpts, connect_stream};
//!
//! let opts = StreamOpts::builder()
//!     .follow(true)
//!     .kinds(KindFilter::only(StreamKind::Stdout))
//!     .build();
//! let mut reader = connect_stream("my-vm", opts)?;
//! while let Some(record) = reader.next_record()? {
//!     // Bytes are verbatim: this is exactly what the workload wrote.
//!     print!("{}", String::from_utf8_lossy(&record.payload));
//! }
//! # Ok::<(), mvm_sdk::stream::StreamError>(())
//! ```
//!
//! Records arrive verified. A window that does not chain from its anchor is
//! a [`StreamError::Chain`], never a short read, so a workload author cannot
//! mistake tampering or loss for the end of output.
//!
//! [`connect_stream`] is the *live* half, and it attaches at the broker's
//! current head: it shows nothing an idle VM has already printed, and it fails
//! outright once the VM exits and its broker is gone. A caller that wants a
//! workload's whole output — the after-exit case included — uses
//! [`open_vm_output`], which splices the VM's durable transcript ahead of the
//! live stream and reports what, if anything, either source is missing.

pub use mvm_core::stream_client::{
    ConsoleUnsupported, EmptyHistory, FramedStreamReader, KindFilter, OutputLocator, OutputRecord,
    OutputRequest, RecordOrigin, SpliceGap, StreamAvailability, StreamError, StreamOpts,
    StreamOptsBuilder, StreamReader, Truncation, VmOutputStream, connect_stream, connect_stream_at,
    open_vm_output, open_vm_output_at,
};
pub use mvm_protocol::stream::{StreamKind, StreamRecord, StreamSource};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sdk_exposes_the_same_reader_the_client_facade_does() {
        // Not a re-declaration: the types must be identical, or a consumer
        // holding one surface cannot pass a reader to the other.
        let opts: mvm_core::stream_client::StreamOpts = StreamOpts::builder()
            .follow(true)
            .kinds(KindFilter::only(StreamKind::Stderr))
            .build();
        assert!(opts.follow);
        assert!(opts.kinds.matches(StreamKind::Stderr));
        assert!(!opts.kinds.matches(StreamKind::Stdout));
    }

    #[test]
    fn a_reader_yields_verified_records_from_a_framed_source() {
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        for seq in 0..3u64 {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: format!("out-{seq}").into_bytes(),
            };
            prev = record.hash();
            records.push(record);
        }
        let mut framed = Vec::new();
        mvm_core::stream_client::write_batch(
            &mut framed,
            &mvm_core::stream_client::StreamBatch {
                anchor: [0u8; 32],
                records,
                gap: None,
                caught_up: true,
            },
        )
        .expect("frame");

        let mut reader = FramedStreamReader::new(framed.as_slice(), StreamOpts::default());
        let mut seen = Vec::new();
        while let Some(record) = reader.next_record().expect("reader must not fail") {
            seen.push(record);
        }
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2].payload, b"out-2");
    }

    #[test]
    fn a_workload_author_gets_an_error_naming_the_vm_when_nothing_is_serving() {
        let dir = tempfile::tempdir().expect("tempdir");
        let Err(err) = connect_stream_at(&dir.path().join("gone.sock"), StreamOpts::default())
        else {
            panic!("no broker is serving that path");
        };
        assert!(matches!(err, StreamError::Connect { .. }), "{err}");
    }
}
