//! Per-VM Unix-socket fan-out for gateway flow events
//! ([Plan 102 W6.A] / [ADR-058] claim 10 leg 2).
//!
//! The gateway bridge ([`crate::supervisor::gateway_bridge`], lands in commit 5)
//! emits each `FlowEvent` twice: once to the signer mpsc (chain of
//! truth — `~/.mvm/audit/<tenant>.jsonl`), once to this sink's
//! bounded broadcast for live subscribers. Subscribers attach via
//! `nc -U ~/.mvm/audit/gateway-<vm>.sock` and read NDJSON.
//!
//! Subscriber socket is **informational**: the per-tenant signed
//! chain is the source of truth. Slow subscribers get a
//! `RecvError::Lagged` and are dropped — the bridge never blocks
//! on a stalled subscriber. The broadcast buffer is bounded at
//! 256 events; bursts above that drop oldest.
//!
//! Threat model:
//! - Socket mode 0700 + parent dir 0700 keeps cross-UID processes
//!   from reading flow metadata.
//! - Same-UID processes are documented as accepted (they can already
//!   read the audit chain file directly).
//! - `exit()` skips Drop; the socket file is pre-unlinked on
//!   [`Self::bind`] so a fresh boot rebinds cleanly even after an
//!   ungraceful supervisor exit.
//!
//! [Plan 102 W6.A]: ../../../specs/plans/103-w6a-implementation-tracker.md
//! [ADR-058]: ../../../specs/adrs/058-claim-10-bytes-leaving-trust-boundary.md

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

/// Bounded capacity for the broadcast fan-out. Subscribers that
/// can't keep up see `RecvError::Lagged(n)` and are dropped; the
/// bridge never blocks on a stalled subscriber.
pub const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

/// Per-VM gateway flow-event subscriber sink. Owns a [`UnixListener`]
/// at `~/.mvm/audit/gateway-<vm>.sock` and a bounded broadcast
/// channel that the bridge task pushes serialised `FlowEvent`s
/// into.
pub struct GatewayAuditSink {
    listener: UnixListener,
    tx: broadcast::Sender<String>,
    socket_path: PathBuf,
}

impl GatewayAuditSink {
    /// Bind a fresh sink at `path`. Pre-unlinks any stale socket
    /// from a prior supervisor process (since libkrun's `exit()`
    /// skips Drop), ensures the parent dir exists with mode 0700,
    /// then chmods the socket itself to 0700.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let socket_path = path.as_ref().to_path_buf();

        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }

        // Pre-unlink — `exit()` skips Drop, so a prior supervisor's
        // socket file might still own the path even though its
        // listener is dead. `remove_file` errors-other-than-NotFound
        // are real and propagate; the missing-file case is success.
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700))?;

        let (tx, _) = broadcast::channel(SUBSCRIBER_CHANNEL_CAPACITY);

        Ok(Self {
            listener,
            tx,
            socket_path,
        })
    }

    /// Cloneable sender. The bridge task holds one of these and
    /// pushes each serialised `FlowEvent` line into it; every
    /// connected subscriber receives a copy.
    pub fn sender(&self) -> broadcast::Sender<String> {
        self.tx.clone()
    }

    /// Direct in-process subscription. Tests use this to verify
    /// fan-out without round-tripping through the socket. Production
    /// subscribers connect via `nc -U` and are wired up by
    /// [`Self::run`].
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    /// Where the listener is bound. Mostly for diagnostics +
    /// `mvmctl doctor`.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accept loop. Per accepted connection, spawns a forward task
    /// that drains a fresh broadcast receiver into the stream as
    /// NDJSON. Returns only on listener fault (logged + treated as
    /// transient — the accept loop continues).
    ///
    /// Production callers spawn this on the bridge thread's tokio
    /// runtime and let it run for the supervisor's lifetime.
    /// `exit()` reaps the task + closes the listener.
    pub async fn run(self) -> ! {
        let listener = self.listener;
        let tx = self.tx;
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let rx = tx.subscribe();
                    tokio::spawn(forward_to_subscriber(stream, rx));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "gateway-audit accept failed");
                    // Yield briefly so a tight failure loop doesn't
                    // starve the runtime if the listener is wedged.
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

/// Drain `rx` into `stream` as NDJSON. Returns on subscriber
/// disconnect, broadcast lag, or channel close.
async fn forward_to_subscriber(mut stream: UnixStream, mut rx: broadcast::Receiver<String>) {
    loop {
        match rx.recv().await {
            Ok(line) => {
                if stream.write_all(line.as_bytes()).await.is_err() {
                    // Subscriber closed; let the task drop.
                    return;
                }
                if stream.write_all(b"\n").await.is_err() {
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    dropped = n,
                    "gateway-audit subscriber lagged; dropping connection"
                );
                return;
            }
            Err(broadcast::error::RecvError::Closed) => {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tokio::io::{AsyncBufReadExt, BufReader};

    /// Pre-unlink path on bind — exit() skips Drop, so a prior
    /// supervisor's socket inode often outlives its listener.
    /// Bind on top of a stale file must succeed, not fail with
    /// EADDRINUSE.
    #[tokio::test]
    async fn bind_pre_unlinks_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-vm.sock");

        // Stale file: write some bytes pretending a prior process
        // left an inode here. `bind()` on a SOCK_STREAM-style
        // listener errors with EADDRINUSE without pre-unlink.
        std::fs::write(&path, b"stale").unwrap();
        assert!(path.exists());

        let sink = GatewayAuditSink::bind(&path).expect("must rebind over stale file");
        assert_eq!(sink.socket_path(), path);

        // The bound path should be a socket now, not the stale
        // regular file we wrote.
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.mode() & 0o777;
        assert_eq!(mode, 0o700, "socket mode must be 0700");
    }

    /// Three subscribers attach; we push one event via the sender;
    /// each reads the same NDJSON line. Exercises the live-tail
    /// fan-out shape `nc -U` consumers see.
    #[tokio::test]
    async fn accepts_many_subscribers_fans_out_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-vm.sock");
        let sink = GatewayAuditSink::bind(&path).unwrap();
        let tx = sink.sender();
        let socket = sink.socket_path().to_path_buf();

        tokio::spawn(sink.run());

        // Connect three subscribers.
        let mut readers = Vec::new();
        for _ in 0..3 {
            let stream = UnixStream::connect(&socket).await.unwrap();
            readers.push(BufReader::new(stream));
        }

        // Wait for the accept loop to wire each subscriber's
        // receiver. There's no clean signal so a tiny sleep — the
        // alternative is racy.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let payload = r#"{"kind":"flow_opened","flow_id":"f1","direction":"egress"}"#;
        // Send returns receiver count — must equal 3.
        let count = tx.send(payload.to_string()).expect("send must succeed");
        assert_eq!(count, 3, "all three subscribers must be wired");

        for reader in readers.iter_mut() {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim_end_matches('\n'), payload);
        }
    }

    /// One slow subscriber that never reads its stream + one fast
    /// subscriber that drains. The bridge's `tx.send()` never blocks
    /// regardless of subscriber state, and the fast subscriber keeps
    /// receiving despite the slow peer's stream backpressure.
    ///
    /// Mechanism: tokio's broadcast queue is per-receiver and bounded;
    /// the slow forward task gets stuck on write_all to its
    /// never-draining stream (kernel send buffer full), but that
    /// doesn't propagate to other receivers. The bridge sender's
    /// `send()` returns immediately whether or not all forward
    /// tasks are draining; the slow receiver's queue may overflow
    /// and drop oldest, but the fast receiver's queue drains normally.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_subscriber_does_not_block_fast_subscriber_or_sender() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-vm.sock");
        let sink = GatewayAuditSink::bind(&path).unwrap();
        let tx = sink.sender();
        let socket = sink.socket_path().to_path_buf();

        tokio::spawn(sink.run());

        let fast = UnixStream::connect(&socket).await.unwrap();
        let _slow = UnixStream::connect(&socket).await.unwrap(); // never reads

        // Wait for the accept loop to register both subscribers.
        for _ in 0..40 {
            if tx.receiver_count() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(
            tx.receiver_count(),
            2,
            "both subscribers must be wired before the burst"
        );

        // Drain the fast subscriber in parallel.
        let drained = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let drained_w = drained.clone();
        let drain_task = tokio::spawn(async move {
            let mut reader = BufReader::new(fast);
            // Cap reads so the test bounds work; we just need to
            // see "a lot" of lines arrive, not all of them.
            for _ in 0..100 {
                let mut line = String::new();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    reader.read_line(&mut line),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) => {
                        drained_w.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });

        // Burst events with periodic sleeps so the forward tasks
        // get clock-time to drain into the fast stream and the
        // drain task gets clock-time to read.
        for i in 0..(SUBSCRIBER_CHANNEL_CAPACITY * 2) {
            let _ = tx.send(format!("{{\"i\":{i}}}"));
            if i % 8 == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }

        // Give the drain task wall-clock time to finish reading.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), drain_task).await;

        let received = drained.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            received >= 50,
            "fast subscriber must keep receiving despite slow peer; got {received} lines"
        );
    }
}
