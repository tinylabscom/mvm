//! Forensic transcript byte-capture tap (Plan 203) on the gateway bridge.
//!
//! [`TranscriptObserver`] is a host-initiated, opt-in [`Observer`] that copies
//! every forwarded frame's raw bytes into an AEAD-encrypted transcript for a
//! capture armed via `mvmctl trust audit transcript arm`. It is added to a VM's
//! bridge observer list only when a capture directory is armed for that VM;
//! `on_packet` always returns [`Verdict::Forward`] — capture never alters,
//! delays, or drops traffic.
//!
//! The `Observer` contract requires `on_packet` to be cheap (microseconds), so
//! the encryption + disk writes happen on a dedicated worker thread: `on_packet`
//! only clones the frame and `try_send`s it down a bounded channel (dropping —
//! and counting — frames if the worker falls behind, so a slow disk can never
//! back-pressure the guest's network). The worker owns the [`TranscriptWriter`]
//! and is joined on drop, which flushes a final manifest — the natural
//! capture-seal point when the VM's bridge tears down.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread::JoinHandle;

use anyhow::{Context, Result};

use mvm_core::transcript::{
    self, Direction, TranscriptManifest, TranscriptWriter, TranscriptWriterConfig,
};

use super::audit::FlowDirection;
use super::gateway_bridge::FlowEvent;
use super::network::packet::ParsedPacket;
use super::network::{Directions, Observer, PacketCtx, RequiredCapabilities, Verdict};

/// Bounded capture queue depth. Frames beyond this (worker behind a slow disk)
/// are dropped + counted rather than blocking the network path.
const CAPTURE_QUEUE_DEPTH: usize = 1024;

/// Rewrite `manifest.json` every N captured chunks (chunk files are written
/// immediately; only the manifest index is batched to bound fsync churn).
const FLUSH_EVERY: usize = 16;

type CaptureMsg = (Direction, Vec<u8>);

/// A live forensic capture tapped onto the bridge.
pub struct TranscriptObserver {
    /// `None` after drop has closed the channel.
    tx: Option<SyncSender<CaptureMsg>>,
    worker: Option<JoinHandle<()>>,
    /// Frames dropped because the worker queue was full (observability).
    dropped: Arc<AtomicU64>,
}

impl TranscriptObserver {
    /// Activate capture for an already-armed capture directory: load the host
    /// KEK, unwrap the per-capture data key from the manifest, and start a
    /// worker that continues writing chunks into the same directory.
    ///
    /// The capture must already be armed (its `manifest.json` carries the
    /// wrapped data key); this is the sole writer for the VM's lifetime, so it
    /// continues from the armed (empty) chunk list at seq 0.
    pub fn activate(capture_dir: &Path, keys_dir: &Path) -> Result<Self> {
        let manifest = read_manifest(capture_dir)?;
        let kek =
            transcript::load_or_init_kek(keys_dir).context("loading the host transcript KEK")?;
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64)
            .context("unwrapping the per-capture data key")?;
        let cfg = TranscriptWriterConfig {
            capture_id: manifest.capture_id,
            binding: manifest.binding,
            bounds: manifest.bounds,
            created_unix_secs: manifest.created_unix_secs,
            recipient: manifest.recipient,
            wrapped_data_key_b64: manifest.wrapped_data_key_b64,
        };
        let writer = TranscriptWriter::new(capture_dir, data_key, cfg);
        Ok(Self::spawn(writer))
    }

    fn spawn(writer: TranscriptWriter) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<CaptureMsg>(CAPTURE_QUEUE_DEPTH);
        let worker = std::thread::Builder::new()
            .name("transcript-capture".to_string())
            .spawn(move || run_worker(rx, writer))
            .expect("spawning transcript-capture worker");
        Self {
            tx: Some(tx),
            worker: Some(worker),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Frames dropped so far because the worker queue was full.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Enqueue one frame for capture. Cheap + non-blocking: a full queue drops
    /// (and counts) the frame rather than stalling the network path.
    fn capture(&self, dir: Direction, bytes: &[u8]) {
        let Some(tx) = &self.tx else { return };
        match tx.try_send((dir, bytes.to_vec())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // Worker gone (it hit a bound + exited): stop counting, never block.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

impl Drop for TranscriptObserver {
    fn drop(&mut self) {
        // Close the channel so the worker drains, writes a final manifest, and
        // exits; then join so the capture is fully flushed before we return.
        self.tx.take();
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

impl Observer for TranscriptObserver {
    fn name(&self) -> &'static str {
        "transcript-capture"
    }

    fn required_capabilities(&self) -> RequiredCapabilities {
        RequiredCapabilities {
            flow_events: false,
            payload_tap: true,
        }
    }

    fn on_flow_event(&self, _event: &FlowEvent) {}

    fn directions(&self) -> Directions {
        Directions::Both
    }

    fn on_packet(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> Verdict {
        let dir = match ctx.direction {
            FlowDirection::Egress => Direction::Egress,
            FlowDirection::Ingress => Direction::Ingress,
        };
        self.capture(dir, pkt.raw_frame);
        Verdict::Forward
    }
}

/// Worker loop: drain frames, encrypt + append each, flush the manifest on a
/// cadence, and write a final manifest when the channel closes. A bound hit
/// (`push` refusal) stops capture cleanly — the flow is never affected.
fn run_worker(rx: std::sync::mpsc::Receiver<CaptureMsg>, mut writer: TranscriptWriter) {
    let mut since_flush = 0usize;
    while let Ok((dir, bytes)) = rx.recv() {
        match writer.push(dir, &bytes) {
            Ok(()) => {
                since_flush += 1;
                if since_flush >= FLUSH_EVERY {
                    flush_manifest(&writer);
                    since_flush = 0;
                }
            }
            Err(e) => {
                tracing::warn!("transcript capture stopped: {e}");
                break;
            }
        }
    }
    flush_manifest(&writer);
}

fn flush_manifest(writer: &TranscriptWriter) {
    if let Err(e) = write_manifest(writer.dir(), &writer.snapshot_manifest()) {
        tracing::warn!("transcript manifest flush failed: {e}");
    }
}

fn read_manifest(dir: &Path) -> Result<TranscriptManifest> {
    let path = dir.join("manifest.json");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn write_manifest(dir: &Path, manifest: &TranscriptManifest) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    std::fs::write(dir.join("manifest.json"), json)
        .with_context(|| format!("writing manifest under {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::aead;
    use mvm_core::transcript::{CaptureBinding, CaptureBounds};

    /// Arm a capture the way the CLI does: write an empty manifest carrying the
    /// data key wrapped under the host KEK. Returns the capture + keys dirs.
    fn arm(root: &Path, bounds: CaptureBounds) -> (std::path::PathBuf, std::path::PathBuf) {
        let capture_dir = root.join("cap");
        let keys_dir = root.join("keys");
        std::fs::create_dir_all(&capture_dir).unwrap();
        let kek = transcript::load_or_init_kek(&keys_dir).unwrap();
        let data_key = aead::Key::random();
        let wrapped = transcript::wrap_data_key(&kek, &data_key);
        let manifest = TranscriptWriter::new(
            &capture_dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: "cap".to_string(),
                binding: CaptureBinding {
                    tenant_id: "t1".to_string(),
                    vm_name: "vm1".to_string(),
                    session_id: None,
                },
                bounds,
                created_unix_secs: 1,
                recipient: "transcript-kek".to_string(),
                wrapped_data_key_b64: wrapped,
            },
        )
        .seal();
        write_manifest(&capture_dir, &manifest).unwrap();
        (capture_dir, keys_dir)
    }

    fn bounds() -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: 3600,
            max_bytes: 1 << 20,
            max_chunks: 1000,
        }
    }

    fn export(capture_dir: &Path, keys_dir: &Path) -> Vec<u8> {
        let manifest = read_manifest(capture_dir).unwrap();
        let kek = transcript::load_or_init_kek(keys_dir).unwrap();
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        transcript::export(&manifest, capture_dir, &data_key).unwrap()
    }

    #[test]
    fn captures_frames_then_exports_in_order() {
        let d = tempfile::tempdir().unwrap();
        let (capture_dir, keys_dir) = arm(d.path(), bounds());
        {
            let obs = TranscriptObserver::activate(&capture_dir, &keys_dir).unwrap();
            obs.capture(Direction::Egress, b"GET / HTTP/1.1\r\n");
            obs.capture(Direction::Ingress, b"HTTP/1.1 200 OK\r\n");
            // drop → worker drains + final-flushes the manifest + joins.
        }
        let out = export(&capture_dir, &keys_dir);
        assert_eq!(out, b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn on_packet_forwards_and_captures_via_the_observer_trait() {
        let d = tempfile::tempdir().unwrap();
        let (capture_dir, keys_dir) = arm(d.path(), bounds());
        {
            let obs = TranscriptObserver::activate(&capture_dir, &keys_dir).unwrap();
            let ctx = PacketCtx {
                vm_name: "vm1",
                tenant: "t1",
                direction: FlowDirection::Egress,
                flow_id: "vm1-egress",
            };
            let pkt = ParsedPacket {
                five_tuple: super::super::network::packet::FiveTuple {
                    proto: super::super::network::packet::L4Proto::Tcp,
                    src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                    dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                    src_port: 1234,
                    dst_port: 80,
                },
                l4_payload: b"",
                raw_frame: b"frame-bytes",
            };
            // The bridge calls on_packet; it must forward, not alter.
            assert!(matches!(obs.on_packet(&ctx, &pkt), Verdict::Forward));
        }
        assert_eq!(export(&capture_dir, &keys_dir), b"frame-bytes");
    }

    #[test]
    fn capture_stops_cleanly_at_the_chunk_bound() {
        let d = tempfile::tempdir().unwrap();
        let tight = CaptureBounds {
            max_duration_secs: 3600,
            max_bytes: 1 << 20,
            max_chunks: 2,
        };
        let (capture_dir, keys_dir) = arm(d.path(), tight);
        {
            let obs = TranscriptObserver::activate(&capture_dir, &keys_dir).unwrap();
            for _ in 0..10 {
                obs.capture(Direction::Egress, b"x");
            }
        }
        // The bound caps the capture at 2 chunks; export still verifies + decrypts.
        let manifest = read_manifest(&capture_dir).unwrap();
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(export(&capture_dir, &keys_dir), b"xx");
    }
}
