//! Supervisor-owned protected console capture. The UART only enqueues bounded
//! chunks; this owner survives the launcher and owns encryption, seals and readers.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mvm_contract::stream::{StreamKind, StreamSource};
use mvm_core::config;
use mvm_core::plan::StreamRetention;
use mvm_core::policy::RedactionPolicy;
use mvm_core::stream_client::protected::ProtectedRun;
use mvm_core::transcript::{AtRestRetention, TranscriptManifest};
use mvm_vmm::host::console_capture::bounded::{self, Consumer, Producer};

use super::console_source::SharedBroker;
use super::plane::{anchor_sealed_transcript, build_writer_with_policy, write_manifest};
use super::{StreamBroker, StreamRedaction, StreamServerHandle, serve_stream};

/// Shutdown is bounded even if the storage worker cannot leave a host syscall.
const OWNER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct CaptureOwner {
    worker: Option<JoinHandle<()>>,
    exited: mpsc::Receiver<()>,
    failed: Arc<AtomicBool>,
}

impl CaptureOwner {
    /// Provision keys, writer and live server before the caller announces boot.
    pub fn start(
        vm: &str,
        redaction: &RedactionPolicy,
        retention: StreamRetention,
    ) -> Result<(Self, Producer)> {
        Self::start_with_period(vm, redaction, retention, Duration::from_secs(3600))
    }

    fn start_with_period(
        vm: &str,
        redaction: &RedactionPolicy,
        retention: StreamRetention,
        period: Duration,
    ) -> Result<(Self, Producer)> {
        let root = config::vm_stream_transcript_dir(vm);
        config::create_private_dir(&root).context("prepare protected capture directory")?;
        let broker = Arc::new(Mutex::new(StreamBroker::live_only(
            vm,
            StreamRedaction::curated(redaction),
        )));
        // Claim live ownership before installing storage or publishing routing.
        let server = serve_stream(&config::vm_stream_socket(vm), Arc::clone(&broker))
            .context("claim protected console owner")?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("protected capture clock")?
            .as_nanos();
        let run = ProtectedRun {
            version: 1,
            run: format!("{stamp}-{}", std::process::id()),
            persists: retention.persists(),
        };
        let run_dir = run.directory(&root)?;
        let active = run_dir.join("00000000000000000000");
        if run.persists {
            let writer = build_writer_with_policy(vm, &active, Some(AtRestRetention::default()))?;
            let mut broker = broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            broker.replace_writer(Some(writer));
            anyhow::ensure!(
                broker.durable_ready(),
                "protected capture storage worker unavailable"
            );
        }
        run.publish(&root)
            .context("publish protected console routing")?;
        let (producer, consumer) = bounded::channel();
        let failed = Arc::new(AtomicBool::new(false));
        let (exit, exited) = mpsc::channel();
        let state = Worker {
            vm: vm.to_string(),
            run_dir,
            active,
            generation: 0,
            persists: run.persists,
            broker,
            server,
            consumer,
            failed: Arc::clone(&failed),
            period,
            last_loss: (0, 0),
        };
        let worker = std::thread::Builder::new()
            .name("mvm-protected-console".into())
            .spawn(move || {
                let _exit = exit;
                state.run();
            })
            .context("start protected console owner")?;
        Ok((
            Self {
                worker: Some(worker),
                exited,
                failed,
            },
            producer,
        ))
    }

    /// The producer must be dropped first, including the UART's final partial
    /// line. False explicitly means incomplete capture, never a plaintext retry.
    pub fn finish(mut self) -> bool {
        self.join()
    }

    fn join(&mut self) -> bool {
        let Some(worker) = self.worker.take() else {
            return !self.failed.load(Ordering::Relaxed);
        };
        if self.exited.recv_timeout(OWNER_JOIN_TIMEOUT) == Err(RecvTimeoutError::Timeout) {
            self.failed.store(true, Ordering::Relaxed);
            return false;
        }
        if worker.join().is_err() {
            self.failed.store(true, Ordering::Relaxed);
        }
        !self.failed.load(Ordering::Relaxed)
    }
}

impl Drop for CaptureOwner {
    fn drop(&mut self) {
        self.join();
    }
}

struct Worker {
    vm: String,
    run_dir: PathBuf,
    active: PathBuf,
    generation: u64,
    persists: bool,
    broker: SharedBroker,
    server: StreamServerHandle,
    consumer: Consumer,
    failed: Arc<AtomicBool>,
    period: Duration,
    last_loss: (u64, u64),
}

impl Worker {
    fn run(mut self) {
        let mut deadline = Instant::now() + self.period;
        loop {
            match self
                .consumer
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(chunk) => {
                    self.broker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .ingest(StreamSource::Console, StreamKind::Stdout, chunk.as_bytes());
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                self.account_loss();
                if self.rotate().is_err() {
                    self.failed.store(true, Ordering::Relaxed);
                    // Never retry with plaintext. End this generation and keep
                    // live output; the explicit failure persists at shutdown.
                    self.seal_active();
                    self.persists = false;
                }
                deadline = Instant::now() + self.period;
            }
        }
        self.account_loss();
        self.seal_active();
        self.server.stop();
    }

    fn account_loss(&mut self) {
        let counts = self.consumer.counters.snapshot();
        let chunks = counts.dropped_chunks.saturating_sub(self.last_loss.0);
        let bytes = counts.dropped_bytes.saturating_sub(self.last_loss.1);
        if chunks != 0 || counts.is_saturated() {
            self.failed.store(true, Ordering::Relaxed);
        }
        self.broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .note_unwritten(chunks.max(u64::from(counts.is_saturated())), bytes);
        self.last_loss = (counts.dropped_chunks, counts.dropped_bytes);
    }

    fn rotate(&mut self) -> Result<()> {
        if !self.persists {
            return Ok(());
        }
        let next = self
            .generation
            .checked_add(1)
            .context("capture generation exhausted")?;
        let dir = self.run_dir.join(format!("{next:020}"));
        let writer = build_writer_with_policy(&self.vm, &dir, Some(AtRestRetention::default()))?;
        let sealed = self
            .broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace_writer(Some(writer));
        self.publish(sealed);
        self.generation = next;
        self.active = dir;
        Ok(())
    }

    fn seal_active(&mut self) {
        let sealed = self
            .broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace_writer(None);
        self.publish(sealed);
    }

    fn publish(&self, manifest: Option<TranscriptManifest>) {
        let Some(manifest) = manifest else { return };
        if manifest.is_truncated() || manifest.sealed_unix_secs.is_none() {
            self.failed.store(true, Ordering::Relaxed);
        }
        if write_manifest(&self.active, &manifest).is_err() {
            self.failed.store(true, Ordering::Relaxed);
            return;
        }
        anchor_sealed_transcript(&self.vm, &manifest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::transcript::{self, MANIFEST_FILENAME};
    use mvm_core::util::test_env::TestEnv;
    use mvm_vmm::vmm::device::{MmioDevice, Pl011};

    #[test]
    fn supervisor_owner_captures_after_launcher_drop_without_plaintext_files() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let vm = "owner-lifetime";
        let launcher = super::super::StreamPlane::new();
        let (owner, producer) =
            CaptureOwner::start(vm, &RedactionPolicy::default(), StreamRetention::Persist).unwrap();
        drop(launcher);
        let marker = b"synthetic-after-launcher-exit";
        let mut uart = Pl011::new(0);
        uart.stream_to(Box::new(producer));
        for byte in marker {
            uart.write(0, u64::from(*byte), 1);
        }
        drop(uart);
        assert!(owner.finish());
        let root = config::vm_stream_transcript_dir(vm);
        let run = ProtectedRun::read(&root).unwrap().unwrap();
        let dir = run.directory(&root).unwrap().join("00000000000000000000");
        let manifest_bytes = std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap();
        let manifest: TranscriptManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert!(manifest.sealed_unix_secs.is_some());
        let kek = transcript::load_or_init_kek(&config::mvm_keys_dir()).unwrap();
        let key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let chunks = transcript::export_chunks(&manifest, &dir, &key).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].plaintext, marker);
        assert!(
            !manifest_bytes
                .windows(marker.len())
                .any(|bytes| bytes == marker)
        );
        for entry in std::fs::read_dir(&dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(marker.len()).any(|bytes| bytes == marker));
        }
        assert!(!config::vm_console_log(vm).exists());
        assert!(
            !config::vm_state_dir(vm)
                .join("supervisor.stderr.log")
                .exists()
        );
    }

    #[test]
    fn required_key_setup_failure_returns_no_producer_and_no_plaintext() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let keys = config::mvm_keys_dir();
        std::fs::create_dir_all(keys.parent().unwrap()).unwrap();
        std::fs::write(&keys, b"synthetic-key-setup-obstruction").unwrap();
        assert!(
            CaptureOwner::start(
                "owner-failed",
                &RedactionPolicy::default(),
                StreamRetention::Persist,
            )
            .is_err()
        );
        assert!(!config::vm_console_log("owner-failed").exists());
        assert!(
            !config::vm_stream_transcript_dir("owner-failed")
                .join("manifest.json")
                .exists()
        );
    }
}
