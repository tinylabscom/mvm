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
use mvm_core::plan::{ExecutionPlan, StreamRetention};
use mvm_core::policy::RedactionPolicy;
use mvm_core::stream_client::protected::ProtectedRun;
use mvm_core::transcript::{AtRestRetention, TranscriptManifest};
use mvm_vmm::host::console_capture::bounded::{self, Consumer, Producer};

use super::console_source::SharedBroker;
use super::plane::{build_writer_with_policy, write_manifest};
use super::{StreamBroker, StreamRedaction, StreamServerHandle, serve_stream};
use crate::audit::{emitter::AuditEmitter, host_keypair};

/// Shutdown is bounded even if the storage worker cannot leave a host syscall.
const OWNER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// Concrete instance identity comes from the authenticated launch/handoff,
/// independently of the logical workload named by an admitted plan.
pub enum CaptureAuthority<'a> {
    Admitted(&'a ExecutionPlan),
    /// Only a validated builder/standby launch role may select this variant.
    OperationalLiveOnly,
}

pub struct CaptureParams<'a> {
    pub vm: &'a str,
    pub authority: CaptureAuthority<'a>,
    pub redaction: &'a RedactionPolicy,
}

pub struct CaptureOwner {
    worker: Option<JoinHandle<()>>,
    exited: mpsc::Receiver<()>,
    failed: Arc<AtomicBool>,
}

impl CaptureOwner {
    /// Provision keys, writer and live server before the caller announces boot.
    pub fn start(params: CaptureParams<'_>) -> Result<(Self, Producer)> {
        Self::start_with_period(params, Duration::from_secs(3600))
    }

    fn start_with_period(params: CaptureParams<'_>, period: Duration) -> Result<(Self, Producer)> {
        let CaptureParams {
            vm,
            authority,
            redaction,
        } = params;
        let (plan, retention) = match authority {
            CaptureAuthority::Admitted(plan) => (Some(plan.clone()), plan.stream_retention),
            CaptureAuthority::OperationalLiveOnly => (None, StreamRetention::Ephemeral),
        };
        mvm_core::naming::validate_vm_name(vm)?;
        let keys = config::mvm_keys_dir();
        let state_dir = config::vm_state_dir(vm);
        let emitter = if retention.persists() {
            let (signing, _) = mvm_core::crypto::ed25519_keypair::load_existing(
                &keys.join(host_keypair::SECRET_FILENAME),
                &keys.join(host_keypair::PUBLIC_FILENAME),
            )
            .context("load existing capture audit authority")?;
            Some(AuditEmitter::new(signing)?)
        } else {
            None
        };
        let root = config::vm_stream_transcript_dir(vm);
        config::create_private_dir(&root).context("prepare protected capture directory")?;
        let broker = Arc::new(Mutex::new(
            StreamBroker::live_only(vm, StreamRedaction::curated(redaction)).with_replay(),
        ));
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
            let tenant = &plan
                .as_ref()
                .context("durable capture needs admitted authority")?
                .tenant
                .0;
            let writer = build_writer_with_policy(
                vm,
                &active,
                Some(AtRestRetention::default()),
                tenant,
                &keys,
            )?;
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
            state_dir,
            keys,
            run_dir,
            active,
            generation: 0,
            persists: run.persists,
            plan,
            emitter,
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
    state_dir: PathBuf,
    keys: PathBuf,
    run_dir: PathBuf,
    active: PathBuf,
    generation: u64,
    persists: bool,
    plan: Option<ExecutionPlan>,
    emitter: Option<AuditEmitter>,
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
        let mut maintenance = Instant::now() + MAINTENANCE_INTERVAL;
        loop {
            match self.consumer.receiver.recv_timeout(
                deadline
                    .min(maintenance)
                    .saturating_duration_since(Instant::now()),
            ) {
                Ok(chunk) => {
                    self.broker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .ingest(StreamSource::Console, StreamKind::Stdout, chunk.as_bytes());
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= maintenance {
                self.account_loss();
                let failures = self
                    .broker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .counters()
                    .persist_failures;
                if failures != 0 {
                    self.mark_failed();
                }
                maintenance = Instant::now() + MAINTENANCE_INTERVAL;
            }
            if Instant::now() >= deadline {
                self.account_loss();
                if self.rotate().is_err() {
                    self.mark_failed();
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
            self.mark_failed();
        }
        self.broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .note_unwritten(chunks.max(u64::from(counts.is_saturated())), bytes);
        self.last_loss = (counts.dropped_chunks, counts.dropped_bytes);
    }

    fn mark_failed(&self) {
        if !self.failed.swap(true, Ordering::Relaxed) {
            let _ = mvm_vmm::host::hvf_supervisor::ProtectedSupervisorStatus::CaptureFailed
                .publish(&self.state_dir);
        }
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
        let tenant = &self
            .plan
            .as_ref()
            .context("durable capture needs admitted authority")?
            .tenant
            .0;
        let writer = build_writer_with_policy(
            &self.vm,
            &dir,
            Some(AtRestRetention::default()),
            tenant,
            &self.keys,
        )?;
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
        if mvm_core::transcript::retention_now()
            .and_then(|now| manifest.check_readable_at(now))
            .is_err()
        {
            self.broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .purge_replay();
        }
        if manifest.is_truncated() || manifest.sealed_unix_secs.is_none() {
            self.mark_failed();
        }
        if write_manifest(&self.active, &manifest).is_err() {
            self.mark_failed();
            return;
        }
        if let (Some(plan), Some(emitter)) = (&self.plan, &self.emitter) {
            if emitter
                .emit_transcript_sealed(
                    plan,
                    &manifest.capture_id,
                    &self.vm,
                    &manifest.sealed_root_hex,
                    manifest.chunks.len(),
                    manifest.adopted,
                )
                .is_err()
            {
                self.mark_failed();
            }
        } else {
            self.mark_failed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::test_support::PlanFixture;
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
        host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap();
        let plan = PlanFixture::new().tenant("capture-tenant").build();
        let (owner, producer) = CaptureOwner::start(CaptureParams {
            vm,
            authority: CaptureAuthority::Admitted(&plan),
            redaction: &plan.redaction,
        })
        .unwrap();
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
        let record: mvm_contract::stream::StreamRecord =
            serde_json::from_slice(&chunks[0].plaintext).unwrap();
        assert_eq!(record.payload, marker);
        assert_eq!(manifest.binding.tenant_id, "capture-tenant");
        assert_eq!(manifest.binding.vm_name, vm);
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
    fn ephemeral_owner_never_provisions_a_key_or_durable_payload() {
        use std::io::Write;
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let vm = "owner-ephemeral";
        let plan = PlanFixture::new()
            .stream_retention(StreamRetention::Ephemeral)
            .build();
        let (owner, mut producer) = CaptureOwner::start(CaptureParams {
            vm,
            authority: CaptureAuthority::Admitted(&plan),
            redaction: &plan.redaction,
        })
        .unwrap();
        producer.write_all(b"synthetic-ephemeral-marker").unwrap();
        drop(producer);
        assert!(owner.finish());
        let root = config::vm_stream_transcript_dir(vm);
        let run = ProtectedRun::read(&root).unwrap().unwrap();
        assert!(!run.persists);
        assert!(!run.directory(&root).unwrap().exists());
        assert!(!config::mvm_keys_dir().exists());
        assert!(!config::vm_console_log(vm).exists());
    }

    #[test]
    fn two_instances_of_one_workload_have_distinct_authenticated_capture_bindings() {
        use std::io::Write;
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap();
        let plan = PlanFixture::new().tenant("shared-tenant").build();
        let mut wrapped_keys = Vec::new();
        for vm in ["instance-one", "instance-two"] {
            let (owner, mut producer) = CaptureOwner::start(CaptureParams {
                vm,
                authority: CaptureAuthority::Admitted(&plan),
                redaction: &plan.redaction,
            })
            .unwrap();
            producer.write_all(b"synthetic-instance-output").unwrap();
            drop(producer);
            assert!(owner.finish());
            let root = config::vm_stream_transcript_dir(vm);
            let run = ProtectedRun::read(&root).unwrap().unwrap();
            let dir = run.directory(&root).unwrap().join("00000000000000000000");
            let manifest: TranscriptManifest =
                serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap())
                    .unwrap();
            assert_eq!(manifest.binding.vm_name, vm);
            assert_eq!(manifest.binding.tenant_id, plan.tenant.0);
            assert_ne!(plan.workload.0, vm);
            wrapped_keys.push(manifest.wrapped_data_key_b64);
            let mut reader = mvm_core::stream_client::open_vm_output(
                vm,
                mvm_core::stream_client::OutputRequest::default(),
            )
            .unwrap();
            assert_eq!(
                reader.next_output().unwrap().unwrap().payload,
                b"synthetic-instance-output"
            );
        }
        assert_ne!(wrapped_keys[0], wrapped_keys[1]);
    }

    #[test]
    fn operational_authority_is_live_only_without_an_admission_plan() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let (owner, producer) = CaptureOwner::start(CaptureParams {
            vm: "operational",
            authority: CaptureAuthority::OperationalLiveOnly,
            redaction: &RedactionPolicy::default(),
        })
        .unwrap();
        drop(producer);
        assert!(owner.finish());
        let root = config::vm_stream_transcript_dir("operational");
        let run = ProtectedRun::read(&root).unwrap().unwrap();
        assert!(!run.persists);
        assert!(!run.directory(&root).unwrap().exists());
        assert!(!config::mvm_keys_dir().exists());
    }

    #[test]
    fn required_key_setup_failure_returns_no_producer_and_no_plaintext() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let keys = config::mvm_keys_dir();
        std::fs::create_dir_all(keys.parent().unwrap()).unwrap();
        std::fs::write(&keys, b"synthetic-key-setup-obstruction").unwrap();
        let plan = PlanFixture::new().build();
        assert!(
            CaptureOwner::start(CaptureParams {
                vm: "owner-failed",
                authority: CaptureAuthority::Admitted(&plan),
                redaction: &plan.redaction,
            })
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
