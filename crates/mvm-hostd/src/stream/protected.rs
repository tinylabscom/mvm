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
use super::plane::build_writer_with_policy;
use super::protected_retention::ManagedRetention;
use super::{StreamBroker, StreamRedaction, StreamServerHandle, serve_stream};
use crate::audit::evidence::EvidenceReceipt;
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
    #[cfg(test)]
    rotations: mpsc::Receiver<()>,
}

impl CaptureOwner {
    /// Provision keys, writer and live server before the caller announces boot.
    pub fn start(params: CaptureParams<'_>) -> Result<(Self, Producer)> {
        Self::start_with_period(
            params,
            Duration::from_secs(AtRestRetention::default().max_generation_secs),
        )
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
            Some(AuditEmitter::with_dir(signing, &config::mvm_audit_dir())?)
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
        let mut managed = None;
        if run.persists {
            let tenant = &plan
                .as_ref()
                .context("durable capture needs admitted authority")?
                .tenant
                .0;
            let authority = emitter
                .as_ref()
                .context("durable capture needs audit authority")?;
            let mut retention = ManagedRetention::new(&root, vm, tenant, authority)?;
            retention.maintain(authority, &broker)?;
            let writer = build_writer_with_policy(
                vm,
                &active,
                Some(AtRestRetention::default()),
                tenant,
                &keys,
            )?;
            record_opening(
                plan.as_ref()
                    .context("durable capture needs admitted authority")?,
                emitter
                    .as_ref()
                    .context("durable capture needs audit authority")?,
                &writer.sealed_manifest(),
            )?;
            let mut broker = broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            broker.replace_writer(Some(writer), Some(Arc::clone(&retention.reservations)));
            anyhow::ensure!(
                broker.durable_ready(),
                "protected capture storage worker unavailable"
            );
            managed = Some(retention);
        }
        run.publish(&root)
            .context("publish protected console routing")?;
        let (producer, consumer) = bounded::channel();
        let failed = Arc::new(AtomicBool::new(false));
        let (exit, exited) = mpsc::channel();
        #[cfg(test)]
        let (rotation, rotations) = mpsc::sync_channel(1);
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
            managed,
            broker,
            server,
            consumer,
            failed: Arc::clone(&failed),
            period,
            last_loss: (0, 0),
            #[cfg(test)]
            rotation,
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
                #[cfg(test)]
                rotations,
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
    managed: Option<ManagedRetention>,
    broker: SharedBroker,
    server: StreamServerHandle,
    consumer: Consumer,
    failed: Arc<AtomicBool>,
    period: Duration,
    last_loss: (u64, u64),
    #[cfg(test)]
    rotation: mpsc::SyncSender<()>,
}

pub(super) fn record_opening(
    plan: &ExecutionPlan,
    emitter: &AuditEmitter,
    seed: &TranscriptManifest,
) -> Result<()> {
    use mvm_core::transcript::evidence;
    let mut entry =
        crate::supervisor::audit::for_plan(plan, None, evidence::TRANSCRIPT_OPENED_EVENT, []);
    entry.labels = evidence::opening_labels(seed)?;
    emitter.emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)?;
    // Verification also syncs the matching segment and directory. Visibility
    // alone must not expose a producer whose opening is lost after a crash.
    evidence::authenticate_opening(emitter.audit_dir(), &emitter.verifying_key(), seed)?;
    Ok(())
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
                if let (Some(managed), Some(emitter)) = (&mut self.managed, &self.emitter)
                    && managed.maintain(emitter, &self.broker).is_err()
                {
                    self.mark_failed();
                }
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
            if Instant::now() >= deadline
                || (self.persists
                    && self
                        .managed
                        .as_ref()
                        .is_some_and(|m| m.pressure().is_some()))
            {
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
        let pressure = self.managed.as_ref().and_then(ManagedRetention::pressure);
        let sealed = self
            .broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace_writer(None, None);
        self.publish(sealed)?;
        if let Some(incoming) = pressure {
            self.managed
                .as_mut()
                .context("managed capture owner missing")?
                .reclaim(
                    self.emitter
                        .as_ref()
                        .context("capture audit authority missing")?,
                    &self.broker,
                    incoming,
                )?;
        }
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
        record_opening(
            self.plan
                .as_ref()
                .context("durable capture needs admitted authority")?,
            self.emitter
                .as_ref()
                .context("durable capture needs audit authority")?,
            &writer.sealed_manifest(),
        )?;
        self.broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace_writer(
                Some(writer),
                self.managed.as_ref().map(|m| Arc::clone(&m.reservations)),
            );
        self.generation = next;
        self.active = dir;
        #[cfg(test)]
        let _ = self.rotation.try_send(());
        Ok(())
    }

    fn seal_active(&mut self) {
        let sealed = self
            .broker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace_writer(None, None);
        if self.publish(sealed).is_err() {
            self.mark_failed();
        }
    }

    fn publish(&mut self, manifest: Option<TranscriptManifest>) -> Result<()> {
        let Some(mut manifest) = manifest else {
            return Ok(());
        };
        // A timed-out writer can still hold the generation lease and append.
        // Its integrity snapshot is not terminal evidence: leave the seed and
        // journal for a later owner that can positively establish quiescence.
        if manifest.sealed_unix_secs.is_none() {
            self.mark_failed();
            anyhow::bail!("capture writer did not terminate");
        }
        if self.failed.load(Ordering::Relaxed) {
            manifest.adopted = true;
            manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&manifest)?;
        }
        // A late joined recovery can clamp sealing before the last record's
        // wall timestamp. Revoke that live epoch rather than let its record-
        // based deadline extend beyond the authenticated generation deadline.
        if manifest.adopted
            || mvm_core::transcript::retention_now()
                .and_then(|now| manifest.check_readable_at(now))
                .is_err()
        {
            self.broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .purge_replay();
        }
        if manifest.is_truncated() {
            self.mark_failed();
        }
        super::protected_recovery::stage(&self.active, &manifest)?;
        if let (Some(plan), Some(emitter)) = (&self.plan, &self.emitter) {
            emitter.emit_transcript_sealed(
                plan,
                &manifest.capture_id,
                &self.vm,
                &manifest.sealed_root_hex,
                manifest.chunks.len(),
                manifest.adopted,
            )?;
            anyhow::ensure!(
                mvm_core::transcript::evidence::authenticated_seal(
                    emitter.audit_dir(),
                    &emitter.verifying_key(),
                    &manifest,
                )?
                .is_some(),
                "capture terminal evidence unavailable"
            );
        } else {
            anyhow::bail!("capture audit authority missing");
        }
        self.managed
            .as_mut()
            .context("managed capture owner missing")?
            .record_sealed(&self.active, manifest)?;
        super::journal::CaptureJournal::discard(
            &self.active.join(super::journal::JOURNAL_FILENAME),
        );
        Ok(())
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
    fn rotation_seals_fresh_keys_and_history_splices_without_sequence_reset() {
        use std::io::Write;
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap();
        let plan = PlanFixture::new().build();
        let vm = "rotation-owner";
        let (owner, mut producer) = CaptureOwner::start_with_period(
            CaptureParams {
                vm,
                authority: CaptureAuthority::Admitted(&plan),
                redaction: &plan.redaction,
            },
            Duration::from_millis(50),
        )
        .unwrap();
        producer.write_all(b"before-rotation").unwrap();
        owner
            .rotations
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        producer.write_all(b"after-rotation").unwrap();
        drop(producer);
        assert!(owner.finish());
        let root = config::vm_stream_transcript_dir(vm);
        let run = ProtectedRun::read(&root).unwrap().unwrap();
        let mut keys = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(run.directory(&root).unwrap()).unwrap() {
            let manifest: TranscriptManifest = serde_json::from_slice(
                &std::fs::read(entry.unwrap().path().join(MANIFEST_FILENAME)).unwrap(),
            )
            .unwrap();
            assert!(manifest.sealed_unix_secs.is_some());
            assert!(keys.insert(manifest.wrapped_data_key_b64));
        }
        assert!(keys.len() >= 2);
        let mut output = mvm_core::stream_client::open_vm_output(
            vm,
            mvm_core::stream_client::OutputRequest::default(),
        )
        .unwrap();
        let first = output.next_output().unwrap().unwrap();
        let second = output.next_output().unwrap().unwrap();
        assert_eq!(first.payload, b"before-rotation");
        assert_eq!(second.payload, b"after-rotation");
        assert_eq!(second.seq, first.seq + 1);
        assert!(output.next_output().unwrap().is_none());
    }

    #[test]
    fn cross_generation_pressure_is_authenticated_and_reader_refuses_unlinked_late_payload() {
        use crate::audit::transcript_retirement::GenerationReservation;
        use mvm_core::transcript::GenerationBudget;
        use std::io::Write;
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let keys = config::mvm_keys_dir();
        host_keypair::load_or_init_at(&keys).unwrap();
        let plan = PlanFixture::new().tenant("pressure-tenant").build();
        let vm = "pressure-owner";
        let (owner, mut producer) = CaptureOwner::start(CaptureParams {
            vm,
            authority: CaptureAuthority::Admitted(&plan),
            redaction: &plan.redaction,
        })
        .unwrap();
        producer.write_all(b"private-retired-output").unwrap();
        drop(producer);
        assert!(owner.finish());
        let root = config::vm_stream_transcript_dir(vm);
        let run = ProtectedRun::read(&root).unwrap().unwrap();
        let dir = run.directory(&root).unwrap().join("00000000000000000000");
        let manifest: TranscriptManifest =
            serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap()).unwrap();
        let segment = dir.join(&manifest.chunks[0].file);
        let ciphertext = std::fs::read(&segment).unwrap();
        let (signing, _) = mvm_core::crypto::ed25519_keypair::load_existing(
            &keys.join(host_keypair::SECRET_FILENAME),
            &keys.join(host_keypair::PUBLIC_FILENAME),
        )
        .unwrap();
        let emitter = AuditEmitter::with_dir(signing, &config::mvm_audit_dir()).unwrap();
        let mut managed = ManagedRetention::new(&root, vm, &plan.tenant.0, &emitter).unwrap();
        let mut opened_before_retirement = mvm_core::stream_client::open_vm_output(
            vm,
            mvm_core::stream_client::OutputRequest::default(),
        )
        .unwrap();
        assert_eq!(opened_before_retirement.history_len(), 1);
        let mut opened_before_authority_loss = mvm_core::stream_client::open_vm_output(
            vm,
            mvm_core::stream_client::OutputRequest::default(),
        )
        .unwrap();
        let unavailable_audit = home.path().join("temporarily-unavailable-audit");
        std::fs::rename(emitter.audit_dir(), &unavailable_audit).unwrap();
        assert!(opened_before_authority_loss.next_output().is_err());
        assert_eq!(opened_before_authority_loss.history_len(), 0);
        std::fs::rename(&unavailable_audit, emitter.audit_dir()).unwrap();
        let limit = GenerationBudget::default().max_plaintext_bytes;
        assert!(
            !managed.reservations.lock().unwrap().reserve(limit),
            "old sealed generation must count against the new producer"
        );
        let broker = Arc::new(Mutex::new(StreamBroker::live_only(
            vm,
            StreamRedaction::curated(&plan.redaction),
        )));
        managed
            .reclaim(
                &emitter,
                &broker,
                GenerationReservation {
                    plaintext_bytes: limit,
                    chunks: 1,
                },
            )
            .unwrap();
        assert!(!segment.exists());
        assert!(opened_before_retirement.next_output().is_err());
        assert_eq!(opened_before_retirement.history_len(), 0);
        assert!(opened_before_retirement.next_output().unwrap().is_none());
        assert!(manifest.chunks[0].size_bytes > 28);
        assert!(managed.reservations.lock().unwrap().reserve(limit));
        assert!(!managed.reservations.lock().unwrap().reserve(1));
        // Simulate an interrupted unlink: the signed retirement, not path
        // absence, must prevent readers from exposing retained ciphertext.
        mvm_core::util::atomic_io::atomic_write(&segment, &ciphertext).unwrap();
        let mut output = mvm_core::stream_client::open_vm_output(
            vm,
            mvm_core::stream_client::OutputRequest::default(),
        )
        .unwrap();
        assert!(output.next_output().unwrap().is_none());
        assert_eq!(
            output.empty_history(),
            Some(mvm_core::stream_client::EmptyHistory::Retired)
        );
        assert!(!config::vm_console_log(vm).exists());
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
