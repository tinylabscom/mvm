//! Supervisor-owned accounting and bounded maintenance of terminal generations.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use mvm_core::transcript::{GenerationBudget, TranscriptManifest, retention_now};

use super::console_source::SharedBroker;
use super::protected_budget::{Reservations, SharedReservations};
use super::protected_inventory::{Inventory, check_declared_segments};
use crate::audit::emitter::AuditEmitter;
use crate::audit::transcript_retirement::{
    BudgetOwner, GenerationReservation, RetirementContext, RetirementOutcome, reconcile_capture,
    reconcile_pressure,
};

const MAINTENANCE_BATCH: usize = 32;

pub(super) struct ManagedRetention {
    root: PathBuf,
    vm: String,
    tenant: String,
    owner: BudgetOwner,
    inventory: Inventory,
    pub reservations: SharedReservations,
}

impl ManagedRetention {
    pub fn new(root: &Path, vm: &str, tenant: &str, emitter: &AuditEmitter) -> Result<Self> {
        let budget = GenerationBudget::default();
        let owner = BudgetOwner::acquire(root, tenant, vm, budget)?;
        let inventory = Inventory::load(root, vm, tenant, emitter)?;
        ensure!(
            inventory.usage.plaintext_bytes <= budget.max_plaintext_bytes
                && inventory.usage.chunks <= budget.max_chunks,
            "managed capture budget already exceeded"
        );
        let reservations = Arc::new(Mutex::new(Reservations::new(budget, inventory.usage)));
        Ok(Self {
            root: root.to_path_buf(),
            vm: vm.into(),
            tenant: tenant.into(),
            owner,
            inventory,
            reservations,
        })
    }

    pub fn pressure(&self) -> Option<GenerationReservation> {
        self.reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pressure()
    }

    pub fn maintain(&mut self, emitter: &AuditEmitter, broker: &SharedBroker) -> Result<()> {
        let now = retention_now()?;
        let mut index = 0;
        let mut attempts = 0;
        while index < self.inventory.generations.len() && attempts < MAINTENANCE_BATCH {
            let generation = &self.inventory.generations[index];
            let due = generation
                .manifest
                .retention_deadline()?
                .is_some_and(|deadline| now >= deadline);
            if !generation.retired && !generation.retry && !due {
                index += 1;
                continue;
            }
            attempts += 1;
            // Revoke any RAM copy before the durable retirement transaction.
            broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .purge_replay();
            let outcome = reconcile_capture(
                RetirementContext {
                    root: &self.root,
                    relative_capture: &generation.relative,
                    capture_id: &generation.manifest.capture_id,
                    tenant: &self.tenant,
                    vm: &self.vm,
                    emitter,
                },
                now,
            )?;
            if matches!(outcome, RetirementOutcome::Retired { .. }) {
                self.release(index)?;
            } else {
                self.inventory.generations[index].retry = false;
                index += 1;
            }
        }
        Ok(())
    }

    /// Called only between joined generations, never while a writer is active.
    pub fn reclaim(
        &mut self,
        emitter: &AuditEmitter,
        broker: &SharedBroker,
        incoming: GenerationReservation,
    ) -> Result<()> {
        self.maintain(emitter, broker)?;
        let budget = GenerationBudget::default();
        let fits = |usage: GenerationReservation| {
            usage
                .plaintext_bytes
                .checked_add(incoming.plaintext_bytes)
                .is_some_and(|n| n <= budget.max_plaintext_bytes)
                && usage
                    .chunks
                    .checked_add(incoming.chunks)
                    .is_some_and(|n| n <= budget.max_chunks)
        };
        for _ in 0..MAINTENANCE_BATCH {
            if fits(self.inventory.usage) {
                return Ok(());
            }
            let index = self
                .inventory
                .generations
                .iter()
                .position(|g| !g.retired)
                .context("managed budget cannot be reclaimed")?;
            self.inventory.generations[index].retry = true;
            let generation = &self.inventory.generations[index];
            let candidates: Vec<_> = self
                .inventory
                .generations
                .iter()
                .filter(|g| !g.retired)
                .map(|g| g.manifest.clone())
                .collect();
            broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .purge_replay();
            let outcome = reconcile_pressure(
                RetirementContext {
                    root: &self.root,
                    relative_capture: &generation.relative,
                    capture_id: &generation.manifest.capture_id,
                    tenant: &self.tenant,
                    vm: &self.vm,
                    emitter,
                },
                &self.owner,
                &candidates,
                incoming,
                retention_now()?,
            )?;
            ensure!(
                matches!(outcome, RetirementOutcome::Retired { .. }),
                "managed pressure retirement did not complete"
            );
            self.release(index)?;
        }
        ensure!(
            fits(self.inventory.usage),
            "managed maintenance batch exhausted"
        );
        Ok(())
    }

    fn release(&mut self, index: usize) -> Result<()> {
        let released = self.inventory.remove(index)?;
        self.reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_retired(released);
        Ok(())
    }

    /// The old durable worker has exited and its terminal root is anchored.
    pub fn record_sealed(&mut self, dir: &Path, manifest: TranscriptManifest) -> Result<()> {
        let relative = dir.strip_prefix(&self.root)?.to_path_buf();
        let capture = CaptureDirectory::open(&self.root, &relative)?;
        capture.prepare_payload(&manifest, false)?;
        check_declared_segments(dir, &manifest)?;
        self.inventory.track(relative, manifest)?;
        self.reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reconcile(self.inventory.usage);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::transcript_retirement::authenticated_retirement;
    use crate::stream::{StreamBroker, StreamRedaction};
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::stream_client::protected::GENERATIONS_DIRECTORY;
    use mvm_core::transcript::{
        AtRestRetention, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME,
        RetentionPolicy, TranscriptWriter, TranscriptWriterConfig, verify_sealed_root,
    };

    struct SealedGeneration {
        dir: PathBuf,
        manifest: TranscriptManifest,
        segment: PathBuf,
        segment_bytes: Vec<u8>,
    }

    fn seal_generation(
        root: &Path,
        run: &str,
        vm: &str,
        tenant: &str,
        created: u64,
        sealed: u64,
        marker: &[u8],
    ) -> SealedGeneration {
        let relative = Path::new(GENERATIONS_DIRECTORY)
            .join(run)
            .join("00000000000000000000");
        let dir = root.join(&relative);
        mvm_core::private_fs::ensure_private_dir(&dir).unwrap();
        let mut writer = TranscriptWriter::new(
            &dir,
            mvm_core::crypto::aead::Key::random(),
            TranscriptWriterConfig {
                capture_id: format!("synthetic-{run}"),
                binding: CaptureBinding {
                    tenant_id: tenant.into(),
                    vm_name: vm.into(),
                    session_id: None,
                },
                bounds: CaptureBounds {
                    max_duration_secs: 3_600,
                    max_bytes: 1 << 20,
                    max_chunks: 100,
                },
                retention: RetentionPolicy::FailClosed,
                at_rest: Some(AtRestRetention::default()),
                generation_budget: Some(GenerationBudget::default()),
                payload_encoding: Default::default(),
                created_unix_secs: created,
                recipient: "transcript-kek".into(),
                wrapped_data_key_b64: "synthetic-envelope".into(),
            },
        )
        .unwrap();
        writer.push(Direction::Stdout, marker).unwrap();
        let manifest = writer.finalize_at(sealed).unwrap();
        drop(writer);
        std::fs::write(
            dir.join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let segment = dir.join(&manifest.chunks[0].file);
        let segment_bytes = std::fs::read(&segment).unwrap();
        SealedGeneration {
            dir,
            manifest,
            segment,
            segment_bytes,
        }
    }

    /// One maintenance pass retires only the generation whose deadline has
    /// passed: its ciphertext is unlinked while its manifest and audit
    /// evidence keep verifying, and the unexpired generation in the same
    /// family keeps its payload, its manifest, and its read window.
    #[test]
    fn maintenance_removes_only_due_payload_and_keeps_unexpired_generation_readable() {
        let root = tempfile::tempdir().unwrap();
        mvm_core::private_fs::ensure_private_dir(root.path()).unwrap();
        let vm = "maintained-instance";
        let tenant = "maintained-tenant";
        let plan = PlanFixture::new().tenant(tenant).build();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[41; 32]),
            &root.path().join("audit"),
        )
        .unwrap();
        let now = retention_now().unwrap();
        let due = seal_generation(
            root.path(),
            "run-due",
            vm,
            tenant,
            now - 700_000,
            now - 699_000,
            b"synthetic-due",
        );
        let fresh = seal_generation(
            root.path(),
            "run-fresh",
            vm,
            tenant,
            now - 100,
            now - 50,
            b"synthetic-fresh",
        );
        for generation in [&due, &fresh] {
            emitter
                .emit_transcript_sealed(
                    &plan,
                    &generation.manifest.capture_id,
                    &generation.manifest.binding.vm_name,
                    &generation.manifest.sealed_root_hex,
                    generation.manifest.chunks.len(),
                    false,
                )
                .unwrap();
        }
        let chain = emitter.audit_dir().join(format!("{tenant}.jsonl"));
        let mut managed = ManagedRetention::new(root.path(), vm, tenant, &emitter).unwrap();
        assert_eq!(managed.inventory.generations.len(), 2);
        let broker: SharedBroker = Arc::new(Mutex::new(StreamBroker::live_only(
            vm,
            StreamRedaction::curated(&plan.redaction),
        )));
        managed.maintain(&emitter, &broker).unwrap();
        // Due: payload unlinked, verification metadata preserved.
        assert!(!due.segment.exists());
        let retired_manifest: TranscriptManifest =
            serde_json::from_slice(&std::fs::read(due.dir.join(MANIFEST_FILENAME)).unwrap())
                .unwrap();
        assert_eq!(retired_manifest, due.manifest);
        verify_sealed_root(&retired_manifest).unwrap();
        assert!(
            authenticated_retirement(emitter.audit_dir(), &emitter.verifying_key(), &due.manifest)
                .unwrap()
        );
        // Not due: payload, manifest and read window untouched; no evidence.
        assert_eq!(std::fs::read(&fresh.segment).unwrap(), fresh.segment_bytes);
        let kept_manifest: TranscriptManifest =
            serde_json::from_slice(&std::fs::read(fresh.dir.join(MANIFEST_FILENAME)).unwrap())
                .unwrap();
        assert_eq!(kept_manifest, fresh.manifest);
        assert!(
            !authenticated_retirement(
                emitter.audit_dir(),
                &emitter.verifying_key(),
                &fresh.manifest
            )
            .unwrap()
        );
        assert!(
            fresh
                .manifest
                .check_readable_at(retention_now().unwrap())
                .is_ok()
        );
        assert_eq!(managed.inventory.generations.len(), 1);
        assert_eq!(
            managed.inventory.generations[0].manifest.capture_id,
            fresh.manifest.capture_id
        );
        // A second pass is a no-op: nothing new is signed or removed.
        let evidence = std::fs::read(&chain).unwrap();
        managed.maintain(&emitter, &broker).unwrap();
        assert_eq!(std::fs::read(&chain).unwrap(), evidence);
        assert!(fresh.segment.exists());
        assert!(!due.segment.exists());
    }
}
