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
