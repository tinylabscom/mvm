//! The root consumes the same ledger dimensions and attempts as its children.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::workload_actor::WorkflowRole;
use mvm_core::util::atomic_io::{NewFile, write_private_new};
use mvm_runtime::actor_teardown::{ActorTeardownJournal, TerminalProof};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::actor_bootstrap::ActorBootstrap;
use crate::actor_reservations::{
    ActorReservations, ReservationIdentity, ReservationRequest, ReserveOutcome,
};
use crate::audit::emitter::AuditEmitter;

pub(super) struct RootReservation {
    ledger: ActorReservations,
    identity: ReservationIdentity,
    terminal_path: PathBuf,
    terminal: bool,
}

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum TerminalEvidence<'a> {
    NoDispatch,
    Stopped {
        original_owner: &'a ActorTeardownJournal,
    },
}

impl RootReservation {
    pub(super) fn reserve(
        path: &Path,
        terminal_path: PathBuf,
        bootstrap: &ActorBootstrap,
    ) -> Result<Self> {
        let membership = bootstrap
            .parent
            .workflow
            .as_ref()
            .context("root workflow absent")?;
        let WorkflowRole::Controller { grant } = &membership.role else {
            anyhow::bail!("root controller grant absent");
        };
        let identity = ReservationIdentity {
            tenant: hash(&grant.controller.tenant)?,
            workflow: hash(&membership.workflow_id)?,
            controller: hash(&grant.controller)?,
            controller_generation: grant.controller.generation.get(),
            idempotency_key: hash(&("mvm.actor.root.v1", &grant.controller))?,
            template_digest: hash(&bootstrap.launch)?,
            parent_plan_digest: hash(&bootstrap.parent.plan_id)?,
            request_digest: hash(&(
                "mvm.actor.root.v1",
                &bootstrap.parent.plan_id,
                bootstrap.constraints.parent_charge,
            ))?,
        };
        let ledger = ActorReservations::open_with_host_budget(path, bootstrap.host_budget)?;
        let outcome = ledger.reserve(
            ReservationRequest {
                identity: identity.clone(),
                resources: bootstrap.constraints.parent_charge,
            },
            bootstrap.constraints.ceilings,
        )?;
        ensure!(
            matches!(outcome, ReserveOutcome::Reserved(_)),
            "actor root reservation already exists; reconcile retained outcome"
        );
        Ok(Self {
            ledger,
            identity,
            terminal_path,
            terminal: false,
        })
    }

    pub(super) fn prepared(&self, signed: &mvm_core::plan::SignedExecutionPlan) -> Result<()> {
        self.ledger.mark_prepared(&self.identity, hash(signed)?)?;
        Ok(())
    }

    pub(super) fn running(&self, signed: &mvm_core::plan::SignedExecutionPlan) -> Result<()> {
        self.ledger.mark_running(&self.identity, hash(signed)?)?;
        Ok(())
    }

    pub(super) fn stopped(
        &mut self,
        proof: &TerminalProof,
        plan: &ExecutionPlan,
        emitter: &AuditEmitter,
    ) -> Result<()> {
        self.finish(
            TerminalEvidence::Stopped {
                original_owner: proof.journal(),
            },
            plan,
            emitter,
        )
    }

    pub(super) fn never_dispatched(
        &mut self,
        plan: &ExecutionPlan,
        emitter: &AuditEmitter,
    ) -> Result<()> {
        self.finish(TerminalEvidence::NoDispatch, plan, emitter)
    }

    fn finish(
        &mut self,
        evidence: TerminalEvidence<'_>,
        plan: &ExecutionPlan,
        emitter: &AuditEmitter,
    ) -> Result<()> {
        if self.terminal {
            return Ok(());
        }
        let record = (&self.identity, evidence);
        let bytes = serde_jcs::to_vec(&record)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if write_private_new(&self.terminal_path, &bytes)? != NewFile::Created {
            ensure!(
                std::fs::read(&self.terminal_path)? == bytes,
                "root terminal evidence conflicts"
            );
        }
        emitter.emit(
            plan,
            "actor.controller.terminal",
            [
                (
                    "reservation_digest".into(),
                    hex::encode(self.identity.request_digest),
                ),
                ("result_digest".into(), hex::encode(digest)),
            ],
        )?;
        self.ledger.reconcile_terminal(&self.identity, digest)?;
        self.terminal = true;
        Ok(())
    }
}

fn hash(value: &impl Serialize) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_jcs::to_vec(value)?).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_child_share_the_same_live_workload_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        mvm_core::private_fs::ensure_private_dir(dir.path()).unwrap();
        let mut bootstrap = crate::actor_bootstrap::tests::authored();
        bootstrap.host_budget.resources.live_vms = 1;
        bootstrap.host_budget.resources.concurrent_launches = 2;
        bootstrap
            .constraints
            .ceilings
            .tenant
            .resources
            .concurrent_launches = 2;
        bootstrap
            .constraints
            .ceilings
            .controller
            .resources
            .concurrent_launches = 2;
        bootstrap
            .constraints
            .ceilings
            .workflow
            .resources
            .concurrent_launches = 2;
        bootstrap.constraints.ceilings.workflow.resources.live_vms = 1;
        let bootstrap = bootstrap.bind().unwrap();
        let path = dir.path().join("reservations.json");
        let ledger = ActorReservations::create(&path, bootstrap.host_budget).unwrap();
        let root =
            RootReservation::reserve(&path, dir.path().join("terminal.json"), &bootstrap).unwrap();
        let mut child = root.identity.clone();
        child.idempotency_key = hash(&"child").unwrap();
        child.request_digest = hash(&"child-request").unwrap();
        let child_request = ReservationRequest {
            identity: child,
            resources: bootstrap.templates[0].definition.charge,
        };
        assert!(
            ledger
                .reserve(child_request, bootstrap.constraints.ceilings)
                .is_err()
        );
        assert!(!dir.path().join("terminal.json").exists());
    }

    #[test]
    fn undispatched_root_release_preserves_its_total_attempt() {
        let dir = tempfile::tempdir().unwrap();
        mvm_core::private_fs::ensure_private_dir(dir.path()).unwrap();
        let mut bootstrap = crate::actor_bootstrap::tests::authored();
        bootstrap.host_budget.max_total_attempts = 1;
        let bootstrap = bootstrap.bind().unwrap();
        let path = dir.path().join("reservations.json");
        let ledger = ActorReservations::create(&path, bootstrap.host_budget).unwrap();
        let mut root =
            RootReservation::reserve(&path, dir.path().join("terminal.json"), &bootstrap).unwrap();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &dir.path().join("audit"),
        )
        .unwrap();
        root.never_dispatched(&bootstrap.parent, &emitter).unwrap();
        assert!(dir.path().join("terminal.json").is_file());
        assert!(matches!(
            ledger.observe(&root.identity).unwrap().state,
            crate::actor_reservations::ReservationState::Terminal { .. }
        ));
        let mut next = root.identity.clone();
        next.idempotency_key = hash(&"next").unwrap();
        assert!(
            ledger
                .reserve(
                    ReservationRequest {
                        identity: next,
                        resources: bootstrap.constraints.parent_charge,
                    },
                    bootstrap.constraints.ceilings
                )
                .is_err()
        );
    }
}
