//! The `vm_full` fork arms: branching a fresh VM identity out of a saved
//! machine state, per VMM.
//!
//! Everything above this module is backend-neutral — the clone, the verity
//! binding check, the lineage record. What differs per VMM is the admission
//! label and the restore mechanism. Neither arm carries a live-parent
//! restriction: a guest has no NIC (egress rides per-VM vsock proxies keyed
//! by VM name), so a restored child has no host network identity to collide
//! with its parent. The per-child resources a restore does carry — the vsock
//! UDS path and the block devices recorded in the snapshot — are remapped to
//! the child's own state dir before the child VMM starts.

use anyhow::{Context, Result};
use mvm_client::checkpoint::CheckpointStore;
use mvm_core::checkpoint::{CheckpointId, VmFullOrigin, vm_full_origin};
use mvm_core::config::vm_state_dir;

use super::{
    CheckpointForkJson, ForkIntent, bind_checkpoint_forked, grant_predecessor_from_vm_name,
    now_unix, read_grant_envelope_for,
};
use crate::ui;

/// Inputs for [`fork_vm_full_arm`]. Grouped to stay under the
/// `clippy::too_many_arguments` workspace ceiling.
pub(in crate::commands) struct ForkVmFullArmParams<'a> {
    pub(in crate::commands) store: &'a CheckpointStore,
    pub(in crate::commands) checkpoint: &'a CheckpointId,
    pub(in crate::commands) new_id: Option<String>,
    /// Refused with a user-visible error: a vm_full fork restores the saved
    /// machine state (cpu/mem baked into the snapshot), so the shape is fixed.
    /// Use an fs_quick fork to boot a resized child.
    pub(in crate::commands) cpus_override: Option<u32>,
    /// Refused with a user-visible error for the same reason as `cpus_override`.
    pub(in crate::commands) memory_override: Option<&'a str>,
    pub(in crate::commands) json: bool,
    /// Secret bindings declared for the child. Empty reproduces the prior
    /// behaviour: a child admitted with no bindings.
    pub(in crate::commands) declared_secrets: &'a [mvm_core::plan::SecretBinding],
    pub(in crate::commands) allow_secret_drop: bool,
    pub(in crate::commands) intent: ForkIntent,
}

/// vm_full fork: clone the captured triple into a new child identity, admit a
/// fresh claim-8 plan for the child (using the parent's saved cpu/mem — the
/// restore shape is fixed), rewrite the supervisor config, and boot the child
/// in restore mode. The child's admitted plan is distinct from the parent's.
pub(in crate::commands) fn fork_vm_full_arm(
    p: ForkVmFullArmParams<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    let _activation_barrier =
        mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
    mvm_client::policy_profiles::coordinator::recover_workload_ledger()?;
    if cfg!(target_os = "linux") {
        mvm_client::policy_profiles::coordinator::ensure_if_activated()?;
    }
    fork_vm_full_arm_inner(p)
}

fn fork_vm_full_arm_inner(
    p: ForkVmFullArmParams<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    // A vm_full fork restores a saved machine state whose cpu/mem are baked
    // into the snapshot, and a restoring VMM validates device config against
    // the saved state and refuses a mismatch. Accepting these flags
    // would silently fail at restore time with a confusing hypervisor error
    // — refuse early.
    if p.cpus_override.is_some() {
        anyhow::bail!(
            "--cpus is not valid for a vm_full fork: a memory restore resumes the saved \
             machine shape; use an fs_quick fork to resize"
        );
    }
    if p.memory_override.is_some() {
        anyhow::bail!(
            "--memory is not valid for a vm_full fork: a memory restore resumes the saved \
             machine shape; use an fs_quick fork to resize"
        );
    }

    let now = now_unix();
    let child_vm_name = p
        .new_id
        .unwrap_or_else(|| format!("{}-fork-{now}", p.checkpoint.as_str()));
    let dest_dir = vm_state_dir(&child_vm_name);
    let child_id = CheckpointId::new(format!("fork-{child_vm_name}-{now}"));

    let parent_meta = p.store.read_meta(p.checkpoint)?;

    // Dispatch on the machine state the checkpoint actually carries. HVF and
    // Firecracker forks differ in more than mechanics: an HVF guest has no NIC
    // at all, so the parent/child address collision that keeps the Firecracker
    // arm behind an opt-in cannot arise there.
    match vm_full_origin(&parent_meta) {
        Some(VmFullOrigin::Hvf) => fork_vm_full_arm_hvf(ForkVmFullArmHvfParams {
            store: p.store,
            checkpoint: p.checkpoint,
            parent_meta,
            child_vm_name,
            dest_dir,
            child_id,
            now,
            json: p.json,
            declared_secrets: p.declared_secrets,
            allow_secret_drop: p.allow_secret_drop,
            intent: p.intent,
        }),
        Some(VmFullOrigin::Firecracker) => fork_vm_full_arm_fc(ForkVmFullArmFcParams {
            store: p.store,
            checkpoint: p.checkpoint,
            parent_meta,
            child_vm_name,
            dest_dir,
            child_id,
            now,
            json: p.json,
            declared_secrets: p.declared_secrets,
            allow_secret_drop: p.allow_secret_drop,
            intent: p.intent,
        }),
        Some(VmFullOrigin::Retired) => anyhow::bail!(
            "this vm_full checkpoint was captured under a backend that has been removed; \
             nothing on this host can load its saved machine state. Use an fs_quick fork \
             instead."
        ),
        None => anyhow::bail!(
            "vm_full checkpoint '{}' names no saved machine state; use an fs_quick fork",
            parent_meta.id
        ),
    }
}

/// Inputs for [`fork_vm_full_arm_fc`]. Grouped to stay under the
/// `clippy::too_many_arguments` workspace ceiling.
pub(in crate::commands) struct ForkVmFullArmFcParams<'a> {
    pub(in crate::commands) store: &'a CheckpointStore,
    pub(in crate::commands) checkpoint: &'a CheckpointId,
    pub(in crate::commands) parent_meta: mvm_core::checkpoint::CheckpointMeta,
    pub(in crate::commands) child_vm_name: String,
    pub(in crate::commands) dest_dir: std::path::PathBuf,
    pub(in crate::commands) child_id: CheckpointId,
    pub(in crate::commands) now: u64,
    pub(in crate::commands) json: bool,
    /// Secret bindings declared for the child. Empty reproduces the prior
    /// behaviour: a child admitted with no bindings.
    pub(in crate::commands) declared_secrets: &'a [mvm_core::plan::SecretBinding],
    pub(in crate::commands) allow_secret_drop: bool,
    pub(in crate::commands) intent: ForkIntent,
}

/// FC vm_full fork: clone the captured triple, admit a fresh claim-8 plan for
/// the child, rename `memory.bin` → `mem.bin`, and boot the child via a fresh
/// Firecracker VMM loaded from the checkpoint snapshot.
///
/// The parent may be running: a workload Firecracker carries no NIC (egress
/// rides per-VM vsock proxies keyed by VM name), so a forked child has no
/// host network identity to collide with. The snapshot's recorded device
/// paths — the vsock UDS above all — are pointed at the child's own state dir
/// while the child VMM is still paused, and the
/// no-NIC device-model guard runs between the child's load and resume, so a
/// NIC-carrying snapshot can never execute. The only true parent/child
/// identity collision — an equal VM name — is refused by the shared
/// `fork_vm_full` gate upstream of this arm.
pub(in crate::commands) fn fork_vm_full_arm_fc(
    p: ForkVmFullArmFcParams<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    // Only a Firecracker-produced machine state can be loaded here. A caller
    // that reached this arm with anything else has mis-dispatched.
    if vm_full_origin(&p.parent_meta) != Some(VmFullOrigin::Firecracker) {
        anyhow::bail!(
            "checkpoint '{}' does not carry a Firecracker machine state",
            p.parent_meta.id
        );
    }

    let prepared = prepare_forked_child(PrepareForkedChildParams {
        store: p.store,
        checkpoint: p.checkpoint,
        child_vm_name: &p.child_vm_name,
        child_id: p.child_id,
        destination: p.dest_dir,
        created_unix: p.now,
        declared_secrets: p.declared_secrets,
        allow_secret_drop: p.allow_secret_drop,
        intent: p.intent,
    })?;
    let dispatched = prepared.dispatch();
    let admission = dispatched.admission;
    let fork_result = dispatched.result;
    if let Err(ref e) = fork_result {
        audit_fork_failure(&admission, &p.child_vm_name, "fork-vm-full-fc", e);
    }
    let meta = fork_result
        .with_context(|| format!("forking FC vm_full checkpoint {:?}", p.checkpoint.as_str()))?;

    if let Err(error) = bind_checkpoint_forked(
        p.checkpoint,
        &meta,
        &p.child_vm_name,
        p.store,
        p.declared_secrets,
        &crate::commands::vm::tenant_resolution::resolve_tenant(None),
    ) {
        let error = stop_fc_child_after_restore_failure(&p.child_vm_name, error);
        audit_fork_failure(&admission, &p.child_vm_name, "fork-lineage", &error);
        return Err(error);
    }
    crate::commands::vm::up::emit_launched(&admission, "firecracker", true);

    // Deliver the fresh generation token to every restored child. A grant is
    // optional for dev/test forks, but identity rotation is not: the token is
    // bound to the child's recorded snapshot identity, not its human-readable
    // VM name. When a grant exists, re-pin it in the same PostRestore RPC.
    let mut grant_env = read_grant_envelope_for(&p.child_vm_name);
    if let Some(grant) = grant_env.as_mut()
        && let Some(parent_vm_name) = p.store.read_meta(p.checkpoint).ok().map(|m| m.vm_name)
        && let Some((session_id, plan_nonce)) = grant_predecessor_from_vm_name(&parent_vm_name)
    {
        grant.predecessor_session_id = Some(session_id);
        grant.predecessor_plan_nonce_hex = Some(plan_nonce.as_hex().to_string());
    }
    if let Err(error) = deliver_fc_fork_post_restore(
        &p.child_vm_name,
        p.parent_meta.meta_digest.as_str(),
        grant_env,
    ) {
        let error = stop_fc_child_after_restore_failure(&p.child_vm_name, error);
        audit_fork_failure(&admission, &p.child_vm_name, "fork-post-restore", &error);
        return Err(error);
    }

    if let Err(error) = record_fork_runtime_meta(&p.child_vm_name, &p.parent_meta) {
        let error = stop_fc_child_after_restore_failure(&p.child_vm_name, error);
        audit_fork_failure(&admission, &p.child_vm_name, "fork-runtime-meta", &error);
        return Err(error);
    }

    if p.json {
        crate::json_out::emit_json(&CheckpointForkJson {
            schema_version: 1,
            action: "fork",
            parent_id: p.checkpoint,
            child_vm_name: &p.child_vm_name,
            booted: true,
            checkpoint: &meta,
        })?;
    } else {
        ui::success(&format!(
            "forked {} -> checkpoint {} (vm '{}', auto-booted on firecracker)",
            p.checkpoint.as_str(),
            meta.id.as_str(),
            p.child_vm_name
        ));
    }
    Ok(meta)
}

/// CLI intent adapter for the client-owned full-VM fork pipeline.
struct PrepareForkedChildParams<'a> {
    store: &'a CheckpointStore,
    checkpoint: &'a CheckpointId,
    child_vm_name: &'a str,
    child_id: CheckpointId,
    destination: std::path::PathBuf,
    created_unix: u64,
    declared_secrets: &'a [mvm_core::plan::SecretBinding],
    allow_secret_drop: bool,
    intent: ForkIntent,
}

fn prepare_forked_child(
    p: PrepareForkedChildParams<'_>,
) -> Result<mvm_client::checkpoint::vm_full::PreparedVmFullFork> {
    let intent = match p.intent {
        ForkIntent::Ordinary => mvm_client::checkpoint::vm_full::VmFullForkIntent::Ordinary,
        ForkIntent::Replay => mvm_client::checkpoint::vm_full::VmFullForkIntent::Replay,
    };
    mvm_client::checkpoint::vm_full::prepare_vm_full_fork(
        p.store,
        mvm_client::checkpoint::vm_full::VmFullForkRequest {
            checkpoint: p.checkpoint,
            child_id: p.child_id,
            child_name: p.child_vm_name.to_string(),
            destination: p.destination,
            created_unix: p.created_unix,
            declared_secrets: p.declared_secrets,
            allow_secret_drop: p.allow_secret_drop,
            intent,
            fallback_network_mode: crate::commands::machine::preflight_network(),
        },
    )
}

/// Inputs for [`fork_vm_full_arm_hvf`].
struct ForkVmFullArmHvfParams<'a> {
    store: &'a CheckpointStore,
    checkpoint: &'a CheckpointId,
    parent_meta: mvm_core::checkpoint::CheckpointMeta,
    child_vm_name: String,
    dest_dir: std::path::PathBuf,
    child_id: CheckpointId,
    now: u64,
    json: bool,
    /// Secret bindings declared for the child. Empty reproduces the prior
    /// behaviour: a child admitted with no bindings.
    declared_secrets: &'a [mvm_core::plan::SecretBinding],
    allow_secret_drop: bool,
    intent: ForkIntent,
}

/// HVF vm_full fork: clone the captured state into a fresh child identity, admit
/// a claim-8 plan of the child's own, restore the saved machine state into a new
/// supervisor, and rotate the child's generation identity.
///
/// Unlike the Firecracker arm this needs no experimental opt-in. That guard
/// exists because a restored Firecracker child inherits the parent's guest
/// IP/MAC out of saved memory and collides with it on the shared bridge. An HVF
/// guest has no NIC to inherit an address on: its only path off the box is the
/// vsock relay the host binds, and the restore binds none.
fn fork_vm_full_arm_hvf(
    p: ForkVmFullArmHvfParams<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    let prepared = prepare_forked_child(PrepareForkedChildParams {
        store: p.store,
        checkpoint: p.checkpoint,
        child_vm_name: &p.child_vm_name,
        child_id: p.child_id,
        destination: p.dest_dir,
        created_unix: p.now,
        declared_secrets: p.declared_secrets,
        allow_secret_drop: p.allow_secret_drop,
        intent: p.intent,
    })?;
    let dispatched = prepared.dispatch();
    let admission = dispatched.admission;
    let fork_result = dispatched.result;
    if let Err(ref e) = fork_result {
        audit_fork_failure(&admission, &p.child_vm_name, "fork-vm-full-hvf", e);
    }
    let meta = fork_result
        .with_context(|| format!("forking HVF vm_full checkpoint {:?}", p.checkpoint.as_str()))?;

    if let Err(error) = bind_checkpoint_forked(
        p.checkpoint,
        &meta,
        &p.child_vm_name,
        p.store,
        p.declared_secrets,
        &admission.admitted.plan().tenant.0,
    ) {
        let error = stop_child_after_restore_failure(&p.child_vm_name, error);
        audit_fork_failure(&admission, &p.child_vm_name, "fork-lineage", &error);
        return Err(error);
    }
    crate::commands::vm::up::emit_launched(&admission, "hvf", true);

    if let Err(error) = deliver_hvf_fork_post_restore(
        &p.child_vm_name,
        p.parent_meta.meta_digest.as_str(),
        read_grant_envelope_for(&p.child_vm_name),
    ) {
        let error = stop_child_after_restore_failure(&p.child_vm_name, error);
        audit_fork_failure(&admission, &p.child_vm_name, "fork-post-restore", &error);
        return Err(error);
    }

    if let Err(error) = record_fork_runtime_meta(&p.child_vm_name, &p.parent_meta) {
        let error = stop_child_after_restore_failure(&p.child_vm_name, error);
        audit_fork_failure(&admission, &p.child_vm_name, "fork-runtime-meta", &error);
        return Err(error);
    }

    if p.json {
        crate::json_out::emit_json(&CheckpointForkJson {
            schema_version: 1,
            action: "fork",
            parent_id: p.checkpoint,
            child_vm_name: &p.child_vm_name,
            booted: true,
            checkpoint: &meta,
        })?;
    } else {
        ui::success(&format!(
            "forked {} -> checkpoint {} (vm '{}', auto-booted on hvf)",
            p.checkpoint.as_str(),
            meta.id.as_str(),
            p.child_vm_name
        ));
    }
    Ok(meta)
}

fn audit_fork_failure(
    admission: &crate::commands::vm::up::AdmissionContext,
    name: &str,
    stage: &str,
    error: &anyhow::Error,
) {
    if error
        .downcast_ref::<mvm_client::checkpoint::ForkStopUncertain>()
        .is_some()
    {
        mvm_client::admission::record_uncertain_restore_stop(admission, name, error);
    } else {
        crate::commands::vm::up::emit_failed(admission, fork_failure_stage(stage, error), error);
    }
    // The child is stopped (or its stop is uncertain) by now; release the
    // host hold only on the same liveness evidence the budget counts with.
    if let Err(settle) = admission.admitted.settle_failed_host_budget_launch(name) {
        tracing::warn!(error = %settle, "fork host hold not settled; retaining its capacity");
    }
}

/// A host-budget refusal is audited under the launch tail's stage label.
fn fork_failure_stage<'a>(stage: &'a str, error: &anyhow::Error) -> &'a str {
    if error
        .downcast_ref::<mvm_client::admission::HostBudgetRefused>()
        .is_some()
    {
        "host-budget"
    } else {
        stage
    }
}

fn stop_hvf_fork_child(child_vm_name: &str) -> Result<()> {
    let backend = mvm_client::AnyBackend::for_started_vm(child_vm_name)
        .with_context(|| format!("no backend claims restored child '{child_vm_name}'"))?;
    backend
        .stop(&mvm_core::vm_backend::VmId(child_vm_name.to_string()))
        .map(|_| ())
}

/// Stop a restored child when identity rotation, lineage binding or runtime
/// metadata fails. An unconfirmed stop stays a typed unsealed outcome.
fn stop_child_after_restore_failure(child_vm_name: &str, error: anyhow::Error) -> anyhow::Error {
    match stop_hvf_fork_child(child_vm_name) {
        Ok(()) => error.context(format!(
            "stopped forked child '{child_vm_name}' after restore completion failure"
        )),
        Err(stop) => mvm_client::checkpoint::ForkStopUncertain {
            name: child_vm_name.to_string(),
            primary: error,
            stop,
        }
        .into(),
    }
}

/// Stop a restored Firecracker child when post-restore hygiene or its runtime
/// metadata fails, and report both the original failure and the stop outcome.
fn stop_fc_child_after_restore_failure(child_vm_name: &str, error: anyhow::Error) -> anyhow::Error {
    match mvm_client::checkpoint::stop_vm(child_vm_name) {
        Ok(()) => error.context(format!(
            "stopped forked child '{child_vm_name}' after restore completion failure"
        )),
        Err(stop) => mvm_client::checkpoint::ForkStopUncertain {
            name: child_vm_name.to_string(),
            primary: error,
            stop,
        }
        .into(),
    }
}

/// Record a restored child's runtime metadata (`mode.json`) exactly as a cold
/// boot does: its own rootfs, the accessibility bit from the guest sidecar the
/// checkpoint carried beside it, and the parent's runtime overlay version and
/// authenticated runtime launch binding — plus the device paths its restored
/// VMM still names, which a snapshot of the child embeds and a fork of that
/// snapshot must remap.
///
/// A step checkpoint of the child resolves its rootfs from this record, so a
/// child without it answers prompts but can never be checkpointed or replayed
/// past them.
fn record_fork_runtime_meta(
    child_vm_name: &str,
    parent: &mvm_core::checkpoint::CheckpointMeta,
) -> Result<()> {
    use mvm_client::checkpoint::runtime_meta;

    let state_dir = vm_state_dir(child_vm_name);
    let rootfs = state_dir.join(mvm_core::checkpoint::ROOTFS_BLOB);
    anyhow::ensure!(
        rootfs.is_file(),
        "restored child has no rootfs at {}",
        rootfs.display()
    );
    runtime_meta::record_from_rootfs(
        child_vm_name,
        mvm_core::vm_backend::StartMode::Detached,
        &rootfs,
    )?;
    let mut meta = runtime_meta::read(child_vm_name)?
        .context("restored child runtime metadata was not written")?;
    meta.runtime_overlay_version = parent.runtime_overlay_version.clone();
    meta.runtime_launch_binding = parent.runtime_launch_binding.clone();
    meta.restored_device_anchors = runtime_meta::read_restored_device_anchors(&state_dir)?;
    runtime_meta::write(child_vm_name, &meta)?;
    let persisted = runtime_meta::read(child_vm_name)?
        .context("restored child runtime metadata did not persist")?;
    anyhow::ensure!(
        persisted == meta,
        "restored child runtime metadata changed during write"
    );
    Ok(())
}

/// Hand a freshly restored HVF child its fresh generation token (and its grant,
/// when one was minted) over the backend-agnostic vsock dispatcher, and refuse
/// anything short of a full acknowledgement.
fn deliver_hvf_fork_post_restore(
    child_vm_name: &str,
    parent_snapshot_digest: &str,
    grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
) -> Result<()> {
    let token = mvm_core::crypto::vmgenid::fresh_generation_token(parent_snapshot_digest).token;
    let outcome = mvm_vmm::post_restore::signal_post_restore(
        child_vm_name,
        &mvm_vmm::post_restore::VsockPostRestoreSignal::for_resumed_child(token, grant_envelope),
        mvm_vmm::post_restore::POST_RESTORE_CLAIM_READY_TIMEOUT,
    )
    .with_context(|| format!("sending PostRestore to '{child_vm_name}'"))?;
    anyhow::ensure!(
        outcome.acknowledged,
        "guest did not acknowledge PostRestore"
    );
    anyhow::ensure!(
        outcome.reseeded,
        "refusing the fork: {}",
        mvm_agentd::vsock::describe_missing_reseed(
            outcome.reseed_shortfall,
            outcome.detail.as_deref()
        )
    );
    anyhow::ensure!(
        outcome.clock_resynced,
        "guest acknowledged PostRestore without resynchronizing its wall clock"
    );
    Ok(())
}

fn deliver_fc_fork_post_restore(
    child_vm_name: &str,
    parent_snapshot_digest: &str,
    grant_env: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
) -> Result<()> {
    let vm_dir = mvm_client::checkpoint::resolve_running_vm_dir(child_vm_name)
        .with_context(|| format!("resolving VM dir for '{child_vm_name}'"))?;
    let vsock_path_str = mvm_client::checkpoint::firecracker_vsock_uds_path(&vm_dir);
    const POLL_ATTEMPTS: u32 = 40; // 20 seconds max
    for _ in 0..POLL_ATTEMPTS {
        if mvm_agentd::vsock::ping_at(&vsock_path_str).unwrap_or(false) {
            let token =
                mvm_core::crypto::vmgenid::fresh_generation_token(parent_snapshot_digest).token;
            let host_epoch_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("reading host wall clock for fork PostRestore")?
                .as_secs();
            let reply = mvm_agentd::vsock::post_restore_with_grant_and_clock_at(
                &vsock_path_str,
                token,
                grant_env,
                Some(host_epoch_secs),
            )
            .with_context(|| format!("sending PostRestore to '{child_vm_name}'"))?;
            require_fork_post_restore_success(reply)?;
            tracing::info!(
                "FC fork post-restore identity rotation acknowledged for '{}'",
                child_vm_name
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    anyhow::bail!("guest agent not reachable for '{child_vm_name}' after fork restore")
}

fn require_fork_post_restore_success(reply: mvm_agentd::vsock::PostRestoreReply) -> Result<()> {
    anyhow::ensure!(reply.acknowledged, "guest did not acknowledge PostRestore");
    anyhow::ensure!(
        reply.reseeded,
        "refusing the fork: {}",
        mvm_agentd::vsock::describe_missing_reseed(reply.reseed_shortfall, reply.detail.as_deref())
    );
    anyhow::ensure!(
        reply.clock_resynced,
        "guest acknowledged PostRestore without resynchronizing its wall clock"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_contract::ir::AuthType;
    use mvm_contract::plan::{SecretBinding, SecretSource};
    use mvm_contract::protocol::vm_backend::BackendKind;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta, ROOTFS_BLOB};
    use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};

    struct TestAdmitted {
        plan: mvm_core::plan::ExecutionPlan,
    }

    impl TestAdmitted {
        fn plan(&self) -> &mvm_core::plan::ExecutionPlan {
            &self.plan
        }
    }

    struct TestAdmission {
        admitted: TestAdmitted,
    }

    struct AdmittedForkChild {
        admission: TestAdmission,
    }

    struct AdmitForkedChildParams<'a> {
        store: &'a CheckpointStore,
        checkpoint: &'a CheckpointId,
        parent_meta: &'a CheckpointMeta,
        child_vm_name: &'a str,
        backend_kind: BackendKind,
        declared_secrets: &'a [SecretBinding],
        allow_secret_drop: bool,
        intent: ForkIntent,
    }

    fn admit_forked_child(p: &AdmitForkedChildParams<'_>) -> Result<AdmittedForkChild> {
        let _ = (p.parent_meta, p.backend_kind);
        let intent = match p.intent {
            ForkIntent::Ordinary => mvm_client::checkpoint::vm_full::VmFullForkIntent::Ordinary,
            ForkIntent::Replay => mvm_client::checkpoint::vm_full::VmFullForkIntent::Replay,
        };
        let prepared = mvm_client::checkpoint::vm_full::prepare_vm_full_fork(
            p.store,
            mvm_client::checkpoint::vm_full::VmFullForkRequest {
                checkpoint: p.checkpoint,
                child_id: CheckpointId::new(format!("test-{}", p.child_vm_name)),
                child_name: p.child_vm_name.to_string(),
                destination: p.store.root().join(format!("vm-{}", p.child_vm_name)),
                created_unix: 2,
                declared_secrets: p.declared_secrets,
                allow_secret_drop: p.allow_secret_drop,
                intent,
                fallback_network_mode: mvm_contract::plan::NetworkMode::HostVsockProxy,
            },
        )?;
        Ok(AdmittedForkChild {
            admission: TestAdmission {
                admitted: TestAdmitted {
                    plan: prepared.admitted_plan().clone(),
                },
            },
        })
    }

    fn inherited_runtime_config(
        binding: Option<&mvm_core::protocol::runtime_release::RuntimeLaunchBinding>,
        rootfs: &std::path::Path,
    ) -> Option<mvm_core::vm_backend::VmStartConfig> {
        binding.map(|binding| {
            let mut config = mvm_core::vm_backend::VmStartConfig::default();
            binding.apply_to_config(&mut config);
            config.rootfs_path = rootfs.display().to_string();
            config
        })
    }

    fn replay_source_permits_exec(
        source: &mvm_core::plan::ExecutionPlan,
        recorded_plan_id: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            source.plan_id.0 == recorded_plan_id,
            "replay source plan differs from signed checkpoint creation"
        );
        anyhow::ensure!(
            source.agent_verbs.is_none(),
            "replay source has attenuated agent verbs"
        );
        Ok(())
    }

    fn fork_admission_rootfs(
        store: &CheckpointStore,
        parent: &CheckpointMeta,
        scratch: &std::path::Path,
    ) -> Result<(std::path::PathBuf, String)> {
        let rootfs =
            mvm_client::checkpoint::materialized_source(store, parent, ROOTFS_BLOB, scratch)?;
        let digest = mvm_client::checkpoint::materialized_blob_sha256(store, parent, ROOTFS_BLOB)?;
        Ok((rootfs, digest))
    }

    #[test]
    fn inherited_legacy_runtime_uses_the_verified_materialized_rootfs() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = mvm_runtime::signed_legacy_runtime_fixture(home.path(), home.path(), false);
        let rootfs = home.path().join("child.ext4");
        std::fs::copy(&config.rootfs_path, &rootfs).unwrap();
        let binding = mvm_core::protocol::runtime_release::RuntimeLaunchBinding::LegacyBundle {
            proof: config.legacy_bundle_runtime.clone().unwrap(),
            rootfs_path: config.rootfs_path.clone().into(),
            initramfs_path: config.initrd_path.as_ref().map(std::path::PathBuf::from),
        };
        std::fs::remove_file(&config.rootfs_path).unwrap();
        let inherited = inherited_runtime_config(Some(&binding), &rootfs).unwrap();
        assert_eq!(inherited.rootfs_path, rootfs.display().to_string());
        assert!(inherited.runtime_overlay_path.is_none());
        assert!(inherited.runtime_overlay_version.is_none());
        assert!(inherited.runtime_release_proof.is_none());
        assert!(!inherited.unsigned_runtime_development);
        mvm_runtime::runtime_evidence::verify_runtime_for_launch(
            &inherited,
            mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        )
        .unwrap();
        std::fs::write(&rootfs, b"changed child").unwrap();
        assert!(
            mvm_runtime::runtime_evidence::verify_runtime_for_launch(
                &inherited,
                mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
            )
            .is_err()
        );
    }

    #[test]
    fn a_restored_child_records_its_own_rootfs_and_overlay() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let child = "restored-meta-child";
        let child_dir = vm_state_dir(child);
        std::fs::create_dir_all(&child_dir).expect("child dir");
        let rootfs = child_dir.join(ROOTFS_BLOB);
        std::fs::write(&rootfs, b"rootfs").expect("rootfs");
        // The anchors the checkpoint carried: the parent's paths, which the
        // child's restored VMM keeps naming.
        let inherited = mvm_core::checkpoint::DeviceAnchors {
            rootfs: "/parent/rootfs.ext4".into(),
            rootfs_verity: None,
            config: Some("/parent/vm/config.ext4".into()),
            secrets: None,
            identity: None,
            vsock: "/parent/vm/runtime/v.sock".into(),
        };
        std::fs::write(
            child_dir.join(mvm_core::checkpoint::DEVICE_ANCHORS_BLOB),
            serde_json::to_vec(&inherited).expect("anchors json"),
        )
        .expect("anchors");
        let mut parent = CheckpointMeta::builder(
            CheckpointId::new("parent-meta"),
            CheckpointClass::VmFull,
            "source-meta",
        )
        .build();
        parent.runtime_overlay_version = Some("overlay-v1".into());

        record_fork_runtime_meta(child, &parent).expect("record child metadata");
        let saved = mvm_runtime::vm::runtime_meta::read(child)
            .expect("read child metadata")
            .expect("present");
        assert_eq!(saved.rootfs_path.as_deref(), rootfs.to_str());
        assert_eq!(saved.runtime_overlay_version.as_deref(), Some("overlay-v1"));
        assert_eq!(
            saved.mode,
            mvm_runtime::vm::runtime_meta::StartModeKind::Detached
        );
        assert!(saved.accessible, "no sidecar reads as accessible");
        assert_eq!(saved.restored_device_anchors, Some(inherited));
    }

    /// A checkpoint carries the image's `mvm-meta.json` beside the rootfs it
    /// restores, so a child of a sealed image records itself sealed and the
    /// console gate refuses it, as it refuses the parent.
    #[test]
    fn a_restored_child_of_a_sealed_image_records_itself_sealed() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let child = "restored-sealed-child";
        let child_dir = vm_state_dir(child);
        std::fs::create_dir_all(&child_dir).expect("child dir");
        std::fs::write(child_dir.join(ROOTFS_BLOB), b"rootfs").expect("rootfs");
        std::fs::write(
            child_dir.join(mvm_core::guest_sidecar::SIDECAR_FILENAME),
            br#"{"accessible": false}"#,
        )
        .expect("sidecar");
        let parent = CheckpointMeta::builder(
            CheckpointId::new("parent-meta"),
            CheckpointClass::VmFull,
            "source-meta",
        )
        .build();

        record_fork_runtime_meta(child, &parent).expect("record child metadata");
        let saved = mvm_runtime::vm::runtime_meta::read(child)
            .expect("read child metadata")
            .expect("present");
        assert!(!saved.accessible);
        assert!(crate::commands::vm::console::enforce_accessible_gate(child, false).is_err());
    }

    #[test]
    fn a_restored_child_without_a_rootfs_records_no_metadata() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let parent = CheckpointMeta::builder(
            CheckpointId::new("parent-meta"),
            CheckpointClass::VmFull,
            "source-meta",
        )
        .build();
        assert!(record_fork_runtime_meta("missing-child", &parent).is_err());
        assert!(
            mvm_runtime::vm::runtime_meta::read("missing-child")
                .expect("read metadata")
                .is_none()
        );
    }

    #[test]
    fn replay_only_permits_the_audited_unrestricted_source() {
        let mut source = mvm_core::plan::test_support::PlanFixture::new().build();
        source.plan_id = mvm_core::plan::compute_plan_id(&source);
        let recorded = source.plan_id.0.clone();
        assert!(replay_source_permits_exec(&source, &recorded).is_ok());
        assert!(replay_source_permits_exec(&source, "sha256:other").is_err());

        source.agent_verbs = Some(Vec::new());
        source.plan_id = mvm_core::plan::compute_plan_id(&source);
        assert!(replay_source_permits_exec(&source, &source.plan_id.0).is_err());
    }

    fn chunked_parent(store: &CheckpointStore, source: &std::path::Path) -> CheckpointMeta {
        std::fs::write(source, b"chunked rootfs bytes").unwrap();
        mvm_runtime::checkpoint::capture_fs_quick(
            store,
            mvm_runtime::checkpoint::CaptureFsQuickParams {
                id: CheckpointId::new("chunked-parent"),
                vm_name: "parent-vm".into(),
                rootfs: source.to_path_buf(),
                supervisor_config_digest: "digest".into(),
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
                key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
            },
        )
        .unwrap()
    }

    #[test]
    fn fork_admission_reads_and_binds_chunked_rootfs_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = chunked_parent(&store, &tmp.path().join(ROOTFS_BLOB));
        assert!(!store.content_dir(&parent.id).join(ROOTFS_BLOB).exists());
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        let (rootfs, digest) = fork_admission_rootfs(&store, &parent, &scratch).unwrap();
        assert_eq!(std::fs::read(&rootfs).unwrap(), b"chunked rootfs bytes");
        assert_eq!(
            mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap(),
            digest
        );
    }

    #[test]
    fn fork_admission_refuses_tampered_chunk_index() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = chunked_parent(&store, &tmp.path().join(ROOTFS_BLOB));
        std::fs::write(
            store
                .content_dir(&parent.id)
                .join("rootfs.ext4.chunks.json"),
            b"tampered",
        )
        .unwrap();
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        assert!(fork_admission_rootfs(&store, &parent, &scratch).is_err());
    }

    struct CapturedParent(std::path::PathBuf);

    impl mvm_vmm::checkpoint::VmFullControl for CapturedParent {
        fn pause(&self) -> Result<()> {
            Ok(())
        }
        fn resume(&self) -> Result<()> {
            Ok(())
        }
        fn rootfs_path(&self) -> Result<std::path::PathBuf> {
            Ok(self.0.clone())
        }
        fn save_memory(&self, memory: &std::path::Path) -> Result<()> {
            std::fs::write(memory, b"mock parent memory")?;
            std::fs::write(
                memory.with_file_name(mvm_core::checkpoint::HVF_FRAME_BLOB),
                b"mock HVF frame",
            )?;
            Ok(())
        }
        fn runtime_artifacts(&self) -> Result<mvm_vmm::runtime_artifacts::RuntimeArtifacts> {
            Ok(mvm_vmm::runtime_artifacts::RuntimeArtifacts {
                kernel: None,
                initramfs: None,
                disks: vec![mvm_vmm::runtime_artifacts::RuntimeArtifact {
                    path: self.0.clone(),
                    sha256: mvm_core::crypto::image_verify::sha256_file(&self.0)?,
                }],
                kernel_cmdline: String::new(),
                firecracker_drives: None,
            })
        }
        fn extra_content(
            &self,
            directory: &std::path::Path,
        ) -> Result<Vec<mvm_core::checkpoint::ContentBlob>> {
            let name = mvm_core::checkpoint::HVF_FRAME_BLOB;
            Ok(vec![mvm_core::checkpoint::ContentBlob {
                name: name.into(),
                sha256: mvm_core::crypto::image_verify::sha256_file(&directory.join(name))?,
            }])
        }
        fn device_anchors(&self) -> Result<mvm_core::checkpoint::DeviceAnchors> {
            Ok(mvm_core::checkpoint::DeviceAnchors {
                rootfs: self.0.clone(),
                rootfs_verity: None,
                config: None,
                secrets: None,
                identity: None,
                vsock: self.0.with_extension("sock"),
            })
        }
    }

    /// Drive the real capture and signed audit paths with an explicit mock HVF
    /// observation. Admission must verify both the rootfs and the audit anchor.
    fn parent_with_grants(
        store: &CheckpointStore,
        id: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> CheckpointMeta {
        let source = tempfile::tempdir().unwrap();
        let rootfs = source.path().join(ROOTFS_BLOB);
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();
        let params = mvm_runtime::checkpoint::CaptureVmFullParams::builder()
            .id(CheckpointId::new(id))
            .vm_name("parent-vm".into())
            .supervisor_config_digest("d".into())
            .created_unix(1)
            .retain_paused(false)
            .grants(grants)
            .build()
            .unwrap();
        let meta = mvm_runtime::checkpoint::capture_vm_full(store, params, &CapturedParent(rootfs))
            .unwrap();
        let signer = mvm_client::host_keypair::load_or_init().unwrap();
        let emitter = mvm_client::audit::chain::emitter::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-fork-parent")
            .build();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        meta
    }

    fn admitted_child_secrets(declared: &[SecretBinding], vm: &str) -> Vec<SecretBinding> {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let id = format!("ck-{vm}");
        // `parent_with_grants` is the helper that survived on main; the
        // binding-store seeding below is what the enforcement tests need, so
        // this keeps both rather than choosing one.
        let parent_meta = parent_with_grants(&store, &id, None);
        let binding_store = FileBindingStore::default_location().unwrap();
        for binding in declared {
            let SecretSource::Keystore { address } = &binding.source else {
                continue;
            };
            binding_store
                .put(
                    "local",
                    address,
                    &SecretBindingMeta {
                        auth_type: AuthType::Bearer,
                        allowed_hosts: vec!["api.example.com".into()],
                        sigv4: None,
                        inject: Default::default(),
                        provider: None,
                        approve: Default::default(),
                        oauth: None,
                    },
                )
                .unwrap();
        }
        let admitted = admit_forked_child(&AdmitForkedChildParams {
            store: &store,
            checkpoint: &CheckpointId::new(&id),
            parent_meta: &parent_meta,
            child_vm_name: vm,
            backend_kind: BackendKind::Hvf,
            declared_secrets: declared,
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        })
        .expect("a fork child is admitted");
        admitted.admission.admitted.plan().secrets.clone()
    }

    /// The declared set reaches the child's own signed plan. Declared, not
    /// inherited: the parent above holds no bindings, so anything present here
    /// came from the caller.
    #[test]
    fn a_declared_binding_lands_in_the_forked_childs_plan() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());

        let declared = vec![SecretBinding {
            name: "STRIPE_KEY".to_string(),
            source: SecretSource::Keystore {
                address: "stripe".to_string(),
            },
            destinations: Vec::new(),
            approval_required: false,
        }];
        let got = admitted_child_secrets(&declared, "child-declared");
        assert_eq!(got, declared);
    }

    /// The default is unchanged behaviour: declare nothing, carry nothing. This
    /// is the half that keeps the parent's set from leaking in by accident.
    #[test]
    fn a_fork_declaring_nothing_admits_a_child_with_no_bindings() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());

        assert!(admitted_child_secrets(&[], "child-bare").is_empty());
    }

    /// A parent that bounded its CPU can still be forked.
    ///
    /// The child inherits the parent's grants and is admitted prod-profile, so
    /// the grant gate refuses anything it cannot name a mechanism for. Passing
    /// no backend made that refusal unconditional: every such parent became
    /// unforkable, with an error naming the missing backend rather than the
    /// grant. The tier is known here — each arm is one backend — so the gate
    /// measures against it.
    ///
    /// The companion `a_share_the_tier_cannot_serve_is_still_refused` covers
    /// the other direction, so this pair says "admitted where a mechanism
    /// exists, refused where it does not" rather than either alone.
    #[test]
    fn a_parent_that_bounded_cpu_can_still_be_forked() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let launcher = home.path().join("systemd-run");
        std::fs::write(&launcher, b"").unwrap();
        env.set("PATH", home.path());
        env.set("DBUS_SESSION_BUS_ADDRESS", "unix:path=/unused-test-bus");

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let id = "ck-cpu-bounded";
        let parent_meta = parent_with_grants(
            &store,
            id,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
                ..Default::default()
            }),
        );

        let admitted = admit_forked_child(&AdmitForkedChildParams {
            store: &store,
            checkpoint: &CheckpointId::new(id),
            parent_meta: &parent_meta,
            child_vm_name: "child-cpu-bounded",
            backend_kind: BackendKind::Hvf,
            declared_secrets: &[],
            // Strict default: these cases do not exercise attenuation.
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        });
        if !cfg!(target_os = "macos") {
            let error = admitted
                .err()
                .expect("HVF CPU metering is unavailable here");
            assert!(format!("{error:#}").contains("hvf"));
            return;
        }
        let admitted = admitted.expect("a cpu-bounded HVF parent is forkable on macOS");

        let plan = admitted.admission.admitted.plan();
        assert_eq!(
            plan.grants.as_ref().and_then(|g| g.cpu),
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
            "the inherited grant rides in the child's signed plan"
        );
    }

    /// The other half: passing the backend did not weaken the gate. A share the
    /// tier genuinely cannot serve is still refused — and now the refusal names
    /// the tier and its limit, instead of reporting a missing backend.
    ///
    /// 1000 millicores is hvf's ceiling, so 1500 is unenforceable there. That is
    /// a property of the tier, not of forking: the same grant is refused on the
    /// same tier however the run was started.
    #[test]
    fn a_share_the_tier_cannot_serve_is_still_refused() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let id = "ck-cpu-unenforceable";
        let parent_meta = parent_with_grants(
            &store,
            id,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
                ..Default::default()
            }),
        );

        let err = match admit_forked_child(&AdmitForkedChildParams {
            store: &store,
            checkpoint: &CheckpointId::new(id),
            parent_meta: &parent_meta,
            child_vm_name: "child-cpu-unenforceable",
            backend_kind: BackendKind::Hvf,
            declared_secrets: &[],
            // Strict default: these cases do not exercise attenuation.
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        }) {
            // `AdmittedForkChild` carries the child's plan JSON and is
            // deliberately not `Debug`, so this cannot use `expect_err`.
            Ok(_) => panic!("a share above the tier's ceiling must be refused"),
            Err(e) => e,
        };

        let msg = format!("{err:#}");
        assert!(msg.contains("hvf"), "the refusal names the tier: {msg}");
        assert!(
            msg.contains("cpu.share"),
            "the refusal names the grant: {msg}"
        );
        assert!(
            !msg.contains("without the backend"),
            "the refusal must not be the no-backend arm any more: {msg}"
        );
    }

    /// The plan records the tier the gate measured against. Two values derived
    /// from one typed kind cannot drift into disagreeing about what boots.
    #[test]
    fn the_childs_plan_names_the_backend_the_gate_measured() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let id = "ck-tier-agrees";
        let parent_meta = parent_with_grants(&store, id, None);

        let admitted = admit_forked_child(&AdmitForkedChildParams {
            store: &store,
            checkpoint: &CheckpointId::new(id),
            parent_meta: &parent_meta,
            child_vm_name: "child-tier-agrees",
            backend_kind: BackendKind::Hvf,
            declared_secrets: &[],
            // Strict default: these cases do not exercise attenuation.
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        })
        .expect("a grantless parent is forkable");

        let plan = admitted.admission.admitted.plan();
        // The gate refuses outright when the plan's recorded tier disagrees
        // with the one it measures against, so these being one value is what
        // keeps a fork admissible at all.
        assert_eq!(plan.runtime_profile.0, BackendKind::Hvf.as_str());
    }

    #[test]
    fn fork_post_restore_requires_acknowledgement_and_reseed() {
        use mvm_agentd::vsock::{PostRestoreReply, ReseedShortfall};
        let proven = PostRestoreReply {
            acknowledged: true,
            reseeded: true,
            clock_resynced: true,
            detail: None,
            reseed_shortfall: None,
        };
        assert!(require_fork_post_restore_success(proven.clone()).is_ok());

        let helper_missing = PostRestoreReply {
            reseeded: false,
            detail: Some("restore reseed unavailable: no helper".into()),
            reseed_shortfall: Some(ReseedShortfall::HelperMissing),
            ..proven.clone()
        };
        let err = require_fork_post_restore_success(helper_missing).unwrap_err();
        assert!(
            err.to_string().contains("rebuild the image") && err.to_string().contains("no helper"),
            "{err}"
        );

        let not_acknowledged = PostRestoreReply {
            acknowledged: false,
            reseeded: false,
            clock_resynced: false,
            ..proven.clone()
        };
        let err = require_fork_post_restore_success(not_acknowledged).unwrap_err();
        assert!(err.to_string().contains("did not acknowledge"));

        let not_clock_resynced = PostRestoreReply {
            clock_resynced: false,
            ..proven
        };
        let err = require_fork_post_restore_success(not_clock_resynced).unwrap_err();
        assert!(err.to_string().contains("wall clock"));
    }

    /// Passing --cpus to a vm_full fork is refused with a clear error message
    /// that explains the memory-restore constraint and names the fs_quick
    /// alternative.
    #[test]
    fn a_host_budget_refusal_is_audited_under_the_tail_stage() {
        let refused = anyhow::anyhow!("boot would exceed this host's budget")
            .context(mvm_client::admission::HostBudgetRefused);
        assert_eq!(
            fork_failure_stage("fork-vm-full-hvf", &refused),
            "host-budget"
        );
        let other = anyhow::anyhow!("restore failed");
        assert_eq!(
            fork_failure_stage("fork-vm-full-hvf", &other),
            "fork-vm-full-hvf"
        );
    }

    #[test]
    fn vm_full_fork_refuses_cpus_override() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_vm_full_arm_inner(ForkVmFullArmParams {
            store: &CheckpointStore::at(tmp.path()),
            checkpoint: &CheckpointId::new("ck-unused"),
            new_id: None,
            cpus_override: Some(8),
            memory_override: None,
            json: false,
            declared_secrets: &[],
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--cpus"), "error must name --cpus: {msg}");
        assert!(
            msg.contains("fs_quick") || msg.contains("fs-quick"),
            "error must name the fs_quick alternative: {msg}"
        );
    }

    /// Passing --memory to a vm_full fork is refused with a clear error message.
    #[test]
    fn vm_full_fork_refuses_memory_override() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_vm_full_arm_inner(ForkVmFullArmParams {
            store: &CheckpointStore::at(tmp.path()),
            checkpoint: &CheckpointId::new("ck-unused"),
            new_id: None,
            cpus_override: None,
            memory_override: Some("2G"),
            json: false,
            declared_secrets: &[],
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--memory"), "error must name --memory: {msg}");
        assert!(
            msg.contains("fs_quick") || msg.contains("fs-quick"),
            "error must name the fs_quick alternative: {msg}"
        );
    }

    fn fork_child_of(
        store: &CheckpointStore,
        id: &str,
        parent_meta: &CheckpointMeta,
        child: &str,
    ) -> Result<AdmittedForkChild> {
        admit_forked_child(&AdmitForkedChildParams {
            store,
            checkpoint: &CheckpointId::new(id),
            parent_meta,
            child_vm_name: child,
            backend_kind: BackendKind::Hvf,
            declared_secrets: &[],
            allow_secret_drop: false,
            intent: ForkIntent::Ordinary,
        })
    }

    /// A child of a parent that booted a bundle is admitted under that bundle,
    /// so the bundle is re-verified at the child's admission. Here it has been
    /// uninstalled since the parent booted, and the child is refused rather
    /// than booting unpinned; a parent whose plan names no bundle forks as
    /// before.
    #[test]
    fn a_fork_of_a_bundle_booted_parent_re_verifies_the_parents_bundle() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let id = "ck-bundle-parent";
        let parent_meta = parent_with_grants(&store, id, None);

        // The parent's plan, as its boot persisted it.
        let unpinned = fork_child_of(&store, id, &parent_meta, "plain-child")
            .expect("a parent with no plan forks unpinned");
        let mut parent_plan = unpinned.admission.admitted.plan().clone();
        assert!(parent_plan.bundle.is_none());
        mvm_client::audit::chain::plan_persist::write_plan(&parent_meta.vm_name, &parent_plan)
            .unwrap();
        fork_child_of(&store, id, &parent_meta, "plain-child-2")
            .expect("a parent whose plan names no bundle forks as before");

        let bundle_sha256 = "ab".repeat(32);
        parent_plan.bundle = Some(mvm_core::plan::bundle::PlanArtifact::new(
            bundle_sha256.clone(),
            &[0; 64],
            mvm_core::plan::bundle::KeyId("publisher".into()),
        ));
        mvm_client::audit::chain::plan_persist::write_plan(&parent_meta.vm_name, &parent_plan)
            .unwrap();

        let err = match fork_child_of(&store, id, &parent_meta, "bundle-child") {
            Ok(_) => panic!("a child of an uninstalled bundle must not be admitted"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("reading bundle archive"), "{err}");
        assert!(err.contains(&bundle_sha256), "{err}");
    }
}
