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
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::checkpoint::{CheckpointId, VmFullOrigin, vm_full_origin};
use mvm_core::config::vm_state_dir;
use mvm_runtime::checkpoint::{CheckpointStore, ForkParams, ForkParentLiveness, fork_vm_full};

use super::{
    CheckpointForkJson, SignedChainAnchor, bind_checkpoint_forked, grant_predecessor_from_vm_name,
    now_unix, parent_agent_verb_override, read_grant_envelope_for,
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
}

/// vm_full fork: clone the captured triple into a new child identity, admit a
/// fresh claim-8 plan for the child (using the parent's saved cpu/mem — the
/// restore shape is fixed), rewrite the supervisor config, and boot the child
/// in restore mode. The child's admitted plan is distinct from the parent's.
pub(in crate::commands) fn fork_vm_full_arm(
    p: ForkVmFullArmParams<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
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
}

/// FC vm_full fork: clone the captured triple, admit a fresh claim-8 plan for
/// the child, rename `memory.bin` → `mem.bin`, and boot the child via a fresh
/// Firecracker VMM loaded from the checkpoint snapshot.
///
/// The parent may be running: a workload Firecracker carries no NIC (egress
/// rides per-VM vsock proxies keyed by VM name), so a forked child has no
/// host network identity to collide with. The snapshot's recorded device
/// paths — the vsock UDS above all — are remapped onto the child's own state
/// dir in a private mount namespace before the child VMM starts, and the
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

    let AdmittedForkChild {
        admission,
        child_plan_json,
        child_tenant_id,
    } = admit_forked_child(&AdmitForkedChildParams {
        store: p.store,
        checkpoint: p.checkpoint,
        parent_meta: &p.parent_meta,
        child_vm_name: &p.child_vm_name,
        backend_kind: BackendKind::Firecracker,
        declared_secrets: p.declared_secrets,
        allow_secret_drop: p.allow_secret_drop,
    })?;

    // Verify the parent against the signed audit chain before cloning/restoring.
    let parent_meta = p.store.read_meta(p.checkpoint)?;
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the fork parent")?;
    let fork_result = fork_vm_full(
        p.store,
        ForkParams {
            checkpoint: p.checkpoint.clone(),
            child_id: p.child_id,
            child_vm_name: p.child_vm_name.clone(),
            dest_dir: p.dest_dir,
            created_unix: p.now,
            parent_liveness: ForkParentLiveness::MayBeRunning,
            child_plan_json: Some(child_plan_json),
            child_tenant_id: Some(child_tenant_id),
        },
        &|child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            mvm_runtime::firecracker::FcForkRestorer.restore_fork(
                child.vm_name,
                child.state_dir,
                child.cpu_grant,
            )
        },
        &anchor,
    );
    if let Err(ref e) = fork_result {
        crate::commands::vm::up::emit_failed(&admission, "fork-vm-full-fc", e);
    }
    let meta = fork_result
        .with_context(|| format!("forking FC vm_full checkpoint {:?}", p.checkpoint.as_str()))?;

    bind_checkpoint_forked(
        p.checkpoint,
        &meta,
        &p.child_vm_name,
        p.store,
        p.declared_secrets,
        &crate::commands::vm::tenant_resolution::resolve_tenant(None),
    )?;
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
        parent_meta.meta_digest.as_str(),
        grant_env,
    ) {
        let stop_result = mvm_runtime::microvm::stop_vm(&p.child_vm_name);
        return match stop_result {
            Ok(()) => Err(error.context(format!(
                "stopped forked child '{}' after post-restore hygiene failure",
                p.child_vm_name
            ))),
            Err(stop_error) => Err(error.context(format!(
                "post-restore hygiene failed for '{}' and stopping the child also failed: {}",
                p.child_vm_name, stop_error
            ))),
        };
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

/// Inputs for [`admit_forked_child`].
struct AdmitForkedChildParams<'a> {
    store: &'a CheckpointStore,
    checkpoint: &'a CheckpointId,
    parent_meta: &'a mvm_core::checkpoint::CheckpointMeta,
    child_vm_name: &'a str,
    /// The tier that will boot this child. Typed, not a label: the grant gate
    /// measures against it, and a grant checked against a string is checked
    /// against whatever the caller typed. The plan's `backend_name` is derived
    /// from this, so the two cannot disagree.
    backend_kind: BackendKind,
    /// Secret bindings the caller declares for this child.
    ///
    /// Declared, never inherited: the parent's set is not consulted, so the
    /// child's capability is readable from the child's own plan without
    /// walking the lineage. An empty set is the default and reproduces the
    /// prior behaviour exactly.
    ///
    /// Carries a name and a source reference only. The destination binding
    /// (`auth_type` + `allowed_hosts`) is resolved by name against the
    /// tenant's `BindingStore` at the substitution endpoint, so a name the
    /// operator has not bound grants nothing.
    declared_secrets: &'a [mvm_core::plan::SecretBinding],
    allow_secret_drop: bool,
}

/// The admitted claim-8 envelope a vm_full fork boots its child under.
struct AdmittedForkChild {
    admission: crate::commands::vm::up::AdmissionContext,
    child_plan_json: String,
    child_tenant_id: String,
}

/// Admit a fresh claim-8 plan for a vm_full fork child, and mint its verb-grant
/// sidecar so post-restore delivery can re-pin it.
///
/// The child's plan is its own, never the parent's: a distinct nonce, a distinct
/// VM name, and `deny_all` networking. A restored guest resumes already past its
/// own boot, so it must not inherit an egress capability from the state it came
/// out of — the plan is what re-grants one, and this one grants none.
///
/// cpu/mem come from the host defaults rather than the parent plan on purpose:
/// the real shape is baked into the saved machine state and enforced by the VMM
/// at load time, so these values are claim-8 admission metadata only.
fn admit_forked_child(p: &AdmitForkedChildParams<'_>) -> Result<AdmittedForkChild> {
    let user_cfg = mvm_core::user_config::load(None);
    // The checkpoint's RECORDED rootfs sha, so admission pins the bytes the
    // capture sealed rather than re-hashing a file that could have moved.
    let rootfs_blob = p
        .store
        .content_dir(p.checkpoint)
        .join(mvm_core::checkpoint::ROOTFS_BLOB);
    let recorded_sha = p
        .parent_meta
        .content
        .iter()
        .find(|b| b.name == mvm_core::checkpoint::ROOTFS_BLOB)
        .map(|b| b.sha256.clone());
    let parent_agent_verbs = parent_agent_verb_override(p.checkpoint, p.store);
    let tenant = crate::commands::vm::tenant_resolution::resolve_tenant(None);
    super::validate_fork_secret_policy(
        p.checkpoint,
        p.store,
        &tenant,
        p.declared_secrets,
        p.allow_secret_drop,
    )?;
    let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::new();
    let admission = crate::commands::vm::up::admit_plan_for_boot(
        crate::commands::vm::up::AdmitPlanForBootParams {
            instructions: Default::default(),
            outputs: Vec::new(),
            network_mode: super::parent_network_mode(p.checkpoint, p.store),
            tenant: &tenant,
            vm_name: p.child_vm_name,
            backend_name: p.backend_kind.as_str(),
            configured_images_dir: mvm_build::image_source::configured_images_dir().as_deref(),
            rootfs_path: &rootfs_blob,
            // A fork resumes a saved VM state rather than booting a kernel of
            // its own, so this admission has no kernel to name. Deliberately
            // not the parent's: a child admitted under an environment it did
            // not itself load would record a pin nothing here verified.
            kernel_path: None,
            precomputed_image_sha256: recorded_sha,
            boot_artifact_identity: None,
            cpus: user_cfg.default_cpus,
            mem_mib: user_cfg.default_memory_mib as u64,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            // Derived from the set, never defaulted: `SecretReleasePolicy`
            // defaults to `None` — "no secrets may be released" — so a child
            // admitted with declared bindings under the default would carry a
            // list nothing could ever release.
            secret_release: crate::commands::vm::managed_secrets::secret_release_for_bindings(
                p.declared_secrets,
            ),
            secrets: p.declared_secrets.to_vec(),
            caller_commitment: None,
            ledger: &ledger,
            keys_dir: None,
            audit_dir: None,
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: parent_agent_verbs.clone(),
            // A restored child is never interactive, never carries ad-hoc argv, and
            // is always prod-profile, so it qualifies for the attenuated grant.
            restrict_agent_verbs: !parent_agent_verbs.is_empty()
                || crate::commands::vm::agent_verbs::grant_eligible(false, false, false),
            services: Vec::new(),
            // The child inherits the permission set the parent was captured
            // under. Anything else is refused downstream, and declaring nothing
            // is the widest ask rather than the narrowest — an absent CPU or
            // wall-clock grant means unbounded.
            grants: p.parent_meta.grants.clone(),
            // The tier that will actually boot this child, typed rather than
            // parsed from a label. `None` here made the gate take its
            // fail-closed "no backend object, no answer" arm, and a fork child
            // is admitted prod-profile, so that arm is a refusal: a parent
            // carrying any cpu or wall-clock grant could not be forked at all.
            backend_kind: Some(p.backend_kind),
            entrypoint: crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint::unresolved(
                "a checkpoint fork boots the image the parent booted; this path resolves no entrypoint",
            ),
        },
    )?;

    let child_plan_json = serde_json::to_string(admission.admitted.signed())
        .expect("admitted plan is always serializable");
    let child_tenant_id = admission.admitted.plan().tenant.0.clone();

    let mint_cfg = mvm_core::vm_backend::VmStartConfig {
        name: p.child_vm_name.to_string(),
        plan_json: Some(child_plan_json.clone()),
        ..Default::default()
    };
    mvm_hostd::plan_admission::stash_plan_for_bridge(&mint_cfg)?;

    Ok(AdmittedForkChild {
        admission,
        child_plan_json,
        child_tenant_id,
    })
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
    let AdmittedForkChild {
        admission,
        child_plan_json,
        child_tenant_id,
    } = admit_forked_child(&AdmitForkedChildParams {
        store: p.store,
        checkpoint: p.checkpoint,
        parent_meta: &p.parent_meta,
        child_vm_name: &p.child_vm_name,
        backend_kind: BackendKind::Hvf,
        declared_secrets: p.declared_secrets,
        allow_secret_drop: p.allow_secret_drop,
    })?;

    // Verify the parent against the signed audit chain before cloning anything.
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the fork parent")?;
    let fork_result = fork_vm_full(
        p.store,
        ForkParams {
            checkpoint: p.checkpoint.clone(),
            child_id: p.child_id,
            child_vm_name: p.child_vm_name.clone(),
            dest_dir: p.dest_dir,
            created_unix: p.now,
            parent_liveness: ForkParentLiveness::MayBeRunning,
            child_plan_json: Some(child_plan_json),
            child_tenant_id: Some(child_tenant_id),
        },
        &mvm_runtime::hvf_restore::HvfForkRestorer,
        &anchor,
    );
    if let Err(ref e) = fork_result {
        crate::commands::vm::up::emit_failed(&admission, "fork-vm-full-hvf", e);
    }
    let meta = fork_result
        .with_context(|| format!("forking HVF vm_full checkpoint {:?}", p.checkpoint.as_str()))?;

    bind_checkpoint_forked(
        p.checkpoint,
        &meta,
        &p.child_vm_name,
        p.store,
        p.declared_secrets,
        &crate::commands::vm::tenant_resolution::resolve_tenant(None),
    )?;
    crate::commands::vm::up::emit_launched(&admission, "hvf", true);

    if let Err(error) = deliver_hvf_fork_post_restore(
        &p.child_vm_name,
        p.parent_meta.meta_digest.as_str(),
        read_grant_envelope_for(&p.child_vm_name),
    ) {
        return Err(stop_child_after_post_restore_failure(
            &p.child_vm_name,
            error,
        ));
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

/// A restored child that cannot prove it rotated its identity must not stay up:
/// it is still running with the parent's CSPRNG state. Stop it and report both
/// the original failure and the outcome of the stop.
fn stop_child_after_post_restore_failure(
    child_vm_name: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    match mvm_runtime::backend::AnyBackend::for_started_vm(child_vm_name) {
        Some(backend) => match backend.stop(&mvm_core::vm_backend::VmId(child_vm_name.to_string()))
        {
            Ok(()) => error.context(format!(
                "stopped forked child '{child_vm_name}' after post-restore hygiene failure"
            )),
            Err(stop_error) => error.context(format!(
                "post-restore hygiene failed for '{child_vm_name}' and stopping the child \
                 also failed: {stop_error}"
            )),
        },
        None => error.context(format!(
            "post-restore hygiene failed for '{child_vm_name}' and no backend claims it"
        )),
    }
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
        mvm_vmm::post_restore::POST_RESTORE_READY_TIMEOUT,
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
    let vm_dir = mvm_runtime::microvm::resolve_running_vm_dir(child_vm_name)
        .with_context(|| format!("resolving VM dir for '{child_vm_name}'"))?;
    let vsock_path_str = mvm_runtime::microvm::firecracker_vsock_uds_path(&vm_dir);
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
    use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta, ContentBlob, ROOTFS_BLOB};
    use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};

    /// A parent checkpoint whose recorded rootfs sha matches a real blob on
    /// disk. The blob has to exist: admission *verifies* the recorded digest
    /// against the bytes rather than trusting it, so a fixture that records a
    /// sha without writing the file fails before it reaches the plan.
    fn parent_with_grants(
        store: &CheckpointStore,
        id: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> CheckpointMeta {
        use sha2::{Digest, Sha256};
        let content_dir = store.content_dir(&CheckpointId::new(id));
        std::fs::create_dir_all(&content_dir).unwrap();
        let bytes = b"fixture rootfs";
        std::fs::write(content_dir.join(ROOTFS_BLOB), bytes).unwrap();

        let mut meta =
            CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::VmFull, "parent-vm")
                .content(vec![ContentBlob {
                    name: ROOTFS_BLOB.to_string(),
                    sha256: hex::encode(Sha256::digest(bytes)),
                }])
                .supervisor_config_digest("d")
                .created_unix(1)
                .build();
        meta.grants = grants;
        store.write_meta(&meta).unwrap();
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
                        provider: None,
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

    /// The tier this test must use to mean anything: one that actually meters
    /// CPU on the host running it.
    ///
    /// `ResourceControls::for_backend` answers per host, not per kind alone —
    /// HVF reports `HvfVcpuQuota` only under `cfg!(target_os = "macos")`, and
    /// `CpuControl::None` elsewhere, because there is no in-process vCPU
    /// scheduler to enforce a share on Linux. Firecracker is the mirror image:
    /// `CgroupShare` on Linux, nothing on macOS. Hardcoding either one makes
    /// the test assert the opposite thing on the other platform — which is why
    /// it passed locally on a Mac and failed in Linux CI, where the refusal it
    /// was written to disprove is the correct answer.
    const CPU_METERING_TIER: BackendKind = if cfg!(target_os = "macos") {
        BackendKind::Hvf
    } else {
        BackendKind::Firecracker
    };

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
            backend_kind: CPU_METERING_TIER,
            declared_secrets: &[],
            // Strict default: these cases do not exercise attenuation.
            allow_secret_drop: false,
        })
        .expect("a cpu-bounded parent is forkable on a tier that meters CPU");

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
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--memory"), "error must name --memory: {msg}");
        assert!(
            msg.contains("fs_quick") || msg.contains("fs-quick"),
            "error must name the fs_quick alternative: {msg}"
        );
    }
}
