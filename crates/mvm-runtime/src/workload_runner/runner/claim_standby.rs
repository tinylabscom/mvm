//! Warm claim: fork a clean standby parent into a fresh, admitted child.

use super::*;

impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Fork a clean standby parent into a fresh, admitted child, gated exactly as
    /// strictly as a cold boot — the guarded heart of the warm pool.
    ///
    /// Runs the fail-closed sequence in order, cloning or booting nothing until
    /// every gate passes: reserve the parent atomically and verify its sealed
    /// content + signed-audit lineage; bind the already-admitted plan's image
    /// digest to that verified parent (so the audit-recorded plan describes
    /// exactly what boots); mint a fresh, registry-unique identity; materialize
    /// the child's rootfs from the parent's own verified content; run the
    /// host-side overlay-contract gate, spawn the child's own 0700 substitution
    /// endpoint keyed on its fresh id, resolve its host channel set and register
    /// its host-services broker; then fork the VMM, start following its console
    /// (the only channel that would show a hang or panic inside the handshake
    /// window that follows), and require the restored guest to prove it adopted
    /// a fresh VMGenID before the claim commits, so the child's CSPRNG diverges
    /// from the parent's.
    ///
    /// The host-side plumbing is deliberately all on the near side of the fork.
    /// A cold boot has a kernel boot between wiring its channels and the guest
    /// dialing them; a restore has nothing — the guest comes back already booted
    /// and runs the moment the fork resumes it. Anything wired afterwards would
    /// be wired against a guest already dialing sockets that do not exist.
    ///
    /// Layering the runner does NOT own (enforced at their own layers, mirroring
    /// a cold boot): claim-8 admission of the child plan (CLI mint + supervisor
    /// re-verify at attach), dm-verity inherit (CLI populates the child config),
    /// per-service confinement (guest init, inherited via the post-init parent
    /// snapshot), and the `plan.launched` chain emit (the CLI audit layer, which
    /// owns the host signer). The runner receives the admitted plan and the
    /// verity-populated config in `claim` and consumes them.
    pub fn claim_standby(
        &self,
        ctx: &ClaimContext<'_>,
        handle: &StandbyHandle,
        claim: &StandbyClaim,
    ) -> std::result::Result<VmId, StandbyError> {
        self.claim_standby_owned(ctx, handle, claim)
            .map(|owned| owned.id)
    }

    /// Claim a child while retaining its lifecycle gate through caller custody capture.
    ///
    /// # Errors
    /// Refuses invalid parents, admission failures, and failed child preparation or boot.
    pub fn claim_standby_owned(
        &self,
        ctx: &ClaimContext<'_>,
        handle: &StandbyHandle,
        claim: &StandbyClaim,
    ) -> std::result::Result<crate::backend::OwnedWarmClaim, StandbyError> {
        let _activation_barrier =
            mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()
                .map_err(|error| StandbyError::ClaimFailed(format!("{error:#}")))?;
        if claim
            .start_config
            .as_ref()
            .is_some_and(|config| config.mailbox_conversation.is_some())
        {
            return Err(StandbyError::ClaimFailed(
                "mailbox conversation identity requires a fresh cold boot".into(),
            ));
        }
        if claim
            .start_config
            .as_ref()
            .is_some_and(|config| config.caller_registration.is_some())
        {
            return Err(StandbyError::ClaimFailed(
                "caller registration requires cold launch; caller-authenticated warm handoff is unavailable".into(),
            ));
        }
        use std::io::Write;

        let claim_started = Instant::now();
        let mut claim_debug = mvm_vmm::agent_debug::open();
        macro_rules! claim_phase {
            ($phase:literal) => {
                warm_claim::record_phase(claim_started, &mut claim_debug, $phase);
                mvm_core::launch_trace::lap(concat!("warm_claim.", $phase));
            };
        }
        let resident_handoff = self.driver.supports_resident_handoff();
        // (1) Reserve the parent atomically, then verify it — before any clone.
        // Resident HVF claims use the signed bundle manifest as their O(1)
        // publication witness; saved-state claims retain full content hashing.
        let parent = reserve_and_verify_parent(ctx, handle, resident_handoff)?;
        claim_phase!("parent_verified");

        // The parent is now reserved (`Claimed`) and verified healthy. Arm the
        // release-unless-committed guard: any early return past this point returns
        // the good parent to claimable (so a failed claim never strands warm
        // capacity) and removes a partial child dir. Only a booted child commits.
        let preloaded_child_name = handle.preloaded_child_vm_name.clone();
        // Declared before cleanup so rollback completes before the gate unlocks.
        let lifecycle;
        let mut cleanup = WarmClaimLease::new(ctx.pool, handle.id.as_str(), &self.driver);
        if parent.class != mvm_core::checkpoint::CheckpointClass::VmFull {
            return Err(StandbyError::ClaimFailed(
                "warm memory restore requires a vm_full checkpoint".into(),
            ));
        }
        let runtime_verified = if let Some(name) = &preloaded_child_name {
            verify_preloaded_child_name_is_available(ctx, name)?;
            crate::checkpoint::verify_checkpoint_runtime_at(
                ctx.checkpoints,
                &parent,
                &vm_state_dir(name),
            )
        } else {
            crate::checkpoint::verify_checkpoint_runtime(ctx.checkpoints, &parent)
        };
        let runtime_verified = runtime_verified.map_err(|error| {
            StandbyError::ClaimFailed(format!("verify paused runtime: {error:#}"))
        })?;
        crate::runtime_evidence::verify_runtime_for_claim(
            &runtime_verified,
            claim.start_config.as_ref(),
        )
        .map_err(|error| {
            StandbyError::ClaimFailed(format!("verify inherited runtime: {error:#}"))
        })?;
        mvm_core::launch_trace::lap("warm_claim.runtime_verified");

        // (2) + (4) Bind the admitted plan's image digest to the verified parent.
        // A missing plan or a digest mismatch refuses before any child side effect.
        let plan = claim_plan(claim)?;
        if let Some(child) = &preloaded_child_name {
            require_preloaded_child_admission(child, &plan)?;
        }
        if let Some(identity) = runtime_verified.identity() {
            plan.require_runtime_identity(identity).map_err(|error| {
                StandbyError::ClaimFailed(format!("verify inherited runtime: {error}"))
            })?;
        }
        let parent_image_sha256 =
            materialized_blob_sha256(ctx.checkpoints, &parent, mvm_core::checkpoint::ROOTFS_BLOB)
                .map_err(|_| refuse(ClaimRefusal::ParentTampered))?;
        bind_plan_to_parent_digest(&plan.image.sha256, &parent_image_sha256).map_err(refuse)?;
        // The same comparison a vm_full fork makes, against the same
        // chain-verified parent record and through the same predicate. A warm
        // claim restores a child out of a parent's saved memory exactly as a
        // fork does, so it must not be the one restore path where a child can
        // ask for more than its parent held. Placed beside the image-digest
        // bind — both bind the admitted plan to this verified parent — and
        // before the child gets an identity, a state dir, or any bytes.
        let parent_bound = claim_parent_grant_bound(
            parent.grants.as_ref(),
            handle.vsock_egress,
            plan.grants.as_ref(),
        );
        ensure_child_grants_within_parent(plan.grants.as_ref(), parent_bound.as_ref()).map_err(
            |e| {
                refuse(ClaimRefusal::GrantsExceedParent {
                    reason: e.to_string(),
                })
            },
        )?;
        // The policy this claim installs in the child's endpoint below must be
        // the one the child's own signed plan recorded — never the parent's,
        // which booted with none, and never one supplied beside the plan.
        bind_claim_policy_to_plan(&plan.asset_identities, &claim.network_policy).map_err(refuse)?;
        // A standby parent carries no grant, so the comparison above has
        // nothing to bind a claimed child's CPU share against and would admit
        // any share at all. The host's own ceiling is what bounds it instead —
        // the same operator-configured maximum every cold boot on this host
        // clears, read from host config rather than from the plan being
        // admitted. It is a host-wide maximum and not a pool-specific grant, so
        // it bounds a claim no more tightly than it bounds anything else here;
        // it is only stronger than the unbounded claim it replaces.
        //
        // Deliberately after the parent has been matched and reserved rather
        // than part of the pool's compatibility key: keying on a grant value
        // would split one pool into a pool per distinct share and cost the warm
        // hit rate the pool exists for. The price is a claim that matches and is
        // then refused, so the refusal names the ceiling and the request.
        ensure_child_grants_within_host_ceiling(
            plan.grants.as_ref(),
            &mvm_core::user_config::load(None).grant_ceiling(),
        )
        .map_err(refuse)?;
        mvm_core::launch_trace::lap("warm_claim.plan_and_grant_binds");

        // (6a) Fresh, registry-unique identity for the child.
        let child = match preloaded_child_name.clone() {
            Some(name) => {
                verify_preloaded_child_name_is_available(ctx, &name)?;
                VmId(name)
            }
            None => fresh_child_id(ctx)?,
        };
        lifecycle = match ctx.preloaded_child_lifecycle {
            Some(held) => {
                held.require_name(&child.0).map_err(|error| {
                    StandbyError::ClaimFailed(format!("preloaded child reservation: {error:#}"))
                })?;
                None
            }
            None => Some(
                crate::vm::instance_snapshot::MachineLifecycleLock::acquire(&child.0).map_err(
                    |error| {
                        StandbyError::ClaimFailed(format!(
                            "acquire child lifecycle gate: {error:#}"
                        ))
                    },
                )?,
            ),
        };
        // Selection precedes the gate; recheck under it before touching child state.
        verify_preloaded_child_name_is_available(ctx, &child.0)?;
        let child_dir = vm_state_dir(&child.0);
        // Track it before creating or materializing anything so even a partial
        // claim is cleaned up.
        cleanup.track_child_dir(child_dir.clone());
        if preloaded_child_name.is_some() {
            cleanup.track_preloaded_child(child.0.clone());
        }
        mvm_core::launch_trace::lap("warm_claim.child_identity_and_lock");

        // (3) A resident handoff transfers the already-paused HVF machine and
        // creates only the fresh child state directory. Saved-state backends
        // still materialize the verified parent content before restoring.
        let child_rootfs_dir = if resident_handoff {
            std::fs::create_dir_all(&child_dir).map_err(|e| {
                StandbyError::ClaimFailed(format!(
                    "create resident HVF child state {}: {e:#}",
                    child_dir.display()
                ))
            })?;
            warm_claim::resident_parent_rootfs_dir(handle.id.as_str())?
        } else if preloaded_child_name.is_some() {
            child_dir.clone()
        } else {
            let materialize =
                if is_trusted_snapshot_id(parent.snapshot_id.as_deref().unwrap_or_default()) {
                    let backend = mvm_fs::trusted_snapshot::platform_backend(ctx.snapshots.root())
                        .map_err(|e| {
                            StandbyError::ClaimFailed(format!(
                                "open trusted snapshot backend: {e:#}"
                            ))
                        })?;
                    materialize_child_from_trusted_parent(
                        ctx.checkpoints,
                        backend.as_ref(),
                        ctx.parent_checkpoint,
                        ctx.anchor,
                        &child_dir,
                    )
                } else {
                    materialize_child_from_parent(
                        ctx.checkpoints,
                        ctx.snapshots,
                        ctx.parent_checkpoint,
                        ctx.anchor,
                        &child_dir,
                    )
                };
            materialize.map_err(|e| {
                StandbyError::ClaimFailed(format!("materialize child rootfs: {e:#}"))
            })?;
            claim_phase!("child_materialized");
            child_dir.clone()
        };
        if resident_handoff {
            claim_phase!("resident_handoff_ready");
        }

        // (8) The runner-side host gates a cold boot runs, before the child boots:
        // the overlay contract, then the child's own 0700 substitution endpoint
        // keyed on its fresh id (never a sibling's; the factory parent has none).
        let mut child_cfg = child_start_config(claim, &child, &child_rootfs_dir);
        if let Some(binding) = &parent.runtime_launch_binding {
            // The parent record and these retained bytes were verified above.
            // A restored child inherits the parent's generation, not cache paths.
            binding.apply_to_config(&mut child_cfg);
        }
        // Recorded before the fork, as a cold boot records before it boots, so
        // a step checkpoint of the claimed child resolves its own rootfs and
        // the device paths its restored VMM names. A resident handoff keeps the
        // parent's live machine and has no materialized copy of its own to
        // describe; its record stays with the parent's.
        if !resident_handoff {
            warm_claim::record_claimed_child_runtime_meta(&child, &child_cfg, &child_dir)?;
        }
        // The launch's read-only volumes go behind the late-volume slots the
        // parent booted, and the guest is told to mount them before the claim
        // commits. A launch with none attaches nothing.
        let late_volumes = if child_cfg.volumes.is_empty() {
            Vec::new()
        } else {
            mvm_vmm::host::late_volumes::attachments(&child_cfg, self.driver.late_volume_slots())
                .map_err(|e| StandbyError::ClaimFailed(format!("late volumes: {e:#}")))?
        };
        let late_volume_configs = crate::microvm::activation::build_volume_configs(&child_cfg)
            .map_err(|e| StandbyError::ClaimFailed(format!("late volumes: {e:#}")))?;
        let guards = ClaimGuards::new(&self.spawner);
        // Gate the image the claim was admitted for, not the clone the child
        // boots: the sidecar describes how the image was built and is not part
        // of the captured snapshot, so it exists only beside the image.
        guards
            .admit_overlay_contract(std::path::Path::new(&claim.rootfs_path))
            .map_err(|e| StandbyError::ClaimFailed(format!("overlay contract: {e:#}")))?;

        let grant_envelope = issue_child_grant(&plan, &child_cfg, ctx.grant_issuer)
            .map_err(|e| StandbyError::ClaimFailed(format!("issue child verb grant: {e:#}")))?;

        let secrets =
            mvm_core::plan::secrets_from_signed_json(&claim.plan_json).unwrap_or_default();
        let redaction =
            mvm_core::plan::redaction_from_signed_json(&claim.plan_json).unwrap_or_default();
        let network_limits = plan
            .effective_network_limits()
            .map_err(|e| StandbyError::ClaimFailed(format!("network limits: {e:#}")))?;
        let ingress = plan.ingress.clone();
        if let Some(file) = claim_debug.as_mut() {
            let _ = writeln!(
                file,
                "[warm-claim] inputs allows_egress={} secrets={}",
                claim.network_policy.allows_egress(),
                secrets.len()
            );
        }
        // A saved-state parent's own dir is gone; its identity travelled in
        // the checkpoint and was materialized into the child's dir. A resident
        // parent keeps its dir and has nothing materialized.
        let parent_state_dir = if child_dir
            .join(mvm_vmm::host::flowmux_identity::PUBLIC_IDENTITY_FILE)
            .is_file()
        {
            child_dir.clone()
        } else {
            vm_state_dir(handle.id.as_str())
        };
        if let Some(audit) = &claim.audit_context
            && audit.plan() != Some(&plan)
        {
            return Err(StandbyError::ClaimFailed(
                "workload audit context differs from admitted claim plan".into(),
            ));
        }
        let endpoint = guards
            .spawn_endpoint(
                &child,
                &EndpointSpawnInputs {
                    state_dir: &child_dir,
                    tenant: claim.tenant_id.as_str(),
                    audit: claim.audit_context.as_ref(),
                    secrets: &secrets,
                    redaction: &redaction,
                    network_policy: &claim.network_policy,
                    network_limits,
                    ingress: &ingress,
                    // A warm child must rekey and enroll independently; it
                    // cannot inherit a parent's mailbox ACK authority.
                    reader_plan: None,
                    mailbox_conversation: None,
                    actor: None,
                    // A restored child already holds its parent's signing key
                    // in the memory image it woke from, and there is no way to
                    // put a different one there. Its endpoint pins what the
                    // guest actually has.
                    identity: FlowMuxIdentitySource::InheritFrom(&parent_state_dir),
                },
            )
            .map_err(|e| StandbyError::ClaimFailed(format!("spawn child endpoint: {e:#}")))?;
        claim_phase!("endpoint_ready");

        // The child's host channel set, resolved under its own state dir and
        // mapped through the one mapper a cold boot's set comes from. The fork
        // wires these before it resumes the child; a restored guest is already
        // booted, so it dials the instant its vCPUs run.
        let socks = standing_sockets(&child_dir, &child_cfg);
        let channels = workload_vsock_ports(&socks.with_egress(endpoint.egress_uds()));
        cleanup.track_endpoint(endpoint);

        // Register the child's exact admitted host-service set before the fork,
        // because the restored guest can dial `BROKER_PORT` immediately. Any
        // registration failure refuses the claim; the guard reaps until commit.
        let child_capabilities: Vec<_> = plan
            .extensions
            .iter()
            .flat_map(|extension| extension.capabilities.iter().cloned())
            .collect();
        let child_epoch = super::broker::plan_call_epoch(&plan)
            .map_err(|e| StandbyError::ClaimFailed(format!("child broker epoch: {e:#}")))?;
        let broker_guard = self
            .broker
            .register(&BrokerRegisterRequest {
                vm_name: &child.0,
                state_dir: &child_dir,
                tenant: child_cfg.tenant_id.as_deref(),
                broker_listen_socket: socks.broker.as_deref(),
                services: &plan.services,
                capability_bindings: &child_capabilities,
                service_proxies: &child_cfg.service_proxies,
                epoch: Some(&child_epoch),
            })
            .map_err(|e| StandbyError::ClaimFailed(format!("register child broker: {e:#}")))?;
        cleanup.track_broker(broker_guard);
        claim_phase!("broker_registered");

        // (6b) Mint a fresh VMGenID bound to the child's content-address and fork
        // the VMM. A fork restores a running guest out of the parent's saved
        // memory, so the child comes back holding the parent's CSPRNG state and
        // the parent's wall clock — nothing is scrubbed yet at this point.
        let content_hash =
            materialized_blob_sha256(ctx.checkpoints, &parent, mvm_core::checkpoint::ROOTFS_BLOB)
                .map_err(|_| refuse(ClaimRefusal::ParentTampered))?;
        let genid = fresh_generation_token(content_hash);
        let token = genid.token;
        let runtime_digest = crate::checkpoint::metadata_blob_sha256(
            ctx.checkpoints,
            &parent,
            "runtime-artifacts.json",
        )
        .map_err(|_| refuse(ClaimRefusal::ParentTampered))?;
        let anchors_digest = crate::checkpoint::metadata_blob_sha256(
            ctx.checkpoints,
            &parent,
            "device-anchors.json",
        )
        .map_err(|_| refuse(ClaimRefusal::ParentTampered))?;
        let fork_request = ChildForkRequest {
            child_vm_name: &child.0,
            child_dir: &child_dir,
            runtime_artifacts_sha256: Some(&runtime_digest),
            device_anchors_sha256: Some(&anchors_digest),
            // A resident HVF claim addresses the paused parent by its stable
            // pool identity. Saved-state drivers receive no parent name and
            // restore from the materialized child directory instead.
            parent_vm_name: resident_handoff.then_some(handle.id.as_str()),
            genid,
            channels: &channels,
            // Straight off the admitted plan — the value the subset comparison
            // above cleared. Taking it from `child_cfg` instead would take it
            // from a start config the claim supplied, which is not what was
            // checked.
            cpu_grant: plan.grants.as_ref().and_then(|grants| grants.cpu),
            // The same admitted plan `claim_plan` decoded the bindings above
            // from, so the bounds the child's owner arms are the ones checked.
            admitted_plan: Some(&claim.plan_json),
            late_volumes: &late_volumes,
        };
        // The restored guest runs the moment the fork resumes it, so this is
        // the warm counterpart of activation: everything above prepared the
        // child on the host beside the admission's audit sync, and nothing the
        // plan authorizes may run until that sync has succeeded. A failure
        // here unwinds through `cleanup` with no child VMM to stop.
        claim
            .start_config
            .as_ref()
            .map_or(Ok(()), VmStartConfig::wait_for_admission_durability)
            .map_err(|error| StandbyError::ClaimFailed(format!("{error:#}")))?;
        claim_phase!("admission_durability");
        let forked = if preloaded_child_name.is_some() {
            self.driver.resume_preloaded_child(&fork_request)
        } else {
            self.driver.fork_standby_child(&fork_request)
        };
        if let Err(StandbyError::Unrestorable(reason)) = &forked {
            tracing::warn!(
                parent = %handle.id,
                %reason,
                "dropping a standby parent this host cannot restore"
            );
            cleanup.quarantine();
        }
        if let Err(error) = forked {
            // A driver can fail after it has created a child VMM. Do not
            // release its parent's reservation and remove its state dir while
            // that child might still be running.
            if let Err(stop) = self.driver.attach(&child).and_then(|vm| vm.kill()) {
                cleanup.retain_uncertain_child();
                return Err(StandbyError::StopUnconfirmed(format!(
                    "fork failed ({error}); stopping child {} failed: {stop:#}",
                    child.0
                )));
            }
            return Err(error);
        }
        if preloaded_child_name.is_some() {
            claim_phase!("preloaded_resumed");
        } else {
            claim_phase!("child_forked");
        }

        // Unconditional and best-effort, mirroring `start_workload`: started
        // the moment the restored guest is live, before the fallible
        // post-restore handshake below. A cold boot has a kernel boot to
        // blame a silent hang on; a fork has none — the guest is already
        // running the instant the fork resumes it — so the handshake window
        // this call precedes is the one place a restore can wedge or panic
        // with nothing else to show why.
        self.console_streamer.start(&ConsoleCapture {
            vm_name: &child.0,
            supervisor_owned: supervisor_owns_console(self.driver.kind()),
            console_log: &socks.console_log,
            display_socket: socks.display.as_deref(),
            redaction: &redaction,
            retention: plan_stream_retention(child_cfg.plan_json.as_deref()),
        });

        // (7) Close that window before the claim commits: deliver the token to
        // the now-reachable guest and make it prove, on its own report, that it
        // rotated its generation identity and took the host's clock. Two children
        // of one parent that skipped this would draw identical randomness, which
        // is the whole reason a warm child needs a fresh identity — so a child
        // that cannot prove it is never admitted.
        //
        // The same answer admits the child's seccomp tier. The parent booted
        // with no plan and so holds none; the tier comes from the plan this
        // claim was admitted under, and the guest must report holding exactly
        // that tier before the claim commits and any workload process starts.
        let identity = ChildIdentity {
            token,
            grant_envelope,
            seccomp_tier: Some(admitted_seccomp_tier(&plan)),
            volumes: late_volume_configs,
        };
        if let Err(refusal) = self.take_fresh_child_identity(&child.0, identity) {
            // The child is live and still carrying its parent's random state.
            // Unwinding alone would leave running exactly the VM this refusal
            // exists to prevent, so stop it before returning. `force_stop`
            // only tears down the VMM, not the console follower this claim
            // started above and `VmBackend::stop` never runs for a name that
            // is refused here and never becomes live state, so this is the
            // one place responsible for reaping it — after the teardown, so
            // whatever the refused child prints as it dies is in the record
            // of why it was refused.
            if let Err(error) = self.checked_force_stop(&child.0, "refused forked standby child") {
                cleanup.retain_unknown_child();
                return Err(StandbyError::StopUnconfirmed(format!(
                    "{refusal}; child stop unconfirmed: {error:#}; retaining child state and parent reservation"
                )));
            }
            cleanup.confirm_child_stopped();
            self.console_streamer.stop(&child.0);
            return Err(refusal);
        }
        claim_phase!("identity_verified");

        // The child booted and proved a fresh identity: disarm the endpoint and
        // broker reapers (the stop path owns them now) and commit — the parent
        // stays reserved and the child dir is real state.
        cleanup.commit();
        // Both handoff shapes consume the standby parent's state without being
        // able to remove it at claim time (resident: the child runs out of the
        // parent dir; preloaded: the paused child was loaded from it), so the
        // consumption is recorded in the child dir for the child's stop path
        // once the child's exit is confirmed. Best-effort: a write failure
        // must not fail a claim whose child is already live.
        warm_claim::record_consumed_parent(
            resident_handoff,
            preloaded_child_name.is_some(),
            &child_dir,
            handle.id.as_str(),
            child.0.as_str(),
        );
        if resident_handoff {
            schedule_resident_checkpoint_reclaim(ctx, &parent);
        }
        mvm_core::launch_trace::lap("warm_claim.commit");
        Ok(crate::backend::OwnedWarmClaim {
            id: child,
            lifecycle,
        })
    }

    /// Deliver `token` to the forked child's guest agent and judge what it
    /// reports. The driver owns the transport; the verdict is the claim's.
    fn take_fresh_child_identity(
        &self,
        child_vm_name: &str,
        identity: ChildIdentity,
    ) -> std::result::Result<(), StandbyError> {
        let requested_tier = identity.seccomp_tier;
        let requested_volumes = identity.volumes.len();
        let outcome = self
            .driver
            .deliver_child_identity(child_vm_name, identity)
            .map_err(|e| {
                StandbyError::ClaimFailed(format!(
                    "forked child '{child_vm_name}' never answered the post-restore identity \
                     handshake: {e:#}; a guest agent too old to take the claim's seccomp tier \
                     refuses this handshake, and the claim is refused rather than run \
                     unfiltered — `mvmctl bootstrap` refreshes the guest runtime"
                ))
            })?;
        require_fresh_child_identity(child_vm_name, &outcome)?;
        require_admitted_seccomp_tier(child_vm_name, requested_tier, &outcome)?;
        require_late_volumes_mounted(child_vm_name, requested_volumes, &outcome)
    }
}

/// The admitted plan from the claim.
/// The runner does not re-verify the signature — the host admitted the plan and
/// the supervisor re-verifies at attach. The runner reads the image binding and
/// child-grant fields it must enforce. A claim carrying no parseable plan fails
/// closed.
fn claim_plan(claim: &StandbyClaim) -> std::result::Result<ExecutionPlan, StandbyError> {
    mvm_core::plan::plan_from_admitted_json(&claim.plan_json)
        .map_err(|_| refuse(ClaimRefusal::PlanMissing))
}

/// How many times to redraw a fresh child name before giving up. A collision is
/// astronomically unlikely (random suffix), so a small bound is a fail-closed
/// backstop, never a hot loop.
pub(super) const MAX_CHILD_NAME_ATTEMPTS: usize = 8;

/// Select a fresh child [`VmId`] that collides with no existing VM registration.
/// The name is a fresh random id (never the parent's), which — with the fresh
/// VMGenID and per-child endpoint — is the identity scrub that stops a fork from
/// inheriting the parent's identity. Selection does not reserve the name: the
/// caller acquires its lifecycle gate and rechecks the registry before creating
/// child state. A concurrent registration then refuses rather than being adopted.
fn fresh_child_id(ctx: &ClaimContext<'_>) -> std::result::Result<VmId, StandbyError> {
    let _lock = acquire_registry_lock(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("acquire registry lock: {e:#}")))?;
    let registry = VmNameRegistry::load(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("load vm registry: {e:#}")))?;
    for _ in 0..MAX_CHILD_NAME_ATTEMPTS {
        let name = generate_vm_name();
        if registry.lookup(&name).is_none() {
            return Ok(VmId(name));
        }
    }
    Err(StandbyError::ClaimFailed(
        "could not mint a registry-unique child name".into(),
    ))
}

/// A preloaded child already has its name and its VMM, so it can serve only
/// the plan admitted under that name, and only a plan that grants no CPU
/// share: its VMM was started before the claim, outside any CPU scope. A
/// launch with a CPU grant takes the fork path, which starts the child's VMM
/// inside a scope carrying the grant.
fn require_preloaded_child_admission(
    child: &str,
    plan: &ExecutionPlan,
) -> std::result::Result<(), StandbyError> {
    if plan.image.name != child {
        return Err(StandbyError::ClaimFailed(format!(
            "preloaded child '{child}' cannot run a plan admitted under '{}'",
            plan.image.name
        )));
    }
    if plan
        .grants
        .as_ref()
        .is_some_and(|grants| grants.cpu.is_some())
    {
        return Err(StandbyError::ClaimFailed(format!(
            "preloaded child '{child}' was started without a CPU scope and cannot carry a CPU grant"
        )));
    }
    Ok(())
}

/// Recheck a preloaded child's registry identity immediately before claim-side
/// authority is created. The preload name was collision-checked when the pool
/// record was written, but another VM may have registered the same random name
/// before a later process claimed the persisted record.
fn verify_preloaded_child_name_is_available(
    ctx: &ClaimContext<'_>,
    child_name: &str,
) -> std::result::Result<(), StandbyError> {
    let _lock = acquire_registry_lock(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("acquire registry lock: {e:#}")))?;
    let registry = VmNameRegistry::load(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("load vm registry: {e:#}")))?;
    if registry.lookup(child_name).is_some() {
        return Err(StandbyError::ClaimFailed(format!(
            "preloaded child name '{child_name}' is already registered"
        )));
    }
    Ok(())
}
/// The child's launch config: the CLI-populated claim config (carrying the
/// verity fields the CLI already resolved on the cloned rootfs) rekeyed onto the
/// fresh child identity and its materialized rootfs. The runner consumes verity;
/// it never derives it.
fn child_start_config(claim: &StandbyClaim, child: &VmId, rootfs_dir: &Path) -> VmStartConfig {
    let mut cfg = claim.start_config.clone().unwrap_or_default();
    cfg.name = child.0.clone();
    cfg.rootfs_path = rootfs_dir
        .join("rootfs.ext4")
        .to_string_lossy()
        .into_owned();
    cfg.tenant_id = Some(claim.tenant_id.clone());
    cfg.network_policy = claim.network_policy.clone();
    cfg.plan_json = Some(claim.plan_json.clone());
    cfg
}
