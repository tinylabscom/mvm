//! Fresh child admission and retained dispatch for full-VM checkpoint forks.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta, VmFullOrigin};
use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_runtime::checkpoint::{CheckpointStore, ForkParams, ForkParentLiveness};

use super::anchor::SignedChainAnchor;

/// Caller-selected fork purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmFullForkIntent {
    /// Ordinary fork with production-safe verb attenuation.
    Ordinary,
    /// Replay fork, allowed only when the authenticated source plan permits it.
    Replay,
}

/// Caller intent for a fresh child forked from retained machine state.
///
/// Runtime evidence, parent authority, tenant, backend, grants, bundle,
/// network, agent verbs, seccomp, rootfs and bridge projections are derived
/// behind this facade.
pub struct VmFullForkRequest<'a> {
    pub checkpoint: &'a CheckpointId,
    pub child_id: CheckpointId,
    pub child_name: String,
    pub destination: PathBuf,
    pub created_unix: u64,
    pub declared_secrets: &'a [SecretBinding],
    pub allow_secret_drop: bool,
    pub intent: VmFullForkIntent,
    /// Network transport used only when the authenticated parent plan predates
    /// persisted plan evidence.
    pub fallback_network_mode: mvm_contract::plan::NetworkMode,
}

/// One admitted retained fork ready for exactly one backend dispatch.
pub struct PreparedVmFullFork {
    store: CheckpointStore,
    anchor: SignedChainAnchor,
    source: mvm_hostd::plan_admission::VerifiedVmFullForkSource,
    admission: crate::admission::AdmissionContext,
    params: ForkParams,
}

/// Result plus exact admission retained for source-compatible finalization.
pub struct VmFullForkDispatch {
    pub result: Result<CheckpointMeta>,
    pub admission: crate::admission::AdmissionContext,
}

/// Authenticate the source and admit one fresh child without dispatching.
pub fn prepare_vm_full_fork(
    store: &CheckpointStore,
    request: VmFullForkRequest<'_>,
) -> Result<PreparedVmFullFork> {
    let anchor = SignedChainAnchor::load().context("loading fork runtime audit chain")?;
    let expected_parent = store.read_meta(request.checkpoint)?;
    let source = mvm_hostd::plan_admission::verify_vm_full_fork_source(
        store,
        request.checkpoint,
        &expected_parent,
        &anchor,
    )
    .context("authenticating inherited runtime metadata before admission")?;
    let backend_kind = backend_for_origin(source.origin())?;
    let parent_plan = crate::audit::chain::plan_persist::read_plan(&expected_parent.vm_name).ok();
    let generation_assets =
        crate::policy_profiles::coordinator::restore_plan(&expected_parent.vm_name)?
            .into_iter()
            .flat_map(|parent| parent.asset_identities)
            .filter(|asset| {
                asset
                    .name
                    .starts_with(crate::policy_profiles::coordinator::GENERATION_ASSET_PREFIX)
            })
            .map(crate::admission::AssetSpec::CommittedPolicy)
            .collect();
    let network_mode = parent_plan
        .as_ref()
        .map_or(request.fallback_network_mode, |plan| plan.network_mode);
    let parent_agent_verbs = parent_plan
        .as_ref()
        .and_then(|plan| plan.agent_verbs.as_ref())
        .into_iter()
        .flatten()
        .map(|verb| verb.as_str().to_string())
        .collect::<Vec<_>>();
    let restrict_agent_verbs = restrict_agent_verbs(
        request.intent,
        &anchor,
        &expected_parent,
        parent_plan.as_ref(),
    )?;
    let parent_bundle = crate::admission::InheritedBundle::of_parent_vm(&expected_parent.vm_name)?;
    let tenant = resolve_tenant();
    validate_secret_policy(
        parent_plan.as_ref(),
        &tenant,
        request.declared_secrets,
        request.allow_secret_drop,
    )?;

    let scratch = tempfile::Builder::new()
        .prefix(".fork-admit-")
        .tempdir_in(store.root())
        .context("creating fork admission materialization")?;
    let rootfs = mvm_runtime::checkpoint::materialized_source(
        store,
        &expected_parent,
        mvm_core::checkpoint::ROOTFS_BLOB,
        scratch.path(),
    )?;
    let rootfs_sha256 = source.restored_rootfs_sha256().to_string();
    let inherited_runtime =
        inherited_runtime_config(expected_parent.runtime_launch_binding.as_ref(), &rootfs);
    let user_cfg = mvm_core::user_config::load(None);
    let ledger = crate::admission::InMemoryNonceLedger::new();
    let admission = crate::admission::admit_plan_for_boot_with_verified_retained(
        crate::admission::AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            outputs: Vec::new(),
            network_mode,
            tenant: &tenant,
            vm_name: &request.child_name,
            backend_name: backend_kind.as_str(),
            configured_images_dir: mvm_build::image_source::configured_images_dir().as_deref(),
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: Some(rootfs_sha256.clone()),
            boot_artifact_identity: None,
            runtime_config: inherited_runtime.as_ref(),
            cpus: user_cfg.default_cpus,
            mem_mib: user_cfg.default_memory_mib as u64,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: crate::admission::secrets::release_for_bindings(
                request.declared_secrets,
            ),
            secrets: request.declared_secrets.to_vec(),
            caller_commitment: None,
            ledger: &ledger,
            keys_dir: None,
            audit_dir: None,
            bundle_pin: parent_bundle
                .as_ref()
                .map(crate::admission::InheritedBundle::pin),
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: generation_assets,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: parent_agent_verbs,
            restrict_agent_verbs,
            services: Vec::new(),
            grants: expected_parent.grants.clone(),
            backend_kind: Some(backend_kind),
            entrypoint: crate::admission::entrypoint_resolve::ResolvedEntrypoint::unresolved(
                "a checkpoint fork boots the image the parent booted; this path resolves no entrypoint",
            ),
        },
        source.runtime(),
    )?;
    verify_child_plan(&admission, &request.child_name, &rootfs_sha256)?;
    let mint_config = mvm_core::vm_backend::VmStartConfig {
        name: request.child_name.clone(),
        plan_json: Some(serde_json::to_string(admission.admitted.signed())?),
        ..Default::default()
    };
    crate::admission::stash_plan_for_bridge(&mint_config)?;

    Ok(PreparedVmFullFork {
        store: store.clone(),
        anchor,
        source,
        admission,
        params: ForkParams {
            checkpoint: request.checkpoint.clone(),
            child_id: request.child_id,
            child_vm_name: request.child_name,
            dest_dir: request.destination,
            created_unix: request.created_unix,
            parent_liveness: ForkParentLiveness::MayBeRunning,
            child_plan_json: None,
            child_tenant_id: None,
        },
    })
}

impl PreparedVmFullFork {
    /// Read-only admitted child plan for UI and compatibility inspection.
    #[must_use]
    pub fn admitted_plan(&self) -> &mvm_core::plan::ExecutionPlan {
        self.admission.admitted.plan()
    }

    /// Spend admission and dispatch the restorer fixed by authenticated origin.
    pub fn dispatch(self) -> VmFullForkDispatch {
        let Self {
            store,
            anchor,
            source,
            admission,
            params,
        } = self;
        let crate::admission::AdmissionContext {
            admitted,
            emitter,
            host_signer_public_path,
        } = admission;
        let origin = source.origin();
        let bound = source.bind_child(admitted, params);
        let dispatched = match origin {
            Some(VmFullOrigin::Firecracker) => bound.dispatch_firecracker(
                &store,
                &mvm_runtime::firecracker::FcForkRestorer,
                &anchor,
                &mvm_runtime::microvm::stop_vm,
            ),
            Some(VmFullOrigin::Hvf) => bound.dispatch_hvf(
                &store,
                &mvm_runtime::hvf_restore::HvfForkRestorer,
                &anchor,
                &stop_hvf_child,
            ),
            Some(VmFullOrigin::Retired) | None => {
                unreachable!("source verification refuses unsupported full-VM backend origins")
            }
        };
        VmFullForkDispatch {
            result: dispatched.result,
            admission: crate::admission::AdmissionContext {
                admitted: dispatched.admitted,
                emitter,
                host_signer_public_path,
            },
        }
    }
}

fn backend_for_origin(origin: Option<VmFullOrigin>) -> Result<BackendKind> {
    match origin {
        Some(VmFullOrigin::Firecracker) => Ok(BackendKind::Firecracker),
        Some(VmFullOrigin::Hvf) => Ok(BackendKind::Hvf),
        Some(VmFullOrigin::Retired) | None => {
            bail!("checkpoint has no supported authenticated runtime backend identity")
        }
    }
}

fn stop_hvf_child(name: &str) -> Result<()> {
    let backend = crate::AnyBackend::for_started_vm(name)
        .with_context(|| format!("no backend claims restored child '{name}'"))?;
    backend
        .stop(&mvm_core::vm_backend::VmId(name.to_string()))
        .map(|_| ())
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

fn resolve_tenant() -> String {
    if let Ok(tenant) = std::env::var("MVM_TENANT")
        && !tenant.is_empty()
    {
        return tenant;
    }
    let configured = mvm_core::user_config::load(None).tenant.name;
    if configured.is_empty() {
        "local".to_string()
    } else {
        configured
    }
}

fn validate_secret_policy(
    parent_plan: Option<&mvm_core::plan::ExecutionPlan>,
    tenant: &str,
    declared: &[SecretBinding],
    allow_secret_drop: bool,
) -> Result<()> {
    use mvm_hostd::keyholder::BindingStore as _;

    let bindings = mvm_hostd::keyholder::FileBindingStore::default_location()
        .context("opening the child tenant's secret-binding store")?;
    for binding in declared {
        let SecretSource::Keystore { address } = &binding.source else {
            continue;
        };
        bindings
            .get(tenant, address)?
            .with_context(|| {
                format!(
                    "secret {address:?} has no binding in child tenant {tenant:?}; bind it before forking"
                )
            })?;
    }
    let declared_names = declared
        .iter()
        .map(|binding| binding.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let dropped = parent_plan
        .into_iter()
        .flat_map(|plan| &plan.secrets)
        .filter(|binding| !declared_names.contains(binding.name.as_str()))
        .map(|binding| binding.name.clone())
        .collect::<Vec<_>>();
    if !dropped.is_empty() && !allow_secret_drop {
        bail!(
            "fork child would drop parent secret bindings: {}. Redeclare each required binding or explicitly allow attenuation",
            dropped.join(", ")
        );
    }
    if !dropped.is_empty() {
        tracing::warn!(
            secrets = %dropped.join(", "),
            count = dropped.len(),
            "fork child intentionally drops parent secret bindings"
        );
    }
    Ok(())
}

fn restrict_agent_verbs(
    intent: VmFullForkIntent,
    anchor: &SignedChainAnchor,
    parent: &CheckpointMeta,
    parent_plan: Option<&mvm_core::plan::ExecutionPlan>,
) -> Result<bool> {
    match intent {
        VmFullForkIntent::Ordinary => Ok(true),
        VmFullForkIntent::Replay => {
            let recorded_plan_id = anchor
                .checkpoint_plan_id(parent)?
                .context("replay source checkpoint has no signed plan identity")?;
            let source = parent_plan.context("reading replay source plan")?;
            mvm_core::plan::verify_plan_id(source)
                .context("verifying replay source plan content id")?;
            if source.plan_id.0 != recorded_plan_id {
                bail!("replay source plan differs from the signed checkpoint creation entry");
            }
            if source.agent_verbs.is_some() {
                bail!("replay source has an attenuated agent-verb grant; exec is not authorized");
            }
            Ok(false)
        }
    }
}

fn verify_child_plan(
    admission: &crate::admission::AdmissionContext,
    child_name: &str,
    image_sha256: &str,
) -> Result<()> {
    let now = mvm_core::util::time::try_utc_timestamp_now()
        .context("the host clock is unusable, so the child plan's validity cannot be checked")?;
    let trusted = crate::host_keypair::load_or_init()?.verifying_key();
    mvm_core::plan::verify_restored_child_plan(
        admission.admitted.signed(),
        &trusted,
        &mvm_core::plan::RestoredChildBinding {
            vm_name: child_name,
            image: mvm_core::plan::ImageBinding::Pinned(image_sha256),
            now,
        },
    )
    .context("the admitted child plan does not bind the restore")
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CapturedParent(PathBuf);

    impl mvm_vmm::checkpoint::VmFullControl for CapturedParent {
        fn pause(&self) -> Result<()> {
            Ok(())
        }

        fn resume(&self) -> Result<()> {
            Ok(())
        }

        fn rootfs_path(&self) -> Result<PathBuf> {
            Ok(self.0.clone())
        }

        fn save_memory(&self, memory: &std::path::Path) -> Result<()> {
            std::fs::write(memory, b"memory")?;
            std::fs::write(
                memory.with_file_name(mvm_core::checkpoint::HVF_FRAME_BLOB),
                b"frame",
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

    fn fixture() -> (
        mvm_core::util::test_env::TestEnv,
        tempfile::TempDir,
        tempfile::TempDir,
        CheckpointStore,
        CheckpointMeta,
    ) {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let root = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(root.path().join("store"));
        let rootfs = root.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let meta = mvm_runtime::checkpoint::capture_vm_full(
            &store,
            mvm_runtime::checkpoint::CaptureVmFullParams::builder()
                .id(CheckpointId::new("parent"))
                .vm_name("parent-vm".into())
                .supervisor_config_digest("config".into())
                .created_unix(1)
                .retain_paused(false)
                .grants(None)
                .build()
                .unwrap(),
            &CapturedParent(rootfs),
        )
        .unwrap();
        let signer = crate::host_keypair::load_or_init().unwrap();
        let emitter = crate::audit::chain::emitter::AuditEmitter::new(signer.signing).unwrap();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("parent-vm")
            .build();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        crate::audit::chain::plan_persist::write_plan(&meta.vm_name, &plan).unwrap();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        drop(emitter);
        (env, home, root, store, meta)
    }

    fn request<'a>(meta: &'a CheckpointMeta, root: &std::path::Path) -> VmFullForkRequest<'a> {
        VmFullForkRequest {
            checkpoint: &meta.id,
            child_id: CheckpointId::new("child-checkpoint"),
            child_name: "child-vm".into(),
            destination: root.join("child-vm"),
            created_unix: 2,
            declared_secrets: &[],
            allow_secret_drop: false,
            intent: VmFullForkIntent::Ordinary,
            fallback_network_mode: mvm_contract::plan::NetworkMode::HostVsockProxy,
        }
    }

    #[test]
    fn facade_binds_fresh_child_to_authenticated_source_and_backend() {
        let (_env, _home, root, store, meta) = fixture();
        let prepared = prepare_vm_full_fork(&store, request(&meta, root.path())).unwrap();
        let plan = prepared.admitted_plan();
        assert_eq!(plan.workload.0, "child-vm");
        assert_eq!(plan.tenant.0, "local");
        assert_eq!(plan.runtime_profile.0, BackendKind::Hvf.as_str());
        assert_eq!(
            plan.image.sha256,
            mvm_runtime::checkpoint::materialized_blob_sha256(
                &store,
                &meta,
                mvm_core::checkpoint::ROOTFS_BLOB,
            )
            .unwrap()
        );
    }

    #[test]
    fn altered_metadata_and_retained_content_refuse_before_admission() {
        {
            let (_env, _home, root, store, mut meta) = fixture();
            meta.vm_name = "altered-parent".into();
            store.write_meta(&meta).unwrap();
            assert!(prepare_vm_full_fork(&store, request(&meta, root.path())).is_err());
        }
        {
            let (_env, _home, root, store, meta) = fixture();
            std::fs::write(
                store.content_dir(&meta.id).join("runtime-artifacts.json"),
                b"altered",
            )
            .unwrap();
            assert!(prepare_vm_full_fork(&store, request(&meta, root.path())).is_err());
        }
        {
            let (_env, _home, root, store, meta) = fixture();
            std::fs::write(
                store.content_dir(&meta.id).join("rootfs.ext4.chunks.json"),
                b"altered rootfs",
            )
            .unwrap();
            assert!(prepare_vm_full_fork(&store, request(&meta, root.path())).is_err());
        }
        {
            let (_env, _home, root, store, meta) = fixture();
            let wrong = CheckpointId::new("different-checkpoint");
            let mut wrong_request = request(&meta, root.path());
            wrong_request.checkpoint = &wrong;
            assert!(prepare_vm_full_fork(&store, wrong_request).is_err());
        }
    }

    #[test]
    fn backend_mismatch_spends_admission_without_invoking_restorer() {
        let (_env, _home, root, store, meta) = fixture();
        let prepared = prepare_vm_full_fork(&store, request(&meta, root.path())).unwrap();
        let PreparedVmFullFork {
            store,
            anchor,
            source,
            admission,
            params,
        } = prepared;
        let crate::admission::AdmissionContext { admitted, .. } = admission;
        let bound = source.bind_child(admitted, params);
        let dispatched = bound.dispatch_firecracker(
            &store,
            &mvm_runtime::firecracker::FcForkRestorer,
            &anchor,
            &|_| Ok(()),
        );
        let error = dispatched.result.expect_err("backend mismatch must refuse");
        assert!(
            error.to_string().contains("restorer for the wrong backend"),
            "{error:#}"
        );
        assert!(dispatched.admitted.was_dispatched());
    }

    fn retained_fork_contained_after_admission(
        stop_fails: bool,
    ) -> (anyhow::Error, bool, Vec<String>) {
        use std::cell::{Cell, RefCell};

        let (_env, home, root, store, meta) = fixture();
        let prepared = prepare_vm_full_fork(&store, request(&meta, root.path())).unwrap();
        let PreparedVmFullFork {
            store,
            anchor,
            source,
            admission,
            params,
        } = prepared;
        let crate::admission::AdmissionContext { admitted, .. } = admission;
        let bound = source.bind_child(admitted, params);
        let restored = Cell::new(false);
        let stops = RefCell::new(Vec::new());
        let restorer = |_child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            restored.set(true);
            mvm_hostd::policy_generation::workload_store::OwnedWorkloadStore::open(home.path())?
                .commit(
                    &mvm_core::host_interface::workload::WorkloadChange::Quarantine {
                        workload: "child-vm".into(),
                    },
                )?;
            Ok(())
        };
        let dispatched = bound.dispatch_test_hvf(&store, &restorer, &anchor, &|name| {
            stops.borrow_mut().push(name.to_string());
            if stop_fails {
                anyhow::bail!("stop not confirmed");
            }
            Ok(())
        });
        assert!(dispatched.admitted.was_dispatched());
        (
            dispatched
                .result
                .expect_err("quarantined child must not be returned"),
            restored.get(),
            stops.into_inner(),
        )
    }

    #[test]
    fn retained_fork_stops_child_quarantined_after_admission() {
        let (error, restored, stopped) = retained_fork_contained_after_admission(false);
        assert!(restored, "restorer was not invoked: {error:#}");
        assert_eq!(stopped, vec!["child-vm"]);
        assert!(
            format!("{error:#}").contains("no longer admits"),
            "{error:#}"
        );
        assert!(
            error
                .downcast_ref::<mvm_runtime::checkpoint::ForkStopUncertain>()
                .is_none(),
            "{error:#}"
        );
    }

    fn configure_host_budget(home: &std::path::Path, memory_mib: u64) {
        let config = home.join("config");
        mvm_core::config::create_private_dir(&config).unwrap();
        mvm_core::atomic_io::write_private(
            &config.join("config.toml"),
            format!("host_budget_memory_mib = {memory_mib}").as_bytes(),
        )
        .unwrap();
    }

    /// Publish a backend PID marker for `vm` naming `pid`, as a restore does.
    fn write_pid_marker(home: &std::path::Path, vm: &str, pid: u32) {
        let directory = mvm_core::config::vm_state_dir_at(home, vm);
        std::fs::create_dir_all(&directory).unwrap();
        mvm_core::atomic_io::write_private(
            &directory.join("hvf.pid"),
            mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(pid)
                .render()
                .as_bytes(),
        )
        .unwrap();
    }

    fn exited_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// Whether the host can still admit a machine of `memory_mib` right now.
    fn host_admits(memory_mib: u64) -> bool {
        mvm_hostd::admission_budget::HostBudgetPermit::reserve(
            "budget-probe",
            mvm_contract::grants::budget::MachineCharge {
                memory_mib,
                cpu_millicores: 0,
            },
        )
        .is_ok()
    }

    fn bound_fork(
        store: &CheckpointStore,
        meta: &CheckpointMeta,
        root: &std::path::Path,
    ) -> (
        mvm_hostd::plan_admission::RetainedVmFullFork,
        CheckpointStore,
        SignedChainAnchor,
        u64,
    ) {
        let prepared = prepare_vm_full_fork(store, request(meta, root)).unwrap();
        let memory_mib = prepared.admitted_plan().resources.mem_mib;
        let PreparedVmFullFork {
            store,
            anchor,
            source,
            admission,
            params,
        } = prepared;
        let crate::admission::AdmissionContext { admitted, .. } = admission;
        (
            source.bind_child(admitted, params),
            store,
            anchor,
            memory_mib,
        )
    }

    impl PreparedVmFullFork {
        fn dispatch_with_test_hvf(
            self,
            restorer: &dyn mvm_runtime::checkpoint::ForkRestorer,
        ) -> mvm_hostd::plan_admission::VmFullForkDispatch {
            let crate::admission::AdmissionContext { admitted, .. } = self.admission;
            self.source
                .bind_child(admitted, self.params)
                .dispatch_test_hvf(&self.store, restorer, &self.anchor, &|_| Ok(()))
        }
    }

    const BUDGET_MIB: u64 = 1 << 20;

    #[test]
    fn a_vm_full_fork_that_fits_is_charged_and_counted_by_the_next_admission() {
        let (_env, home, root, store, meta) = fixture();
        configure_host_budget(home.path(), BUDGET_MIB);
        let (bound, store, anchor, memory_mib) = bound_fork(&store, &meta, root.path());
        let restorer = |child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            write_pid_marker(home.path(), child.vm_name, std::process::id());
            Ok(())
        };
        let dispatched = bound.dispatch_test_hvf(&store, &restorer, &anchor, &|_| Ok(()));
        dispatched.result.expect("a fork that fits is admitted");
        drop(dispatched.admitted);

        assert!(
            !host_admits(BUDGET_MIB - memory_mib + 1),
            "the running fork's configured memory must be charged to the host"
        );
        assert!(host_admits(BUDGET_MIB - memory_mib));
    }

    #[test]
    fn a_vm_full_fork_past_the_budget_at_dispatch_is_refused_before_restore() {
        use std::cell::Cell;

        let (_env, home, root, store, meta) = fixture();
        configure_host_budget(home.path(), BUDGET_MIB);
        let (bound, store, anchor, memory_mib) = bound_fork(&store, &meta, root.path());
        // A machine that started after this fork was admitted takes the rest.
        mvm_hostd::admission_budget::record_charge_at(
            home.path(),
            "neighbour",
            mvm_contract::grants::budget::MachineCharge {
                memory_mib: BUDGET_MIB - memory_mib + 1,
                cpu_millicores: 0,
            },
        )
        .unwrap();
        write_pid_marker(home.path(), "neighbour", std::process::id());
        let restored = Cell::new(false);
        let restorer = |_child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            restored.set(true);
            Ok(())
        };
        let dispatched = bound.dispatch_test_hvf(&store, &restorer, &anchor, &|_| Ok(()));
        let error = dispatched.result.expect_err("a fork past the budget");
        assert!(!restored.get(), "no VMM may start: {error:#}");
        assert!(
            error
                .downcast_ref::<mvm_hostd::plan_admission::HostBudgetRefused>()
                .is_some(),
            "the refusal is the launch tail's typed host-budget refusal: {error:#}"
        );
        assert!(format!("{error:#}").contains("host-budget dispatch refused"));

        std::fs::remove_dir_all(mvm_core::config::vm_state_dir_at(home.path(), "neighbour"))
            .unwrap();
        assert!(
            host_admits(BUDGET_MIB),
            "a refused fork holds nothing, even before its admission is dropped"
        );
        drop(dispatched.admitted);
    }

    #[test]
    fn a_vm_full_fork_past_the_budget_is_refused_at_admission() {
        let (_env, home, root, store, meta) = fixture();
        configure_host_budget(home.path(), 1);
        let error = prepare_vm_full_fork(&store, request(&meta, root.path()))
            .err()
            .expect("a child larger than the host budget is not admitted");
        assert!(format!("{error:#}").contains("budget"), "{error:#}");
    }

    /// How a fork's launch fails once its hold may have been spent.
    #[derive(Clone, Copy, Debug)]
    enum LaunchFailure {
        /// The restorer refuses before publishing any process.
        RestoreWithoutProcess,
        /// The restorer started a VMM, then failed and reaped it.
        RestoreReapedItsProcess,
        /// The restored child is contained by the workload ledger and stopped.
        ContainedAfterRestore,
        /// The child's charge record cannot be written, so it is stopped.
        ChargeRecordUnwritable,
    }

    fn fork_failing_with(failure: LaunchFailure) {
        let (_env, home, root, store, meta) = fixture();
        configure_host_budget(home.path(), BUDGET_MIB);
        let (bound, store, anchor, _) = bound_fork(&store, &meta, root.path());
        let restorer = |child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            match failure {
                LaunchFailure::RestoreWithoutProcess => anyhow::bail!("restore refused"),
                LaunchFailure::RestoreReapedItsProcess => {
                    write_pid_marker(home.path(), child.vm_name, exited_pid());
                    anyhow::bail!("restore failed after spawning")
                }
                LaunchFailure::ContainedAfterRestore => {
                    write_pid_marker(home.path(), child.vm_name, exited_pid());
                    mvm_hostd::policy_generation::workload_store::OwnedWorkloadStore::open(
                        home.path(),
                    )?
                    .commit(
                        &mvm_core::host_interface::workload::WorkloadChange::Quarantine {
                            workload: child.vm_name.into(),
                        },
                    )?;
                }
                LaunchFailure::ChargeRecordUnwritable => {
                    use std::os::unix::fs::PermissionsExt as _;
                    write_pid_marker(home.path(), child.vm_name, exited_pid());
                    std::fs::set_permissions(
                        mvm_core::config::vm_state_dir_at(home.path(), child.vm_name),
                        std::fs::Permissions::from_mode(0o500),
                    )?;
                }
            }
            Ok(())
        };
        let dispatched = bound.dispatch_test_hvf(&store, &restorer, &anchor, &|_| Ok(()));
        let error = dispatched.result.expect_err("the launch fails");
        assert!(
            error
                .downcast_ref::<mvm_runtime::checkpoint::ForkStopUncertain>()
                .is_none(),
            "{failure:?}: {error:#}"
        );
        if let LaunchFailure::ChargeRecordUnwritable = failure {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                mvm_core::config::vm_state_dir_at(home.path(), "child-vm"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            assert!(
                format!("{error:#}").contains("recording the fork child's host charge"),
                "{error:#}"
            );
        }
        assert!(
            host_admits(BUDGET_MIB),
            "{failure:?}: a failed fork must not leave phantom load ({error:#})"
        );
        drop(dispatched.admitted);
    }

    #[test]
    fn a_fork_whose_restore_fails_before_any_process_releases_its_charge() {
        fork_failing_with(LaunchFailure::RestoreWithoutProcess);
    }

    #[test]
    fn a_fork_whose_restore_reaped_its_process_releases_its_charge() {
        fork_failing_with(LaunchFailure::RestoreReapedItsProcess);
    }

    #[test]
    fn a_fork_contained_after_restore_releases_its_charge() {
        fork_failing_with(LaunchFailure::ContainedAfterRestore);
    }

    #[test]
    fn a_fork_whose_charge_cannot_be_recorded_releases_its_charge() {
        fork_failing_with(LaunchFailure::ChargeRecordUnwritable);
    }

    #[test]
    fn a_failed_fork_whose_vmm_still_runs_stays_charged() {
        let (_env, home, root, store, meta) = fixture();
        configure_host_budget(home.path(), BUDGET_MIB);
        let (bound, store, anchor, memory_mib) = bound_fork(&store, &meta, root.path());
        let restorer = |child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            write_pid_marker(home.path(), child.vm_name, std::process::id());
            anyhow::bail!("restore failed and could not reap its process")
        };
        let dispatched = bound.dispatch_test_hvf(&store, &restorer, &anchor, &|_| Ok(()));
        assert!(dispatched.result.is_err());
        drop(dispatched.admitted);
        assert!(
            !host_admits(BUDGET_MIB - memory_mib + 1),
            "a VMM that may still run keeps its capacity reserved"
        );
    }

    #[test]
    fn many_forks_fill_a_budget_sized_for_them_and_the_next_is_refused() {
        const FORKS: u64 = 4;
        let (_env, home, root, store, meta) = fixture();
        let memory_mib = prepare_vm_full_fork(&store, request(&meta, root.path()))
            .unwrap()
            .admitted_plan()
            .resources
            .mem_mib;
        configure_host_budget(home.path(), FORKS * memory_mib);
        let restorer = |child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            write_pid_marker(home.path(), child.vm_name, std::process::id());
            Ok(())
        };
        for fork in 0..FORKS {
            let mut forked = request(&meta, root.path());
            forked.child_id = CheckpointId::new(format!("child-checkpoint-{fork}"));
            forked.child_name = format!("child-vm-{fork}");
            forked.destination = root.path().join(&forked.child_name);
            let prepared = prepare_vm_full_fork(&store, forked).unwrap();
            let dispatched = prepared.dispatch_with_test_hvf(&restorer);
            dispatched
                .result
                .unwrap_or_else(|e| panic!("fork {fork}: {e:#}"));
        }
        let mut over = request(&meta, root.path());
        over.child_name = "one-too-many".into();
        let error = prepare_vm_full_fork(&store, over)
            .err()
            .expect("a budget full of running forks refuses the next one");
        assert!(
            format!("{error:#}").contains("exceed this host's budget"),
            "{error:#}"
        );
    }

    #[test]
    fn without_a_host_budget_a_vm_full_fork_writes_no_accounting() {
        let (_env, home, root, store, meta) = fixture();
        let (bound, store, anchor, _) = bound_fork(&store, &meta, root.path());
        let restorer = |child: &mvm_runtime::checkpoint::RestoredChild<'_>| {
            write_pid_marker(home.path(), child.vm_name, std::process::id());
            Ok(())
        };
        let dispatched = bound.dispatch_test_hvf(&store, &restorer, &anchor, &|_| Ok(()));
        dispatched.result.expect("an unbudgeted fork");
        assert!(
            !mvm_core::config::vm_state_dir_at(home.path(), "child-vm")
                .join("admitted-charge.json")
                .exists()
        );
        assert!(!home.path().join("admission-budget").exists());
    }

    #[test]
    fn retained_fork_keeps_uncertain_stop_custody() {
        let (error, restored, stopped) = retained_fork_contained_after_admission(true);
        assert!(restored, "restorer was not invoked: {error:#}");
        assert_eq!(stopped, vec!["child-vm"]);
        let uncertain = error
            .downcast_ref::<mvm_runtime::checkpoint::ForkStopUncertain>()
            .unwrap_or_else(|| panic!("expected ForkStopUncertain: {error:#}"));
        assert_eq!(uncertain.name, "child-vm");
    }
}
