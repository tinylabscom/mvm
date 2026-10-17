use anyhow::{Context, Result};
use serde::Serialize;

use mvm_core::checkpoint::{CheckpointDigest, CheckpointMeta};
use mvm_core::image_lineage::ImageNode;
use mvm_runtime::checkpoint::{CheckpointChainAnchor, CheckpointStore, verify_lineage};
use mvm_runtime::image_lineage::ImageChainAnchor;

use super::validated_checkpoint_id;
use crate::ui;

/// Classify a no-boot request before any permissive checkpoint-store read.
/// This also bounds classification of vm_full records; their valid records
/// continue through the existing vm_full arm, not the strict fs_quick route.
pub(super) fn read_unbooted_fork_parent(
    store: &CheckpointStore,
    id: &mvm_core::checkpoint::CheckpointId,
) -> Result<CheckpointMeta> {
    #[cfg(unix)]
    {
        let mut remaining = strict_fs_quick::METADATA_READ_BUDGET;
        strict_fs_quick::read_checkpoint(store, id, &mut remaining)
    }
    #[cfg(not(unix))]
    {
        let _ = (store, id);
        anyhow::bail!("guarded unbooted checkpoint classification is unavailable on this platform")
    }
}

/// The guarded no-boot route has no legacy/unlocked fallback.
pub(super) fn fork_fs_quick_unbooted(p: super::ForkFsQuickArmParams<'_>) -> Result<()> {
    #[cfg(unix)]
    {
        strict_fs_quick::run(p)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        anyhow::bail!("authenticated fs_quick forks are unavailable on this platform")
    }
}

/// Existing canonical delegates are path-rooted. The configured home and its
/// ancestors are trusted, and hostile same-UID namespace replacement is outside
/// this boundary. Static managed symlinks and unsafe members refuse; this is not
/// an atomic destination reservation or a pinned audit-engine implementation.
#[cfg(unix)]
mod strict_fs_quick {
    use super::*;
    use anyhow::bail;
    use std::collections::{BTreeSet, HashMap};
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use mvm_core::plan::ExecutionPlan;
    use mvm_core::transcript::local_store::LocalTranscriptStore;
    use mvm_hostd::audit::emitter::AuditEmitter;

    // Intentional fail-closed compatibility bound, including envelope encoding.
    const MAX_FORK_PLAN_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_CHECKPOINT_META_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_CHECKPOINT_STORE_ENTRIES: usize = 256;
    pub(super) const METADATA_READ_BUDGET: u64 = 64 * 1024 * 1024;

    fn owned(metadata: &std::fs::Metadata) -> bool {
        // SAFETY: geteuid only reads the process's effective user ID.
        metadata.uid() == unsafe { libc::geteuid() }
    }

    fn private_directory(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .context("required existing fork authority directory is unavailable")?;
        if !metadata.is_dir() || !owned(&metadata) || metadata.mode() & 0o7777 != 0o700 {
            bail!("fork authority directory must be existing, owned and private");
        }
        Ok(())
    }

    fn authority_file(path: &Path, allowed_modes: &[u32]) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .context("required existing fork authority file is unavailable")?;
        let metadata = file.metadata().context("reading fork authority metadata")?;
        if !metadata.is_file()
            || !owned(&metadata)
            || metadata.nlink() != 1
            || !allowed_modes.contains(&(metadata.mode() & 0o7777))
        {
            bail!("fork authority file must be regular, owned, private and single-link");
        }
        Ok(file)
    }

    fn absent(path: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => anyhow::bail!("fork destination is occupied or cannot be inspected"),
        }
    }

    pub(super) fn read_checkpoint(
        store: &CheckpointStore,
        id: &mvm_core::checkpoint::CheckpointId,
        remaining: &mut u64,
    ) -> Result<CheckpointMeta> {
        private_directory(store.root())?;
        private_directory(&store.dir_for(id))?;
        // Same member layout as CheckpointStore::meta_path, which is private.
        // Type/mode/ownership and bytes use this one opened handle.
        let file = authority_file(&store.dir_for(id).join("meta.json"), &[0o600])?;
        // Reserve the EOF/over-limit probe inside the aggregate read budget.
        let limit = MAX_CHECKPOINT_META_BYTES.min(
            remaining
                .checked_sub(1)
                .context("checkpoint metadata read budget exceeded")?,
        );
        if file.metadata()?.len() > limit {
            bail!("checkpoint metadata exceeds the 4 MiB member or 64 MiB aggregate bound");
        }
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded checkpoint metadata")?;
        *remaining -= bytes.len() as u64;
        if bytes.len() as u64 > limit {
            bail!("checkpoint metadata exceeds the 4 MiB member or 64 MiB aggregate bound");
        }
        let meta: CheckpointMeta = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("checkpoint metadata is malformed"))?;
        if meta.id != *id {
            bail!("checkpoint metadata ID does not match its directory");
        }
        Ok(meta)
    }

    fn preflight_store(store: &CheckpointStore) -> Result<()> {
        private_directory(store.root())?;
        let mut remaining = METADATA_READ_BUDGET;
        for (examined, entry) in std::fs::read_dir(store.root())?.enumerate() {
            // Count everything, including dot staging/pools, files and rejected
            // names, before any filter, allocation of metadata bytes, or push.
            if examined >= MAX_CHECKPOINT_STORE_ENTRIES {
                bail!("checkpoint store exceeds the 256 examined-entry bound");
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .context("checkpoint directory name is unsupported")?;
            if name.starts_with('.') {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("checkpoint store member must not be a symlink");
            }
            if !kind.is_dir() {
                continue;
            }
            let id = validated_checkpoint_id(name)
                .map_err(|_| anyhow::anyhow!("checkpoint directory ID is invalid"))?;
            read_checkpoint(store, &id, &mut remaining)?;
        }
        // verify_lineage's canonical by-digest lookup scans the store again.
        // These are static availability/type preflights, not same-FD custody
        // across canonical rereads or a hostile namespace replacement defense.
        Ok(())
    }

    fn load_anchor(
        home: &Path,
        key_store: &LocalTranscriptStore,
    ) -> Result<(SignedChainAnchor, ed25519_dalek::VerifyingKey)> {
        private_directory(home)?;
        let dir = home.join("audit");
        private_directory(&dir)?;
        let verifying = key_store
            .existing_host_public_key()
            .context("existing host verification authority is required")?;
        let mut bases = BTreeSet::new();
        for member in std::fs::read_dir(&dir).context("reading existing audit directory")? {
            let path = member?.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("audit member name is not supported")?;
            // Validate the actual files the canonical history reader can use,
            // including root-history JSONL, before its path-rooted reads.
            if name.ends_with(".jsonl") {
                // Canonical emitters create 0644 members under the validated
                // 0700 directory. Accept existing bytes without mode repair.
                authority_file(&path, &[0o600, 0o644])?;
            }
            if mvm_core::config::is_host_lifecycle_chain(&path)
                && let Some(base) = mvm_core::config::lifecycle_chain_base(name)
            {
                bases.insert(base.to_owned());
            }
        }
        if bases.is_empty() {
            bail!("authenticated original checkpoint history is missing");
        }
        let mut recorded = HashMap::new();
        for base in bases {
            let history =
                mvm_core::audit_verify::set::read_verified_history(&dir, &base, &verifying)
                    .map_err(|_| {
                        anyhow::anyhow!("original checkpoint history failed verification")
                    })?;
            if history.pruned.is_some() {
                bail!("pruned history cannot establish unambiguous original checkpoint policy");
            }
            for segment in history.segments {
                let entries = segment
                    .entries
                    .context("verified lifecycle entries are unavailable")?;
                for entry in entries {
                    if entry.tenant.0 != base {
                        bail!("verified audit tenant does not match its lifecycle chain");
                    }
                    let Some((id_key, digest_key, namespace)) = creation_keys(&entry.event) else {
                        continue;
                    };
                    if namespace != CHECKPOINT_NS {
                        continue;
                    }
                    let id = entry
                        .labels
                        .get(id_key)
                        .context("checkpoint creation ID is missing")?;
                    let digest = entry
                        .labels
                        .get(digest_key)
                        .context("checkpoint creation digest is missing")?;
                    let value = RecordedCreation {
                        digest: CheckpointDigest::parse(digest.clone())?,
                        tenant: entry.tenant.0,
                        plan_id: entry.plan_id.0,
                    };
                    if recorded.insert(anchor_key(namespace, id), value).is_some() {
                        bail!("duplicate or conflicting original checkpoint creation evidence");
                    }
                }
            }
        }
        Ok((
            SignedChainAnchor {
                recorded,
                unverifiable: Vec::new(),
            },
            verifying,
        ))
    }

    fn original_plan(
        home: &Path,
        anchor: &SignedChainAnchor,
        parent: &CheckpointMeta,
    ) -> Result<ExecutionPlan> {
        mvm_core::naming::validate_vm_name(&parent.vm_name)?;
        private_directory(&home.join("vms"))?;
        private_directory(&mvm_core::config::vm_state_dir(&parent.vm_name))?;
        let path = super::super::super::plan_persist::plan_path(&parent.vm_name)?;
        let mut bytes = Vec::new();
        authority_file(&path, &[0o600])?
            .take(MAX_FORK_PLAN_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded original-plan candidate")?;
        if bytes.len() as u64 > MAX_FORK_PLAN_BYTES {
            bail!("original-plan candidate exceeds the 4 MiB bound");
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| anyhow::anyhow!("original-plan candidate is malformed"))?;
        let plan = mvm_core::plan::plan_from_admitted_json(text)
            .map_err(|_| anyhow::anyhow!("original-plan candidate is malformed"))?;
        mvm_core::plan::verify_plan_id(&plan)
            .map_err(|_| anyhow::anyhow!("original-plan candidate is not content-addressed"))?;
        if anchor.checkpoint_plan_id(parent)?.as_deref() != Some(plan.plan_id.0.as_str())
            || anchor.recorded_creation_tenant(parent)?.as_deref() != Some(plan.tenant.0.as_str())
            || plan.workload.0 != parent.vm_name
        {
            bail!("plan candidate does not match authenticated original checkpoint identity");
        }
        mvm_client::admission::secrets::validate_secret_sources(&plan.secrets)?;
        Ok(plan)
    }

    struct PreparedFork<'a> {
        store: &'a CheckpointStore,
        parent: CheckpointMeta,
        plan: ExecutionPlan,
        anchor: SignedChainAnchor,
        emitter: AuditEmitter,
        child_id: mvm_core::checkpoint::CheckpointId,
        name: String,
        destination: std::path::PathBuf,
        now: u64,
        json: bool,
    }

    fn prepare(p: super::super::ForkFsQuickArmParams<'_>) -> Result<PreparedFork<'_>> {
        mvm_client::admission::secrets::validate_secret_sources(p.declared_secrets)?;
        if !p.declared_secrets.is_empty() {
            bail!(
                "--secret requires --boot for an fs_quick fork because an unbooted clone has no child plan"
            );
        }
        let mut remaining = METADATA_READ_BUDGET;
        let parent = read_checkpoint(p.store, p.checkpoint, &mut remaining)?;
        if parent.class != mvm_core::checkpoint::CheckpointClass::FsQuick {
            bail!("unbooted fork requires an fs_quick checkpoint");
        }
        let home = mvm_core::config::mvm_home_strict()?;
        let key_store = LocalTranscriptStore::open(&home)
            .context("existing fork authority root is required")?;
        let (anchor, history_key) = load_anchor(&home, &key_store)?;
        preflight_store(p.store)?;
        verify_lineage(p.store, p.checkpoint, &anchor)?;
        let plan = original_plan(&home, &anchor, &parent)?;
        let names = plan
            .secrets
            .iter()
            .map(|binding| binding.name.clone())
            .collect::<Vec<_>>();
        super::super::enforce_secret_attenuation(
            &super::super::dropped_parent_secret_names(&names, &[]),
            p.allow_secret_drop,
        )?;
        let now = super::super::now_unix();
        let name = p
            .new_id
            .unwrap_or_else(|| format!("{}-fork-{now}", p.checkpoint.as_str()));
        mvm_core::naming::validate_vm_name(&name)?;
        let child_id = validated_checkpoint_id(&format!("fork-{name}-{now}"))?;
        if name == parent.vm_name || child_id == *p.checkpoint {
            bail!("fork destination must differ from the parent");
        }
        let destination = mvm_core::config::vm_state_dir(&name);
        absent(&destination)?;
        absent(&p.store.dir_for(&child_id))?;
        let (signing, verifying) = key_store
            .existing_host_keypair()
            .context("existing matching host signing authority is required")?;
        // Do not silently accept replacement authority after history verification.
        if history_key != verifying {
            bail!("fork verification authority changed");
        }
        private_directory(&home)?;
        private_directory(&home.join("audit"))?;
        let emitter = AuditEmitter::with_dir(signing, &home.join("audit"))?;
        Ok(PreparedFork {
            store: p.store,
            parent,
            plan,
            anchor,
            emitter,
            child_id,
            name,
            destination,
            now,
            json: p.json,
        })
    }

    impl PreparedFork<'_> {
        fn materialize(&self) -> Result<CheckpointMeta> {
            let mut remaining = METADATA_READ_BUDGET;
            if read_checkpoint(self.store, &self.parent.id, &mut remaining)? != self.parent {
                bail!("parent checkpoint changed during fork preparation");
            }
            absent(&self.destination)?;
            absent(&self.store.dir_for(&self.child_id))?;
            let child = mvm_runtime::checkpoint::fork_checkpoint(
                self.store,
                mvm_runtime::checkpoint::ForkParams {
                    checkpoint: self.parent.id.clone(),
                    child_id: self.child_id.clone(),
                    child_vm_name: self.name.clone(),
                    dest_dir: self.destination.clone(),
                    created_unix: self.now,
                    parent_liveness: mvm_runtime::checkpoint::ForkParentLiveness::MustBeStopped,
                    child_plan_json: None,
                    child_tenant_id: None,
                },
                &self.anchor,
            )
            .with_context(|| {
                format!(
                    "fork failed; inspect retained artifacts at {} and checkpoint location {}",
                    self.destination.display(),
                    self.store.dir_for(&self.child_id).display()
                )
            })?;
            Ok(child)
        }

        fn publish(&self, child: &CheckpointMeta) -> Result<()> {
            let publication = (|| -> Result<()> {
                if child.id != self.child_id
                    || child.vm_name != self.name
                    || child.parent.as_ref() != Some(&self.parent.meta_digest)
                {
                    bail!("materialized fork identity does not match its prepared parent");
                }
                let mut remaining = METADATA_READ_BUDGET;
                if read_checkpoint(self.store, &self.parent.id, &mut remaining)? != self.parent {
                    bail!("parent checkpoint changed during materialization");
                }
                mvm_hostd::audit::bind::bind_checkpoint_forked(
                    &self.emitter,
                    &self.plan,
                    &self.parent.id,
                    child,
                    &self.name,
                    &[],
                )
            })();
            publication.with_context(|| format!(
            "fork materialized at {}; checkpoint {} retained at {}; lineage publication failed",
            self.destination.display(), child.id.as_str(), self.store.dir_for(&child.id).display()
        ))
        }
    }

    pub(super) fn run(p: super::super::ForkFsQuickArmParams<'_>) -> Result<()> {
        let prepared = prepare(p)?;
        let child = prepared.materialize()?;
        prepared.publish(&child)?;
        let name = &prepared.name;
        if prepared.json {
            crate::json_out::emit_json(&super::super::CheckpointForkJson {
                schema_version: 1,
                action: "fork",
                parent_id: &prepared.parent.id,
                child_vm_name: name,
                booted: false,
                checkpoint: &child,
            })?;
        } else {
            ui::success(&format!(
                "forked {} -> checkpoint {} (vm '{}')",
                prepared.parent.id.as_str(),
                child.id.as_str(),
                name
            ));
            ui::info(&format!(
                "child '{name}' materialized at {}; re-run the fork with --boot to admit and launch a child, or delete the directory to discard this one",
                prepared.destination.display()
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::commands::dispatch::TopLevelCommand;
        use clap::Parser;
        use mvm_core::checkpoint::CheckpointId;
        use mvm_core::plan::{SecretBinding, SecretSource, test_support::PlanFixture};
        use mvm_core::util::test_env::TestEnv;
        use std::os::unix::fs::{PermissionsExt, symlink};

        struct Fixture {
            _env: TestEnv,
            home: tempfile::TempDir,
            store: CheckpointStore,
            parent: CheckpointMeta,
            plan: ExecutionPlan,
        }

        fn write_private(path: &Path, bytes: &[u8]) {
            mvm_core::config::create_private_dir(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn secret(source: SecretSource) -> SecretBinding {
            SecretBinding {
                name: "TOKEN".into(),
                source,
                destinations: Vec::new(),
                approval_required: true,
            }
        }

        impl Fixture {
            fn new(secrets: Vec<SecretBinding>) -> Self {
                let mut env = TestEnv::new();
                let home = tempfile::tempdir().unwrap();
                env.isolate_mvm_home(home.path());
                env.set(
                    mvm_runtime::vm::snapshot_key::SNAPSHOT_TENANT_KEY_ENV,
                    "19".repeat(32),
                );
                let source = home.path().join("rootfs.ext4");
                write_private(&source, b"fake-ext4-bytes");
                let store = CheckpointStore::open();
                let parent = mvm_runtime::checkpoint::capture_fs_quick(
                    &store,
                    mvm_runtime::checkpoint::CaptureFsQuickParams {
                        id: CheckpointId::new("parent"),
                        vm_name: "parentvm".into(),
                        rootfs: source,
                        supervisor_config_digest: "config".into(),
                        runtime_overlay_version: None,
                        tag: None,
                        created_unix: 1,
                        quiesced: true,
                        grants: None,
                        key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
                    },
                )
                .unwrap();
                let mut plan = PlanFixture::new()
                    .tenant("local")
                    .workload("parentvm")
                    .secrets(secrets)
                    .build();
                plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
                let fixture = Self {
                    _env: env,
                    home,
                    store,
                    parent,
                    plan,
                };
                fixture.persist_plan(&fixture.plan);
                fixture.emit_creation(&fixture.plan, &fixture.parent);
                fixture
            }

            fn plan_path(&self) -> std::path::PathBuf {
                self.home.path().join("vms/parentvm/plan.json")
            }

            fn persist_plan(&self, plan: &ExecutionPlan) {
                write_private(&self.plan_path(), &serde_json::to_vec(plan).unwrap());
            }

            fn emit_creation(&self, plan: &ExecutionPlan, parent: &CheckpointMeta) {
                let key = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
                let emitter = AuditEmitter::new(key.signing).unwrap();
                mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, plan, parent).unwrap();
            }

            fn params(
                &self,
                allow_secret_drop: bool,
            ) -> super::super::super::ForkFsQuickArmParams<'_> {
                super::super::super::ForkFsQuickArmParams {
                    store: &self.store,
                    checkpoint: &self.parent.id,
                    new_id: Some("childvm".into()),
                    boot: false,
                    hypervisor: "firecracker",
                    cpus_override: None,
                    memory_override: None,
                    declared_secrets: &[],
                    allow_secret_drop,
                    json: true,
                }
            }

            fn invoke(&self, allow_secret_drop: bool) -> Result<()> {
                let mut args = vec![
                    "mvmctl",
                    "machine",
                    "checkpoint",
                    "fork",
                    "parent",
                    "--new-id",
                    "childvm",
                    "--json",
                ];
                if allow_secret_drop {
                    args.push("--allow-secret-drop");
                }
                let cli = crate::commands::Cli::try_parse_from(args)?;
                cli.command
                    .clone()
                    .run(&cli, &mvm_core::user_config::MvmConfig::default())
            }

            fn assert_refused_unchanged(&self, allow_secret_drop: bool, message: &str) {
                let before = snapshot(self.home.path());
                let error = self.invoke(allow_secret_drop).unwrap_err();
                assert!(format!("{error:#}").contains(message), "{error:#}");
                assert_eq!(
                    before,
                    snapshot(self.home.path()),
                    "refusal must not mutate state"
                );
            }
        }

        fn snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, (u32, Vec<u8>)> {
            fn walk(
                root: &Path,
                path: &Path,
                result: &mut std::collections::BTreeMap<std::path::PathBuf, (u32, Vec<u8>)>,
            ) {
                let metadata = std::fs::symlink_metadata(path).unwrap();
                let bytes = if metadata.is_file() {
                    std::fs::read(path).unwrap()
                } else if metadata.file_type().is_symlink() {
                    std::fs::read_link(path)
                        .unwrap()
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec()
                } else {
                    Vec::new()
                };
                result.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    (metadata.mode(), bytes),
                );
                if metadata.is_dir() {
                    for entry in std::fs::read_dir(path).unwrap() {
                        walk(root, &entry.unwrap().path(), result);
                    }
                }
            }
            let mut result = std::collections::BTreeMap::new();
            walk(root, root, &mut result);
            result
        }

        #[test]
        fn parsed_unbooted_fork_requires_explicit_drop_of_known_parent_bindings() {
            let fixture = Fixture::new(vec![secret(SecretSource::Keystore {
                address: "missing".into(),
            })]);
            fixture.assert_refused_unchanged(false, "would drop parent secret bindings");
            assert!(!fixture.home.path().join("keyholder").exists());
        }

        #[test]
        fn parsed_unbooted_fork_materializes_and_audits_authenticated_empty_parent() {
            let fixture = Fixture::new(Vec::new());
            fixture.invoke(false).unwrap();
            assert_eq!(
                std::fs::read(fixture.home.path().join("vms/childvm/rootfs.ext4")).unwrap(),
                b"fake-ext4-bytes"
            );
            let keys = LocalTranscriptStore::open(fixture.home.path()).unwrap();
            let (anchor, _) = load_anchor(fixture.home.path(), &keys).unwrap();
            let children = fixture
                .store
                .list()
                .unwrap()
                .into_iter()
                .filter(|meta| meta.vm_name == "childvm")
                .collect::<Vec<_>>();
            assert_eq!(children.len(), 1);
            verify_lineage(&fixture.store, &children[0].id, &anchor).unwrap();
            assert_eq!(
                anchor.checkpoint_plan_id(&children[0]).unwrap(),
                Some(fixture.plan.plan_id.0)
            );
        }

        #[test]
        fn canonical_audit_member_modes_are_accepted_without_chmod_or_rewrite() {
            for mode in [0o600, 0o644] {
                let fixture = Fixture::new(Vec::new());
                let path = fixture.home.path().join("audit/local.jsonl");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                let before = snapshot(fixture.home.path());
                let _prepared = prepare(fixture.params(false)).unwrap();
                assert_eq!(before, snapshot(fixture.home.path()));
            }
        }

        #[test]
        fn parsed_explicit_drop_materializes_without_child_plan_or_secret_lookup() {
            let fixture = Fixture::new(vec![secret(SecretSource::Keystore {
                address: "missing".into(),
            })]);
            fixture.invoke(true).unwrap();
            assert!(!fixture.home.path().join("vms/childvm/plan.json").exists());
            let chain =
                std::fs::read_to_string(fixture.home.path().join("audit/local.jsonl")).unwrap();
            let event: mvm_hostd::supervisor::SignedEnvelope =
                serde_json::from_str(chain.lines().last().unwrap()).unwrap();
            assert_eq!(event.entry.event, "checkpoint.forked");
            assert_eq!(
                event
                    .entry
                    .labels
                    .get("secret_bindings")
                    .map(String::as_str),
                Some("[]")
            );
        }

        #[test]
        fn parsed_missing_candidate_refuses_even_with_allow_drop() {
            let fixture = Fixture::new(Vec::new());
            std::fs::remove_file(fixture.plan_path()).unwrap();
            fixture.assert_refused_unchanged(true, "required existing fork authority file");
        }

        #[test]
        fn envelope_candidate_is_data_bound_to_the_original_content_id() {
            let fixture = Fixture::new(Vec::new());
            let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
            let envelope = mvm_core::plan::sign_plan(&fixture.plan, &key, "candidate-only");
            write_private(
                &fixture.plan_path(),
                &serde_json::to_vec(&envelope).unwrap(),
            );
            let before = snapshot(fixture.home.path());
            let _prepared = prepare(fixture.params(false)).unwrap();
            assert_eq!(before, snapshot(fixture.home.path()));
            let mut different = fixture.plan.clone();
            different.resources.cpus += 1;
            let envelope = mvm_core::plan::sign_plan(&different, &key, "candidate-only");
            write_private(
                &fixture.plan_path(),
                &serde_json::to_vec(&envelope).unwrap(),
            );
            fixture.assert_refused_unchanged(true, "does not match authenticated original");
        }

        #[test]
        fn replaced_or_non_content_addressed_plan_cannot_be_original_policy() {
            for change in 0..5 {
                let fixture = Fixture::new(Vec::new());
                let mut candidate = fixture.plan.clone();
                match change {
                    0 => candidate.plan_id.0 = "legacy-plan-id".into(),
                    1 => candidate.tenant.0 = "other".into(),
                    2 => candidate.workload.0 = "differentvm".into(),
                    3 => candidate.secrets.push(secret(SecretSource::Keystore {
                        address: "new".into(),
                    })),
                    _ => candidate.resources.cpus += 1,
                }
                if change != 0 {
                    candidate.plan_id = mvm_core::plan::compute_plan_id(&candidate);
                }
                fixture.persist_plan(&candidate);
                fixture.assert_refused_unchanged(
                    true,
                    if change == 0 {
                        "not content-addressed"
                    } else {
                        "does not match authenticated original"
                    },
                );
            }
        }

        #[test]
        fn malformed_candidate_diagnostics_do_not_echo_sensitive_bytes() {
            let fixture = Fixture::new(Vec::new());
            write_private(
                &fixture.plan_path(),
                br#"{"schema_version":"SENSITIVE_FORK_MARKER"}"#,
            );
            let error = fixture.invoke(true).unwrap_err();
            for exposed in [
                format!("{error}"),
                format!("{error:#}"),
                format!("{error:?}"),
                format!("{error:#?}"),
            ] {
                assert!(!exposed.contains("SENSITIVE_FORK_MARKER"));
                assert!(exposed.contains("malformed"));
            }
        }

        #[test]
        fn oversized_and_unsafe_candidate_members_refuse_without_repair() {
            for kind in 0..6 {
                let fixture = Fixture::new(Vec::new());
                let path = fixture.plan_path();
                match kind {
                    0 => {
                        OpenOptions::new()
                            .write(true)
                            .open(&path)
                            .unwrap()
                            .set_len(MAX_FORK_PLAN_BYTES + 1)
                            .unwrap();
                    }
                    1 => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                        .unwrap(),
                    2 => std::fs::hard_link(&path, fixture.home.path().join("alias")).unwrap(),
                    3 => {
                        let target = fixture.home.path().join("candidate");
                        std::fs::rename(&path, &target).unwrap();
                        symlink(target, &path).unwrap();
                    }
                    4 => {
                        std::fs::remove_file(&path).unwrap();
                        std::fs::create_dir(&path).unwrap();
                    }
                    _ => {
                        std::fs::remove_file(&path).unwrap();
                        assert!(
                            std::process::Command::new("mkfifo")
                                .arg(&path)
                                .status()
                                .unwrap()
                                .success()
                        );
                    }
                }
                fixture.assert_refused_unchanged(
                    true,
                    if kind == 0 { "4 MiB" } else { "fork authority" },
                );
            }
        }

        #[test]
        fn duplicate_and_conflicting_signed_creation_evidence_refuse() {
            for conflicting in [false, true] {
                let fixture = Fixture::new(Vec::new());
                let mut meta = fixture.parent.clone();
                if conflicting {
                    meta.supervisor_config_digest = "changed".into();
                    meta.meta_digest = meta.compute_meta_digest();
                }
                fixture.emit_creation(&fixture.plan, &meta);
                fixture.assert_refused_unchanged(true, "duplicate or conflicting");
            }
        }

        #[test]
        fn missing_tampered_or_wrong_tenant_history_refuses() {
            for kind in 0..3 {
                let fixture = Fixture::new(Vec::new());
                let path = fixture.home.path().join("audit/local.jsonl");
                match kind {
                    0 => std::fs::remove_file(&path).unwrap(),
                    1 => {
                        let text = std::fs::read_to_string(&path)
                            .unwrap()
                            .replace("checkpoint.created", "checkpoint.changed");
                        write_private(&path, text.as_bytes());
                    }
                    _ => std::fs::rename(&path, fixture.home.path().join("audit/other.jsonl"))
                        .unwrap(),
                }
                fixture.assert_refused_unchanged(
                    true,
                    match kind {
                        0 => "history is missing",
                        1 => "failed verification",
                        _ => "tenant does not match",
                    },
                );
            }
        }

        #[test]
        fn pruned_history_refuses_even_when_original_creation_is_retained() {
            use mvm_hostd::supervisor::FileAuditSigner;
            use mvm_hostd::supervisor::audit::{AuditSigner, for_plan};
            use mvm_hostd::supervisor::audit_file::RotationPolicy;

            let fixture = Fixture::new(Vec::new());
            let audit = fixture.home.path().join("audit");
            std::fs::remove_file(audit.join("local.jsonl")).unwrap();
            let keys = LocalTranscriptStore::open(fixture.home.path()).unwrap();
            let (key, verifying) = keys.existing_host_keypair().unwrap();
            let signer = FileAuditSigner::open(key, &audit)
                .unwrap()
                .with_rotation(RotationPolicy::at_bytes(1));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            for _ in 0..2 {
                runtime
                    .block_on(signer.sign_and_emit(&for_plan(
                        &fixture.plan,
                        None,
                        "plan.launched",
                        [],
                    )))
                    .unwrap();
            }
            drop(signer);
            fixture.emit_creation(&fixture.plan, &fixture.parent);
            mvm_client::audit::prune_audit("local", 1, mvm_client::audit::AuditPruneMode::Commit)
                .unwrap();
            let history =
                mvm_core::audit_verify::set::read_verified_history(&audit, "local", &verifying)
                    .unwrap();
            assert!(history.pruned.is_some());
            assert!(
                history
                    .segments
                    .iter()
                    .flat_map(|segment| { segment.entries.as_ref().unwrap() })
                    .any(|entry| entry.event == "checkpoint.created")
            );
            fixture.assert_refused_unchanged(true, "pruned history");
        }

        #[test]
        fn missing_existing_signer_halves_never_initialize_replacements() {
            for member in ["host-signer.ed25519", "host-signer.pub"] {
                let fixture = Fixture::new(Vec::new());
                std::fs::remove_file(fixture.home.path().join("keys").join(member)).unwrap();
                fixture.assert_refused_unchanged(true, "authority");
            }
        }

        #[test]
        fn unsupported_declared_source_precedes_authority_and_metadata_lookups() {
            let fixture = Fixture::new(Vec::new());
            std::fs::remove_dir_all(fixture.home.path().join("keys")).unwrap();
            let bindings = [
                secret(SecretSource::Keystore {
                    address: "missing".into(),
                }),
                secret(SecretSource::External {
                    provider: "external".into(),
                    path: "value".into(),
                }),
            ];
            let before = snapshot(fixture.home.path());
            let mut params = fixture.params(true);
            params.declared_secrets = &bindings;
            let error = match prepare(params) {
                Ok(_) => panic!("unsupported source must refuse"),
                Err(error) => error,
            };
            assert!(format!("{error:#}").contains("unsupported secret source"));
            assert_eq!(before, snapshot(fixture.home.path()));
        }

        #[test]
        fn static_managed_symlinks_and_unsafe_audit_members_refuse_without_repair() {
            for managed in ["audit", "keys", "vms", "vms/parentvm", "checkpoints"] {
                let fixture = Fixture::new(Vec::new());
                let path = fixture.home.path().join(managed);
                let saved = fixture.home.path().join("external-target");
                std::fs::rename(&path, &saved).unwrap();
                symlink(&saved, &path).unwrap();
                fixture.assert_refused_unchanged(
                    true,
                    if managed == "keys" {
                        "authority"
                    } else {
                        "fork authority"
                    },
                );
            }
            for mode in [0o640, 0o666] {
                let fixture = Fixture::new(Vec::new());
                std::fs::set_permissions(
                    fixture.home.path().join("audit/local.jsonl"),
                    std::fs::Permissions::from_mode(mode),
                )
                .unwrap();
                fixture.assert_refused_unchanged(true, "fork authority file");
            }
        }

        #[test]
        fn nonregular_or_aliased_audit_members_and_unsafe_ancestors_refuse() {
            for kind in 0..4 {
                let fixture = Fixture::new(Vec::new());
                let path = fixture.home.path().join("audit/local.jsonl");
                match kind {
                    0 => {
                        std::fs::hard_link(&path, fixture.home.path().join("audit-alias")).unwrap()
                    }
                    1 => {
                        let saved = fixture.home.path().join("saved-chain");
                        std::fs::rename(&path, &saved).unwrap();
                        symlink(saved, &path).unwrap();
                    }
                    2 => {
                        std::fs::remove_file(&path).unwrap();
                        assert!(
                            std::process::Command::new("mkfifo")
                                .arg(&path)
                                .status()
                                .unwrap()
                                .success()
                        );
                    }
                    _ => std::fs::set_permissions(
                        fixture.home.path().join("audit"),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .unwrap(),
                }
                fixture.assert_refused_unchanged(true, "fork authority");
            }
        }

        #[test]
        fn parent_policy_with_unsupported_sources_refuses_without_metadata() {
            let fixture = Fixture::new(vec![secret(SecretSource::External {
                provider: "external".into(),
                path: "value".into(),
            })]);
            fixture.assert_refused_unchanged(true, "unsupported secret source");
        }

        #[test]
        fn preexisting_vm_directory_and_dangling_alias_are_not_overwritten() {
            for alias in [false, true] {
                let fixture = Fixture::new(Vec::new());
                let path = fixture.home.path().join("vms/childvm");
                if alias {
                    symlink(fixture.home.path().join("missing"), &path).unwrap();
                } else {
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(path.join("keep"), b"retained").unwrap();
                }
                fixture.assert_refused_unchanged(true, "occupied");
            }
        }

        #[test]
        fn prepared_checkpoint_collision_and_changed_parent_refuse_before_copy() {
            for kind in 0..3 {
                let fixture = Fixture::new(Vec::new());
                let prepared = prepare(fixture.params(true)).unwrap();
                if kind == 0 {
                    let mut parent = fixture.parent.clone();
                    parent.tag = Some("changed-after-proof".into());
                    fixture.store.write_meta(&parent).unwrap();
                } else if kind == 1 {
                    symlink(
                        fixture.home.path().join("missing"),
                        fixture.store.dir_for(&prepared.child_id),
                    )
                    .unwrap();
                } else {
                    std::fs::create_dir_all(fixture.store.dir_for(&prepared.child_id)).unwrap();
                    std::fs::write(
                        fixture.store.dir_for(&prepared.child_id).join("meta.json"),
                        b"malformed occupant",
                    )
                    .unwrap();
                }
                let before = snapshot(fixture.home.path());
                assert!(prepared.materialize().is_err());
                assert_eq!(before, snapshot(fixture.home.path()));
                assert!(!prepared.destination.exists());
            }
        }

        #[test]
        fn parsed_initial_metadata_fifo_refuses_without_blocking_or_effects() {
            let fixture = Fixture::new(Vec::new());
            let path = fixture.store.dir_for(&fixture.parent.id).join("meta.json");
            std::fs::remove_file(&path).unwrap();
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            fixture.assert_refused_unchanged(true, "fork authority file");
        }

        #[test]
        fn unrelated_metadata_fifo_refuses_before_canonical_ancestry_scan() {
            let fixture = Fixture::new(Vec::new());
            let path = fixture
                .store
                .dir_for(&CheckpointId::new("unrelated"))
                .join("meta.json");
            mvm_core::config::create_private_dir(path.parent().unwrap()).unwrap();
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            fixture.assert_refused_unchanged(true, "fork authority file");
        }

        #[test]
        fn initial_and_unrelated_unsafe_or_oversized_metadata_refuse_unchanged() {
            for initial in [false, true] {
                for kind in 0..7 {
                    let fixture = Fixture::new(Vec::new());
                    let id = if initial {
                        fixture.parent.id.clone()
                    } else {
                        CheckpointId::new("unrelated")
                    };
                    let mut meta = fixture.parent.clone();
                    meta.id = id.clone();
                    mvm_core::config::create_private_dir(fixture.store.dir_for(&id)).unwrap();
                    fixture.store.write_meta(&meta).unwrap();
                    let path = fixture.store.dir_for(&id).join("meta.json");
                    let message = match kind {
                        0 => {
                            OpenOptions::new()
                                .write(true)
                                .open(&path)
                                .unwrap()
                                .set_len(MAX_CHECKPOINT_META_BYTES + 1)
                                .unwrap();
                            "4 MiB"
                        }
                        1 => {
                            std::fs::hard_link(&path, fixture.home.path().join("meta-alias"))
                                .unwrap();
                            "fork authority"
                        }
                        2 => {
                            let saved = fixture.home.path().join("saved-meta");
                            std::fs::rename(&path, &saved).unwrap();
                            symlink(saved, &path).unwrap();
                            "fork authority"
                        }
                        3 => {
                            std::fs::remove_file(&path).unwrap();
                            std::fs::create_dir(&path).unwrap();
                            "fork authority"
                        }
                        4 | 5 => {
                            std::fs::set_permissions(
                                &path,
                                std::fs::Permissions::from_mode(if kind == 4 {
                                    0o640
                                } else {
                                    0o666
                                }),
                            )
                            .unwrap();
                            "fork authority"
                        }
                        _ => {
                            meta.id = CheckpointId::new("different");
                            write_private(&path, &serde_json::to_vec(&meta).unwrap());
                            "ID does not match"
                        }
                    };
                    fixture.assert_refused_unchanged(true, message);
                }
            }
        }

        #[test]
        fn metadata_parse_failures_are_redacted_and_do_not_initialize_authority() {
            for initial in [false, true] {
                let fixture = Fixture::new(Vec::new());
                let id = if initial {
                    fixture.parent.id.clone()
                } else {
                    CheckpointId::new("unrelated")
                };
                let path = fixture.store.dir_for(&id).join("meta.json");
                write_private(&path, br#"{"class":"SENSITIVE_META_MARKER"}"#);
                let before = snapshot(fixture.home.path());
                let error = fixture.invoke(true).unwrap_err();
                for text in [
                    format!("{error}"),
                    format!("{error:#}"),
                    format!("{error:?}"),
                    format!("{error:#?}"),
                ] {
                    assert!(text.contains("malformed"), "{text}");
                    assert!(!text.contains("SENSITIVE_META_MARKER"));
                }
                assert_eq!(before, snapshot(fixture.home.path()));
            }
        }

        #[test]
        fn canonical_metadata_is_0600_and_0644_refuses_without_repair() {
            for initial in [false, true] {
                let fixture = Fixture::new(Vec::new());
                let mut meta = fixture.parent.clone();
                if !initial {
                    meta.id = CheckpointId::new("unrelated");
                    mvm_core::config::create_private_dir(fixture.store.dir_for(&meta.id)).unwrap();
                    fixture.store.write_meta(&meta).unwrap();
                }
                let path = fixture.store.dir_for(&meta.id).join("meta.json");
                assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
                fixture.assert_refused_unchanged(true, "fork authority file");
            }
        }

        #[test]
        fn store_entry_bound_counts_dot_names_and_ignored_files_before_filtering() {
            let fixture = Fixture::new(Vec::new());
            for n in 0..MAX_CHECKPOINT_STORE_ENTRIES {
                std::fs::write(fixture.store.root().join(format!(".ignored-{n}")), []).unwrap();
            }
            fixture.assert_refused_unchanged(true, "256 examined-entry");
        }

        #[test]
        fn store_aggregate_budget_refuses_before_reading_an_excess_metadata_member() {
            let fixture = Fixture::new(Vec::new());
            for n in 0..17 {
                let mut meta = fixture.parent.clone();
                meta.id = CheckpointId::new(format!("large-{n}"));
                meta.tag = Some("x".repeat(MAX_CHECKPOINT_META_BYTES as usize - 4096));
                mvm_core::config::create_private_dir(fixture.store.dir_for(&meta.id)).unwrap();
                fixture.store.write_meta(&meta).unwrap();
                assert!(
                    std::fs::metadata(fixture.store.dir_for(&meta.id).join("meta.json"))
                        .unwrap()
                        .len()
                        <= MAX_CHECKPOINT_META_BYTES
                );
            }
            fixture.assert_refused_unchanged(true, "64 MiB aggregate");
        }

        #[test]
        fn unknown_checkpoint_directory_names_refuse_without_lossy_aliasing() {
            let fixture = Fixture::new(Vec::new());
            let path = fixture.store.root().join("invalid\ncheckpoint");
            mvm_core::config::create_private_dir(&path).unwrap();
            fixture.assert_refused_unchanged(true, "directory ID is invalid");
        }

        #[test]
        fn valid_vm_full_metadata_classification_does_not_boot_or_mutate_it() {
            let fixture = Fixture::new(Vec::new());
            let mut parent = fixture.parent.clone();
            parent.class = mvm_core::checkpoint::CheckpointClass::VmFull;
            parent.meta_digest = parent.compute_meta_digest();
            fixture.store.write_meta(&parent).unwrap();
            let before = snapshot(fixture.home.path());
            let classified =
                super::super::read_unbooted_fork_parent(&fixture.store, &parent.id).unwrap();
            assert_eq!(classified, parent);
            assert_eq!(before, snapshot(fixture.home.path()));
        }

        #[test]
        fn changed_source_refuses_through_canonical_content_verification() {
            let fixture = Fixture::new(Vec::new());
            let prepared = prepare(fixture.params(true)).unwrap();
            let content = std::fs::read_dir(fixture.store.content_dir(&fixture.parent.id))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.is_file())
                .expect("protected capture has an authenticated index");
            std::fs::write(&content, b"changed-content").unwrap();
            assert!(prepared.materialize().is_err());
            assert!(!prepared.destination.exists());
        }

        #[test]
        fn postcopy_audit_failure_reports_and_retains_materialized_artifacts() {
            let fixture = Fixture::new(Vec::new());
            let prepared = prepare(fixture.params(true)).unwrap();
            let child = prepared.materialize().unwrap();
            let chain = fixture.home.path().join("audit/local.jsonl");
            std::fs::remove_file(&chain).unwrap();
            std::fs::create_dir(&chain).unwrap();
            let error = prepared.publish(&child).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("lineage publication failed"), "{message}");
            assert!(message.contains(&prepared.destination.display().to_string()));
            assert!(message.contains(child.id.as_str()));
            assert_eq!(
                std::fs::read(prepared.destination.join("rootfs.ext4")).unwrap(),
                b"fake-ext4-bytes"
            );
            assert_eq!(fixture.store.read_meta(&child.id).unwrap(), child);
        }
    }
}

#[derive(Serialize)]
struct CheckpointVerifyJson<'a> {
    schema_version: u8,
    action: &'static str,
    id: &'a str,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// A [`CheckpointChainAnchor`] backed by the host-signed audit chains on disk.
///
/// Verifies every host-lifecycle chain's signatures up front (skipping the
/// per-VM workload chains, which use a different format) and indexes the
/// content-address each checkpoint's creation entry recorded. Only entries from
/// chains that verify clean are indexed: an entry stranded behind a tampered
/// line is not trusted, so the checkpoint it names fails closed as un-anchored.
///
/// A chain that fails verification is skipped but *remembered*, because the two
/// ways a lookup can come back empty are not the same finding and must not
/// share a message. With every chain clean, an empty lookup means the record
/// was never audited — a step someone skipped, fixable by re-capturing with a
/// signer present. With a chain unreadable, an empty lookup means only that the
/// ledger cannot answer: the record may be perfectly well audited behind the
/// broken line. Reporting the second as the first buries a tamper signal under
/// a routine-looking message. Both fail closed; only the reason differs, and
/// only one of them tells you to investigate.
pub struct SignedChainAnchor {
    /// `<namespace>:<id>` -> content-address the signed chain recorded at
    /// creation. The namespace tag (`checkpoint` / `image`) keeps the checkpoint
    /// and image key spaces structurally disjoint in one map, rather than
    /// relying on their raw id/digest strings happening not to collide.
    recorded: std::collections::HashMap<String, RecordedCreation>,
    /// Host-lifecycle chains whose signatures did not verify, in the order
    /// encountered. Non-empty turns a lookup miss from "never audited" into
    /// "cannot tell" — see the type docs.
    unverifiable: Vec<std::path::PathBuf>,
}

/// What a signed creation entry recorded about one record.
#[derive(Debug, Clone)]
struct RecordedCreation {
    /// The content-address the entry recorded.
    digest: CheckpointDigest,
    /// The tenant whose chain the entry was signed into.
    tenant: String,
    plan_id: String,
}

/// Namespace tag for a checkpoint-id key in [`SignedChainAnchor::recorded`].
const CHECKPOINT_NS: &str = "checkpoint";
/// Namespace tag for an image-node-digest key in [`SignedChainAnchor::recorded`].
const IMAGE_NS: &str = "image";

/// Compose a namespaced anchor-map key so the checkpoint and image key spaces
/// cannot collide. The same composition is used by the indexer (writer) and
/// both `recorded_creation_digest` lookups (readers), so the key cannot drift.
fn anchor_key(namespace: &str, id: &str) -> String {
    format!("{namespace}:{id}")
}

impl SignedChainAnchor {
    /// Plan identity recorded by the verified creation entry for a checkpoint.
    pub(super) fn checkpoint_plan_id(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.plan_id))
    }

    /// Construct an intentionally empty anchor for resident claims whose
    /// signed snapshot manifest is the publication witness. Saved-state
    /// restores must use [`Self::load`] and verify the full audit chain.
    pub fn empty() -> Self {
        Self {
            recorded: std::collections::HashMap::new(),
            unverifiable: Vec::new(),
        }
    }

    pub fn load() -> Result<Self> {
        use mvm_hostd::audit::emitter::default_audit_dir;

        let dir = default_audit_dir()?;
        let mut recorded = std::collections::HashMap::new();
        let mut unverifiable = Vec::new();
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // No audit dir yet → nothing to anchor; every lookup is None (fail closed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    recorded,
                    unverifiable,
                });
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };

        // All lifecycle chains are signed under the one host key.
        let signer = super::super::host_signer::load_or_init()
            .context("loading host signer to anchor checkpoint lineage")?;

        for entry in read_dir {
            let path = entry?.path();
            if !mvm_core::config::is_host_lifecycle_chain(&path) {
                continue;
            }
            // A chain we cannot verify cannot anchor anything: skip it whole so a
            // tampered line strands (rather than silently trusts) its entries.
            // Recorded, not just logged — a later lookup miss has to be able to
            // say "cannot tell" instead of "never audited".
            if let Err(e) = mvm_hostd::supervisor::verify_audit_chain(&path, &signer.verifying) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "audit chain failed verification; its entries will not anchor any checkpoint"
                );
                unverifiable.push(path);
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            for line in content.lines() {
                if line.is_empty() {
                    continue;
                }
                let envelope: mvm_hostd::supervisor::SignedEnvelope = serde_json::from_str(line)
                    .with_context(|| format!("parsing audit line in {}", path.display()))?;
                index_creation_digest(&mut recorded, &envelope)?;
            }
        }
        Ok(Self {
            recorded,
            unverifiable,
        })
    }

    /// Resolve one namespaced anchor key.
    ///
    /// A hit is a hit regardless of what else on disk is broken — it came from a
    /// chain that verified. A miss is only honestly "never audited" when every
    /// chain verified; with one unreadable, the honest answer is that we cannot
    /// tell, which is an `Err` rather than a `None`. Both refuse the record, so
    /// this changes no verdict — it changes what the operator is told to do
    /// about it.
    fn lookup(&self, key: &str) -> Result<Option<RecordedCreation>> {
        if let Some(recorded) = self.recorded.get(key) {
            return Ok(Some(recorded.clone()));
        }
        if self.unverifiable.is_empty() {
            return Ok(None);
        }
        let paths = self
            .unverifiable
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "{}: {} audit chain(s) unverifiable: {paths}. The record may well be audited — the \
             ledger is what cannot be read, so this is a damaged integrity chain and not a \
             missing audit entry. Run `mvmctl trust audit verify` to see where the chain breaks. \
             Recovery is deliberate and manual: quarantine the file under a new name so the \
             evidence survives. Do not delete it, and do not re-sign it — a chain that can be \
             reset on demand cannot detect tampering.",
            mvm_runtime::lineage::LEDGER_UNVERIFIABLE,
            self.unverifiable.len()
        )
    }
}

/// Index one signed audit entry's creation content-address, when it is a
/// checkpoint or image-node creation event. `checkpoint.created` keys on
/// `checkpoint_id`/`meta_digest`; `checkpoint.forked` is a child's creation, so
/// it keys on `child_id`/`child_digest`. `image.created` has no separate id —
/// the node's identity *is* its content-address — so it keys the digest under
/// itself.
fn index_creation_digest(
    recorded: &mut std::collections::HashMap<String, RecordedCreation>,
    envelope: &mvm_hostd::supervisor::SignedEnvelope,
) -> Result<()> {
    index_creation_entry(recorded, &envelope.entry)
}

/// The (id-label, digest-label, namespace) a creation event keys on, or `None`
/// for an event that records no creation.
fn creation_keys(event: &str) -> Option<(&'static str, &'static str, &'static str)> {
    use mvm_hostd::audit::emitter::checkpoint_audit as k;
    use mvm_hostd::audit::emitter::image_audit as ik;
    if event == k::CREATED_EVENT {
        Some((k::LABEL_CHECKPOINT_ID, k::LABEL_META_DIGEST, CHECKPOINT_NS))
    } else if event == k::FORKED_EVENT {
        Some((k::LABEL_CHILD_ID, k::LABEL_CHILD_DIGEST, CHECKPOINT_NS))
    } else if event == ik::CREATED_EVENT {
        Some((ik::LABEL_NODE_DIGEST, ik::LABEL_NODE_DIGEST, IMAGE_NS))
    } else {
        None
    }
}

/// [`index_creation_digest`] for an entry already authenticated.
fn index_creation_entry(
    recorded: &mut std::collections::HashMap<String, RecordedCreation>,
    entry: &mvm_core::audit_verify::PlanAuditEntry,
) -> Result<()> {
    let Some((id_key, digest_key, namespace)) = creation_keys(entry.event.as_str()) else {
        return Ok(());
    };
    let labels = &entry.labels;
    if let (Some(id), Some(digest)) = (labels.get(id_key), labels.get(digest_key)) {
        recorded.insert(
            anchor_key(namespace, id),
            RecordedCreation {
                digest: CheckpointDigest::parse(digest.clone())?,
                tenant: entry.tenant.0.clone(),
                plan_id: entry.plan_id.0.clone(),
            },
        );
    }
    Ok(())
}

/// The anchor a warm claim verifies its parent against.
///
/// [`SignedChainAnchor::load`] verifies every host-lifecycle chain end to end,
/// and that walk grows with every entry the host has ever written: on a host
/// with about 11 MB of audit history it alone put warm claims past the 300 ms
/// ceiling. A claim needs one answer — the creation entry of the parent it is
/// about to restore — and that parent was captured and audited recently, so its
/// entry is almost always in a live segment. This anchor authenticates that one
/// entry in place ([`mvm_core::audit_verify::live::authenticate_live_entries`]):
/// its host signature over the exact signed bytes and its chain link to the
/// line before it. Any other question, and the parent's own question whenever
/// the live segments do not answer it with exactly one authenticated creation
/// entry, falls back to the full walk, so every verdict the full anchor would
/// reach on those paths is unchanged.
///
/// What a claim no longer does is re-attest the rest of the history on every
/// launch. That stays verified where history is the question:
/// `mvmctl trust audit verify`, doctor's chain check, `mvmctl vm checkpoint
/// verify`, and the pool refill, which still use [`SignedChainAnchor::load`].
pub struct ClaimChainAnchor {
    /// Creation entries authenticated in place in a live segment.
    preverified: std::collections::HashMap<String, RecordedCreation>,
    /// The full walk, loaded only when a lookup is not answered above.
    full: std::sync::OnceLock<std::result::Result<SignedChainAnchor, String>>,
}

impl ClaimChainAnchor {
    /// An anchor that answers `checkpoint`'s creation from the live segments
    /// when they hold exactly one authenticated creation entry for it.
    pub fn for_checkpoint(checkpoint: &mvm_core::checkpoint::CheckpointId) -> Result<Self> {
        use mvm_hostd::audit::emitter::default_audit_dir;
        let dir = default_audit_dir()?;
        let signer = super::super::host_signer::load_or_init()
            .context("loading host signer to anchor a warm claim's parent")?;
        let mut preverified = std::collections::HashMap::new();
        if let Some(found) = live_creation_entry(&dir, &signer.verifying, checkpoint.as_str()) {
            preverified.insert(anchor_key(CHECKPOINT_NS, checkpoint.as_str()), found);
        }
        Ok(Self {
            preverified,
            full: std::sync::OnceLock::new(),
        })
    }

    /// Whether a lookup for `checkpoint` will be answered without the full walk.
    #[cfg(test)]
    fn answers_in_place(&self, checkpoint: &str) -> bool {
        self.preverified
            .contains_key(&anchor_key(CHECKPOINT_NS, checkpoint))
    }

    fn lookup(&self, key: &str) -> Result<Option<RecordedCreation>> {
        if let Some(recorded) = self.preverified.get(key) {
            return Ok(Some(recorded.clone()));
        }
        match self
            .full
            .get_or_init(|| SignedChainAnchor::load().map_err(|e| format!("{e:#}")))
        {
            Ok(full) => full.lookup(key),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }
}

/// The one authenticated creation entry for `checkpoint` across every tenant's
/// live segment, or `None` when there is not exactly one — no entry, several,
/// or one that cannot be read or authenticated. `None` sends the caller to the
/// full walk, which reaches its own verdict on every one of those cases.
fn live_creation_entry(
    dir: &std::path::Path,
    key: &ed25519_dalek::VerifyingKey,
    checkpoint: &str,
) -> Option<RecordedCreation> {
    let tenants = live_chain_tenants(dir).ok()?;
    let mut found = Vec::new();
    for tenant in tenants {
        let matches = mvm_core::audit_verify::live::authenticate_live_entries(
            dir,
            &tenant,
            key,
            checkpoint,
            |entry| creation_keys(&entry.event).is_some(),
        )
        .ok()?;
        for entry in matches.entries {
            let mut recorded = std::collections::HashMap::new();
            index_creation_entry(&mut recorded, &entry).ok()?;
            if let Some(hit) = recorded.remove(&anchor_key(CHECKPOINT_NS, checkpoint)) {
                found.push(hit);
            }
        }
    }
    let only = found.pop()?;
    found.is_empty().then_some(only)
}

/// Every tenant with a live host-lifecycle chain in `dir`.
fn live_chain_tenants(dir: &std::path::Path) -> std::io::Result<Vec<String>> {
    let mut tenants = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !mvm_core::config::is_host_lifecycle_chain(&path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.contains(mvm_core::config::AUDIT_SEGMENT_INFIX) {
            continue;
        }
        if let Some(tenant) = name.strip_suffix(".jsonl") {
            tenants.push(tenant.to_string());
        }
    }
    Ok(tenants)
}

impl CheckpointChainAnchor for ClaimChainAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.digest))
    }

    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.tenant))
    }
}

impl CheckpointChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.digest))
    }

    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.tenant))
    }
}

/// The same signed host-lifecycle chains anchor image-lineage nodes. An image
/// node's identity is its own content-address, so the lookup key is the node
/// digest the `image.created` entry recorded, under the image namespace.
impl ImageChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .lookup(&anchor_key(IMAGE_NS, node.node_digest.as_str()))?
            .map(|recorded| recorded.digest))
    }
}

/// `mvmctl vm checkpoint verify <id>`: chain-anchored lineage verification.
/// Exits nonzero on any failure so it is scriptable.
pub(super) fn verify(id: &str, json: bool) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to anchor lineage verification")?;

    match verify_lineage(&store, &checkpoint, &anchor) {
        Ok(()) => {
            if json {
                crate::json_out::emit_json(&CheckpointVerifyJson {
                    schema_version: 1,
                    action: "verify",
                    id: checkpoint.as_str(),
                    verified: true,
                    error: None,
                })?;
            } else {
                ui::success(&format!(
                    "checkpoint {} lineage verifies against the signed audit chain",
                    checkpoint.as_str()
                ));
            }
            Ok(())
        }
        Err(e) => {
            if json {
                crate::json_out::emit_json(&CheckpointVerifyJson {
                    schema_version: 1,
                    action: "verify",
                    id: checkpoint.as_str(),
                    verified: false,
                    error: Some(format!("{e:#}")),
                })?;
            }
            Err(e.context(format!(
                "checkpoint {} lineage verification failed",
                checkpoint.as_str()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, ContentBlob};
    use mvm_core::util::test_env::TestEnv;
    use mvm_hostd::audit::emitter::AuditEmitter;
    use mvm_hostd::audit::host_keypair::load_or_init;

    /// A checkpoint record whose stored digest matches its own recomputation,
    /// so a lookup outcome is the only thing under test.
    fn meta(id: &str) -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new(id),
            CheckpointClass::FsQuick,
            "vm-under-test",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "a".repeat(64),
        }])
        .created_unix(1)
        .build()
    }

    /// Emit one real `checkpoint.created` entry into `<MVM_HOME>/audit/local.jsonl`
    /// under the host signer, and return the content-address it recorded. The
    /// chain is genuinely signed — every test below either leaves it that way or
    /// damages it deliberately, so nothing depends on the developer's `~/.mvm`.
    fn seed_signed_chain(id: &str) -> CheckpointDigest {
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-lineage-test")
            .build();
        let meta = meta(id);
        let digest = meta.compute_meta_digest();
        let emitter = AuditEmitter::new(load_or_init().unwrap().signing).unwrap();
        emitter
            .emit_checkpoint_created(
                &plan,
                id,
                "fs_quick",
                digest.as_str(),
                meta.vm_name.as_str(),
            )
            .unwrap();
        digest
    }

    fn chain_path(home: &std::path::Path) -> std::path::PathBuf {
        home.join("audit").join("local.jsonl")
    }

    /// Damage a signed chain the way a concurrent writer or a partial write
    /// does: the bytes still parse as JSON, but the signed content no longer
    /// matches its signature. This is a *forgery-shaped* break, not a syntax
    /// error — the case the anchor used to silently skip.
    fn break_chain(path: &std::path::Path) {
        let content = std::fs::read_to_string(path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert!(
            !lines.is_empty(),
            "fixture chain must have entries to break"
        );
        lines[0] = lines[0].replace("fs_quick", "vm_full");
        assert!(
            lines[0].contains("vm_full"),
            "the tampered field must actually be present in the fixture"
        );
        std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn checkpoint_plan_identity_comes_only_from_a_verified_creation_entry() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-plan-bound");

        let anchor = SignedChainAnchor::load().expect("signed chain");
        assert_eq!(
            anchor
                .checkpoint_plan_id(&meta("cp-plan-bound"))
                .expect("plan identity"),
            Some("plan-lineage-test".to_string())
        );
        assert_eq!(
            anchor
                .checkpoint_plan_id(&meta("cp-absent"))
                .expect("absent plan identity"),
            None
        );

        break_chain(&chain_path(tmp.path()));
        let damaged = SignedChainAnchor::load().expect("damaged chain recorded");
        assert!(damaged.checkpoint_plan_id(&meta("cp-plan-bound")).is_err());
    }

    /// The regression. A miss against a damaged ledger must not be reported as
    /// "never audited": the record may be perfectly well audited behind the
    /// break. Both answers refuse, so this is about which finding the operator
    /// is handed — a skipped step, or a damaged integrity chain.
    #[test]
    fn a_miss_against_an_unverifiable_chain_is_an_error_not_a_silent_none() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");
        break_chain(&chain_path(tmp.path()));

        let anchor = SignedChainAnchor::load().unwrap();
        let err = CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent"))
            .expect_err("a miss with a damaged ledger cannot claim the record was never audited");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(mvm_runtime::lineage::LEDGER_UNVERIFIABLE),
            "must report an unreadable ledger: {msg}"
        );
        assert!(
            msg.contains("local.jsonl"),
            "must name the chain that failed so it can be found: {msg}"
        );
        assert!(
            !msg.contains(mvm_runtime::lineage::NO_SIGNED_ENTRY),
            "must not also claim the record was never audited: {msg}"
        );
    }

    /// The tenant a checkpoint belongs to is the one whose signed chain carries
    /// its creation entry, read from the entry itself rather than from the
    /// chain's file name or the record on disk.
    #[test]
    fn the_recorded_tenant_is_the_one_the_creation_entry_was_signed_under() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("acme")
            .plan_id("plan-lineage-tenant")
            .build();
        let record = meta("cp-acme");
        let emitter = AuditEmitter::new(load_or_init().unwrap().signing).unwrap();
        emitter
            .emit_checkpoint_created(
                &plan,
                "cp-acme",
                "fs_quick",
                record.compute_meta_digest().as_str(),
                record.vm_name.as_str(),
            )
            .unwrap();

        let anchor = SignedChainAnchor::load().unwrap();
        assert_eq!(
            CheckpointChainAnchor::recorded_creation_tenant(&anchor, &record).unwrap(),
            Some("acme".to_string())
        );
        assert_eq!(
            CheckpointChainAnchor::recorded_creation_tenant(&anchor, &meta("cp-absent")).unwrap(),
            None,
            "no creation entry, no owning tenant"
        );
    }

    /// The other half of the fix: with every chain readable, a miss keeps
    /// today's message, which is now true rather than merely usual.
    #[test]
    fn a_miss_against_clean_chains_still_reports_never_audited() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");

        let anchor = SignedChainAnchor::load().unwrap();
        let found = CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent"))
            .expect("a clean ledger can answer the question");
        assert!(
            found.is_none(),
            "a clean ledger that records nothing for this id is an honest None"
        );
    }

    /// A damaged chain must not poison lookups it has nothing to do with. An
    /// entry that came from a chain that verified is still trustworthy, so the
    /// hit resolves — only the *unanswerable* case escalates.
    #[test]
    fn a_hit_still_resolves_even_when_another_chain_is_unverifiable() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let digest = seed_signed_chain("cp-anchored");
        // A second lifecycle chain, damaged. `local.jsonl` stays clean.
        let other = tmp.path().join("audit").join("other-tenant.jsonl");
        std::fs::copy(chain_path(tmp.path()), &other).unwrap();
        break_chain(&other);

        let anchor = SignedChainAnchor::load().unwrap();
        let found =
            CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-anchored")).unwrap();
        assert_eq!(
            found,
            Some(digest),
            "an entry from a chain that verified stays usable"
        );
        // ...while the unanswerable lookup still escalates.
        assert!(
            CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent")).is_err(),
            "the damaged sibling still makes a miss unanswerable"
        );
    }

    /// The image-lineage half of the anchor answers the same way. Both impls go
    /// through one `lookup`, and this pins that they cannot drift apart —
    /// `image.created` entries live in the very same chains.
    #[test]
    fn the_image_anchor_reports_an_unverifiable_ledger_the_same_way() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");
        break_chain(&chain_path(tmp.path()));

        let node = mvm_core::image_lineage::ImageNode::builder(
            mvm_core::image_lineage::ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            mvm_core::image_lineage::ImageIdentity {
                canonical: mvm_core::image_lineage::ImageCanonicalId::Flake {
                    revision_hash: "rev-1".into(),
                },
                artifacts: vec![ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "b".repeat(64),
                }],
            },
            mvm_core::image_lineage::ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .created_unix(1)
        .build();

        let anchor = SignedChainAnchor::load().unwrap();
        let err = ImageChainAnchor::recorded_creation_digest(&anchor, &node)
            .expect_err("the image anchor must escalate an unreadable ledger too");
        assert!(
            format!("{err:#}").contains(mvm_runtime::lineage::LEDGER_UNVERIFIABLE),
            "{err:#}"
        );
    }

    /// The unsigned `secrets.jsonl` operator log lives in the same directory and
    /// matches the `<tenant>.jsonl` shape, but it is not a chain — no envelope,
    /// no `prev_hash`, no signature. Admitting it makes it fail verification
    /// permanently, and after this change that turns every un-anchored record on
    /// the host into "cannot determine whether this was audited" forever.
    ///
    /// Found on a real host, not hypothesised: `mvmctl doctor` reported
    /// "1 of 3 chain(s) FAIL verification" against it with the message
    /// `unknown field `action``, which is what a plain operator-log line looks
    /// like to a chain parser.
    #[test]
    fn the_unsigned_secrets_operator_log_never_makes_a_lookup_unanswerable() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");
        // Verbatim shape of the real operator log: plain JSON, no envelope.
        std::fs::write(
            tmp.path().join("audit").join("secrets.jsonl"),
            "{\"action\":\"list\",\"error\":null,\"name\":\"*\",\"outcome\":\"ok\",\
             \"pid\":24117,\"tenant\":\"local\",\"timestamp\":\"2026-05-15T04:25:53Z\"}\n",
        )
        .unwrap();

        let anchor = SignedChainAnchor::load().unwrap();
        let found = CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent"))
            .expect("an unsigned operator log is not an unverifiable chain");
        assert!(
            found.is_none(),
            "a clean ledger beside the operator log still answers honestly"
        );
    }

    /// An anchor built for a resident claim carries no chains at all, so it must
    /// keep answering `None` rather than inventing an unverifiable one.
    #[test]
    fn an_empty_anchor_reports_no_entry_rather_than_an_unreadable_ledger() {
        let anchor = SignedChainAnchor::empty();
        assert!(
            CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-any"))
                .unwrap()
                .is_none()
        );
    }

    /// Append `count` copies of the chain's first line: valid-looking signed
    /// entries that no longer chain, so any walk over them fails, standing in
    /// for a long history the claim must not walk. None names a checkpoint.
    fn pad_history(path: &std::path::Path, count: usize) {
        use std::io::Write as _;
        let content = std::fs::read_to_string(path).unwrap();
        let first = content.lines().next().unwrap().to_string();
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        for _ in 0..count {
            writeln!(file, "{first}").unwrap();
        }
    }

    /// A warm claim answers its parent's creation from the live segment and
    /// does not walk the history before it: with that history damaged, the
    /// full anchor can no longer answer, and the claim anchor still does.
    #[test]
    fn a_claim_answers_its_parent_in_place_without_walking_the_history() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-old");
        break_chain(&chain_path(tmp.path()));
        let digest = seed_signed_chain("cp-parent");

        let parent = meta("cp-parent");
        assert!(
            CheckpointChainAnchor::recorded_creation_digest(
                &SignedChainAnchor::load().unwrap(),
                &parent
            )
            .is_err(),
            "only a walk of the history sees the damaged entry"
        );
        let claim = ClaimChainAnchor::for_checkpoint(&parent.id).unwrap();
        assert!(claim.answers_in_place("cp-parent"));
        assert_eq!(
            claim.recorded_creation_digest(&parent).unwrap(),
            Some(digest)
        );
        assert_eq!(
            claim.recorded_creation_tenant(&parent).unwrap(),
            Some("local".to_string())
        );
    }

    /// The claim-path work grows with the entries that name the parent, not
    /// with the history: about 10 MB of history before the parent's entry is
    /// searched but never parsed or verified.
    #[test]
    fn a_large_history_adds_no_parsing_or_verification_to_a_claim() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-history");
        let chain = chain_path(tmp.path());
        let line_len = std::fs::metadata(&chain).unwrap().len() as usize;
        pad_history(&chain, (10 * 1024 * 1024) / line_len.max(1));
        assert!(std::fs::metadata(&chain).unwrap().len() >= 10 * 1024 * 1024 - 2 * line_len as u64);
        let digest = seed_signed_chain("cp-parent");

        let key = load_or_init().unwrap().verifying;
        let live = mvm_core::audit_verify::live::authenticate_live_entries(
            &tmp.path().join("audit"),
            "local",
            &key,
            "cp-parent",
            |entry| creation_keys(&entry.event).is_some(),
        )
        .unwrap();
        assert_eq!(live.parsed, 1, "only the line naming the parent is parsed");
        assert_eq!(live.entries.len(), 1);

        let parent = meta("cp-parent");
        let claim = ClaimChainAnchor::for_checkpoint(&parent.id).unwrap();
        assert!(claim.answers_in_place("cp-parent"));
        assert_eq!(
            claim.recorded_creation_digest(&parent).unwrap(),
            Some(digest)
        );
    }

    /// A parent entry that does not authenticate is never answered in place:
    /// the claim falls back to the full walk, which refuses it exactly as it
    /// always has.
    #[test]
    fn a_tampered_parent_entry_falls_back_to_the_full_walk_and_is_refused() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-parent");
        break_chain(&chain_path(tmp.path()));

        let parent = meta("cp-parent");
        let claim = ClaimChainAnchor::for_checkpoint(&parent.id).unwrap();
        assert!(!claim.answers_in_place("cp-parent"));
        let err = claim
            .recorded_creation_digest(&parent)
            .expect_err("a forged parent entry must not anchor a claim");
        assert!(format!("{err:#}").contains(mvm_runtime::lineage::LEDGER_UNVERIFIABLE));
    }

    /// Anything the live segments do not answer is the full walk's question,
    /// with the full walk's verdict: an unaudited parent is still refused as
    /// never audited.
    #[test]
    fn a_parent_the_live_segment_does_not_name_gets_the_full_walks_verdict() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-other");

        let absent = meta("cp-unaudited");
        let claim = ClaimChainAnchor::for_checkpoint(&absent.id).unwrap();
        assert!(!claim.answers_in_place("cp-unaudited"));
        assert_eq!(claim.recorded_creation_digest(&absent).unwrap(), None);
    }
}
