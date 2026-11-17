//! Candidate local project policy bound to the exact authored bytes it parsed.
//!
//! This module prepares and revalidates a generation; it does not publish one
//! or authorize a launch. The resident lifecycle owner must serialize
//! publication with launch/restore and keep the resulting state private.

#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_policy::{
    CapturedSource, Platform, PolicyBody, PolicyStore, ProjectPolicy, resolve_capturing_sources,
    resolve_from_captured_sources, select_launch_policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod store;
pub(crate) use store::GenerationStore;
pub mod coordinator;

const SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Reserved policy asset name for a generation-1 project closure.
pub const GENERATION_ASSET_PREFIX: &str = "mvm:project-policy:g1:";

/// Verify every project-generation identity in a signed plan against the
/// resident owner's active, independently revalidated source closure.
///
/// # Errors
///
/// The active generation is missing, malformed, mismatched, or unsupported.
pub fn verify_plan_generation_assets(plan: &mvm_core::plan::ExecutionPlan) -> Result<()> {
    if !plan
        .asset_identities
        .iter()
        .any(|asset| asset.name.starts_with(GENERATION_ASSET_PREFIX))
    {
        return Ok(());
    }
    let home = PathBuf::from(mvm_core::config::mvm_home());
    let store = GenerationStore::open(home)?;
    store.verify_plan_assets(plan, &PolicyStore::from_config())
}

/// Whether a committed project exists, requiring every subsequent
/// Firecracker restore to have its original admitted plan on disk.
///
/// # Errors
///
/// Activation state is incomplete or corrupt.
pub fn has_active_generation() -> Result<bool> {
    let home = PathBuf::from(mvm_core::config::mvm_home());
    let root = mvm_core::config::policy_generations_dir_at(&home);
    if !root.try_exists()? {
        return Ok(false);
    }
    GenerationStore::open(home)?.has_active_generation()
}

/// Initial local project policy candidate, not yet a committed authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicyCandidate {
    schema_version: u32,
    generation: u64,
    project_dir: PathBuf,
    manifest_path: PathBuf,
    manifest_text: String,
    defaults: Vec<String>,
    platform: Platform,
    sources: Vec<CapturedSource>,
    effective: PolicyBody,
    effective_sha256: String,
    closure_sha256: String,
}

fn policy_digest(policy: &PolicyBody) -> Result<String> {
    let canonical = serde_jcs::to_vec(policy).context("canonicalizing effective policy")?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}

fn closure_digest(candidate: &ProjectPolicyCandidate) -> Result<String> {
    let canonical = serde_jcs::to_vec(&(
        candidate.schema_version,
        candidate.generation,
        &candidate.project_dir,
        &candidate.manifest_path,
        &candidate.manifest_text,
        &candidate.defaults,
        candidate.platform,
        &candidate.sources,
        &candidate.effective,
        &candidate.effective_sha256,
    ))
    .context("canonicalizing project policy closure")?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}

fn supported_project_policy(
    manifest_path: &Path,
    manifest: &mvm_core::manifest::Manifest,
) -> Result<ProjectPolicy> {
    ensure!(
        manifest.wasm.is_none(),
        "committed Firecracker policy does not support a Wasm project source"
    );
    ensure!(
        manifest.image.is_none(),
        "committed project policy currently requires a local flake source, not an image reference"
    );
    Ok(ProjectPolicy::from_manifest(manifest_path, manifest))
}

#[cfg(unix)]
fn read_manifest_text(path: &Path) -> Result<String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening project manifest {}", path.display()))?;
    let metadata = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&metadata)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "committed project manifest must be an owned regular file without aliases"
    );
    let mut bytes = Vec::new();
    file.take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading project manifest {}", path.display()))?;
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "project manifest exceeds the committed-policy size limit"
    );
    String::from_utf8(bytes).context("project manifest is not UTF-8")
}

#[cfg(not(unix))]
fn read_manifest_text(_path: &Path) -> Result<String> {
    anyhow::bail!("committed project policy requires an owner-only Unix filesystem")
}

/// Prepare generation 1 from a local project on a Linux Firecracker host.
///
/// This only creates a candidate. It cannot activate, admit, or boot anything.
///
/// # Errors
///
/// The host/backend is unsupported, the project has no manifest, or any
/// contributing source or configured default cannot be resolved.
pub fn prepare_initial(project_dir: &Path) -> Result<ProjectPolicyCandidate> {
    ensure!(
        cfg!(target_os = "linux"),
        "committed local project policy initially supports Firecracker on Linux only"
    );
    let config = mvm_core::user_config::load_strict(None)?;
    prepare_with(
        project_dir,
        &config.default_policy,
        Platform::current(Some(BackendKind::Firecracker)),
        &PolicyStore::from_config(),
    )
}

fn prepare_with(
    project_dir: &Path,
    defaults: &[String],
    platform: Platform,
    store: &PolicyStore,
) -> Result<ProjectPolicyCandidate> {
    ensure!(
        platform.os == Some(mvm_policy::model::HostOs::Linux)
            && platform.backend == Some(BackendKind::Firecracker),
        "committed local project policy initially supports Firecracker on Linux only"
    );
    let project_dir = project_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing project {}", project_dir.display()))?;
    let manifest_path = mvm_core::manifest::manifest_in_dir(&project_dir)?
        .with_context(|| format!("no mvm.toml or Mvmfile.toml in {}", project_dir.display()))?;
    let manifest_text = read_manifest_text(&manifest_path)?;
    let manifest = mvm_core::manifest::Manifest::from_file_text(&manifest_path, &manifest_text)?;
    let project = supported_project_policy(&manifest_path, &manifest)?;
    let selection = select_launch_policy(&[], Some(project), defaults)?.unwrap_or_default();
    let (resolved, sources) = resolve_capturing_sources(store, &selection, platform)?;
    let effective = resolved.policy;
    let effective_sha256 = policy_digest(&effective)?;
    let mut candidate = ProjectPolicyCandidate {
        schema_version: SCHEMA_VERSION,
        generation: 1,
        project_dir,
        manifest_path,
        manifest_text,
        defaults: defaults.to_vec(),
        platform,
        sources,
        effective,
        effective_sha256,
        closure_sha256: String::new(),
    };
    candidate.closure_sha256 = closure_digest(&candidate)?;
    Ok(candidate)
}

impl ProjectPolicyCandidate {
    /// Independently check the complete candidate from its captured text,
    /// without reading a staged manifest or authored policy file.
    ///
    /// # Errors
    ///
    /// Unknown schema, malformed or inconsistent closure, unsupported backend,
    /// or effective-policy mismatch.
    pub fn revalidate(&self, store: &PolicyStore) -> Result<()> {
        ensure!(
            closure_digest(self)? == self.closure_sha256,
            "committed project policy source closure digest does not match"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION && self.generation == 1,
            "unknown committed project-policy version or generation"
        );
        ensure!(
            self.platform.os == Some(mvm_policy::model::HostOs::Linux)
                && self.platform.backend == Some(BackendKind::Firecracker),
            "committed project policy has an unsupported platform"
        );
        ensure!(
            self.project_dir.is_absolute()
                && self.manifest_path.parent() == Some(self.project_dir.as_path())
                && self.manifest_path.file_name().is_some_and(|name| {
                    mvm_core::manifest::MANIFEST_FILENAMES
                        .iter()
                        .any(|allowed| name == *allowed)
                })
                && self.manifest_text.len() <= MAX_MANIFEST_BYTES,
            "committed project manifest identity or size is invalid"
        );
        let manifest =
            mvm_core::manifest::Manifest::from_file_text(&self.manifest_path, &self.manifest_text)?;
        let project = supported_project_policy(&self.manifest_path, &manifest)?;
        let selection =
            select_launch_policy(&[], Some(project), &self.defaults)?.unwrap_or_default();
        let resolved =
            resolve_from_captured_sources(store, &selection, self.platform, &self.sources)?;
        ensure!(
            resolved.policy == self.effective
                && policy_digest(&resolved.policy)? == self.effective_sha256,
            "committed project policy differs from its captured source closure"
        );
        Ok(())
    }

    /// The effective authored policy to bind into a signed launch plan.
    #[must_use]
    pub fn policy(&self) -> &PolicyBody {
        &self.effective
    }

    /// The digest of the effective authored policy, not a publication proof.
    #[must_use]
    pub fn policy_sha256(&self) -> &str {
        &self.effective_sha256
    }

    /// The project path whose generation was published.
    #[must_use]
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    /// The original manifest path and the exact text admitted for generation 1.
    ///
    /// # Errors
    ///
    /// The captured manifest no longer parses.
    pub fn manifest(&self) -> Result<(PathBuf, mvm_core::manifest::Manifest)> {
        Ok((
            self.manifest_path.clone(),
            mvm_core::manifest::Manifest::from_file_text(&self.manifest_path, &self.manifest_text)?,
        ))
    }

    /// Select an already-built Firecracker slot whose boot declaration matches
    /// this generation, without consulting the staged manifest.
    ///
    /// # Errors
    ///
    /// The slot or revision is missing, malformed, or was rebuilt from a
    /// different declaration.
    pub fn built_manifest_slot(&self) -> Result<String> {
        use mvm_runtime::vm::template::lifecycle::{
            current_revision_id_for_slot, template_load_slot, validate_slot_revision,
        };

        let (path, manifest) = self.manifest()?;
        let key = mvm_core::manifest::key_for_manifest_identity(
            path.to_str()
                .context("committed manifest path is not UTF-8")?,
        );
        let built =
            template_load_slot(&key).context("loading the committed project's built slot")?;
        let revision_key = current_revision_id_for_slot(&key)
            .context("committed project has no built revision")?;
        // A successful builder may name its revision by a Nix store hash or,
        // without a store-path sidecar, by its job ID. Both are accepted by
        // the slot owner; validate the path component by that same rule.
        validate_slot_revision(&revision_key)
            .context("committed project slot points to an invalid revision")?;
        let revision_path =
            PathBuf::from(mvm_core::manifest::slot_revision_dir(&key, &revision_key))
                .join("revision.json");
        let revision: mvm_core::template::TemplateRevision =
            serde_json::from_slice(&std::fs::read(&revision_path).with_context(|| {
                format!(
                    "reading committed project revision {}",
                    revision_path.display()
                )
            })?)
            .with_context(|| format!("decoding {}", revision_path.display()))?;
        ensure!(
            built.manifest_hash == key
                && revision.revision_hash == revision_key
                && built.manifest_path == path.to_string_lossy()
                && built.backend == "firecracker"
                && built.profile == manifest.profile
                && built.vcpus == manifest.cpus
                && built.mem_mib == manifest.mem_mib()?
                && built.mem_initial_mib == manifest.mem_initial_mib()?
                && built.data_disk_mib == manifest.data_disk_mib()?
                && built.name == manifest.name,
            "built slot does not match the committed manifest; a staged rebuild cannot replace it"
        );
        let flake = manifest.flake_ref();
        let source = if flake == "." {
            self.project_dir.display().to_string()
        } else if !flake.contains(':') && !Path::new(flake).is_absolute() {
            self.project_dir.join(flake).display().to_string()
        } else {
            flake.to_string()
        };
        ensure!(
            revision.flake_ref == source
                && revision.profile == manifest.profile
                && revision.vcpus == manifest.cpus
                && revision.mem_mib == manifest.mem_mib()?
                && built.flake_ref == source,
            "built revision does not match the committed project source"
        );
        Ok(key)
    }

    /// The identity of this generation's entire parsed source closure.
    #[must_use]
    pub fn closure_sha256(&self) -> &str {
        &self.closure_sha256
    }

    /// The published generation number.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Bind this project's generation and complete source closure into a
    /// signed plan, separately from the plan's effective network-policy asset.
    ///
    /// # Errors
    ///
    /// The project path is not representable as the store's UTF-8 identity.
    pub fn plan_asset(&self) -> Result<mvm_core::plan::AssetIdentity> {
        let path = self
            .project_dir
            .to_str()
            .context("committed project path is not UTF-8")?;
        let key = mvm_core::manifest::key_for_manifest_identity(path);
        Ok(mvm_core::plan::AssetIdentity::new(
            mvm_core::plan::AssetKind::Policy,
            format!("{GENERATION_ASSET_PREFIX}{key}"),
            self.closure_sha256.clone(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_replays_captured_project_and_profiles_after_staged_edits() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let policy = root.path().join("policies");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(policy.join("profiles")).unwrap();
        let manifest = project.join("mvm.toml");
        let profile = policy.join("profiles/one.toml");
        std::fs::write(&manifest, "flake = \".\"\n[policy]\nprofile = \"one\"\n").unwrap();
        std::fs::write(&profile, "[overrides.network]\nallow = [\"old.test\"]\n").unwrap();
        let store = PolicyStore::at(&policy);
        let platform = Platform {
            os: Some(mvm_policy::model::HostOs::Linux),
            backend: Some(BackendKind::Firecracker),
            ..Platform::default()
        };
        let candidate = prepare_with(&project, &[], platform, &store).unwrap();
        candidate.revalidate(&store).unwrap();
        assert!(
            candidate.built_manifest_slot().is_err(),
            "a policy candidate alone does not create a bootable project slot"
        );
        assert_eq!(candidate.policy().network.allow, ["old.test:443"]);
        std::fs::write(
            &manifest,
            "flake = \".\"\n[policy]\nprofile = \"missing\"\n",
        )
        .unwrap();
        std::fs::write(&profile, "[overrides.network]\nallow = [\"new.test\"]\n").unwrap();
        candidate.revalidate(&store).unwrap();
        assert_eq!(candidate.policy().network.allow, ["old.test:443"]);

        let mut tampered = candidate.clone();
        tampered.sources[0].text.push('x');
        assert!(tampered.revalidate(&store).is_err());
        let mut tampered = candidate.clone();
        tampered
            .effective
            .network
            .allow
            .push("wider.test:443".into());
        assert!(tampered.revalidate(&store).is_err());
        let mut tampered = candidate.clone();
        tampered.generation = 2;
        assert!(tampered.revalidate(&store).is_err());
        let mut tampered = candidate.clone();
        tampered.manifest_text.push_str("\n# staged-only change\n");
        assert!(tampered.revalidate(&store).is_err());
        let mut tampered = candidate.clone();
        tampered.defaults.push("offline".into());
        assert!(tampered.revalidate(&store).is_err());
        let mut tampered = candidate.clone();
        tampered.manifest_path = project.join("unrelated.toml");
        assert!(tampered.revalidate(&store).is_err());

        std::fs::write(&manifest, "image = \"alpine:latest\"\n").unwrap();
        assert!(
            prepare_with(&project, &[], platform, &store).is_err(),
            "an image-backed project must refuse the flake-only first generation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn candidate_refuses_oversized_or_linked_project_manifest() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let path = project.join("mvm.toml");
        std::fs::write(
            &path,
            format!("flake = \".\"\n#{}\n", "x".repeat(MAX_MANIFEST_BYTES)),
        )
        .unwrap();
        let platform = Platform {
            os: Some(mvm_policy::model::HostOs::Linux),
            backend: Some(BackendKind::Firecracker),
            ..Platform::default()
        };
        let store = PolicyStore::at(root.path());
        let error = prepare_with(&project, &[], platform, &store).unwrap_err();
        assert!(format!("{error:#}").contains("size limit"), "{error:#}");

        let target = project.join("other.toml");
        std::fs::write(&target, "flake = \".\"\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let error = prepare_with(&project, &[], platform, &store).unwrap_err();
        assert!(
            format!("{error:#}").contains("opening project manifest"),
            "{error:#}"
        );
    }

    #[test]
    fn generation_admission_refuses_a_missing_or_widened_cpu_share_grant() {
        use mvm_contract::grants::{CpuGrant, Grants};

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("mvm.toml"),
            "flake = \".\"\n[policy]\nprofile = \"./limit.toml\"\n",
        )
        .unwrap();
        std::fs::write(
            project.join("limit.toml"),
            "[overrides.resources]\ncpu_millicores = 250\n",
        )
        .unwrap();
        let platform = Platform {
            os: Some(mvm_policy::model::HostOs::Linux),
            backend: Some(BackendKind::Firecracker),
            arch: Platform::current(None).arch,
        };
        let source = PolicyStore::at(root.path());
        let candidate = prepare_with(&project, &[], platform, &source).unwrap();
        let store = GenerationStore::open(root.path().join("home")).unwrap();
        store.publish_initial(&candidate, &source).unwrap();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.asset_identities.push(candidate.plan_asset().unwrap());
        assert!(
            store
                .verify_plan_assets(&plan, &source)
                .unwrap_err()
                .to_string()
                .contains("CPU-share bound")
        );
        for cpu in [None, Some(CpuGrant::Fuel { instructions: 250 })] {
            plan.grants = Some(Grants {
                cpu,
                ..Grants::default()
            });
            assert!(store.verify_plan_assets(&plan, &source).is_err());
        }
        for (millicores, accepted) in [(500, false), (250, true), (125, true)] {
            plan.grants = Some(Grants {
                cpu: Some(CpuGrant::Share { millicores }),
                ..Grants::default()
            });
            assert_eq!(store.verify_plan_assets(&plan, &source).is_ok(), accepted);
        }
    }

    #[test]
    fn generation_one_is_durable_and_never_replaced_by_staged_edits() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let policy = root.path().join("policies");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(policy.join("profiles")).unwrap();
        let manifest = project.join("mvm.toml");
        let profile = policy.join("profiles/one.toml");
        std::fs::write(&manifest, "flake = \".\"\n[policy]\nprofile = \"one\"\n").unwrap();
        std::fs::write(&profile, "[overrides.network]\nallow = [\"old.test\"]\n").unwrap();
        let source = PolicyStore::at(&policy);
        let platform = Platform {
            os: Some(mvm_policy::model::HostOs::Linux),
            backend: Some(BackendKind::Firecracker),
            arch: Platform::current(None).arch,
        };
        let candidate = prepare_with(&project, &[], platform, &source).unwrap();
        let generations = GenerationStore::open(root.path().join("home")).unwrap();
        assert!(!generations.has_active_generation().unwrap());
        generations.publish_initial(&candidate, &source).unwrap();
        assert!(generations.has_active_generation().unwrap());
        std::fs::write(
            &manifest,
            "flake = \".\"\n[policy]\nprofile = \"missing\"\n",
        )
        .unwrap();
        std::fs::write(&profile, "[overrides.network]\nallow = [\"new.test\"]\n").unwrap();
        let committed = generations
            .load(&project, &source)
            .unwrap()
            .expect("a committed generation");
        assert_eq!(committed.policy().network.allow, ["old.test:443"]);
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.asset_identities.push(committed.plan_asset().unwrap());
        generations.verify_plan_assets(&plan, &source).unwrap();
        plan.asset_identities.last_mut().unwrap().digest = "0".repeat(64);
        assert!(
            generations.verify_plan_assets(&plan, &source).is_err(),
            "a plan cannot pin a different policy closure"
        );
        plan.asset_identities.pop();
        plan.asset_identities.push(committed.plan_asset().unwrap());
        assert_eq!(
            committed.manifest().unwrap().1.policy.profile.as_deref(),
            Some("one"),
            "the parsed manifest is the committed text, not the staged file"
        );
        assert!(generations.publish_initial(&candidate, &source).is_err());
        let index = root.path().join("home/policy-generations/active.json");
        let index_bytes = std::fs::read(&index).unwrap();
        std::fs::remove_file(&index).unwrap();
        assert!(generations.has_active_generation().is_err());
        assert!(
            generations.load(&project, &source).is_err(),
            "a missing index cannot turn an activated project into an ordinary one"
        );
        assert!(
            generations.verify_plan_assets(&plan, &source).is_err(),
            "host admission must refuse if the active index is missing"
        );
        mvm_core::util::atomic_io::atomic_write_new(&index, &index_bytes).unwrap();
        let marker = root.path().join("home/policy-generations/activated.marker");
        std::fs::remove_file(&marker).unwrap();
        assert!(
            generations.load(&project, &source).is_err(),
            "a missing activation marker cannot turn an indexed project into an ordinary one"
        );
        mvm_core::util::atomic_io::atomic_write_new(&marker, b"policy-generation-v1\n").unwrap();
        let key = mvm_core::manifest::key_for_manifest_identity(
            project.canonicalize().unwrap().to_str().unwrap(),
        );
        let record = root
            .path()
            .join("home/policy-generations")
            .join(format!("{key}.json"));
        let record_bytes = std::fs::read(&record).unwrap();
        std::fs::remove_file(&record).unwrap();
        assert!(generations.has_active_generation().is_err());
        assert!(
            generations.load(&project, &source).is_err(),
            "an activated project with a missing generation must never fall back to authored files"
        );
        mvm_core::util::atomic_io::atomic_write_new(&record, &record_bytes).unwrap();
        std::fs::remove_file(&index).unwrap();
        std::fs::remove_file(&marker).unwrap();
        assert!(
            generations.has_active_generation().is_err(),
            "an orphaned record cannot become an ordinary project after the index is lost"
        );
    }
}
