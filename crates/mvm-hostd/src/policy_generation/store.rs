//! Owner-only, no-clobber persistence for the initial project generation.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use mvm_policy::PolicyStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{GENERATION_ASSET_PREFIX, ProjectPolicyCandidate};

const MAX_RECORD_BYTES: u64 = 6 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveIndex {
    generations: BTreeMap<String, String>,
}

/// The coordinator's private generation store. Publication is only valid
/// while its exclusive launch/restore barrier is held after proving the
/// entire host quiescent; the store does not make that decision.
pub(crate) struct GenerationStore {
    root: PathBuf,
}

impl GenerationStore {
    pub(crate) fn open(home: PathBuf) -> Result<Self> {
        mvm_core::private_fs::create_owned_private_dir(&home)
            .with_context(|| format!("securing MVM home {}", home.display()))?;
        let root = mvm_core::config::policy_generations_dir_at(&home);
        mvm_core::private_fs::create_owned_private_dir(&root)
            .with_context(|| format!("securing {}", root.display()))?;
        Ok(Self { root })
    }

    fn path(&self, project_dir: &Path) -> Result<PathBuf> {
        let canonical = project_dir
            .canonicalize()
            .with_context(|| format!("canonicalizing project {}", project_dir.display()))?;
        let identity = canonical
            .to_str()
            .with_context(|| format!("project path is not UTF-8: {}", canonical.display()))?;
        Ok(self.root.join(format!(
            "{}.json",
            hex::encode(Sha256::digest(identity.as_bytes()))
        )))
    }

    fn index(&self) -> Result<ActiveIndex> {
        let path = self.root.join("active.json");
        let marker = self.root.join("activated.marker");
        let marker_present = match open_record(&marker) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(64).read_to_end(&mut bytes)?;
                ensure!(
                    bytes == b"policy-generation-v1\n",
                    "invalid activation marker"
                );
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("opening activation marker {}", marker.display()));
            }
        };
        let file = match open_record(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    !marker_present,
                    "activation marker exists without an active index; recovery is required"
                );
                return Ok(ActiveIndex::default());
            }
            Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
        };
        ensure!(
            marker_present,
            "active policy index has no activation marker"
        );
        ensure!(
            file.metadata()?.len() <= MAX_INDEX_BYTES,
            "policy index exceeds its size limit"
        );
        let mut bytes = Vec::new();
        file.take(MAX_INDEX_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_INDEX_BYTES,
            "policy index exceeds its size limit"
        );
        serde_json::from_slice(&bytes)
            .with_context(|| format!("corrupt committed policy index {}", path.display()))
    }

    pub(super) fn has_active_generation(&self) -> Result<bool> {
        let index = self.index()?;
        for key in index.generations.keys() {
            let path = self.root.join(format!("{key}.json"));
            open_record(&path)
                .with_context(|| format!("opening indexed policy generation {}", path.display()))?;
        }
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                anyhow::bail!("non-UTF8 entry in policy-generation state");
            };
            if let Some(key) = name.strip_suffix(".json")
                && name != "active.json"
            {
                ensure!(
                    index.generations.contains_key(key),
                    "orphaned policy-generation record {name} requires recovery"
                );
            }
        }
        Ok(!index.generations.is_empty())
    }

    pub(crate) fn publish_initial(
        &self,
        candidate: &ProjectPolicyCandidate,
        source: &PolicyStore,
    ) -> Result<()> {
        candidate.revalidate(source)?;
        let path = self.path(&candidate.project_dir)?;
        let key = path
            .file_stem()
            .context("policy record has no project key")?;
        let mut index = self.index()?;
        ensure!(
            !index
                .generations
                .contains_key(key.to_string_lossy().as_ref()),
            "project already has a committed policy generation"
        );
        let bytes = serde_json::to_vec(candidate).context("serializing initial project policy")?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "committed project policy exceeds its size limit"
        );
        let marker = self.root.join("activated.marker");
        if !marker.try_exists()? {
            mvm_core::util::atomic_io::atomic_write_new(&marker, b"policy-generation-v1\n")
                .with_context(|| format!("marking activation at {}", marker.display()))?;
            mvm_core::util::atomic_io::sync_dir(&self.root)
                .context("making activation intent durable")?;
        }
        mvm_core::util::atomic_io::atomic_write_new(&path, &bytes)
            .with_context(|| format!("publishing initial policy at {}", path.display()))?;
        mvm_core::util::atomic_io::sync_dir(&self.root)
            .with_context(|| format!("syncing policy directory {}", self.root.display()))?;
        index.generations.insert(
            key.to_string_lossy().into_owned(),
            candidate.closure_sha256.clone(),
        );
        let index_path = self.root.join("active.json");
        mvm_core::util::atomic_io::atomic_write_durable(
            &index_path,
            &serde_json::to_vec(&index).context("serializing policy index")?,
        )
        .with_context(|| format!("publishing policy index {}", index_path.display()))
    }

    pub(crate) fn load(
        &self,
        project_dir: &Path,
        source: &PolicyStore,
    ) -> Result<Option<ProjectPolicyCandidate>> {
        let path = self.path(project_dir)?;
        let key = path
            .file_stem()
            .context("policy record has no project key")?;
        let index = self.index()?;
        let expected = index.generations.get(key.to_string_lossy().as_ref());
        let file = match open_record(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && expected.is_none() => {
                return Ok(None);
            }
            Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
        };
        let expected = expected.context("unindexed project generation requires recovery")?;
        ensure!(
            file.metadata()?.len() <= MAX_RECORD_BYTES,
            "committed project policy exceeds its size limit"
        );
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "committed project policy exceeds its size limit"
        );
        let record: ProjectPolicyCandidate = serde_json::from_slice(&bytes)
            .with_context(|| format!("corrupt committed project policy {}", path.display()))?;
        ensure!(
            record.project_dir == project_dir.canonicalize()?,
            "committed project identity does not match the requested project"
        );
        ensure!(
            record.closure_sha256 == *expected,
            "committed policy generation differs from active index"
        );
        record.revalidate(source)?;
        Ok(Some(record))
    }

    pub(crate) fn verify_plan_assets(
        &self,
        plan: &mvm_core::plan::ExecutionPlan,
        source: &PolicyStore,
    ) -> Result<()> {
        for asset in &plan.asset_identities {
            let Some(key) = asset.name.strip_prefix(GENERATION_ASSET_PREFIX) else {
                continue;
            };
            ensure!(
                asset.kind == mvm_core::plan::AssetKind::Policy
                    && key.len() == 64
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "invalid project-policy generation asset"
            );
            let path = self.root.join(format!("{key}.json"));
            let record = open_record(&path)
                .with_context(|| format!("opening pinned generation {}", path.display()))?;
            ensure!(
                record.metadata()?.len() <= MAX_RECORD_BYTES,
                "pinned generation exceeds its size limit"
            );
            let mut bytes = Vec::new();
            record.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_RECORD_BYTES,
                "pinned generation exceeds its size limit"
            );
            let candidate: ProjectPolicyCandidate =
                serde_json::from_slice(&bytes).context("decoding pinned generation")?;
            let committed = self
                .load(&candidate.project_dir, source)?
                .context("pinned generation is not active")?;
            if cfg!(target_os = "linux") {
                ensure!(
                    committed.platform
                        == mvm_policy::Platform::current(Some(
                            mvm_contract::protocol::vm_backend::BackendKind::Firecracker
                        )),
                    "committed policy platform differs from this host"
                );
            }
            ensure!(
                committed.plan_asset()? == *asset,
                "plan's project-policy generation does not match committed authority"
            );
            if let Some(limit) = committed.policy().resources.cpu_millicores {
                ensure!(
                    matches!(
                        plan.grants.as_ref().and_then(|grants| grants.cpu),
                        Some(mvm_contract::grants::CpuGrant::Share { millicores })
                            if millicores <= limit
                    ),
                    "plan is missing the committed CPU-share bound"
                );
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn open_record(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    mvm_core::private_fs::require_current_owner(&metadata)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is not an owner-only regular policy record",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_record(path: &Path) -> std::io::Result<fs::File> {
    Err(mvm_core::private_fs::unsupported_platform_error(path))
}
