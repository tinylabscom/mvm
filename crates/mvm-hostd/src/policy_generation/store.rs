//! Owner-only, no-clobber persistence for the initial project generation.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use mvm_core::policy::authored::PolicyStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{GENERATION_ASSET_PREFIX, ProjectPolicyCandidate};

const MAX_RECORD_BYTES: u64 = 6 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 1024 * 1024;
const MAX_OBLIGATION_BYTES: u64 = 4096;
const OBLIGATION_FILE: &str = "pending.json";

/// A publication whose outcome is unknown: the store refuses every read and
/// every further activation until recovery resolves it.
#[derive(Debug)]
pub(crate) struct PublicationUnresolved(String);

impl PublicationUnresolved {
    #[cfg(test)]
    pub(super) fn new(message: &str) -> Self {
        Self(message.to_owned())
    }
}

impl std::fmt::Display for PublicationUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy publication outcome is unknown and requires recovery: {}",
            self.0
        )
    }
}

impl std::error::Error for PublicationUnresolved {}

/// Written durably before the first publication step, so a crash between the
/// record and the index leaves a marker that readers refuse on.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Obligation {
    project: String,
    closure: String,
}

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

    fn obligation_path(&self) -> PathBuf {
        self.root.join(OBLIGATION_FILE)
    }

    pub(crate) fn has_obligation(&self) -> Result<bool> {
        let path = self.obligation_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| format!("checking {}", path.display())),
        }
    }

    /// The index every reader and activation goes through. It refuses while a
    /// publication is unresolved, even if the index already names the project.
    fn index(&self) -> Result<ActiveIndex> {
        self.refuse_unresolved()?;
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
        let index_file = self.read_index_file()?;
        // The obligation exists before the index rename and is removed only
        // after the index is durable, so its absence after the read means the
        // index read is durable.
        self.refuse_unresolved()?;
        let Some(index) = index_file else {
            ensure!(
                !marker_present,
                "activation marker exists without an active index; recovery is required"
            );
            return Ok(ActiveIndex::default());
        };
        ensure!(
            marker_present,
            "active policy index has no activation marker"
        );
        Ok(index)
    }

    fn refuse_unresolved(&self) -> Result<()> {
        if self.has_obligation()? {
            return Err(anyhow::Error::new(PublicationUnresolved(
                "an unresolved policy publication requires recovery".to_owned(),
            )));
        }
        Ok(())
    }

    /// The index file alone, with none of the marker or obligation checks;
    /// recovery reads it while an obligation is still present.
    fn read_index_file(&self) -> Result<Option<ActiveIndex>> {
        let path = self.root.join("active.json");
        let file = match open_record(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
        };
        let bytes = read_bounded(file, MAX_INDEX_BYTES, "policy index")?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("corrupt committed policy index {}", path.display()))
    }

    fn read_obligation(&self) -> Result<Option<Obligation>> {
        let path = self.obligation_path();
        let file = match open_record(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("opening {}", path.display()));
            }
        };
        let bytes = read_bounded(file, MAX_OBLIGATION_BYTES, "publication obligation")?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("corrupt publication obligation {}", path.display()))
    }

    fn read_record(&self, key: &str) -> Result<Option<ProjectPolicyCandidate>> {
        let path = self.root.join(format!("{key}.json"));
        let file = match open_record(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
        };
        let bytes = read_bounded(file, MAX_RECORD_BYTES, "committed project policy")?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("corrupt committed project policy {}", path.display()))
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
        let index = self.index()?;
        let key = key.to_string_lossy().into_owned();
        ensure!(
            !index.generations.contains_key(&key),
            "project already has a committed policy generation"
        );
        match fs::symlink_metadata(&path) {
            Ok(_) => anyhow::bail!("project has an unindexed policy record that requires recovery"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("checking {}", path.display()));
            }
        }
        let bytes = serde_json::to_vec(candidate).context("serializing initial project policy")?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "committed project policy exceeds its size limit"
        );
        self.write_obligation(&key, &candidate.closure_sha256)?;
        self.write_marker()
            .and_then(|()| self.write_record(&path, &bytes))
            .and_then(|()| self.write_index(&key, &candidate.closure_sha256))
            .and_then(|()| self.clear_obligation())
            .map_err(|error| anyhow::Error::new(PublicationUnresolved(format!("{error:#}"))))
    }

    fn write_marker(&self) -> Result<()> {
        let marker = self.root.join("activated.marker");
        if !marker.try_exists()? {
            mvm_core::util::atomic_io::atomic_write_new(&marker, b"policy-generation-v1\n")
                .with_context(|| format!("marking activation at {}", marker.display()))?;
            mvm_core::util::atomic_io::sync_dir(&self.root)
                .context("making activation intent durable")?;
        }
        Ok(())
    }

    pub(super) fn write_obligation(&self, key: &str, closure: &str) -> Result<()> {
        let path = self.obligation_path();
        let bytes = serde_json::to_vec(&Obligation {
            project: key.to_owned(),
            closure: closure.to_owned(),
        })?;
        mvm_core::util::atomic_io::atomic_write_new(&path, &bytes)
            .with_context(|| format!("recording publication at {}", path.display()))?;
        mvm_core::util::atomic_io::sync_dir(&self.root)
            .context("making the publication obligation durable")
    }

    fn write_record(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        mvm_core::util::atomic_io::atomic_write_new(path, bytes)
            .with_context(|| format!("publishing initial policy at {}", path.display()))?;
        mvm_core::util::atomic_io::sync_dir(&self.root)
            .with_context(|| format!("syncing policy directory {}", self.root.display()))
    }

    fn write_index(&self, key: &str, closure: &str) -> Result<()> {
        let mut index = self.read_index_file()?.unwrap_or_default();
        index.generations.insert(key.to_owned(), closure.to_owned());
        let index_path = self.root.join("active.json");
        mvm_core::util::atomic_io::atomic_write_durable(
            &index_path,
            &serde_json::to_vec(&index).context("serializing policy index")?,
        )
        .with_context(|| format!("publishing policy index {}", index_path.display()))
    }

    fn clear_obligation(&self) -> Result<()> {
        let path = self.obligation_path();
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        mvm_core::util::atomic_io::sync_dir(&self.root)
            .context("making the publication resolution durable")
    }

    /// Resolve an interrupted publication from what is durably on disk. It
    /// only ever removes files; it never writes an index or a record.
    pub(crate) fn recover(&self) -> Result<()> {
        self.recover_inner()
            .map_err(|error| anyhow::Error::new(PublicationUnresolved(format!("{error:#}"))))
    }

    fn recover_inner(&self) -> Result<()> {
        let Some(pending) = self.read_obligation()? else {
            return Ok(());
        };
        ensure!(
            pending.project.len() == 64
                && pending
                    .project
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "publication obligation names an invalid project key"
        );
        mvm_core::util::atomic_io::sync_dir(&self.root)
            .context("syncing the policy directory before recovery")?;
        let indexed = self
            .read_index_file()?
            .and_then(|index| index.generations.get(&pending.project).cloned());
        let record = self.read_record(&pending.project)?;
        let matches = |record: &ProjectPolicyCandidate| record.closure_sha256 == pending.closure;
        match (indexed, record) {
            (Some(closure), Some(record)) => {
                ensure!(
                    closure == pending.closure && matches(&record),
                    "indexed policy generation differs from the pending publication"
                );
                self.clear_obligation()
            }
            (Some(_), None) => anyhow::bail!("indexed policy generation has no record"),
            (None, None) => self.roll_back(&pending.project, false),
            (None, Some(record)) => {
                ensure!(
                    matches(&record),
                    "unindexed policy record differs from the pending publication"
                );
                self.roll_back(&pending.project, true)
            }
        }
    }

    /// Undo a publication that never reached the index. The activation marker
    /// goes too when no index exists at all, since only this publication can
    /// have written it; it is removed after the record and before the
    /// obligation so a crash in between still recovers.
    fn roll_back(&self, key: &str, record_present: bool) -> Result<()> {
        if record_present {
            let path = self.root.join(format!("{key}.json"));
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            mvm_core::util::atomic_io::sync_dir(&self.root)
                .context("making the record removal durable")?;
        }
        if self.read_index_file()?.is_none() {
            let marker = self.root.join("activated.marker");
            match fs::remove_file(&marker) {
                Ok(()) => mvm_core::util::atomic_io::sync_dir(&self.root)
                    .context("making the marker removal durable")?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("removing {}", marker.display()));
                }
            }
        }
        self.clear_obligation()
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
                        == mvm_core::policy::authored::Platform::current(Some(
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

fn read_bounded(file: fs::File, max: u64, what: &str) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.len() <= max,
        "{what} exceeds its size limit"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "{what} exceeds its size limit");
    Ok(bytes)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use mvm_contract::protocol::vm_backend::BackendKind;
    use mvm_core::policy::authored::Platform;

    struct Fixture {
        _root: tempfile::TempDir,
        project: PathBuf,
        source: PolicyStore,
        candidate: ProjectPolicyCandidate,
        store: GenerationStore,
        key: String,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let policy = root.path().join("policies");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(policy.join("profiles")).unwrap();
        fs::write(
            project.join("mvm.toml"),
            "flake = \".\"\n[policy]\nprofile = \"one\"\n",
        )
        .unwrap();
        fs::write(
            policy.join("profiles/one.toml"),
            "[overrides.network]\nallow = [\"old.test\"]\n",
        )
        .unwrap();
        let source = PolicyStore::at(&policy);
        let platform = Platform {
            os: Some(mvm_core::policy::authored::model::HostOs::Linux),
            backend: Some(BackendKind::Firecracker),
            arch: Platform::current(None).arch,
        };
        let candidate = super::super::prepare_with(&project, &[], platform, &source).unwrap();
        let store = GenerationStore::open(root.path().join("home")).unwrap();
        let key = store
            .path(&project)
            .unwrap()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        Fixture {
            _root: root,
            project,
            source,
            candidate,
            store,
            key,
        }
    }

    impl Fixture {
        fn bytes(&self) -> Vec<u8> {
            serde_json::to_vec(&self.candidate).unwrap()
        }

        fn closure(&self) -> String {
            self.candidate.closure_sha256.clone()
        }

        fn record_path(&self) -> PathBuf {
            self.store.root.join(format!("{}.json", self.key))
        }

        /// The first publication step: the obligation alone.
        fn through_obligation(&self) {
            self.store
                .write_obligation(&self.key, &self.closure())
                .unwrap();
        }

        fn through_marker(&self) {
            self.through_obligation();
            self.store.write_marker().unwrap();
        }

        fn through_record(&self) {
            self.through_marker();
            self.store
                .write_record(&self.record_path(), &self.bytes())
                .unwrap();
        }

        fn through_index(&self) {
            self.through_record();
            self.store.write_index(&self.key, &self.closure()).unwrap();
        }

        /// A second project's key, closure and record bytes.
        fn second_project(&self) -> (String, String, Vec<u8>) {
            let other = self._root.path().join("project2");
            fs::create_dir_all(&other).unwrap();
            fs::write(
                other.join("mvm.toml"),
                "flake = \".\"\n[policy]\nprofile = \"one\"\n",
            )
            .unwrap();
            let platform = self.candidate.platform;
            let candidate =
                super::super::prepare_with(&other, &[], platform, &self.source).unwrap();
            let key = self
                .store
                .path(&other)
                .unwrap()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let bytes = serde_json::to_vec(&candidate).unwrap();
            (key, candidate.closure_sha256, bytes)
        }

        fn load(&self) -> Result<Option<ProjectPolicyCandidate>> {
            self.store.load(&self.project, &self.source)
        }
    }

    fn refused_for_recovery(error: anyhow::Error) -> bool {
        error.to_string().contains("requires recovery")
    }

    #[test]
    fn a_publication_stopped_after_its_obligation_is_refused_then_rolled_back() {
        let f = fixture();
        f.through_obligation();
        assert!(refused_for_recovery(f.load().unwrap_err()));
        assert!(
            f.store
                .has_active_generation()
                .unwrap_err()
                .to_string()
                .contains("requires recovery")
        );
        f.store.recover().unwrap();
        assert!(!f.store.has_obligation().unwrap());
        assert!(!f.store.root.join("activated.marker").exists());
        assert!(f.load().unwrap().is_none());
        assert!(!f.store.has_active_generation().unwrap());
        f.store.publish_initial(&f.candidate, &f.source).unwrap();
        assert!(f.load().unwrap().is_some());
    }

    #[test]
    fn a_publication_stopped_after_its_marker_recovers_clean() {
        let f = fixture();
        f.through_marker();
        assert!(refused_for_recovery(f.load().unwrap_err()));
        f.store.recover().unwrap();
        assert!(!f.store.has_obligation().unwrap());
        assert!(!f.store.root.join("activated.marker").exists());
        assert!(f.load().unwrap().is_none());
        f.store.publish_initial(&f.candidate, &f.source).unwrap();
        assert!(f.load().unwrap().is_some());
    }

    #[test]
    fn a_publication_stopped_after_its_record_is_refused_then_rolled_back() {
        let f = fixture();
        f.through_record();
        assert!(refused_for_recovery(f.load().unwrap_err()));
        f.store.recover().unwrap();
        assert!(!f.store.has_obligation().unwrap());
        assert!(!f.record_path().exists());
        assert!(!f.store.root.join("activated.marker").exists());
        assert!(f.load().unwrap().is_none());
        assert!(!f.store.has_active_generation().unwrap());
        f.store.publish_initial(&f.candidate, &f.source).unwrap();
        assert!(f.load().unwrap().is_some());
    }

    #[test]
    fn an_indexed_publication_is_not_readable_until_recovery_confirms_it() {
        let f = fixture();
        f.through_index();
        assert!(refused_for_recovery(f.load().unwrap_err()));
        f.store.recover().unwrap();
        assert!(!f.store.has_obligation().unwrap());
        let loaded = f.load().unwrap().expect("the committed generation");
        assert_eq!(loaded.closure_sha256, f.closure());
    }

    #[test]
    fn recovery_refuses_an_obligation_the_record_does_not_match() {
        let f = fixture();
        f.through_obligation();
        fs::remove_file(f.store.obligation_path()).unwrap();
        f.store.write_obligation(&f.key, &"0".repeat(64)).unwrap();
        f.store.write_record(&f.record_path(), &f.bytes()).unwrap();
        let before = fs::read(f.record_path()).unwrap();
        assert!(f.store.recover().is_err());
        assert!(f.store.has_obligation().unwrap());
        assert_eq!(fs::read(f.record_path()).unwrap(), before);
        assert!(refused_for_recovery(f.load().unwrap_err()));
    }

    #[test]
    fn recovery_refuses_a_malformed_or_oversized_obligation_and_leaves_it() {
        for contents in [b"not json".to_vec(), vec![b' '; 5000]] {
            let f = fixture();
            f.through_obligation();
            fs::remove_file(f.store.obligation_path()).unwrap();
            mvm_core::util::atomic_io::atomic_write_new(&f.store.obligation_path(), &contents)
                .unwrap();
            assert!(f.store.recover().is_err());
            assert!(f.store.has_obligation().unwrap());
            assert!(refused_for_recovery(f.load().unwrap_err()));
        }
    }

    #[test]
    fn an_existing_record_refuses_publication_without_blocking_the_store() {
        let f = fixture();
        f.store.write_record(&f.record_path(), &f.bytes()).unwrap();
        let error = f
            .store
            .publish_initial(&f.candidate, &f.source)
            .unwrap_err();
        assert!(error.downcast_ref::<PublicationUnresolved>().is_none());
        assert!(!f.store.has_obligation().unwrap());
    }

    #[test]
    fn a_dangling_symlink_at_the_record_path_is_an_ordinary_refusal() {
        let f = fixture();
        std::os::unix::fs::symlink(f.store.root.join("nowhere"), f.record_path()).unwrap();
        let error = f
            .store
            .publish_initial(&f.candidate, &f.source)
            .unwrap_err();
        assert!(error.downcast_ref::<PublicationUnresolved>().is_none());
        assert!(!f.store.has_obligation().unwrap());
    }

    #[test]
    fn an_unresolved_obligation_is_reported_as_unresolved_on_read_and_recover() {
        let f = fixture();
        f.through_obligation();
        assert!(
            f.load()
                .unwrap_err()
                .downcast_ref::<PublicationUnresolved>()
                .is_some()
        );
        fs::remove_file(f.store.obligation_path()).unwrap();
        mvm_core::util::atomic_io::atomic_write_new(&f.store.obligation_path(), b"not json")
            .unwrap();
        assert!(
            f.store
                .recover()
                .unwrap_err()
                .downcast_ref::<PublicationUnresolved>()
                .is_some()
        );
    }

    #[test]
    fn a_rolled_back_second_publication_leaves_the_first_generation_readable() {
        let f = fixture();
        f.store.publish_initial(&f.candidate, &f.source).unwrap();
        let second = f.second_project();
        f.store.write_obligation(&second.0, &second.1).unwrap();
        f.store
            .write_record(&f.store.root.join(format!("{}.json", second.0)), &second.2)
            .unwrap();
        f.store.recover().unwrap();
        assert!(!f.store.root.join(format!("{}.json", second.0)).exists());
        assert!(!f.store.has_obligation().unwrap());
        assert!(f.store.root.join("activated.marker").exists());
        assert!(f.load().unwrap().is_some());
    }

    #[test]
    fn a_crash_between_marker_removal_and_obligation_removal_recovers_clean() {
        let f = fixture();
        f.store.write_obligation(&f.key, &f.closure()).unwrap();
        f.store.recover().unwrap();
        assert!(!f.store.has_obligation().unwrap());
        assert!(f.load().unwrap().is_none());
        f.store.publish_initial(&f.candidate, &f.source).unwrap();
        assert!(f.load().unwrap().is_some());
    }
}
