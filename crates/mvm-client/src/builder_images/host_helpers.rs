//! Verified host-helper acquisition for an explicitly registered frontend.
//!
//! The frontend supplies only its compiled identity and installation directory.
//! Download selection, signature verification and installation remain here.
//! Embedders must register a target; we never infer an install directory from
//! their process executable (which could be Python or another host application).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result, ensure};
use mvm_build::release_signature::{ReleaseSignatureRequest, ReleaseTrain};

const MARKER: &str = ".mvm-host-helpers-source-commit";
const HELPERS: &[&str] = &[
    "mvm-hvf-supervisor",
    "mvm-libkrun-supervisor",
    "mvm-network-endpoint",
];

#[derive(Debug, Clone)]
pub struct SourceBuild {
    pub commit: String,
    pub dirty: bool,
}

#[derive(Debug, Clone)]
pub struct InstallTarget {
    pub directory: PathBuf,
    /// An explicitly supplied frontend that also needs VM entitlements.
    pub frontend_executable: Option<PathBuf>,
    pub version: String,
    pub source: Option<SourceBuild>,
}

static TARGET: OnceLock<fn() -> Result<InstallTarget>> = OnceLock::new();

/// Register compiled frontend metadata, not a downloader or trust-policy hook.
pub fn register_install_target(provider: fn() -> Result<InstallTarget>) {
    TARGET.get_or_init(|| provider);
}

fn target() -> Result<InstallTarget> {
    let target = registered_target(TARGET.get().copied())?;
    validate_target(&target)?;
    Ok(target)
}

fn registered_target(provider: Option<fn() -> Result<InstallTarget>>) -> Result<InstallTarget> {
    provider.context(
        "host-helper target is not registered; call host_helpers::register_install_target \
         with an explicit helper directory and optional frontend executable before signing or acquisition",
    )?()
}

fn validate_paths(target: &InstallTarget) -> Result<()> {
    ensure!(
        target.directory.is_absolute()
            && !target
                .directory
                .components()
                .any(|part| part == std::path::Component::ParentDir)
            && target.directory.is_dir(),
        "host-helper installation directory must be an existing absolute directory without parent traversal"
    );
    if let Some(frontend) = &target.frontend_executable {
        validate_frontend(frontend)?;
        ensure!(
            frontend.file_name() != Some(std::ffi::OsStr::new(".mvm-host-installation.lock")),
            "explicit frontend cannot be the installation lock"
        );
    }
    let mut destinations = std::collections::BTreeSet::new();
    for path in HELPERS
        .iter()
        .copied()
        .chain([MARKER, ".mvm-host-installation.lock"])
        .map(|name| target.directory.join(name))
        .chain(target.frontend_executable.iter().cloned())
    {
        ensure!(
            destinations.insert(destination_key(&path)?),
            "frontend, helper, marker and lock destinations must be distinct: {path:?}"
        );
    }
    Ok(())
}

fn destination_key(path: &Path) -> Result<PathBuf> {
    Ok(path
        .parent()
        .context("destination has no parent")?
        .canonicalize()?
        .join(path.file_name().context("destination has no basename")?))
}

/// Coordinates cooperating installation writers, including standalone signers.
/// Hold until all replacements and any rollback finish. Never nest these locks.
pub struct InstallationLock {
    _locks: Vec<mvm_core::util::atomic_io::FileLock>,
    target: InstallTarget,
}

impl InstallationLock {
    /// The captured canonical paths protected by this guard. Writers must use
    /// these paths, not resolve the registration callback or original aliases again.
    pub fn target(&self) -> &InstallTarget {
        &self.target
    }
}

fn capture_target(target: &InstallTarget) -> Result<InstallTarget> {
    validate_paths(target)?;
    let mut captured = target.clone();
    captured.directory = target.directory.canonicalize()?;
    captured.frontend_executable = target
        .frontend_executable
        .as_deref()
        .map(destination_key)
        .transpose()?;
    validate_paths(&captured)?;
    Ok(captured)
}

pub fn lock_installation(target: &InstallTarget) -> Result<InstallationLock> {
    let target = capture_target(target)?;
    let mut directories = std::collections::BTreeSet::new();
    directories.insert(target.directory.clone());
    if let Some(frontend) = &target.frontend_executable {
        directories.insert(
            frontend
                .parent()
                .context("frontend has no parent")?
                .to_owned(),
        );
    }
    let locks = directories
        .into_iter()
        .map(|directory| {
            mvm_core::util::atomic_io::FileLock::acquire(&directory.join(".mvm-host-installation"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(InstallationLock {
        _locks: locks,
        target,
    })
}

/// Resolve only explicit installed paths. Local signing has no release identity
/// requirement, and must never invoke acquisition or ambient executable lookup.
pub(crate) fn registered_sign_targets(
    apply: bool,
) -> Result<(
    Vec<mvm_runtime::codesign::SignTarget>,
    Option<InstallationLock>,
)> {
    let target = registered_target(TARGET.get().copied())?;
    signing_context(&target, apply)
}

fn signing_context(
    target: &InstallTarget,
    apply: bool,
) -> Result<(
    Vec<mvm_runtime::codesign::SignTarget>,
    Option<InstallationLock>,
)> {
    if apply {
        let guard = lock_installation(target)?;
        Ok((signing_targets(guard.target())?, Some(guard)))
    } else {
        // Preview must work in read-only installation directories and must not
        // create lock anchors or any other installation files.
        Ok((signing_targets(&capture_target(target)?)?, None))
    }
}

fn signing_targets(target: &InstallTarget) -> Result<Vec<mvm_runtime::codesign::SignTarget>> {
    use mvm_runtime::codesign::{RequiredEntitlement, SignTarget};
    validate_paths(target)?;
    let mut targets = Vec::new();
    if let Some(frontend) = &target.frontend_executable {
        targets.push(SignTarget {
            path: frontend.clone(),
            required: RequiredEntitlement::Virtualization,
        });
    }
    for name in ["mvm-hvf-supervisor", "mvm-libkrun-supervisor"] {
        let path = target.directory.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file(),
                    "signing helper must be a regular file: {path:?}"
                );
                targets.push(SignTarget {
                    path,
                    required: RequiredEntitlement::Hypervisor,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(
        !targets.is_empty(),
        "registered directory has no signing targets; install helpers or explicitly declare a frontend executable"
    );
    Ok(targets)
}

fn validate_target(target: &InstallTarget) -> Result<()> {
    validate_paths(target)?;
    ensure!(
        !target.version.is_empty()
            && target.version.len() <= 128
            && target
                .version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c)),
        "invalid host-helper release version"
    );
    if let Some(source) = &target.source {
        validate_source_identity(source)?;
    }
    Ok(())
}

fn validate_source_identity(source: &SourceBuild) -> Result<()> {
    ensure!(
        !source.dirty,
        "this frontend was built from a dirty or unidentified checkout; \
         explicitly compile local helpers with \
         `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`"
    );
    ensure!(
        source.commit.len() == 40
            && source
                .commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "the source build metadata has no valid commit; explicitly compile local helpers with \
         `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`"
    );
    Ok(())
}

pub fn published_host_helpers_match_current_build() -> Result<bool> {
    let target = target()?;
    Ok(match target.source {
        None => true,
        Some(source) => std::fs::read_to_string(target.directory.join(MARKER))
            .is_ok_and(|recorded| recorded.trim() == source.commit),
    })
}

pub fn prepare_release_host_binaries() -> Result<()> {
    prepare(&target()?)
}

/// Acquire signed helpers into the caller's explicit installation directory.
pub fn prepare(target: &InstallTarget) -> Result<()> {
    validate_target(target)?;
    // Preserve the early writable-directory refusal without elevating privileges.
    let probe = tempfile::NamedTempFile::new_in(&target.directory)
        .context("cannot install published host helpers in the registered directory")?;
    drop(probe);
    let triple = host_target()?;
    let (base, asset, folder, version, train) = match &target.source {
        Some(source) => {
            let folder = format!("mvm-host-helpers-{}-{triple}", source.commit);
            (
                std::env::var("MVM_SOURCE_HELPER_BASE_URL").unwrap_or_else(|_| {
                    format!(
                        "{}/tinylabscom/mvm/releases/download/source-builds",
                        mvm_build::published_image_set::github_download_base()
                    )
                }),
                format!("{folder}.tar.gz"),
                folder,
                source.commit.clone(),
                ReleaseTrain::SourceHelpers,
            )
        }
        None => (
            format!(
                "{}/tinylabscom/mvm/releases/download/v{}",
                mvm_build::published_image_set::github_download_base(),
                target.version
            ),
            format!("mvmctl-{triple}.tar.gz"),
            format!("mvmctl-{triple}"),
            target.version.clone(),
            ReleaseTrain::Cli,
        ),
    };
    let temporary = tempfile::tempdir().context("create host-helper download directory")?;
    let archive = temporary.path().join(&asset);
    super::acquisition::download_locked_artifact(&format!("{base}/{asset}"), &archive)
        .context("published host helpers unavailable; prepare local helpers explicitly with `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`")?;
    mvm_build::release_signature::verify_release_archive_signature(&ReleaseSignatureRequest {
        base_url: &base,
        asset: &asset,
        archive_path: &archive,
        version: &version,
        train,
    })
    .context("verify the host helper bundle")?;
    // Extraction is after verification and confined to a fresh private directory.
    let file = std::fs::File::open(&archive)?;
    tar::Archive::new(flate2::read::GzDecoder::new(file))
        .unpack(temporary.path())
        .context("extract verified host helpers")?;
    let extracted = temporary.path().join(folder);
    if let Some(source) = &target.source {
        let recorded = std::fs::read_to_string(extracted.join("SOURCE_COMMIT"))
            .context("source helper bundle has no SOURCE_COMMIT")?;
        ensure!(
            recorded.trim() == source.commit,
            "source helper bundle records a different commit than requested"
        );
    }
    install(&extracted, target)
}

struct Candidate {
    destination: PathBuf,
    staged: tempfile::NamedTempFile,
    required: Option<mvm_runtime::codesign::RequiredEntitlement>,
    backup: Option<tempfile::TempDir>,
    published: bool,
    original: Option<FileSnapshot>,
    prepared: Option<FileSnapshot>,
}

#[derive(Debug, PartialEq, Eq)]
struct FileSnapshot {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    modified: Option<std::time::SystemTime>,
    digest: [u8; 32],
}

fn snapshot(path: &Path) -> Result<Option<FileSnapshot>> {
    use sha2::Digest;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file(),
        "installation path is not a regular file: {path:?}"
    );
    let mut file = std::fs::File::open(path)?;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    ensure!(
        file.metadata()?.dev() == metadata.dev() && file.metadata()?.ino() == metadata.ino(),
        "installation path changed while inspecting: {path:?}"
    );
    let mut hash = sha2::Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = std::io::Read::read(&mut file, &mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Some(FileSnapshot {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        mode: metadata.mode(),
        modified: metadata.modified().ok(),
        digest: hash.finalize().into(),
    }))
}

impl Candidate {
    fn copy(source: &Path, destination: PathBuf) -> Result<Self> {
        let destination = destination_key(&destination)?;
        let original = snapshot(&destination)?;
        let metadata = std::fs::symlink_metadata(source)?;
        ensure!(
            metadata.is_file(),
            "helper source must be a regular file: {source:?}"
        );
        let parent = destination
            .parent()
            .context("helper destination has no parent")?;
        let mut staged = tempfile::NamedTempFile::new_in(parent)?;
        std::io::copy(&mut std::fs::File::open(source)?, &mut staged)?;
        staged.as_file().set_permissions(metadata.permissions())?;
        Ok(Self {
            destination,
            staged,
            required: None,
            backup: None,
            published: false,
            original,
            prepared: None,
        })
    }
}

fn stage(extracted: &Path, target: &InstallTarget) -> Result<Vec<Candidate>> {
    use mvm_runtime::codesign::RequiredEntitlement;
    validate_paths(target)?;
    ensure!(
        std::fs::symlink_metadata(extracted)?.is_dir(),
        "helper bundle root must be a directory, not a symbolic link"
    );
    // Both source and release bundles promise the network endpoint, plus HVF
    // on macOS. Libkrun is optional; neither archive producer ships it today.
    let mut candidates = Vec::new();
    for name in HELPERS {
        let source = extracted.join(name);
        match std::fs::symlink_metadata(&source) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    *name != "mvm-network-endpoint"
                        && !(*name == "mvm-hvf-supervisor" && cfg!(target_os = "macos")),
                    "helper bundle is missing required helper {name}"
                );
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        let mut candidate = Candidate::copy(&source, target.directory.join(name))?;
        if *name != "mvm-network-endpoint" {
            candidate.required = Some(RequiredEntitlement::Hypervisor);
        }
        candidates.push(candidate);
    }
    if cfg!(target_os = "macos")
        && let Some(frontend) = &target.frontend_executable
    {
        validate_frontend(frontend)?;
        if !mvm_runtime::codesign::entitlement_present(
            frontend,
            RequiredEntitlement::Virtualization,
        )
        .unwrap_or(false)
        {
            let mut candidate = Candidate::copy(frontend, frontend.clone())?;
            candidate.required = Some(RequiredEntitlement::Virtualization);
            candidates.push(candidate);
        }
    }
    if let Some(source) = &target.source {
        let marker = tempfile::NamedTempFile::new_in(&target.directory)?;
        mvm_core::util::atomic_io::atomic_write_durable(
            marker.path(),
            format!("{}\n", source.commit).as_bytes(),
        )?;
        candidates.push(Candidate {
            destination: destination_key(&target.directory.join(MARKER))?,
            staged: marker,
            required: None,
            backup: None,
            published: false,
            original: snapshot(&target.directory.join(MARKER))?,
            prepared: None,
        });
    }
    Ok(candidates)
}

fn validate_frontend(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| part == std::path::Component::ParentDir)
            && std::fs::symlink_metadata(path)?.is_file(),
        "explicit frontend must be an absolute regular file without parent traversal: {path:?}"
    );
    Ok(())
}

fn sign_candidates(candidates: &[Candidate]) -> Result<()> {
    if cfg!(target_os = "macos") {
        let targets: Vec<_> = candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .required
                    .map(|required| mvm_runtime::codesign::SignTarget {
                        path: candidate.staged.path().to_owned(),
                        required,
                    })
            })
            .collect();
        let reports = mvm_runtime::codesign::sign_targets(&targets);
        ensure!(
            reports.len() == targets.len(),
            "signer returned an incomplete result"
        );
        for report in reports {
            ensure!(
                report.entitlements_present && report.error.is_none(),
                "candidate signing failed for {:?}: {:?}",
                report.path,
                report.error
            );
        }
    }
    Ok(())
}

fn install(extracted: &Path, target: &InstallTarget) -> Result<()> {
    let guard = lock_installation(target)?;
    let candidates = stage(extracted, guard.target())?;
    sign_candidates(&candidates)?;
    publish(candidates, |_| Ok(()))
}

// Each rename is atomic, not the whole set. Keep original inodes linked until
// marker-last publication succeeds; ordinary failures get one bounded rollback.
// Locks coordinate participating writers. Identity/content guards detect other
// writers, but are not filesystem compare-and-swap against arbitrary races.
// Hard-link backups share in-place mutations; never restore a changed backup.
fn publish(
    mut candidates: Vec<Candidate>,
    mut before: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    for candidate in &mut candidates {
        // Signing may replace the staged pathname, so reopen it before syncing.
        mvm_core::util::atomic_io::sync_file(candidate.staged.path())?;
        candidate.prepared = snapshot(candidate.staged.path())?;
        ensure!(
            snapshot(&candidate.destination)? == candidate.original,
            "installation conflict before backup: {:?}",
            candidate.destination
        );
        match std::fs::symlink_metadata(&candidate.destination) {
            Ok(metadata) => {
                ensure!(
                    !metadata.is_dir(),
                    "helper destination is a directory: {:?}",
                    candidate.destination
                );
                let backup = tempfile::tempdir_in(
                    candidate.destination.parent().context("missing parent")?,
                )?;
                std::fs::hard_link(&candidate.destination, backup.path().join("original"))?;
                ensure!(
                    snapshot(&backup.path().join("original"))? == candidate.original,
                    "installation conflict while backing up: {:?}",
                    candidate.destination
                );
                candidate.backup = Some(backup);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    for index in 0..candidates.len() {
        let result = (|| {
            before(index)?;
            let candidate = &mut candidates[index];
            ensure!(
                snapshot(&candidate.destination)? == candidate.original,
                "installation conflict before publication: {:?}",
                candidate.destination
            );
            ensure!(
                snapshot(candidate.staged.path())? == candidate.prepared,
                "staged candidate changed before publication: {:?}",
                candidate.destination
            );
            std::fs::rename(candidate.staged.path(), &candidate.destination)?;
            candidate.published = true;
            mvm_core::util::atomic_io::sync_dir(
                candidate.destination.parent().context("missing parent")?,
            )?;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = result {
            let remaining = rollback(&mut candidates);
            anyhow::bail!("helper publication failed: {error:#}; rollback issues: {remaining:?}");
        }
    }
    Ok(())
}

fn rollback(candidates: &mut [Candidate]) -> Vec<String> {
    let mut failures = Vec::new();
    for candidate in candidates.iter_mut().rev() {
        let result = (|| {
            if !candidate.published {
                ensure!(
                    snapshot(&candidate.destination)? == candidate.original,
                    "installation conflict before publication; destination was replaced or modified"
                );
                return Ok(());
            }
            ensure!(
                snapshot(&candidate.destination)? == candidate.prepared,
                "installation conflict during rollback; destination was replaced or modified"
            );
            if let Some(backup) = &candidate.backup {
                ensure!(
                    snapshot(&backup.path().join("original"))? == candidate.original,
                    "installation conflict during rollback; original backup was modified in place"
                );
                // Retain the backup even if rename succeeds but directory sync
                // fails: recovery must still have an original inode to use.
                std::fs::hard_link(backup.path().join("original"), candidate.staged.path())?;
                std::fs::rename(candidate.staged.path(), &candidate.destination)?;
            } else {
                std::fs::remove_file(&candidate.destination)?;
            }
            mvm_core::util::atomic_io::sync_dir(
                candidate.destination.parent().context("missing parent")?,
            )?;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = result {
            let retained = candidate.backup.take().map(tempfile::TempDir::keep);
            failures.push(format!(
                "{:?}: {error}; original retained at {retained:?}",
                candidate.destination
            ));
        }
    }
    failures
}

fn host_target() -> Result<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => Ok("aarch64-apple-darwin"),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin"),
        ("aarch64", "linux") => Ok("aarch64-unknown-linux-gnu"),
        ("x86_64", "linux") => Ok("x86_64-unknown-linux-gnu"),
        _ => anyhow::bail!("unsupported host-helper platform"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_target(directory: PathBuf) -> InstallTarget {
        InstallTarget {
            directory,
            frontend_executable: None,
            version: "1.0.0".into(),
            source: Some(SourceBuild {
                commit: "a".repeat(40),
                dirty: false,
            }),
        }
    }

    fn bundle(directory: &Path) {
        for name in HELPERS {
            std::fs::write(directory.join(name), b"malformed native executable").unwrap();
        }
    }

    #[test]
    fn signing_requires_registration_without_touching_global_state() {
        let error = registered_target(None).unwrap_err().to_string();
        assert!(error.contains("register_install_target"));
        assert!(error.contains("explicit helper directory"));
    }

    #[test]
    fn signing_uses_only_declared_frontend_and_allows_local_dirty_builds() {
        use mvm_runtime::codesign::RequiredEntitlement;
        let directory = tempfile::tempdir().unwrap();
        let mut target = fixture_target(directory.path().to_owned());
        target.source = Some(SourceBuild {
            commit: "local-unpublished".into(),
            dirty: true,
        });
        target.version.clear();
        let helper = directory.path().join("mvm-hvf-supervisor");
        std::fs::write(&helper, b"helper fixture").unwrap();
        let targets = signing_targets(&target).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, helper);
        assert_eq!(targets[0].required, RequiredEntitlement::Hypervisor);
        let frontend = directory.path().join("explicit-python-wrapper");
        std::fs::write(&frontend, b"frontend fixture").unwrap();
        target.frontend_executable = Some(frontend.clone());
        let targets = signing_targets(&target).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].path, frontend);
        assert_eq!(targets[0].required, RequiredEntitlement::Virtualization);
        assert_eq!(targets[1].path, helper);
        assert!(validate_target(&target).is_err());
    }

    #[test]
    fn empty_registered_directory_is_not_signing_success() {
        let directory = tempfile::tempdir().unwrap();
        let target = fixture_target(directory.path().to_owned());
        assert!(
            signing_targets(&target)
                .unwrap_err()
                .to_string()
                .contains("no signing targets")
        );
    }

    #[test]
    fn empty_and_incomplete_bundles_never_publish() {
        let extracted = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let target = fixture_target(destination.path().to_owned());
        assert!(stage(extracted.path(), &target).is_err());
        std::fs::write(extracted.path().join(HELPERS[0]), b"only one helper").unwrap();
        assert!(stage(extracted.path(), &target).is_err());
        assert!(!destination.path().join(MARKER).exists());
    }

    #[cfg(unix)]
    #[test]
    fn helper_symlinks_are_rejected_and_permissions_are_preserved() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let extracted = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let target = fixture_target(destination.path().to_owned());
        bundle(extracted.path());
        let helper = extracted.path().join(HELPERS[0]);
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o751)).unwrap();
        let candidates = stage(extracted.path(), &target).unwrap();
        assert_eq!(
            std::fs::metadata(candidates[0].staged.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        std::fs::remove_file(&helper).unwrap();
        symlink(extracted.path().join(HELPERS[1]), &helper).unwrap();
        assert!(stage(extracted.path(), &target).is_err());
    }

    #[test]
    fn publication_failure_rolls_back_and_marker_is_last() {
        let extracted = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let target = fixture_target(destination.path().to_owned());
        bundle(extracted.path());
        for name in HELPERS.iter().copied().chain([MARKER]) {
            std::fs::write(destination.path().join(name), b"old").unwrap();
        }
        let candidates = stage(extracted.path(), &target).unwrap();
        assert_eq!(
            candidates.last().unwrap().destination,
            destination_key(&destination.path().join(MARKER)).unwrap()
        );
        // This seam exercises filesystem publication only, not crypto acceptance.
        assert!(
            publish(candidates, |index| {
                assert_eq!(
                    std::fs::read(destination.path().join(MARKER)).unwrap(),
                    b"old"
                );
                if index == 2 {
                    anyhow::bail!("injected publication refusal");
                }
                Ok(())
            })
            .is_err()
        );
        for name in HELPERS.iter().copied().chain([MARKER]) {
            assert_eq!(
                std::fs::read(destination.path().join(name)).unwrap(),
                b"old"
            );
        }
    }

    #[test]
    fn failed_rollback_retains_original_backup() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original-source");
        std::fs::write(&original, b"original").unwrap();
        let destination = root.path().join("destination");
        std::fs::write(&destination, b"original").unwrap();
        let mut candidate = Candidate::copy(&original, destination.clone()).unwrap();
        let backup = tempfile::tempdir_in(root.path()).unwrap();
        let retained = backup.path().to_owned();
        std::fs::hard_link(&destination, retained.join("original")).unwrap();
        candidate.backup = Some(backup);
        candidate.prepared = snapshot(candidate.staged.path()).unwrap();
        std::fs::rename(candidate.staged.path(), &destination).unwrap();
        candidate.published = true;
        std::fs::remove_file(&destination).unwrap();
        std::fs::create_dir(&destination).unwrap();
        let failures = rollback(std::slice::from_mut(&mut candidate));
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("original retained"));
        drop(candidate);
        assert_eq!(
            std::fs::read(retained.join("original")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn rollback_preserves_concurrent_replacements_for_existing_and_absent_paths() {
        for (originally_present, in_place) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let extracted = tempfile::tempdir().unwrap();
            let destination = tempfile::tempdir().unwrap();
            bundle(extracted.path());
            let target = fixture_target(destination.path().to_owned());
            let first = destination.path().join(HELPERS[0]);
            if originally_present {
                std::fs::write(&first, b"original").unwrap();
            }
            let _guard = lock_installation(&target).unwrap();
            let candidates = stage(extracted.path(), &target).unwrap();
            let error = publish(candidates, |index| {
                if index == 1 {
                    if in_place {
                        std::fs::write(&first, b"unrelated replacement")?;
                    } else {
                        let newer = destination.path().join("newer");
                        std::fs::write(&newer, b"unrelated replacement")?;
                        std::fs::rename(&newer, &first)?;
                    }
                    anyhow::bail!("injected failure after unrelated replacement");
                }
                Ok(())
            })
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("installation conflict during rollback")
            );
            assert_eq!(std::fs::read(&first).unwrap(), b"unrelated replacement");
            assert!(!destination.path().join(MARKER).exists());
            let retained: Vec<_> = std::fs::read_dir(destination.path())
                .unwrap()
                .map(|entry| entry.unwrap().path().join("original"))
                .filter(|path| path.is_file())
                .collect();
            assert_eq!(retained.len(), usize::from(originally_present));
            if originally_present {
                assert_eq!(std::fs::read(&retained[0]).unwrap(), b"original");
            }
        }
    }

    #[test]
    fn publication_rejects_changed_destination_and_retains_backup() {
        let extracted = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        bundle(extracted.path());
        let target = fixture_target(destination.path().to_owned());
        let first = destination.path().join(HELPERS[0]);
        std::fs::write(&first, b"original").unwrap();
        let candidates = stage(extracted.path(), &target).unwrap();
        let error = publish(candidates, |index| {
            if index == 0 {
                let newer = destination.path().join("newer");
                std::fs::write(&newer, b"replacement")?;
                std::fs::rename(&newer, &first)?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("installation conflict before publication")
        );
        assert_eq!(std::fs::read(&first).unwrap(), b"replacement");
        assert!(std::fs::read_dir(destination.path()).unwrap().any(|entry| {
            std::fs::read(entry.unwrap().path().join("original"))
                .is_ok_and(|bytes| bytes == b"original")
        }));
    }

    #[test]
    fn rollback_refuses_backup_mutated_through_old_hardlink() {
        let extracted = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        bundle(extracted.path());
        let target = fixture_target(destination.path().to_owned());
        let first = destination.path().join(HELPERS[0]);
        let old_link = destination.path().join("old-link");
        std::fs::write(&first, b"original").unwrap();
        std::fs::hard_link(&first, &old_link).unwrap();
        let candidates = stage(extracted.path(), &target).unwrap();
        let error = publish(candidates, |index| {
            if index == 1 {
                std::fs::write(&old_link, b"mutated original")?;
                anyhow::bail!("injected failure");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original backup was modified in place")
        );
        assert_eq!(
            std::fs::read(&first).unwrap(),
            b"malformed native executable"
        );
        assert_eq!(std::fs::read(&old_link).unwrap(), b"mutated original");
    }

    #[cfg(unix)]
    #[test]
    fn parent_alias_and_marker_frontends_are_rejected_without_mutations() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("real");
        let alias = root.path().join("alias");
        std::fs::create_dir(&directory).unwrap();
        symlink(&directory, &alias).unwrap();
        bundle(&directory);
        std::fs::write(directory.join(MARKER), b"original marker").unwrap();
        for frontend in [
            alias.join(HELPERS[0]),
            alias.join(MARKER),
            directory.join(MARKER),
        ] {
            let mut target = fixture_target(directory.clone());
            target.frontend_executable = Some(frontend);
            let before: Vec<_> = HELPERS
                .iter()
                .copied()
                .chain([MARKER])
                .map(|name| snapshot(&directory.join(name)).unwrap())
                .collect();
            assert!(signing_targets(&target).is_err());
            assert!(stage(&directory, &target).is_err());
            assert!(lock_installation(&target).is_err());
            let after: Vec<_> = HELPERS
                .iter()
                .copied()
                .chain([MARKER])
                .map(|name| snapshot(&directory.join(name)).unwrap())
                .collect();
            assert_eq!(before, after);
            assert_eq!(
                std::fs::read_dir(&directory).unwrap().count(),
                HELPERS.len() + 1
            );
        }
    }

    #[test]
    fn installation_lock_coordinates_helper_and_external_frontend_directories() {
        use mvm_core::util::atomic_io::FileLock;
        let directory = tempfile::tempdir().unwrap();
        let frontend_directory = tempfile::tempdir().unwrap();
        let frontend = frontend_directory.path().join("frontend");
        std::fs::write(&frontend, b"fixture").unwrap();
        let mut target = fixture_target(directory.path().to_owned());
        target.frontend_executable = Some(frontend);
        let guard = lock_installation(&target).unwrap();
        for parent in [directory.path(), frontend_directory.path()] {
            assert!(
                FileLock::try_acquire(&parent.join(".mvm-host-installation"))
                    .unwrap()
                    .is_none()
            );
        }
        drop(guard);
        for parent in [directory.path(), frontend_directory.path()] {
            assert!(
                FileLock::try_acquire(&parent.join(".mvm-host-installation"))
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn signing_preview_does_not_create_lock_anchors() {
        let directory = tempfile::tempdir().unwrap();
        let target = fixture_target(directory.path().to_owned());
        let helper = directory.path().join(HELPERS[0]);
        std::fs::write(&helper, b"fixture").unwrap();
        let before = snapshot(&helper).unwrap();
        let (targets, guard) = signing_context(&target, false).unwrap();
        assert!(guard.is_none());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, destination_key(&helper).unwrap());
        assert_eq!(snapshot(&helper).unwrap(), before);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn locked_target_does_not_follow_retargeted_parent_alias() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let other = root.path().join("other");
        let alias = root.path().join("alias");
        for directory in [&original, &other] {
            std::fs::create_dir(directory).unwrap();
            bundle(directory);
            std::fs::write(directory.join("frontend"), b"fixture").unwrap();
        }
        symlink(&original, &alias).unwrap();
        let mut target = fixture_target(alias.clone());
        target.frontend_executable = Some(alias.join("frontend"));
        let guard = lock_installation(&target).unwrap();
        std::fs::remove_file(&alias).unwrap();
        symlink(&other, &alias).unwrap();
        let expected = original.canonicalize().unwrap();
        assert_eq!(guard.target().directory, expected);
        assert_eq!(
            guard.target().frontend_executable,
            Some(expected.join("frontend"))
        );
        let targets = signing_targets(guard.target()).unwrap();
        assert!(
            targets
                .iter()
                .all(|target| target.path.parent() == Some(expected.as_path()))
        );
        let candidates = stage(&original, guard.target()).unwrap();
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.destination.parent() == Some(expected.as_path()))
        );
        assert!(!other.join(".mvm-host-installation.lock").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_sign_refusal_preserves_live_bytes_inodes_frontend_and_marker() {
        use std::os::unix::fs::MetadataExt;
        let extracted = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        bundle(extracted.path());
        let mut target = fixture_target(destination.path().to_owned());
        target.frontend_executable = Some(destination.path().join("explicit-embedder"));
        let paths: Vec<_> = HELPERS
            .iter()
            .copied()
            .chain([MARKER, "explicit-embedder"])
            .map(|name| destination.path().join(name))
            .collect();
        for path in &paths {
            std::fs::write(path, b"old fixture").unwrap();
        }
        let inodes: Vec<_> = paths
            .iter()
            .map(|path| std::fs::metadata(path).unwrap().ino())
            .collect();
        assert!(
            install(extracted.path(), &target)
                .unwrap_err()
                .to_string()
                .contains("candidate signing failed")
        );
        for (path, inode) in paths.iter().zip(inodes) {
            assert_eq!(std::fs::read(path).unwrap(), b"old fixture");
            assert_eq!(std::fs::metadata(path).unwrap().ino(), inode);
        }
    }

    #[test]
    fn source_identity_requires_clean_exact_commit() {
        let mut source = SourceBuild {
            commit: "a".repeat(40),
            dirty: false,
        };
        validate_source_identity(&source).unwrap();
        source.dirty = true;
        assert!(validate_source_identity(&source).is_err());
        source.dirty = false;
        source.commit = "../other".into();
        assert!(validate_source_identity(&source).is_err());
    }

    #[test]
    fn installation_replaces_links_without_modifying_their_target() {
        let root = tempfile::tempdir().unwrap();
        let extracted = root.path().join("extracted");
        let destination = root.path().join("install");
        std::fs::create_dir(&extracted).unwrap();
        std::fs::create_dir(&destination).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"unchanged").unwrap();
        bundle(&extracted);
        std::fs::write(extracted.join(HELPERS[0]), b"verified helper").unwrap();
        std::fs::hard_link(&outside, destination.join(HELPERS[0])).unwrap();
        let candidates = stage(&extracted, &fixture_target(destination.clone())).unwrap();
        publish(candidates, |_| Ok(())).unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
        assert_eq!(
            std::fs::read(destination.join(HELPERS[0])).unwrap(),
            b"verified helper"
        );
    }
}
