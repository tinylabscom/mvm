use super::*;

static ACTIVE_STAGE0_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Held for the lifetime of an in-process Stage 0 build. The inner file lock
/// serializes the shared store; the process-local count lets Ctrl-C explain
/// exactly what was interrupted without probing another process's lock.
pub(super) struct Stage0LockGuard {
    _lock: std::fs::File,
}

impl Drop for Stage0LockGuard {
    fn drop(&mut self) {
        ACTIVE_STAGE0_BUILDS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(in crate::commands) fn stage0_active_in_process() -> bool {
    ACTIVE_STAGE0_BUILDS.load(std::sync::atomic::Ordering::SeqCst) > 0
}

/// RAII advisory lock at `<cache parent>/stage0.lock` (for the builder image,
/// `~/.mvm/cache/builder-vm/stage0.lock`), naming what it guards as `what`.
///
/// A second caller wants the same artifact the holder is producing, so it
/// queues behind a live holder with a status line naming it, rather than
/// failing and asking for a retry. A holder that died released its `flock`
/// with it, so a crashed build never needs its lock file deleted. Callers
/// re-check their cache after this returns: the holder they waited on may
/// have produced exactly what they came for.
///
/// `out_dir` is the per-arch cache dir (e.g. `.../builder-vm/aarch64`);
/// the lock file is its sibling `stage0.lock`.
pub(super) fn acquire_stage0_lock(out_dir: &str, what: &str) -> Result<Stage0LockGuard> {
    acquire_stage0_lock_within(out_dir, what, stage0_lock_wait())
}

/// [`acquire_stage0_lock`] with an explicit wait budget, so tests can drive
/// both the queueing and the refusal without the production hour.
pub(super) fn acquire_stage0_lock_within(
    out_dir: &str,
    what: &str,
    wait: mvm_build::builder_vm_runtime::LockWait,
) -> Result<Stage0LockGuard> {
    let lock = lock_builder_vm_cache(std::path::Path::new(out_dir), what, wait)?;
    ACTIVE_STAGE0_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(Stage0LockGuard { _lock: lock })
}

/// What the per-arch builder VM cache lock guards, as a waiting line names it.
pub(super) const BUILDER_VM_CACHE_LOCK_SUBJECT: &str = "the builder VM image";

/// How long a Stage 0 caller queues. `mvm-build`'s own test build flips its
/// default to fail-fast, but that flip does not reach this crate's tests, so
/// the same choice is made here: a test never waits out the production hour.
fn stage0_lock_wait() -> mvm_build::builder_vm_runtime::LockWait {
    if cfg!(test) {
        mvm_build::builder_vm_runtime::LockWait::none()
    } else {
        mvm_build::builder_vm_runtime::LockWait::from_env()
    }
}

/// The advisory lock every writer of a per-arch builder VM cache holds. A
/// published-image fetch takes it without [`acquire_stage0_lock`]'s in-process
/// count, so an interrupted download is not reported as an interrupted build.
fn lock_builder_vm_cache(
    out_dir: &std::path::Path,
    what: &str,
    wait: mvm_build::builder_vm_runtime::LockWait,
) -> Result<std::fs::File> {
    let parent = out_dir.parent().ok_or_else(|| {
        anyhow::anyhow!("builder VM cache path has no parent: {}", out_dir.display())
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let subject = mvm_build::builder_vm_runtime::LockSubject {
        what,
        remedy: "or stop the process holding it if it is stuck — a holder that exits for \
                 any reason, a crash included, releases the lock by itself",
    };
    mvm_build::builder_vm_runtime::acquire_lock_waiting(&parent.join("stage0.lock"), &subject, wait)
        .context("acquiring the Stage 0 lock")
}

/// Remove incomplete Stage 0 directories belonging to one final cache
/// directory. The caller holds the shared Stage 0 lock, so every matching
/// sibling is from an earlier interrupted process rather than a live writer.
pub(super) fn sweep_stage0_staging_siblings(final_dir: &std::path::Path) -> Result<u64> {
    let parent = final_dir.parent().ok_or_else(|| {
        anyhow::anyhow!("Stage 0 cache path has no parent: {}", final_dir.display())
    })?;
    if !parent.is_dir() {
        return Ok(0);
    }
    let name = final_dir
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("kernel cache basename is not UTF-8"))?;
    let prefix = format!(".{name}.stage0-");
    let mut removed = 0u64;
    for entry in std::fs::read_dir(parent)
        .with_context(|| format!("reading Stage 0 cache parent {}", parent.display()))?
        .flatten()
    {
        let path = entry.path();
        if !path.is_dir() || !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        std::fs::remove_dir_all(&path)
            .with_context(|| format!("removing interrupted Stage 0 output {}", path.display()))?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

pub(super) fn unique_builder_vm_stage0_staging_dir(
    final_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let parent = final_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "builder VM cache path has no parent: {}",
            final_dir.display()
        )
    })?;
    let name = final_dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "builder VM cache path has no UTF-8 basename: {}",
                final_dir.display()
            )
        })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(parent.join(format!(".{name}.stage0-{}-{nonce}", std::process::id())))
}

/// Structural validation of a cached `(vmlinux, rootfs.ext4)` pair —
/// size floor + ext4 superblock magic. Cheap and host-agnostic; used by
/// the cache-readiness and promotion paths. The deeper "does the rootfs
/// actually contain the init binary" check is `verify_stage0_rootfs_has_init`,
/// run once at build time (it needs to parse the full ext4 tree).
pub(super) fn validate_builder_vm_stage0_artifacts(dir: &std::path::Path) -> Result<()> {
    validate_dev_image_artifacts(dir.join("vmlinux"), dir.join("rootfs.ext4")).with_context(
        || {
            format!(
                "validating Stage 0 builder VM artifacts in {}",
                dir.display()
            )
        },
    )?;
    mvm_build::builder_vm_image::validate_builder_vm_image_cache(dir).map_err(anyhow::Error::from)
}

/// Whether a Stage 0 bootstrap is currently in flight on this host — i.e. the
/// shared advisory lock at `~/.mvm/cache/builder-vm/stage0.lock` is held by a
/// live build. Non-blocking: tries the lock and reports contention,
/// releasing immediately if it acquires. `cache repair` consults this before
/// clearing the builder store so it never yanks the store from an active build.
pub(in crate::commands) fn stage0_bootstrap_in_flight() -> bool {
    let builder_vm = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm");
    stage0_bootstrap_in_flight_at(&builder_vm)
}

/// Inner form of [`stage0_bootstrap_in_flight`] with an explicit `builder-vm`
/// root, so tests exercise it against a tempdir without touching `MVM_HOME`.
pub(super) fn stage0_bootstrap_in_flight_at(builder_vm: &std::path::Path) -> bool {
    use mvm_core::atomic_io::FileLock;
    // A fresh host with no builder-vm dir has nothing in flight. (Without this
    // guard `try_acquire` would error on the missing parent and we'd read it as
    // "in flight" — the lock anchor's parent isn't auto-created here.)
    if !builder_vm.is_dir() {
        return false;
    }
    let lock_anchor = builder_vm.join("stage0");
    // A just-dropped `flock(2)` can briefly race with a same-process re-check
    // under heavy parallel test and helper load. Accept the first successful
    // acquisition; only after a few consecutive "still held" / I/O outcomes do
    // we fail safe to "in flight" for the destructive repair path.
    for attempt in 0..4 {
        match FileLock::try_acquire(&lock_anchor) {
            Ok(Some(_guard)) => return false,
            Ok(None) | Err(_) if attempt < 3 => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Ok(None) | Err(_) => return true,
        }
    }
    true
}

/// Outcome of [`sweep_orphaned_stage0_staging_dirs`]:
/// either the sweep ran (with counts) or the Stage 0 advisory lock was
/// already held so the sweep was skipped to avoid racing a live
/// bootstrap. The pruner uses the variant to decide what to print.
pub(in crate::commands) enum Stage0SweepOutcome {
    Swept { removed: u64, freed_bytes: u64 },
    SkippedLockHeld,
}

/// Remove staging directories from a crashed Stage 0
/// bootstrap. Only safe to run when no Stage 0 is currently in progress;
/// the function tries the same advisory lock the live bootstrap uses
/// and bails (returns `SkippedLockHeld`) on contention rather than
/// racing it. Called from `mvmctl cache prune` so the cleanup ships
/// with the existing "clean everything" verb.
///
/// "Orphan" means the staging dir was left behind by a crashed run;
/// successful Stage 0 runs `rename(2)` the staging dir into the live
/// cache, so any staging dir on disk is by definition orphaned. Format
/// matches [`unique_builder_vm_stage0_staging_dir`]
/// (`.<arch>.stage0-<pid>-<nonce>`); we also recognise the legacy
/// `<arch>-staging[-...]` shape from older builds on the same host.
pub(in crate::commands) fn sweep_orphaned_stage0_staging_dirs(
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    let builder_vm_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm");
    sweep_orphaned_stage0_staging_dirs_at(&builder_vm_root, dry_run)
}

/// Inner form of [`sweep_orphaned_stage0_staging_dirs`] that takes an
/// explicit root path. Exists so unit tests can exercise the sweep
/// against a tempdir without mutating `MVM_HOME` or any other
/// process-wide env var.
pub(super) fn sweep_orphaned_stage0_staging_dirs_at(
    builder_vm_root: &std::path::Path,
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    use mvm_core::atomic_io::FileLock;

    if !builder_vm_root.is_dir() {
        return Ok(Stage0SweepOutcome::Swept {
            removed: 0,
            freed_bytes: 0,
        });
    }

    // Try the Stage 0 advisory lock. The lock anchor is shared with the
    // live `acquire_stage0_lock` callsite — when a build is in
    // progress, we want the pruner to skip the staging sweep rather
    // than race it. RAII drop releases the lock when this function
    // returns.
    let lock_anchor = builder_vm_root.join("stage0");
    let _guard = match FileLock::try_acquire(&lock_anchor) {
        Ok(Some(guard)) => guard,
        Ok(None) => return Ok(Stage0SweepOutcome::SkippedLockHeld),
        Err(e) => {
            // I/O failure on the lock path is rare (e.g. parent disappeared
            // mid-prune). Treat it as "skip with a warning" rather than
            // failing the whole prune verb — the staging sweep is a best-
            // effort hygiene step.
            tracing::warn!(err = %e, "could not acquire Stage 0 lock for sweep; skipping");
            return Ok(Stage0SweepOutcome::SkippedLockHeld);
        }
    };

    let mut removed = 0u64;
    let mut freed_bytes = 0u64;
    let entries = match std::fs::read_dir(builder_vm_root) {
        Ok(e) => e,
        Err(_) => {
            return Ok(Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            });
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_orphan_stage0_staging_dir_name(&name) || !path.is_dir() {
            continue;
        }
        let size = stage0_dir_size_bytes(&path);
        if dry_run {
            println!(
                "Would remove orphan Stage 0 staging dir: {} ({} bytes)",
                path.display(),
                size,
            );
        } else if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!(path = %path.display(), err = %e, "could not remove orphan staging dir");
            continue;
        }
        removed += 1;
        freed_bytes += size;
    }
    Ok(Stage0SweepOutcome::Swept {
        removed,
        freed_bytes,
    })
}

/// Predicate matching the staging-dir basenames left by Stage 0.
/// Two shapes are recognised:
/// - Current: `.<arch>.stage0-<pid>-<nonce>` (hidden, see
///   [`unique_builder_vm_stage0_staging_dir`]).
/// - Legacy: `<arch>-staging` or `<arch>-staging-<suffix>`
///   left behind by earlier Stage 0 prototypes that were observed on
///   contributor hosts; harmless when they exist but the pruner is
///   the obvious place to clean them up.
pub(super) fn is_orphan_stage0_staging_dir_name(name: &str) -> bool {
    let is_known_arch = |arch: &str| arch == "aarch64" || arch == "x86_64";

    // Current hidden form.
    if let Some(rest) = name.strip_prefix('.')
        && let Some((arch, tail)) = rest.split_once('.')
        && is_known_arch(arch)
        && tail.starts_with("stage0-")
    {
        return true;
    }
    // Legacy `<arch>-staging` / `<arch>-staging-<suffix>`.
    if let Some((arch, tail)) = name.split_once('-')
        && is_known_arch(arch)
        && (tail == "staging" || tail.starts_with("staging"))
    {
        return true;
    }
    false
}

/// Disk clearing the staging tree would return. Shared with `cache prune` so
/// the repair and prune paths quote the same number for the same tree.
fn stage0_dir_size_bytes(path: &std::path::Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(path)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum BuilderVmSourceCacheStatus {
    Hit,
    MissingArtifact,
    InvalidStage0Artifacts,
    MissingFingerprint,
    FingerprintMismatch,
    MissingArtifactDigestManifest,
    ArtifactDigestMismatch,
    MissingProvenance,
    ProvenanceMismatch,
}

impl BuilderVmSourceCacheStatus {
    pub(super) fn is_ready(self) -> bool {
        self == Self::Hit
    }

    #[cfg(test)]
    pub(super) fn reason_code(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::MissingArtifact => "missing_artifact",
            Self::InvalidStage0Artifacts => "invalid_stage0_artifacts",
            Self::MissingFingerprint => "missing_fingerprint",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::MissingArtifactDigestManifest => "missing_artifact_digest_manifest",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::MissingProvenance => "missing_provenance",
            Self::ProvenanceMismatch => "provenance_mismatch",
        }
    }
}

#[cfg(test)]
pub(super) fn builder_vm_source_cache_status(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> BuilderVmSourceCacheStatus {
    cache_status(dir, expected_fingerprint, STAGE0_SOURCE_KIND)
}

fn cache_status(
    dir: &std::path::Path,
    expected_fingerprint: &str,
    source_kind: &str,
) -> BuilderVmSourceCacheStatus {
    if !dir.join("vmlinux").exists() || !dir.join("rootfs.ext4").exists() {
        return BuilderVmSourceCacheStatus::MissingArtifact;
    }
    if validate_builder_vm_stage0_artifacts(dir).is_err() {
        return BuilderVmSourceCacheStatus::InvalidStage0Artifacts;
    }

    let fingerprint_path = dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE);
    let Ok(actual_fingerprint) = std::fs::read_to_string(fingerprint_path) else {
        return BuilderVmSourceCacheStatus::MissingFingerprint;
    };
    if actual_fingerprint.trim() != expected_fingerprint {
        return BuilderVmSourceCacheStatus::FingerprintMismatch;
    }

    match mvm_build::cache_install::verify_digest_manifest(
        dir,
        BUILDER_VM_ARTIFACT_DIGEST_FILE,
        mvm_build::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
    ) {
        mvm_build::cache_install::DigestManifestCheck::Match => {}
        mvm_build::cache_install::DigestManifestCheck::ManifestAbsent => {
            return BuilderVmSourceCacheStatus::MissingArtifactDigestManifest;
        }
        _ => return BuilderVmSourceCacheStatus::ArtifactDigestMismatch,
    }

    let provenance_path = dir.join(BUILDER_VM_PROVENANCE_FILE);
    if !provenance_path.exists() {
        return BuilderVmSourceCacheStatus::MissingProvenance;
    }
    if !builder_vm_source_cache_provenance_matches(dir, expected_fingerprint, source_kind) {
        return BuilderVmSourceCacheStatus::ProvenanceMismatch;
    }

    BuilderVmSourceCacheStatus::Hit
}

#[cfg(test)]
pub(super) fn builder_vm_source_cache_ready(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    cache_ready(dir, expected_fingerprint, STAGE0_SOURCE_KIND)
}

/// Whether a cache installed from a local image pair is ready under
/// `expected_fingerprint`.
pub(super) fn local_pair_cache_ready(dir: &std::path::Path, expected_fingerprint: &str) -> bool {
    cache_ready(dir, expected_fingerprint, LOCAL_PAIR_SOURCE_KIND)
}

fn cache_ready(dir: &std::path::Path, expected_fingerprint: &str, source_kind: &str) -> bool {
    cache_status(dir, expected_fingerprint, source_kind).is_ready()
}

fn builder_vm_source_fingerprint_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    std::fs::read_to_string(dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE))
        .map(|actual| actual.trim() == expected_fingerprint)
        .unwrap_or(false)
}

pub(super) fn write_builder_vm_source_fingerprint(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    std::fs::write(
        dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE),
        format!("{source_fingerprint}\n"),
    )
    .with_context(|| format!("writing builder VM source fingerprint in {}", dir.display()))
}

// Both helpers below are reached only from the builder-VM bootstrap paths;
// the readiness check consults the shared verifier directly.
fn builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<String> {
    mvm_build::cache_install::digest_manifest(
        dir,
        mvm_build::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
    )
    .with_context(|| format!("hashing builder VM artifacts in {}", dir.display()))
}

/// Whole-directory verdict collapsed to a bool, for the callers that only need
/// "is this dir self-consistent" and have their own error to raise.
fn builder_vm_artifact_digest_manifest_matches(dir: &std::path::Path) -> bool {
    matches!(
        mvm_build::cache_install::verify_digest_manifest(
            dir,
            BUILDER_VM_ARTIFACT_DIGEST_FILE,
            mvm_build::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
        ),
        mvm_build::cache_install::DigestManifestCheck::Match
    )
}

pub(super) fn write_builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<()> {
    let manifest = builder_vm_artifact_digest_manifest(dir)?;
    std::fs::write(dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE), manifest)
        .with_context(|| format!("writing builder VM artifact digests in {}", dir.display()))
}

/// Where a builder VM cache came from. A source-checkout build records the
/// fingerprint it was built from; a fetched image has no source to fingerprint
/// and records the release it came from instead.
#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BuilderVmSourceCacheProvenance {
    schema_version: u32,
    source_kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source_fingerprint: String,
    artifacts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acquired_at: Option<String>,
}

/// Provenance `source_kind` of a Stage 0 cache. It is on-disk state, so it
/// keeps its name.
#[cfg(test)]
pub(super) const STAGE0_SOURCE_KIND: &str = "source_checkout_stage0";
/// Provenance `source_kind` for a cache installed from a local image pair's
/// `builder-vm` target; the fingerprint names both checkout identities.
pub(super) const LOCAL_PAIR_SOURCE_KIND: &str = "local_pair";

fn builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
    source_kind: &str,
) -> Result<BuilderVmSourceCacheProvenance> {
    Ok(BuilderVmSourceCacheProvenance {
        schema_version: 1,
        source_kind: source_kind.to_string(),
        source_fingerprint: source_fingerprint.to_string(),
        artifacts: builder_vm_artifact_names_present(dir)?,
        image_tag: None,
        acquired_at: None,
    })
}

fn write_builder_vm_provenance(
    dir: &std::path::Path,
    provenance: &BuilderVmSourceCacheProvenance,
) -> Result<()> {
    let json = serde_json::to_string_pretty(provenance)
        .context("serializing builder VM cache provenance")?;
    std::fs::write(dir.join(BUILDER_VM_PROVENANCE_FILE), format!("{json}\n"))
        .with_context(|| format!("writing builder VM provenance in {}", dir.display()))
}

fn builder_vm_artifact_names_present(dir: &std::path::Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in mvm_build::cache_install::BUILDER_VM_CACHE_ARTIFACTS {
        let path = dir.join(name);
        if !path.exists() {
            anyhow::bail!("builder VM provenance missing artifact {}", path.display());
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn builder_vm_source_cache_provenance_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
    source_kind: &str,
) -> bool {
    let expected = match builder_vm_source_cache_provenance(dir, expected_fingerprint, source_kind)
    {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    std::fs::read_to_string(dir.join(BUILDER_VM_PROVENANCE_FILE))
        .ok()
        .and_then(|actual| serde_json::from_str::<BuilderVmSourceCacheProvenance>(&actual).ok())
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

fn write_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
    source_kind: &str,
) -> Result<()> {
    write_builder_vm_provenance(
        dir,
        &builder_vm_source_cache_provenance(dir, source_fingerprint, source_kind)?,
    )
}

/// Write only the provenance sidecar, for tests that assemble the other
/// sidecars themselves.
#[cfg(test)]
pub(super) fn write_builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    write_cache_provenance(dir, source_fingerprint, STAGE0_SOURCE_KIND)
}

/// Write the full cache-sidecar set for a cache installed from a local image
/// pair. The format is the Stage 0 sidecar format with the `local_pair`
/// provenance kind; the readiness check is [`local_pair_cache_ready`].
pub(super) fn write_local_pair_cache_sidecars(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    write_builder_vm_source_fingerprint(dir, source_fingerprint)?;
    write_builder_vm_artifact_digest_manifest(dir)?;
    write_cache_provenance(dir, source_fingerprint, LOCAL_PAIR_SOURCE_KIND)
}

/// Write the full cache-sidecar set — source fingerprint, artifact-digest
/// manifest, and provenance — that the readiness check reads back to decide a
/// hit. The order matters only in that the digest manifest must be written
/// after the artifacts are final.
#[cfg(test)]
pub(super) fn write_builder_vm_cache_sidecars(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    write_builder_vm_source_fingerprint(dir, source_fingerprint)?;
    write_builder_vm_artifact_digest_manifest(dir)?;
    write_cache_provenance(dir, source_fingerprint, STAGE0_SOURCE_KIND)
}

#[cfg(test)]
pub(super) fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    promote_source_cache(
        staging_dir,
        final_dir,
        source_fingerprint,
        STAGE0_SOURCE_KIND,
    )
}

/// Promote a builder-VM cache staged from a local image pair's `builder-vm`
/// target, validating the same sidecar set Stage 0 promotion does.
pub(super) fn promote_local_pair_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    promote_source_cache(
        staging_dir,
        final_dir,
        source_fingerprint,
        LOCAL_PAIR_SOURCE_KIND,
    )
}

fn promote_source_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
    source_kind: &str,
) -> Result<()> {
    validate_builder_vm_stage0_artifacts(staging_dir)?;
    if !builder_vm_source_fingerprint_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "builder VM staging dir {} is missing the expected source fingerprint",
            staging_dir.display()
        );
    }
    if !builder_vm_artifact_digest_manifest_matches(staging_dir) {
        anyhow::bail!(
            "builder VM staging dir {} is missing matching artifact digests",
            staging_dir.display()
        );
    }
    if !builder_vm_source_cache_provenance_matches(staging_dir, source_fingerprint, source_kind) {
        anyhow::bail!(
            "builder VM staging dir {} is missing matching provenance metadata",
            staging_dir.display()
        );
    }

    if final_dir.exists() && cache_ready(final_dir, source_fingerprint, source_kind) {
        std::fs::remove_dir_all(staging_dir).with_context(|| {
            format!(
                "removing redundant Stage 0 staging dir {}",
                staging_dir.display()
            )
        })?;
        return Ok(());
    }

    replace_builder_vm_cache_dir(staging_dir, final_dir)?;
    if !cache_ready(final_dir, source_fingerprint, source_kind) {
        anyhow::bail!(
            "promoted builder VM cache {} failed source-cache validation",
            final_dir.display()
        );
    }
    Ok(())
}

/// Swap a fully prepared `staging_dir` in as `final_dir`.
///
/// Any previous cache is moved aside rather than deleted first, so a failed
/// rename puts it back: the failure mode is "no update", not "no builder
/// image". The aside path uses the Stage 0 staging name, so a crash between
/// the two renames leaves a directory the orphan sweep already reclaims.
fn replace_builder_vm_cache_dir(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
) -> Result<()> {
    let promote = |from: &std::path::Path| {
        std::fs::rename(from, final_dir).with_context(|| {
            format!(
                "promoting builder VM cache {} to {}",
                from.display(),
                final_dir.display()
            )
        })
    };
    if !final_dir.exists() {
        return promote(staging_dir);
    }

    let mut aside = unique_builder_vm_stage0_staging_dir(final_dir)?.into_os_string();
    aside.push("-previous");
    let aside = std::path::PathBuf::from(aside);
    std::fs::rename(final_dir, &aside).with_context(|| {
        format!(
            "moving the previous builder VM cache {} aside",
            final_dir.display()
        )
    })?;
    if let Err(error) = promote(staging_dir) {
        std::fs::rename(&aside, final_dir).with_context(|| {
            format!(
                "restoring the previous builder VM cache to {} after a failed swap",
                final_dir.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = std::fs::remove_dir_all(&aside) {
        // The new cache is already live; the leftover is reclaimed by the next
        // sweep, so it is not worth failing an install that succeeded.
        tracing::warn!(path = %aside.display(), %error, "could not remove the previous builder VM cache");
    }
    Ok(())
}

/// A boot image release that publishes builder VM images.
#[cfg(test)]
pub(super) struct BuilderVmImageRelease<'a> {
    /// Release tag, e.g. `boot-image/v0.1.5`; recorded as provenance.
    pub(super) tag: &'a str,
    /// Version whose signing identity the checksum manifest must carry.
    pub(super) version: &'a str,
    /// Per-release download base URL, no trailing slash.
    pub(super) base_url: &'a str,
}

/// The two network legs of a published builder VM image fetch.
///
/// Everything else — staging, digest and manifest checks, provenance,
/// promotion — is the same whether the bytes come from a release or from a
/// test, so only these two are substitutable.
#[cfg(test)]
pub(super) trait BuilderVmReleaseSource {
    /// The `asset -> sha256` pins for `wanted`, from a checksum manifest whose
    /// signature has already been verified. A refusal here must come before any
    /// pin is returned.
    fn verified_checksums(
        &self,
        manifest: &ChecksumManifest<'_>,
        wanted: &[&str],
    ) -> Result<std::collections::HashMap<String, String>>;

    /// Download `url` to `dest`.
    fn fetch(&self, url: &str, dest: &str) -> Result<()>;
}

/// Download the per-arch builder VM image from the signed image set the image
/// lock pins into the local cache.
///
/// Every build can reach this: image construction lives in `mvm-images`, so
/// without a selected image checkout the signed set is the only source of a
/// builder image, contributor build or not.
pub(super) fn download_builder_vm_image(arch: &str, cache_dir: &str) -> Result<()> {
    refuse_foreign_builder_vm_arch(arch)?;
    let arch = arch.parse::<mvm_core::arch::GuestArch>()?;
    let cache_dir = std::path::Path::new(cache_dir);
    let _lock =
        lock_builder_vm_cache(cache_dir, BUILDER_VM_CACHE_LOCK_SUBJECT, stage0_lock_wait())?;
    sweep_stage0_staging_siblings(cache_dir)?;
    let staging = unique_builder_vm_stage0_staging_dir(cache_dir)?;
    let outcome = stage_locked_builder_vm_image(arch, &staging).and_then(|tag| {
        write_builder_vm_provenance(
            &staging,
            &fetched_builder_vm_provenance(
                &staging,
                &crate::commands::image::boot::cache::AcquiredProvenance::fetched(&tag),
            )?,
        )?;
        promote_fetched_builder_vm_cache(&staging, cache_dir)?;
        Ok(tag)
    });
    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    let tag = outcome?;
    ui::success(&format!(
        "Builder VM image downloaded from the signed image set and cached at {}.",
        cache_dir.display()
    ));
    ui::notice(&fetched_builder_vm_image_line(
        &tag,
        &active_verification_waivers(),
    ));
    Ok(())
}

fn stage_locked_builder_vm_image(
    arch: mvm_core::arch::GuestArch,
    staging: &std::path::Path,
) -> Result<String> {
    std::fs::create_dir_all(staging)
        .with_context(|| format!("creating builder VM staging dir {}", staging.display()))?;
    let image_set = crate::commands::env::artifact_verify::acquire_image_set()?;
    let target = mvm_core::image_set::MemberTarget::Arch(arch);
    for (asset, cache_name) in [
        (format!("builder-vm-vmlinux-{arch}"), "vmlinux"),
        (format!("builder-vm-{arch}.kernel.config"), "kernel.config"),
        (format!("builder-vm-rootfs-{arch}.ext4"), "rootfs.ext4"),
    ] {
        let artifact =
            image_set.artifact(mvm_core::image_set::ImageSetRole::BuilderVm, target, &asset)?;
        image_set.fetch_artifact(artifact, &staging.join(cache_name))?;
    }
    std::fs::write(
        staging.join("cmdline.txt"),
        super::synthesized_builder_vm_cmdline(),
    )
    .context("write builder VM cmdline derived from the cache contract")?;
    let manifest = serde_json::json!({
        "cache_contract_version": mvm_build::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION,
        "runtime_overlay_ready": true,
        "vsock_egress_ready": true,
        "no_network_devices_ready": true,
    });
    std::fs::write(
        staging.join("manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )
    .context("write builder VM cache manifest derived from the signed set")?;
    Ok(mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str()
        .to_string())
}

/// Fetch, verify, and install a published builder VM image for `arch` into
/// `cache_dir`, all or nothing.
///
/// The checksum manifest's signature is the trust anchor, so it is settled
/// before any artifact is requested. Every artifact then lands in a staging
/// directory beside the cache and is held to its signed pin there, and the
/// image's own manifest must name this architecture and agree with those pins.
/// Only then is the staging directory swapped in. The bootstrap readiness
/// check looks only at the kernel and rootfs, so a cache holding those two
/// without the rest would read as ready and fail at boot; on any refusal the
/// staging directory is removed and an existing cache is not touched.
#[cfg(test)]
pub(super) fn fetch_builder_vm_image(
    source: &dyn BuilderVmReleaseSource,
    release: &BuilderVmImageRelease<'_>,
    arch: &str,
    cache_dir: &std::path::Path,
) -> Result<()> {
    refuse_foreign_builder_vm_arch(arch)?;
    let names = builder_vm_artifact_names(arch);
    let _lock =
        lock_builder_vm_cache(cache_dir, BUILDER_VM_CACHE_LOCK_SUBJECT, stage0_lock_wait())?;
    sweep_stage0_staging_siblings(cache_dir)?;

    let files = names.cache_files();
    let wanted: Vec<&str> = files.iter().map(|file| file.asset).collect();
    let pins = source.verified_checksums(
        &ChecksumManifest {
            base_url: release.base_url,
            asset: &names.checksums,
            version: release.version,
            train: mvm_build::release_signature::ReleaseTrain::BootImage,
        },
        &wanted,
    )?;

    let staging = unique_builder_vm_stage0_staging_dir(cache_dir)?;
    let install = PublishedBuilderVmInstall {
        source,
        release,
        arch,
        names: &names,
        pins: &pins,
    };
    let outcome = install
        .stage(&staging)
        .and_then(|()| promote_fetched_builder_vm_cache(&staging, cache_dir));
    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    outcome?;

    ui::success(&format!(
        "Builder VM image downloaded, hash-verified, and cached at {}.",
        cache_dir.display()
    ));
    ui::notice(&fetched_builder_vm_image_line(
        release.tag,
        &active_verification_waivers(),
    ));
    Ok(())
}

/// A builder VM runs on the host's own CPU, so an image for another
/// architecture can only fail to boot. Refused before any request is made.
fn refuse_foreign_builder_vm_arch(arch: &str) -> Result<()> {
    let host = super::builder_vm_host_arch();
    if arch != host {
        anyhow::bail!(
            "refusing to fetch a builder VM image for {arch}: this host is {host}, and a \
             builder VM image only boots on its own architecture"
        );
    }
    Ok(())
}

/// The one line a log can match to learn where the builder image came from.
///
/// Its wording is a contract with whoever greps for it, so it changes only
/// when what it attests changes — and a waived check is never reported as a
/// verified one.
pub(super) fn fetched_builder_vm_image_line(tag: &str, waivers: &[&str]) -> String {
    let verification = if waivers.is_empty() {
        "signature and digests verified".to_string()
    } else {
        format!("verification waived by {}", waivers.join(", "))
    };
    format!("Builder VM image source: fetched ({tag}), {verification}")
}

fn active_verification_waivers() -> Vec<&'static str> {
    [
        mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV,
        "MVM_SKIP_HASH_VERIFY",
    ]
    .into_iter()
    .filter(|name| std::env::var_os(name).is_some())
    .collect()
}

/// One published asset and the cache file it becomes.
#[cfg(test)]
pub(super) struct BuilderVmCacheFile<'a> {
    /// What an operator calls it in an error.
    pub(super) label: &'static str,
    /// The published asset name.
    pub(super) asset: &'a str,
    /// The file name inside the cache directory.
    pub(super) cache_name: &'static str,
}

/// The inputs one staged install is checked against.
#[cfg(test)]
struct PublishedBuilderVmInstall<'a> {
    source: &'a dyn BuilderVmReleaseSource,
    release: &'a BuilderVmImageRelease<'a>,
    arch: &'a str,
    names: &'a BuilderVmArtifactNames,
    pins: &'a std::collections::HashMap<String, String>,
}

#[cfg(test)]
impl PublishedBuilderVmInstall<'_> {
    /// Populate `staging` with every verified artifact, check the image's own
    /// manifest against the signed pins, and record provenance.
    fn stage(&self, staging: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(staging)
            .with_context(|| format!("creating builder VM staging dir {}", staging.display()))?;
        for file in self.names.cache_files() {
            self.fetch_verified(&file, staging)?;
        }
        check_published_builder_vm_manifest(staging, self.arch, self.names, self.pins)?;
        write_builder_vm_provenance(
            staging,
            &fetched_builder_vm_provenance(
                staging,
                &crate::commands::image::boot::cache::AcquiredProvenance::fetched(self.release.tag),
            )?,
        )
    }

    fn fetch_verified(
        &self,
        file: &BuilderVmCacheFile<'_>,
        staging: &std::path::Path,
    ) -> Result<()> {
        let url = format!("{}/{}", self.release.base_url, file.asset);
        let dest = staging.join(file.cache_name).to_string_lossy().into_owned();
        ui::info(&format!("  Fetching {}...", file.label));
        self.source.fetch(&url, &dest).map_err(|e| {
            bump_verify_outcome("network");
            e.context(format!(
                "Failed to download builder VM {} ({}) from {url}",
                file.label, file.asset
            ))
        })?;
        verify_artifact_hash(&dest, file.asset, self.pins.get(file.asset))
    }
}

fn fetched_builder_vm_provenance(
    dir: &std::path::Path,
    acquired: &crate::commands::image::boot::cache::AcquiredProvenance,
) -> Result<BuilderVmSourceCacheProvenance> {
    Ok(BuilderVmSourceCacheProvenance {
        schema_version: 1,
        source_kind: acquired.source.to_string(),
        source_fingerprint: String::new(),
        artifacts: builder_vm_artifact_names_present(dir)?,
        image_tag: Some(acquired.image_tag.clone()),
        acquired_at: Some(acquired.acquired_at.clone()),
    })
}

/// The fields of the image's own `manifest.json` that bind it to an
/// architecture and to the bytes it ships with. The loader reads the cache
/// contract fields separately; everything else is ignored here.
#[cfg(test)]
#[derive(serde::Deserialize)]
struct PublishedBuilderVmManifest {
    system: String,
    vmlinux: PublishedArtifactPin,
    kernel_config: PublishedArtifactPin,
    rootfs_ext4: PublishedArtifactPin,
}

#[cfg(test)]
#[derive(serde::Deserialize)]
struct PublishedArtifactPin {
    sha256: String,
    #[serde(default)]
    size: Option<u64>,
}

/// Refuse an image whose manifest names another architecture, or describes a
/// kernel or rootfs other than the ones the signed checksums pinned.
///
/// The manifest's own bytes are already digest-verified, so a disagreement is
/// not transport damage: it is a release assembled from mismatched parts.
#[cfg(test)]
fn check_published_builder_vm_manifest(
    staging: &std::path::Path,
    arch: &str,
    names: &BuilderVmArtifactNames,
    pins: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let path = staging.join("manifest.json");
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading builder VM manifest {}", names.manifest))?;
    let manifest: PublishedBuilderVmManifest = serde_json::from_str(&body)
        .with_context(|| format!("parsing builder VM manifest {}", names.manifest))?;

    let expected_system = format!("{arch}-linux");
    if manifest.system != expected_system {
        anyhow::bail!(
            "builder VM manifest {} declares system `{}`, expected `{expected_system}`; \
             refusing an image built for another architecture",
            names.manifest,
            manifest.system
        );
    }
    for (field, pin, asset, cache_name) in [
        ("vmlinux", &manifest.vmlinux, &names.kernel, "vmlinux"),
        (
            "kernel_config",
            &manifest.kernel_config,
            &names.kernel_config,
            "kernel.config",
        ),
        (
            "rootfs_ext4",
            &manifest.rootfs_ext4,
            &names.rootfs,
            "rootfs.ext4",
        ),
    ] {
        check_manifest_pin(field, pin, asset, &staging.join(cache_name), pins)
            .with_context(|| format!("checking builder VM manifest {}", names.manifest))?;
    }
    Ok(())
}

#[cfg(test)]
fn check_manifest_pin(
    field: &str,
    pin: &PublishedArtifactPin,
    asset: &str,
    staged: &std::path::Path,
    pins: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let signed = pins
        .get(asset)
        .ok_or_else(|| anyhow::anyhow!("internal: no signed pin recorded for {asset}"))?;
    if !pin.sha256.eq_ignore_ascii_case(signed) {
        bump_verify_outcome("digest_mismatch");
        anyhow::bail!(
            "`{field}.sha256` is {}, but the signed checksum manifest pins {asset} to {signed}",
            pin.sha256
        );
    }
    if let Some(declared) = pin.size {
        let actual = std::fs::metadata(staged)
            .with_context(|| format!("stat {}", staged.display()))?
            .len();
        if declared != actual {
            bump_verify_outcome("digest_mismatch");
            anyhow::bail!(
                "`{field}.size` is {declared} bytes, but the verified {asset} is {actual} bytes"
            );
        }
    }
    Ok(())
}

/// Promote a fully staged fetched image. The staged directory must already
/// satisfy the readiness check the bootstrap applies, so a promoted cache is
/// never re-fetched as not-ready.
fn promote_fetched_builder_vm_cache(
    staging: &std::path::Path,
    cache_dir: &std::path::Path,
) -> Result<()> {
    validate_builder_vm_stage0_artifacts(staging)?;
    builder_vm_artifact_names_present(staging)?;
    replace_builder_vm_cache_dir(staging, cache_dir)
}

/// Per-arch artifact filenames the release workflow's
/// `builder-vm-image` job uploads. Pure function — no I/O, no
/// network — so the unit test can verify naming matches the
/// build.yml side without touching the network. Gated together
/// with [`download_builder_vm_image`].
#[cfg(test)]
pub(super) struct BuilderVmArtifactNames {
    pub(super) kernel: String,
    pub(super) kernel_config: String,
    pub(super) rootfs: String,
    pub(super) cmdline: String,
    pub(super) manifest: String,
    pub(super) checksums: String,
}

#[cfg(test)]
pub(super) fn builder_vm_artifact_names(arch: &str) -> BuilderVmArtifactNames {
    let [kernel, rootfs, cmdline] = builder_vm_boot_assets(arch);
    BuilderVmArtifactNames {
        kernel,
        kernel_config: format!("builder-vm-{arch}.kernel.config"),
        rootfs,
        cmdline,
        manifest: format!("builder-vm-{arch}.manifest.json"),
        checksums: format!("builder-vm-{arch}-checksums-sha256.txt"),
    }
}

/// The assets the builder VM boots from for `arch`: kernel, rootfs, and
/// kernel command line.
#[cfg(test)]
pub(super) fn builder_vm_boot_assets(arch: &str) -> [String; 3] {
    [
        format!("builder-vm-vmlinux-{arch}"),
        format!("builder-vm-rootfs-{arch}.ext4"),
        format!("builder-vm-{arch}.cmdline.txt"),
    ]
}

#[cfg(test)]
impl BuilderVmArtifactNames {
    /// Every asset the builder cache contract requires, in the order they are
    /// fetched, paired with the cache file it becomes.
    pub(super) fn cache_files(&self) -> [BuilderVmCacheFile<'_>; 5] {
        [
            BuilderVmCacheFile {
                label: "kernel",
                asset: &self.kernel,
                cache_name: "vmlinux",
            },
            BuilderVmCacheFile {
                label: "kernel config",
                asset: &self.kernel_config,
                cache_name: "kernel.config",
            },
            BuilderVmCacheFile {
                label: "rootfs",
                asset: &self.rootfs,
                cache_name: "rootfs.ext4",
            },
            BuilderVmCacheFile {
                label: "cmdline",
                asset: &self.cmdline,
                cache_name: "cmdline.txt",
            },
            BuilderVmCacheFile {
                label: "manifest",
                asset: &self.manifest,
                cache_name: "manifest.json",
            },
        ]
    }
}
