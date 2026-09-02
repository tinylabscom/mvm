use super::*;

#[cfg(any(feature = "builder-vm", test))]
static ACTIVE_STAGE0_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Held for the lifetime of an in-process Stage 0 build. The inner file lock
/// serializes the shared store; the process-local count lets Ctrl-C explain
/// exactly what was interrupted without probing another process's lock.
#[cfg(any(feature = "builder-vm", test))]
pub(super) struct Stage0LockGuard {
    _lock: mvm_core::atomic_io::FileLock,
}

#[cfg(any(feature = "builder-vm", test))]
impl Drop for Stage0LockGuard {
    fn drop(&mut self) {
        ACTIVE_STAGE0_BUILDS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(in crate::commands) fn stage0_active_in_process() -> bool {
    #[cfg(any(feature = "builder-vm", test))]
    {
        ACTIVE_STAGE0_BUILDS.load(std::sync::atomic::Ordering::SeqCst) > 0
    }
    #[cfg(not(any(feature = "builder-vm", test)))]
    false
}

/// Which phase of Stage 0 failed. Each variant maps to a
/// `stage=...` value in the `Stage0Failed` audit detail so a dashboard
/// can break down "Stage 0 reliability" by failure phase. String
/// representations are stable wire format.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy)]
pub(super) enum Stage0FailureStage {
    Build,
    Validate,
}

#[cfg(feature = "builder-vm")]
impl Stage0FailureStage {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Validate => "validate",
        }
    }
}

#[cfg(feature = "builder-vm")]
impl std::fmt::Display for Stage0FailureStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extract libkrunfw's bundled TSI-patched kernel into the host cache
/// and return the on-disk path. Only available when `libkrun-sys` is
/// compiled in (the default on macOS + Linux libkrun hosts) — without
/// that feature the FFI is dead code and the caller falls back.
///
/// Currently unused on the main path; reserved for wiring the
/// initramfs Stage 0 dispatch (the initramfs path needs a kernel and
/// libkrunfw is where we get it).
#[cfg(all(feature = "builder-vm", feature = "libkrun-sys"))]
#[allow(dead_code)]
fn extract_libkrunfw_kernel() -> Result<std::path::PathBuf> {
    let cache_dir =
        std::path::PathBuf::from(format!("{}/libkrunfw", mvm_core::config::mvm_cache_dir()));
    let target = cache_dir.join("vmlinux");
    let bundled = libkrun_sys::extract_bundled_kernel(&target)
        .map_err(|e| anyhow::anyhow!("libkrunfw kernel extraction: {e}"))?;
    ui::info(&format!(
        "Extracted libkrunfw kernel ({} bytes) to {}",
        bundled.size,
        bundled.path.display()
    ));
    Ok(bundled.path)
}

#[cfg(all(feature = "builder-vm", not(feature = "libkrun-sys")))]
#[allow(dead_code)]
fn extract_libkrunfw_kernel() -> Result<std::path::PathBuf> {
    anyhow::bail!(
        "libkrunfw kernel extraction requires the `libkrun-sys` feature; \
         rebuild `mvmctl` with `--features libkrun-sys` on a host with libkrun installed."
    )
}

/// Short prefix of the source fingerprint for audit
/// `fingerprint_prefix=` field. 8 hex chars are enough to disambiguate
/// against unrelated build runs without exposing the full digest.
#[cfg(feature = "builder-vm")]
pub(super) fn stage0_fingerprint_prefix(source_fingerprint: &str) -> String {
    source_fingerprint.chars().take(8).collect::<String>()
}

/// Condense an `anyhow::Error` into the short single-line
/// `reason=` field for `Stage0Failed`. The full chain is on stderr
/// already; the audit field is for "what broke at a glance". Capped
/// at 160 chars and stripped of newlines / commas / spaces around
/// `=`-signs so the space-separated `key=value` detail format stays
/// parseable.
#[cfg(feature = "builder-vm")]
pub(super) fn stage0_failure_reason_summary(err: &anyhow::Error) -> String {
    let raw = err.to_string();
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            // Audit detail is space-separated `key=value` pairs; any
            // bare `=` in the reason text would confuse a downstream
            // parser, so map them to `~` (visibly distinct from `=`).
            '=' => '~',
            _ => c,
        })
        .collect();
    let truncated: String = cleaned.chars().take(160).collect();
    truncated
}

/// RAII advisory lock at
/// `~/.mvm/cache/builder-vm/stage0.lock` (one directory above the
/// per-arch cache). `try_acquire` is non-blocking, so a concurrent
/// invocation bails fast with a clear message instead of silently
/// queuing for minutes behind a libkrun-builder VM that's already
/// busy holding the shared `nix-store-<arch>.img` volume.
///
/// `out_dir` is the per-arch cache dir (e.g. `.../builder-vm/aarch64`);
/// the lock anchor is its sibling `stage0` (so `FileLock::try_acquire`
/// produces `stage0.lock`).
#[cfg(any(feature = "builder-vm", test))]
pub(super) fn acquire_stage0_lock(out_dir: &str) -> Result<Stage0LockGuard> {
    use mvm_core::atomic_io::FileLock;

    let parent = std::path::Path::new(out_dir)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("builder VM cache path has no parent: {out_dir}"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let lock_anchor = parent.join("stage0");

    match FileLock::try_acquire(&lock_anchor) {
        Ok(Some(guard)) => {
            ACTIVE_STAGE0_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Stage0LockGuard { _lock: guard })
        }
        Ok(None) => anyhow::bail!(
            "another caller of Stage 0 is already bootstrapping the \
             builder VM image on this host (lock held at {}.lock). Wait for it to finish, or — \
             only if you are sure no other invocation is running, e.g. after a crash — delete the \
             lock file and retry.",
            lock_anchor.display()
        ),
        Err(e) => Err(e.context("acquiring Stage 0 advisory lock")),
    }
}

/// Remove incomplete Stage 0 directories belonging to one final cache
/// directory. The caller holds the shared Stage 0 lock, so every matching
/// sibling is from an earlier interrupted process rather than a live writer.
#[cfg(any(feature = "builder-vm", test))]
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

#[cfg(any(feature = "builder-vm", test))]
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
    validate_dev_image_artifacts(dir.join("vmlinux"), dir.join("rootfs.ext4")).with_context(|| {
        format!(
            "validating Stage 0 builder VM artifacts in {}",
            dir.display()
        )
    })
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

/// Fingerprint the full set of source inputs that determine the
/// builder-VM rootfs.
///
/// The builder-VM rootfs is built by `nix/images/builder-vm/flake.nix`
/// from these categories of source input:
///
/// 1. The flake itself (`flake.nix` + `flake.lock`) — controls
///    which `nixpkgs` rev, which `mkGuest` shape, which `microvm.nix`,
///    which packages get installed.
/// 2. The embedded host-binary bytes — `build.rs` cross-compiles the
///    in-VM PID-1 + egress-proxy binaries (`cargo build -p mvm-build
///    --bin <name>`) and embeds the bytes in mvmctl; injected into the
///    rootfs at boot. The byte hash captures the bin source, the
///    `mvm-build` lib, its deps, AND the cross-compile toolchain in one
///    shot — strictly more than the per-crate `src/` hash this replaced
///    (which also broke when the two former top-level `crates/<name>/`
///    crates were folded into `crates/mvm-build/src/bin/`).
/// 3. The shared Nix library (`nix/lib`) the flake imports.
///
/// The workspace `Cargo.lock` is deliberately not hashed. The builder-VM
/// flake forbids `rustPlatform.buildRustPackage`, so the only Rust binaries
/// baked into the image are the embedded host binaries, whose byte hashes are
/// already folded into layer 2. `build.rs` watches `Cargo.lock` and
/// `crates/mvm-build/src` so dependency or library changes that affect those
/// binaries rebuild the bytes before this fingerprint is computed.
///
/// Pre-2026-05 this function only hashed (1), so contributor edits to
/// the in-VM binaries silently reused the cached `rootfs.ext4`,
/// burning the dev loop. This version closes that hole — now via the
/// embedded-byte hash rather than a per-crate source walk.
///
/// ## Scope and tradeoffs
///
/// We don't hash the entire workspace. A change to `mvm-cli` doesn't
/// affect the rootfs and shouldn't invalidate the cache; only the
/// embedded binaries' bytes carry the in-VM binary identity.
///
/// ## Hash discipline
///
/// File layers use the original flake-only shape:
/// `{name}\0{u64-length-LE}\0{contents}\0`, repeated for each input.
/// The `name` is the relative path keyed off the workspace, so
/// renaming a file changes the fingerprint. Files within a directory
/// are visited in lexicographic order regardless of filesystem read
/// order so the hash is deterministic across HFS+, APFS, and ext4.
/// The embedded-binary layer folds `(name, sha256_hex)` under a
/// `host-bin\0` domain tag (see `fold_embedded_binary_identity`).
pub(super) fn builder_vm_source_fingerprint(builder_flake_dir: &str) -> Result<String> {
    let flake_dir = std::path::Path::new(builder_flake_dir);
    let workspace_root = workspace_root_for_builder_flake(flake_dir)?;
    let mut hasher = Sha256::new();

    // Layer 1: flake-local inputs.
    for name in ["flake.nix", "flake.lock"] {
        let path = flake_dir.join(name);
        if !path.exists() {
            if name == "flake.nix" {
                anyhow::bail!("builder VM source fingerprint missing {}", path.display());
            }
            continue;
        }
        hash_named_file(&mut hasher, name, &path)?;
    }

    // Layer 2: the embedded host-binary identity — the authoritative
    // fingerprint of every Rust binary baked into the builder VM
    // (`mvm-host-vm-init`, `mvm-egress-proxy`). `build.rs` cross-compiles
    // them and embeds the bytes in mvmctl; Stage 0 installs those bytes into
    // the rootfs. The builder-VM flake forbids `rustPlatform.buildRustPackage`,
    // so no flake artifact consumes the workspace `Cargo.lock` — hashing the
    // embedded bytes already captures the bin source, the `mvm-build` lib,
    // its dep closure, AND the cross-compile toolchain (a gnu→musl switch
    // yields different bytes from identical source) in one shot. The
    // workspace `Cargo.lock` is therefore deliberately NOT hashed: it gates
    // nothing here, and folding it in busts this cache on unrelated
    // workspace-wide dep bumps. (`build.rs` reruns the cross-compile when its
    // real inputs change, so a rebuilt binary's bytes shift this layer.)
    for bin in crate::host_binaries::embedded::EMBEDDED.iter() {
        fold_embedded_binary_identity(&mut hasher, bin.name, bin.sha256_hex);
    }

    // Layer 3: the shared Nix library the flake imports. The builder-vm
    // flake pulls in `nix/lib` (mkGuest, the workspace filter, the
    // host-binaries manifest), so a change there — e.g. a new rootfs
    // mount-point dir — changes the built image. Hashing only the flake
    // dir misses it, which silently reuses a stale image.
    let nix_lib = workspace_root.join("nix").join("lib");
    if nix_lib.is_dir() {
        hash_dir_recursive(&mut hasher, "nix/lib", &nix_lib)?;
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Fold one embedded host-binary's identity into the fingerprint.
/// Keyed on `(name, sha256_hex)` so a rebuilt binary's byte change —
/// the authoritative signal that the in-VM PID-1 / egress-proxy source
/// or toolchain shifted — busts the Stage 0 cache key. The `host-bin\0`
/// domain tag keeps these entries from colliding with the file-hash
/// layers above.
pub(super) fn fold_embedded_binary_identity(hasher: &mut Sha256, name: &str, sha256_hex: &str) {
    hasher.update(b"host-bin\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(sha256_hex.as_bytes());
}

/// Resolve the workspace root from the builder-VM flake dir.
///
/// `find_builder_vm_flake` computes the flake path as
/// `<workspace>/nix/images/builder-vm`, so walking three parents up
/// lands on the workspace. Splitting this out for the fingerprint
/// tests to call without going through `find_builder_vm_flake`'s
/// `CARGO_MANIFEST_DIR` lookup.
fn workspace_root_for_builder_flake(flake_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    flake_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot resolve workspace root from builder-vm flake dir {} \
                 (expected <workspace>/nix/images/builder-vm)",
                flake_dir.display()
            )
        })
}

/// Feed a single named file into the hasher using the original
/// flake-fingerprint discipline: `{name}\0{u64-length-LE}\0{contents}\0`.
fn hash_named_file(hasher: &mut Sha256, name: &str, path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading builder VM source input {}", path.display()))?;
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    hasher.update(b"\0");
    Ok(())
}

/// Hash every regular file under `dir` recursively, keyed by
/// `<prefix>/<relative-path>` so the fingerprint reflects directory
/// structure. Skips hidden entries and `target/`, which are local build/editor
/// artifacts rather than builder-VM source inputs.
fn hash_dir_recursive(hasher: &mut Sha256, prefix: &str, dir: &std::path::Path) -> Result<()> {
    let files = walk_source_dir_sorted(dir)
        .with_context(|| format!("walking builder VM source dir {}", dir.display()))?;
    for path in &files {
        let rel = path.strip_prefix(dir).map_err(|e| {
            anyhow::anyhow!(
                "strip_prefix {} from {}: {e}",
                dir.display(),
                path.display()
            )
        })?;
        let key = format!("{prefix}/{}", rel.display());
        hash_named_file(hasher, &key, path)?;
    }
    Ok(())
}

/// Walk every regular file under `dir`, skipping hidden entries
/// (`.git/`, `.DS_Store`, …), editor swap files (`*.swp`), and
/// `target/` (cargo build output). Paths are returned
/// lexicographically sorted so the hash is deterministic regardless
/// of filesystem read order.
fn walk_source_dir_sorted(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).with_context(|| format!("read_dir {}", d.display()))?;
        for e in entries {
            let e = e.with_context(|| format!("read_dir entry in {}", d.display()))?;
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "target" || name_str.ends_with(".swp") {
                continue;
            }
            let path = e.path();
            let ft = e
                .file_type()
                .with_context(|| format!("file_type {}", path.display()))?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
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

pub(super) fn builder_vm_source_cache_status(
    dir: &std::path::Path,
    expected_fingerprint: &str,
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
    if !builder_vm_source_cache_provenance_matches(dir, expected_fingerprint) {
        return BuilderVmSourceCacheStatus::ProvenanceMismatch;
    }

    BuilderVmSourceCacheStatus::Hit
}

#[cfg(any(feature = "builder-vm", test))]
pub(super) fn builder_vm_source_cache_ready(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    builder_vm_source_cache_status(dir, expected_fingerprint).is_ready()
}

#[cfg(any(feature = "builder-vm", test))]
fn builder_vm_source_fingerprint_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    std::fs::read_to_string(dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE))
        .map(|actual| actual.trim() == expected_fingerprint)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
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
#[cfg(any(feature = "builder-vm", test))]
fn builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<String> {
    mvm_build::cache_install::digest_manifest(
        dir,
        mvm_build::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
    )
    .with_context(|| format!("hashing builder VM artifacts in {}", dir.display()))
}

/// Whole-directory verdict collapsed to a bool, for the callers that only need
/// "is this dir self-consistent" and have their own error to raise.
#[cfg(any(feature = "builder-vm", test))]
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

#[cfg(any(feature = "builder-vm", test))]
pub(super) fn write_builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<()> {
    let manifest = builder_vm_artifact_digest_manifest(dir)?;
    std::fs::write(dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE), manifest)
        .with_context(|| format!("writing builder VM artifact digests in {}", dir.display()))
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BuilderVmSourceCacheProvenance {
    schema_version: u32,
    source_kind: String,
    source_fingerprint: String,
    artifacts: Vec<String>,
}

fn builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<BuilderVmSourceCacheProvenance> {
    Ok(BuilderVmSourceCacheProvenance {
        schema_version: 1,
        source_kind: "source_checkout_stage0".to_string(),
        source_fingerprint: source_fingerprint.to_string(),
        artifacts: builder_vm_artifact_names_present(dir)?,
    })
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
) -> bool {
    let expected = match builder_vm_source_cache_provenance(dir, expected_fingerprint) {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    std::fs::read_to_string(dir.join(BUILDER_VM_PROVENANCE_FILE))
        .ok()
        .and_then(|actual| serde_json::from_str::<BuilderVmSourceCacheProvenance>(&actual).ok())
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
pub(super) fn write_builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    let provenance = builder_vm_source_cache_provenance(dir, source_fingerprint)?;
    let json = serde_json::to_string_pretty(&provenance)
        .context("serializing builder VM source cache provenance")?;
    std::fs::write(dir.join(BUILDER_VM_PROVENANCE_FILE), format!("{json}\n"))
        .with_context(|| format!("writing builder VM provenance in {}", dir.display()))
}

/// Write the full cache-sidecar set — source fingerprint, artifact-digest
/// manifest, and provenance — that [`builder_vm_source_cache_status`] reads
/// back to decide a hit. Shared by Stage 0 promotion and the dev-image
/// fast-path (Fix A) so both write the identical format; the order matters
/// only in that the digest manifest must be written after the artifacts are
/// final.
#[cfg(any(feature = "builder-vm", test))]
pub(super) fn write_builder_vm_cache_sidecars(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    write_builder_vm_source_fingerprint(dir, source_fingerprint)?;
    write_builder_vm_artifact_digest_manifest(dir)?;
    write_builder_vm_source_cache_provenance(dir, source_fingerprint)
}

#[cfg(any(feature = "builder-vm", test))]
pub(super) fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    validate_builder_vm_stage0_artifacts(staging_dir)?;
    if !builder_vm_source_fingerprint_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing the expected source fingerprint",
            staging_dir.display()
        );
    }
    if !builder_vm_artifact_digest_manifest_matches(staging_dir) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing matching artifact digests",
            staging_dir.display()
        );
    }
    if !builder_vm_source_cache_provenance_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing matching provenance metadata",
            staging_dir.display()
        );
    }

    if final_dir.exists() {
        if builder_vm_source_cache_ready(final_dir, source_fingerprint) {
            std::fs::remove_dir_all(staging_dir).with_context(|| {
                format!(
                    "removing redundant Stage 0 staging dir {}",
                    staging_dir.display()
                )
            })?;
            return Ok(());
        }
        std::fs::remove_dir_all(final_dir).with_context(|| {
            format!("removing partial builder VM cache {}", final_dir.display())
        })?;
    }

    std::fs::rename(staging_dir, final_dir).with_context(|| {
        format!(
            "promoting Stage 0 builder VM cache {} to {}",
            staging_dir.display(),
            final_dir.display()
        )
    })?;
    if !builder_vm_source_cache_ready(final_dir, source_fingerprint) {
        anyhow::bail!(
            "promoted Stage 0 builder VM cache {} failed source-cache validation",
            final_dir.display()
        );
    }
    Ok(())
}

/// Download the per-arch Layer 1 builder VM artifacts published by the
/// `builder-vm-image` release-workflow job into the local cache dir,
/// SHA-256-verified.
///
/// Uses the shared verification pipeline: `fetch_expected_hashes` reads the
/// checksum manifest, and `verify_artifact_hash` then holds every artifact to
/// the digest that manifest pins. The required artifacts are `vmlinux`,
/// `rootfs.ext4`, `cmdline.txt`, and `manifest.json`; the runtime
/// builder-image loader rejects caches that do not carry the full
/// contract.
///
/// Gated behind `release-artifact-bootstrap`. Contributor
/// builds (default) never compile this in, so the "no flake + cache
/// miss" branch in [`bootstrap_builder_vm_image`] has no escape hatch
/// and surfaces a hard error. End-user-binary release builds opt in
/// at compile time via `--features release-artifact-bootstrap`.
#[cfg(feature = "release-artifact-bootstrap")]
pub(super) fn download_builder_vm_image(arch: &str, cache_dir: &str) -> Result<()> {
    let names = builder_vm_artifact_names(arch);
    // Builder-VM images ship on the boot image counter, not the CLI's.
    let (tag, image_version) = crate::update::boot_image_release()?;
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/{tag}");
    let kernel_url = format!("{base_url}/{}", names.kernel);
    let rootfs_url = format!("{base_url}/{}", names.rootfs);
    let cmdline_url = format!("{base_url}/{}", names.cmdline);
    let manifest_url = format!("{base_url}/{}", names.manifest);

    // The builder-image cache contract is fail-closed: every artifact
    // the runtime loader consumes must be listed in checksums and
    // downloaded here before the cache is considered usable.
    let expected = fetch_expected_hashes(
        &ChecksumManifest {
            base_url: &base_url,
            asset: &names.checksums,
            version: &image_version,
            train: mvm_build::release_signature::ReleaseTrain::BootImage,
        },
        &[
            &names.kernel,
            &names.rootfs,
            &names.cmdline,
            &names.manifest,
        ],
    )?;

    ui::info("  Fetching kernel...");
    let kernel_path = format!("{cache_dir}/vmlinux");
    download_file(&kernel_url, &kernel_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM kernel from {kernel_url}"
        ))
    })?;
    verify_artifact_hash(&kernel_path, &names.kernel, expected.get(&names.kernel))?;

    ui::info("  Fetching rootfs...");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    download_file(&rootfs_url, &rootfs_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM rootfs from {rootfs_url}"
        ))
    })?;
    verify_artifact_hash(&rootfs_path, &names.rootfs, expected.get(&names.rootfs))?;

    ui::info("  Fetching cmdline...");
    let cmdline_path = format!("{cache_dir}/cmdline.txt");
    download_file(&cmdline_url, &cmdline_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM cmdline from {cmdline_url}"
        ))
    })?;
    verify_artifact_hash(&cmdline_path, &names.cmdline, expected.get(&names.cmdline))?;

    ui::info("  Fetching manifest...");
    let manifest_path = format!("{cache_dir}/manifest.json");
    download_file(&manifest_url, &manifest_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM manifest from {manifest_url}"
        ))
    })?;
    verify_artifact_hash(
        &manifest_path,
        &names.manifest,
        expected.get(&names.manifest),
    )?;

    ui::success(&format!(
        "Builder VM image downloaded, hash-verified, and cached at {cache_dir}."
    ));
    Ok(())
}

/// Per-arch artifact filenames the release workflow's
/// `builder-vm-image` job uploads. Pure function — no I/O, no
/// network — so the unit test can verify naming matches the
/// release.yml side without touching the network. Gated together
/// with [`download_builder_vm_image`].
#[cfg(any(feature = "release-artifact-bootstrap", test))]
pub(super) struct BuilderVmArtifactNames {
    pub(super) kernel: String,
    pub(super) rootfs: String,
    pub(super) cmdline: String,
    pub(super) manifest: String,
    pub(super) checksums: String,
}

#[cfg(any(feature = "release-artifact-bootstrap", test))]
pub(super) fn builder_vm_artifact_names(arch: &str) -> BuilderVmArtifactNames {
    BuilderVmArtifactNames {
        kernel: format!("builder-vm-vmlinux-{arch}"),
        rootfs: format!("builder-vm-rootfs-{arch}.ext4"),
        cmdline: format!("builder-vm-{arch}.cmdline.txt"),
        manifest: format!("builder-vm-{arch}.manifest.json"),
        checksums: format!("builder-vm-{arch}-checksums-sha256.txt"),
    }
}

/// Backend attempt order for the dev-image / default-microvm builds. Delegates
/// to the shared [`mvm_build::builder_backend_select::builder_attempt_order`]
/// (one policy: auto HVF→libkrun on macOS, auto libkrun stays libkrun-only,
/// explicit override stays single-backend) so this CLI loop and the
/// `mvm-build` build paths can't drift. The live platform supplies
/// `is_linux_native`, and the per-host builder-health cache stays advisory only
/// now that qemu is explicit dev/test-only rather than an automatic fallback.
#[cfg(feature = "builder-vm")]
pub(super) fn builder_backend_attempt_order(
    selected: mvm_build::builder_backend_select::BuilderBackendChoice,
    explicit_override: bool,
) -> Vec<mvm_build::builder_backend_select::BuilderBackendChoice> {
    let is_linux_native = matches!(
        mvm_core::platform::current(),
        mvm_core::platform::Platform::LinuxNative
    );
    mvm_build::builder_backend_select::builder_attempt_order(
        selected,
        explicit_override,
        is_linux_native,
        mvm_build::builder_health::libkrun_marked_unavailable(),
    )
}
