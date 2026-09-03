//! Host-side orchestrator for the application-dependency install
//! pipeline.
//!
//! This module is the host-side seam between a user's `mvmctl build`
//! invocation and the builder-VM-side install pipeline that runs
//! `uv pip install --no-deps`, `pnpm install --frozen-lockfile`, etc.
//! It does **two** things:
//!
//! 1. **Cache resolution.** Given an [`InstallSpec`] pointing at a
//!    lockfile, derive a stable `lockfile_hash`, look it up in the
//!    deps-volume index, and — on a cache hit — re-verify the on-disk
//!    sealed volume via
//!    [`mvm_sdk::compile::deps_audit::verify_sealed_volume`]. A hit
//!    returns `InstallResult { cache_hit: true, .. }` carrying the
//!    canonical `volume_hash` + `manifest.sha256` the supervisor's
//!    admission gate pins.
//! 2. **Cache miss → builder-VM dispatch.** Calls
//!    [`InstallDriver::run_install`] (blanket-impl'd for every
//!    [`crate::builder_vm::BuilderVm`]) with the canonical mount
//!    layout (source_root → `/work`, an in-cache scratch dir →
//!    `/out`), then seals the resulting volume via
//!    [`mvm_sdk::compile::deps_audit::seal_volume`] and renames it
//!    into the cache. Callers that want to skip dispatch (testing
//!    a cache-hit-only path) pass `driver = None` and get
//!    [`InstallError::DriverNotProvided`] on miss.
//!
//! ### Why the cache key is a lockfile hash
//!
//! The lifecycle gate pins the *volume* hash at admission time, but
//! the volume hash bakes in `cve.json` and `meta.json` —
//! values only the builder VM knows after the install runs. The
//! orchestrator needs a key it can derive *before* the VM runs so it
//! can answer "have I already installed this lockfile?" without a
//! VM spawn. The lockfile sha256 is that key: same lockfile bytes
//! ⇒ same key ⇒ same cached volume.
//!
//! The cache layout is:
//!
//! ```text
//! <deps_volumes_dir>/
//! ├── <volume_hash>/          # sealed volume (content + sidecars)
//! │   ├── content/
//! │   ├── sbom.cdx.json
//! │   ├── fetch.log
//! │   ├── cve.json
//! │   └── meta.json
//! └── index/
//!     └── <lockfile_hash>     # plain text: <volume_hash>\n
//! ```
//!
//! The supervisor only ever reads the `<volume_hash>/` directories;
//! the `index/` tree is host-orchestrator state. A corrupt index
//! entry can only ever cause a cache *miss* — the verifier still
//! re-derives the canonical volume_hash from disk, so a tampered
//! index can't pass a forged volume into admission.
//!
//! ### Cross-platform
//!
//! Per CLAUDE.md ("Host Nix is never used by mvmctl"): this module
//! does not invoke host Nix and does not call out to any host
//! installer. Every operation here is pure I/O — sha256 streaming,
//! filesystem reads, `verify_sealed_volume`, and a typed dispatch
//! through [`InstallDriver`]. The actual install runs inside the
//! libkrun builder VM, which the driver wraps.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use chrono::Utc;
use mvm_sdk::compile::deps_audit::{
    FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, VolumeError, seal_volume,
    verify_sealed_volume,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError};

/// Subdirectory under the deps-volumes root that holds the
/// `lockfile_hash → volume_hash` index. Kept out of the supervisor's
/// admission path (it only walks `<root>/<volume_hash>/`).
pub const INDEX_SUBDIR: &str = "index";

/// Which language ecosystem the lockfile belongs to. Determines
/// which installer the builder VM dispatches (slice B.2) and
/// participates in the cache key so the same lockfile bytes can't
/// accidentally collide across ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    Node,
}

impl Language {
    /// Short token mixed into the cache key. Stable wire-string;
    /// must not change without a cache-rebuild.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
        }
    }
}

/// The gate level controls strictness of the builder-VM-side checks
/// (attestations, CVE severity). The orchestrator carries it through
/// to the install dispatch, and it participates in the cache key so a
/// `--dev` cache entry can't satisfy a `--prod` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateLevel {
    /// Warnings on missing attestations / non-critical CVEs.
    Dev,
    /// Fails closed on missing attestations or high/critical CVEs.
    Prod,
}

impl GateLevel {
    pub fn token(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Prod => "prod",
        }
    }
}

/// What the caller wants installed. Pure data — the orchestrator
/// reads files at the given paths but does not retain handles.
#[derive(Debug, Clone)]
pub struct InstallSpec {
    /// Path to the lockfile (`uv.lock`, `package-lock.json`,
    /// `pnpm-lock.yaml`). Hashed verbatim — the orchestrator does
    /// not parse it.
    pub lockfile: PathBuf,
    /// Project root that holds the lockfile + any auxiliary inputs
    /// the installer needs (`pyproject.toml`, `package.json`). The
    /// builder VM bind-mounts this; the cache-resolution path records
    /// the path on `InstallResult` for diagnostics but does not read
    /// from it.
    pub source_root: PathBuf,
    pub language: Language,
    pub gate: GateLevel,
    /// Optional override for the deps-volumes cache root. When
    /// `None`, resolves to
    /// [`mvm_core::config::mvm_deps_volumes_dir`] (which itself
    /// honors `MVM_HOME` — the same env knob the
    /// admission verifier uses).
    pub cache_root_override: Option<PathBuf>,
}

/// Result of a successful install resolution. The caller (`mvmctl
/// build` wiring + `ExecutionPlan` synthesis) pins both `volume_hash`
/// and `manifest_sha256` into the plan so the admission verifier can
/// re-derive them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub volume_hash: String,
    pub manifest_sha256: String,
    pub cache_hit: bool,
    /// The path the supervisor will read from at admission time.
    pub volume_dir: PathBuf,
    /// The sha256 of the lockfile bytes, surfaced for diagnostics +
    /// `mvmctl deps inspect`.
    pub lockfile_sha256: String,
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("install spec lockfile `{}` is missing", .0.display())]
    LockfileMissing(PathBuf),

    #[error("install spec source root `{}` is missing", .0.display())]
    SourceRootMissing(PathBuf),

    #[error("failed to read lockfile `{}`: {source}", path.display())]
    LockfileIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read cache index `{}`: {source}", path.display())]
    IndexIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Cache hit on the index, but the volume directory it pointed
    /// at failed [`verify_sealed_volume`]. Propagates the underlying
    /// audit error so tamper-detection messages flow through. The
    /// orchestrator does **not** silently demote this to a miss —
    /// a corrupt cache entry needs operator attention.
    #[error("cache verify failed for lockfile_hash {lockfile_hash}: {source}")]
    CacheVerifyFailed {
        lockfile_hash: String,
        #[source]
        source: VolumeError,
    },

    /// Cache hit on the index, the volume verified, but the
    /// volume_hash that lived inside the volume disagrees with the
    /// hash the index pointed at. Means someone overwrote a
    /// directory in-place. Fail closed — same posture as
    /// [`Self::CacheVerifyFailed`].
    #[error(
        "cache index hash mismatch for lockfile_hash {lockfile_hash}: index said {index_hash}, on-disk volume sealed at {volume_hash}"
    )]
    CacheHashMismatch {
        lockfile_hash: String,
        index_hash: String,
        volume_hash: String,
    },

    /// Cache miss + no driver supplied. The caller asked for a
    /// pure-cache lookup but the entry doesn't exist. Distinct
    /// from a builder-VM failure because no VM was attempted —
    /// this is the "test setup wants a cache hit only" path.
    #[error(
        "no cached deps volume for lockfile_hash {lockfile_hash} ({language}/{gate}); \
         caller passed no InstallDriver so the builder-VM install pipeline was not attempted. \
         Pass `Some(&LibkrunBuilderVm::default())` or hand-author a sealed volume."
    )]
    DriverNotProvided {
        lockfile_hash: String,
        language: &'static str,
        gate: &'static str,
    },

    /// The builder VM ran but its install pipeline failed before
    /// emitting the sealed-volume artifacts. Wraps the underlying
    /// [`BuilderVmError`] so the diagnostic (missing libkrun,
    /// installer non-zero exit, missing sealed-volume artifact) is
    /// surfaced verbatim.
    #[error("builder VM install pipeline failed for lockfile_hash {lockfile_hash}: {source}")]
    BuilderVmFailed {
        lockfile_hash: String,
        #[source]
        source: BuilderVmError,
    },

    /// The builder VM completed but the artifacts it produced
    /// didn't seal cleanly — typically because one of the sealed
    /// sidecars is missing or unreadable. Wraps the
    /// [`VolumeError`] so the operator sees which artifact failed.
    #[error("sealing builder-VM-produced volume for lockfile_hash {lockfile_hash}: {source}")]
    SealFailed {
        lockfile_hash: String,
        #[source]
        source: VolumeError,
    },

    /// Failed to move the sealed volume into the cache. Almost
    /// always a permissions / cross-device-link issue.
    #[error(
        "moving sealed volume into cache `{}`: {source}",
        dest.display()
    )]
    CacheInstallFailed {
        dest: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Builder backend variant returned something other than
    /// [`BuilderArtifacts::InstallVolume`] from an
    /// [`BuilderJob::Install`]. Means the backend has a bug; fail
    /// closed rather than try to interpret a mismatched shape.
    #[error(
        "builder VM returned non-install artifact for an install job (lockfile_hash {lockfile_hash})"
    )]
    BuilderVmShapeMismatch { lockfile_hash: String },
}

/// Driver indirection so `install_app_deps` can be tested without
/// a live libkrun host. Production callers pass an instance of
/// [`crate::libkrun_builder::LibkrunBuilderVm`]; tests pass a
/// fixture that pre-populates `artifact_out` with hand-authored
/// content/SBOM/fetch.log/CVE/result.json.
///
/// Defining this as a trait — rather than wiring `LibkrunBuilderVm`
/// directly — keeps the `builder-vm` feature gate
/// pure: `install_app_deps` compiles + tests without dragging
/// libkrun-sys onto every CI runner.
pub trait InstallDriver {
    fn run_install(
        &self,
        spec_path: &Path,
        source_root: &Path,
        artifact_out: &Path,
    ) -> Result<BuilderArtifacts, BuilderVmError>;
}

/// Adapter that exposes a dynamically selected builder as an install driver.
///
/// Builder selection returns a trait object because the backend is chosen at
/// runtime. Keeping this adapter beside the install contract avoids requiring
/// callers to know the concrete builder type or to duplicate the canonical
/// install mount layout.
pub struct BuilderInstallDriver<'a> {
    builder: &'a dyn BuilderVm,
}

impl<'a> BuilderInstallDriver<'a> {
    /// Wrap a dynamically selected builder for [`install_app_deps`].
    pub fn new(builder: &'a dyn BuilderVm) -> Self {
        Self { builder }
    }
}

impl InstallDriver for BuilderInstallDriver<'_> {
    fn run_install(
        &self,
        spec_path: &Path,
        source_root: &Path,
        artifact_out: &Path,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        run_install_with_builder(self.builder, spec_path, source_root, artifact_out)
    }
}

/// Blanket impl: any [`BuilderVm`] is also an [`InstallDriver`].
/// The driver wraps the `BuilderJob::Install` call with the
/// canonical mount layout (source_root → `/work`, artifact_out
/// → `/out`). Host-Nix store reuse is intentionally absent for
/// install jobs — uv / pnpm don't touch `/nix/store`.
impl<T: BuilderVm + ?Sized> InstallDriver for T {
    fn run_install(
        &self,
        spec_path: &Path,
        source_root: &Path,
        artifact_out: &Path,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        run_install_with_builder(self, spec_path, source_root, artifact_out)
    }
}

fn run_install_with_builder<T: BuilderVm + ?Sized>(
    builder: &T,
    spec_path: &Path,
    source_root: &Path,
    artifact_out: &Path,
) -> Result<BuilderArtifacts, BuilderVmError> {
    let job = BuilderJob::Install {
        spec_path: spec_path.to_path_buf(),
    };
    // Install jobs don't embed host-vm binaries into a rootfs, so
    // host_bin_dir is unused. Use a private temp dir as a valid
    // placeholder so validate_mounts passes.
    let _host_bins_tmp = tempfile::TempDir::new().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("creating temp host_bin_dir: {e}"))
    })?;
    let mounts = BuilderMounts {
        flake_src: source_root.to_path_buf(),
        host_nix_store: None,
        artifact_out: artifact_out.to_path_buf(),
        host_bin_dir: _host_bins_tmp.path().to_path_buf(),
        // App-dep installs stage an install spec, not a user flake; no
        // mvm override applies.
        staged_user_flake: None,
    };
    builder.run_build(&job, &mounts)
}

/// Resolve a deps install for `spec`. Cache-hit path is pure I/O
/// (no driver needed); cache-miss path dispatches the install via
/// [`InstallDriver`] (typically [`crate::libkrun_builder::LibkrunBuilderVm`]),
/// seals the result, and renames it into the cache.
///
/// Pass `driver = None` to assert no VM dispatch can happen —
/// tests that should only exercise the cache-hit path use this to
/// force a panic on inadvertent miss.
pub fn install_app_deps(
    spec: &InstallSpec,
    driver: Option<&dyn InstallDriver>,
) -> Result<InstallResult, InstallError> {
    if !spec.lockfile.is_file() {
        return Err(InstallError::LockfileMissing(spec.lockfile.clone()));
    }
    if !spec.source_root.is_dir() {
        return Err(InstallError::SourceRootMissing(spec.source_root.clone()));
    }

    let lockfile_sha256 =
        sha256_file(&spec.lockfile).map_err(|source| InstallError::LockfileIo {
            path: spec.lockfile.clone(),
            source,
        })?;
    let lockfile_hash = derive_lockfile_hash(&lockfile_sha256, spec.language, spec.gate);
    let cache_root = resolve_cache_root(spec.cache_root_override.as_deref());

    if let Some(volume_hash) = lookup_cached_volume(&cache_root, &lockfile_hash)? {
        return finalize_cache_hit(&cache_root, &lockfile_hash, &volume_hash, &lockfile_sha256);
    }

    let driver = driver.ok_or_else(|| InstallError::DriverNotProvided {
        lockfile_hash: lockfile_hash.clone(),
        language: spec.language.token(),
        gate: spec.gate.token(),
    })?;
    run_install_via_driver(spec, driver, &cache_root, &lockfile_hash, &lockfile_sha256)
}

/// Cache-hit completion path. Verifies the on-disk volume, cross-
/// checks the recorded hash, and builds the `InstallResult`.
fn finalize_cache_hit(
    cache_root: &Path,
    lockfile_hash: &str,
    volume_hash: &str,
    lockfile_sha256: &str,
) -> Result<InstallResult, InstallError> {
    let volume_dir = cache_root.join(volume_hash);
    let computed =
        verify_sealed_volume(&volume_dir).map_err(|source| InstallError::CacheVerifyFailed {
            lockfile_hash: lockfile_hash.to_string(),
            source,
        })?;
    if computed != volume_hash {
        return Err(InstallError::CacheHashMismatch {
            lockfile_hash: lockfile_hash.to_string(),
            index_hash: volume_hash.to_string(),
            volume_hash: computed,
        });
    }
    let manifest_path = volume_dir.join(FILE_MANIFEST);
    let manifest_sha256 =
        sha256_file(&manifest_path).map_err(|source| InstallError::LockfileIo {
            path: manifest_path,
            source,
        })?;
    Ok(InstallResult {
        volume_hash: volume_hash.to_string(),
        manifest_sha256,
        cache_hit: true,
        volume_dir,
        lockfile_sha256: lockfile_sha256.to_string(),
    })
}

/// Cache-miss path: dispatch the install pipeline through the
/// builder VM, seal its output, and install it into the cache.
///
/// Pipeline:
/// 1. Synthesize the install spec JSON the guest reads.
/// 2. Stage a writable scratch dir under
///    `<cache_root>/in-progress/<id>/` — the builder VM mounts
///    this at `/out`. Doing the scratch under the cache root
///    (rather than `/tmp`) avoids cross-device rename when we
///    move the sealed volume into the cache.
/// 3. Drive the VM via [`InstallDriver::run_install`].
/// 4. Seal the artifacts via
///    `mvm_sdk::compile::deps_audit::seal_volume`. Annotates the
///    sealed manifest with the lockfile hash + language/gate
///    tokens so `mvmctl deps inspect` can surface them.
/// 5. Write the manifest, rename the scratch dir to
///    `<cache_root>/<volume_hash>/`, write the index pointer.
fn run_install_via_driver(
    spec: &InstallSpec,
    driver: &dyn InstallDriver,
    cache_root: &Path,
    lockfile_hash: &str,
    lockfile_sha256: &str,
) -> Result<InstallResult, InstallError> {
    fs::create_dir_all(cache_root).map_err(|source| InstallError::IndexIo {
        path: cache_root.to_path_buf(),
        source,
    })?;
    let in_progress_root = cache_root.join("in-progress");
    fs::create_dir_all(&in_progress_root).map_err(|source| InstallError::IndexIo {
        path: in_progress_root.clone(),
        source,
    })?;
    let scratch = in_progress_root.join(unique_scratch_id());
    fs::create_dir_all(&scratch).map_err(|source| InstallError::IndexIo {
        path: scratch.clone(),
        source,
    })?;

    // Stage the install spec JSON next to the scratch dir (not
    // inside it — `/out` should only carry the sealed-volume
    // artifacts post-run).
    let spec_path = scratch.with_extension("spec.json");
    let spec_body = install_spec_json(spec);
    fs::write(&spec_path, spec_body).map_err(|source| InstallError::IndexIo {
        path: spec_path.clone(),
        source,
    })?;

    let artifacts = driver
        .run_install(&spec_path, &spec.source_root, &scratch)
        .map_err(|source| InstallError::BuilderVmFailed {
            lockfile_hash: lockfile_hash.to_string(),
            source,
        })?;
    // Best-effort cleanup of the spec — the install succeeded, so
    // a lingering spec.json under cache_root would only be noise.
    let _ = fs::remove_file(&spec_path);

    let volume_dir = match artifacts {
        BuilderArtifacts::InstallVolume { volume_dir, .. } => volume_dir,
        _ => {
            // Clean up the scratch dir so a buggy backend doesn't
            // leave half-populated dirs lying around.
            let _ = fs::remove_dir_all(&scratch);
            return Err(InstallError::BuilderVmShapeMismatch {
                lockfile_hash: lockfile_hash.to_string(),
            });
        }
    };

    // Seal the artifacts. `seal_volume` reads + hashes the four
    // sidecars; the annotations capture lockfile-key context for
    // `mvmctl deps inspect`.
    let content = volume_dir.join(FILE_CONTENT_DIR);
    let sbom = volume_dir.join(FILE_SBOM);
    let fetch_log = volume_dir.join(FILE_FETCH_LOG);
    let cve = volume_dir.join(FILE_CVE);
    let mut annotations = BTreeMap::new();
    annotations.insert("language".to_string(), spec.language.token().to_string());
    annotations.insert("gate".to_string(), spec.gate.token().to_string());
    annotations.insert(
        "lockfile_relative_path".to_string(),
        lockfile_relative_path(spec).to_string_lossy().into_owned(),
    );
    annotations.insert("lockfile_sha256".to_string(), lockfile_sha256.to_string());
    annotations.insert("lockfile_hash".to_string(), lockfile_hash.to_string());
    let created_at = Utc::now().to_rfc3339();
    let sealed = seal_volume(&content, &sbom, &fetch_log, &cve, created_at, annotations).map_err(
        |source| InstallError::SealFailed {
            lockfile_hash: lockfile_hash.to_string(),
            source,
        },
    )?;
    let manifest_path = volume_dir.join(FILE_MANIFEST);
    fs::write(&manifest_path, &sealed.manifest_bytes).map_err(|source| InstallError::IndexIo {
        path: manifest_path.clone(),
        source,
    })?;

    // Rename the scratch dir to its canonical hash-named slot.
    // If a previous run already populated this slot (concurrent
    // install racing the same lockfile), preserve the older value
    // and delete our scratch — the index/volume both verify the
    // same content, so either is correct.
    let final_dir = cache_root.join(&sealed.volume_hash);
    if final_dir.exists() {
        let _ = fs::remove_dir_all(&volume_dir);
    } else {
        fs::rename(&volume_dir, &final_dir).map_err(|source| InstallError::CacheInstallFailed {
            dest: final_dir.clone(),
            source,
        })?;
    }

    // Write the lockfile_hash → volume_hash index pointer.
    let index_dir = cache_root.join(INDEX_SUBDIR);
    fs::create_dir_all(&index_dir).map_err(|source| InstallError::IndexIo {
        path: index_dir.clone(),
        source,
    })?;
    let index_path = index_dir.join(lockfile_hash);
    fs::write(&index_path, &sealed.volume_hash).map_err(|source| InstallError::IndexIo {
        path: index_path.clone(),
        source,
    })?;

    let manifest_sha256 =
        sha256_file(&final_dir.join(FILE_MANIFEST)).map_err(|source| InstallError::LockfileIo {
            path: final_dir.join(FILE_MANIFEST),
            source,
        })?;
    Ok(InstallResult {
        volume_hash: sealed.volume_hash,
        manifest_sha256,
        cache_hit: false,
        volume_dir: final_dir,
        lockfile_sha256: lockfile_sha256.to_string(),
    })
}

/// Serialize an [`InstallSpec`] into the JSON shape
/// `mvm-host-vm-init::install_spec::parse` expects. Hand-rolled
/// (rather than serde-derived) so the wire shape stays pinned —
/// adding a field on either side surfaces here, not as a silent
/// drift.
fn install_spec_json(spec: &InstallSpec) -> String {
    format!(
        r#"{{"language":"{lang}","lockfile_relative_path":"{path}","source_mount":"/work","gate":"{gate}"}}"#,
        lang = spec.language.token(),
        // The lockfile path is recorded relative to the source
        // root so the guest can resolve it against its `/work`
        // mount. `.strip_prefix` returns the relative tail; on
        // an absolute lockfile that isn't under source_root we
        // fall back to the bare file name (rare but possible
        // for callers that constructed `spec.lockfile` manually).
        path = json_string_escape(&lockfile_relative_path(spec).to_string_lossy()),
        gate = spec.gate.token(),
    )
}

fn lockfile_relative_path(spec: &InstallSpec) -> PathBuf {
    spec.lockfile
        .strip_prefix(&spec.source_root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            spec.lockfile
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_default()
        })
}

/// JSON-string escaper matching the one in
/// `mvm-host-vm-init::install_spec` so the spec round-trips
/// unchanged. Mirrors the RFC 8259 §7 must-escape set.
fn json_string_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Monotonic-with-pid scratch ID for the per-invocation
/// `in-progress/<id>/` dir. Same pattern as
/// `libkrun_builder::unique_job_id` — duplicated here so this
/// module stays usable without the `builder-vm`
/// feature gate.
fn unique_scratch_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{stamp:013}-{pid}")
}

/// Derive the stable cache key from the lockfile sha256 + the
/// language + the gate. Pure function so callers (tests, future
/// `mvmctl deps inspect`) can reproduce it without re-hashing.
///
/// The mix-in tokens prevent two ecosystems from colliding on a
/// byte-identical lockfile (`requirements.txt` vs. a Node lockfile
/// of the same length), and prevent a `--dev` cache entry from
/// satisfying a `--prod` admission request.
pub fn derive_lockfile_hash(lockfile_sha256: &str, language: Language, gate: GateLevel) -> String {
    let mut h = Sha256::new();
    h.update(b"mvm-app-deps-v1\n");
    h.update(language.token().as_bytes());
    h.update(b"\n");
    h.update(gate.token().as_bytes());
    h.update(b"\n");
    h.update(lockfile_sha256.as_bytes());
    hex(&h.finalize())
}

/// Resolve the deps-volumes cache root, honoring the per-call
/// override and falling back to
/// [`mvm_core::config::mvm_deps_volumes_dir`] (which itself honors
/// `MVM_HOME`). Shared lookup with the admission
/// verifier — no duplication.
pub fn resolve_cache_root(override_path: Option<&Path>) -> PathBuf {
    override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(mvm_core::config::mvm_deps_volumes_dir()))
}

/// Read the cache index entry for a `lockfile_hash`. Returns the
/// recorded `volume_hash` on hit, `None` on miss (no index file).
/// I/O errors other than `NotFound` propagate.
fn lookup_cached_volume(
    cache_root: &Path,
    lockfile_hash: &str,
) -> Result<Option<String>, InstallError> {
    let path = cache_root.join(INDEX_SUBDIR).join(lockfile_hash);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim().to_owned();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(InstallError::IndexIo { path, source }),
    }
}

fn sha256_file(path: &Path) -> Result<String, io::Error> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    //! Module-level unit coverage for the pure helpers; the
    //! end-to-end orchestrator paths (cache hit, miss, tamper,
    //! determinism) live in
    //! `crates/mvm-build/tests/app_deps_orchestrator.rs` so they
    //! exercise the public API.
    use super::*;

    struct FailingBuilder;

    impl BuilderVm for FailingBuilder {
        fn run_stage0(
            &self,
            _guest_root_dir: &std::path::Path,
            _entry_path: &str,
            _workspace_dir: &std::path::Path,
            _artifact_out: &std::path::Path,
            _host_bin_dir: &std::path::Path,
        ) -> Result<(), BuilderVmError> {
            Err(BuilderVmError::NotYetImplemented)
        }

        fn capabilities(&self) -> crate::builder_vm::BuilderCapabilities {
            crate::builder_vm::BuilderCapabilities::default()
        }

        fn run_build(
            &self,
            _job: &BuilderJob,
            _mounts: &BuilderMounts,
        ) -> Result<BuilderArtifacts, BuilderVmError> {
            Err(BuilderVmError::NotYetImplemented)
        }
    }

    #[test]
    fn lockfile_hash_differs_across_languages() {
        let h_py = derive_lockfile_hash("aa", Language::Python, GateLevel::Dev);
        let h_node = derive_lockfile_hash("aa", Language::Node, GateLevel::Dev);
        assert_ne!(h_py, h_node);
    }

    #[test]
    fn lockfile_hash_differs_across_gates() {
        let h_dev = derive_lockfile_hash("aa", Language::Python, GateLevel::Dev);
        let h_prod = derive_lockfile_hash("aa", Language::Python, GateLevel::Prod);
        assert_ne!(h_dev, h_prod);
    }

    #[test]
    fn lockfile_hash_is_pure() {
        let h1 = derive_lockfile_hash("aa", Language::Python, GateLevel::Dev);
        let h2 = derive_lockfile_hash("aa", Language::Python, GateLevel::Dev);
        assert_eq!(h1, h2);
    }

    #[test]
    fn resolve_cache_root_prefers_override() {
        let p = PathBuf::from("/tmp/forced");
        assert_eq!(resolve_cache_root(Some(&p)), p);
    }

    #[test]
    fn dynamic_builder_install_adapter_delegates_to_builder() {
        let builder = FailingBuilder;
        let adapter = BuilderInstallDriver::new(&builder);
        let error = adapter
            .run_install(
                Path::new("spec.json"),
                Path::new("source"),
                Path::new("out"),
            )
            .expect_err("the fixture builder must be called");
        assert!(matches!(error, BuilderVmError::NotYetImplemented));
    }
}
