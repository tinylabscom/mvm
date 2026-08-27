//! Host-side source of the guest runtime binaries baked into an OCI rootfs
//! ([`crate::oci_runtime_inject`]).
//!
//! An mkGuest rootfs gets the agent from a nix build inside the builder
//! VM. An arbitrary OCI image has no nix build of its own, so for the
//! `run --image` path the host produces the binaries directly and bakes
//! them in. This module builds the guest artifact with `cargo-zigbuild` to a
//! static musl target and caches the result under
//! `~/.mvm/cache/guest-agent/<version>/<arch>/`.
//!
//! `cargo-zigbuild` is the single portable cross path: the agent pulls
//! `ring` (C), so a static musl build needs a musl C cross-compiler, and
//! zig supplies it without a system `<arch>-linux-musl-gcc`. The
//! source-checkout build ([`resolve_or_build_guest_binaries`]) is only
//! reachable with the workspace + zig. Installed binaries use the universal
//! initramfs and runtime overlay; the host CLI never embeds these workload
//! bytes.

use mvm_core::arch::GuestArch;
use sha2::{Digest, Sha256};

/// Internal CLI-to-builder switch: raw Cargo progress is opt-in with `-v`.
pub const GUEST_BUILD_VERBOSE_ENV: &str = "MVM_GUEST_BUILD_VERBOSE";

/// Static guest binaries required while materializing and booting an OCI root.
/// Release packaging and download verification share this canonical set.
pub const OCI_GUEST_RUNTIME_BINARY_NAMES: [&str; 4] = [
    "mvm-guest-agent",
    "mvm-guest-netinit",
    "mvm-egress-client",
    "mvm-oci-entrypoint",
];
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::oci_runtime_inject::MvmRuntimeBinaries;

#[derive(Debug, Error)]
pub enum GuestAgentBuildError {
    #[error("cargo-zigbuild failed: {reason}")]
    BuildFailed { reason: String },

    #[error("built guest binary missing after zigbuild: {0}")]
    OutputMissing(PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// On-disk cache layout for one `(version, arch)` of the guest binaries.
/// Pure path construction — no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAgentLayout {
    pub dir: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub egress_client: PathBuf,
    pub entrypoint_runner: PathBuf,
}

/// Built guest runtime binary paths ready to install into the cache.
#[derive(Debug, Clone, Copy)]
pub struct GuestRuntimeBinaryPaths<'a> {
    pub agent: &'a Path,
    pub netinit: &'a Path,
    pub egress_client: &'a Path,
    pub entrypoint_runner: &'a Path,
}

/// Bump when a previously populated source-keyed guest cache may contain
/// outputs produced through an incompatible build-cache contract.
const GUEST_SOURCE_CACHE_EPOCH: u32 = 2;

impl GuestAgentLayout {
    /// `cache_key` names the cache generation: an mvmctl `version` for a
    /// compatibility cache, or a guest source fingerprint (`source_cache_key`)
    /// for a contributor checkout so a local edit lands in its own cache dir
    /// and never reuses a stale agent.
    pub fn under(cache_root: &Path, cache_key: &str, arch: GuestArch) -> Self {
        let dir = cache_root
            .join("guest-agent")
            .join(cache_key)
            .join(arch.to_string());
        Self {
            agent: dir.join("mvm-guest-agent"),
            netinit: dir.join("mvm-guest-netinit"),
            egress_client: dir.join("mvm-egress-client"),
            entrypoint_runner: dir.join("mvm-oci-entrypoint"),
            dir,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.agent.is_file()
            && self.netinit.is_file()
            && self.egress_client.is_file()
            && self.entrypoint_runner.is_file()
    }

    pub fn binaries(&self) -> MvmRuntimeBinaries {
        MvmRuntimeBinaries {
            agent: self.agent.clone(),
            netinit: self.netinit.clone(),
            egress_client: self.egress_client.clone(),
            entrypoint_runner: self.entrypoint_runner.clone(),
        }
    }
}

/// Full guest-binary set that the read-only runtime overlay carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayGuestBinaries {
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub seccomp_apply: PathBuf,
    pub runner: PathBuf,
    pub egress_client: PathBuf,
    pub addon_dns: PathBuf,
    pub exit_report: PathBuf,
    pub ping: PathBuf,
    pub forward_proxy: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayGuestLayout {
    pub dir: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub seccomp_apply: PathBuf,
    pub runner: PathBuf,
    pub egress_client: PathBuf,
    pub addon_dns: PathBuf,
    pub exit_report: PathBuf,
    pub ping: PathBuf,
    pub forward_proxy: PathBuf,
}

impl RuntimeOverlayGuestLayout {
    pub fn under(cache_root: &Path, version: &str, arch: GuestArch, fingerprint: &str) -> Self {
        let dir = cache_root
            .join("runtime-overlay-bins")
            .join(version)
            .join(arch.to_string())
            .join(fingerprint);
        Self {
            agent: dir.join("agent"),
            netinit: dir.join("netinit"),
            seccomp_apply: dir.join("seccomp-apply"),
            runner: dir.join("runner"),
            egress_client: dir.join("egress-client"),
            addon_dns: dir.join("addon-dns"),
            exit_report: dir.join("exit-report"),
            ping: dir.join("ping"),
            forward_proxy: dir.join("forward-proxy"),
            dir,
        }
    }

    fn is_complete(&self) -> bool {
        self.agent.is_file()
            && self.netinit.is_file()
            && self.seccomp_apply.is_file()
            && self.runner.is_file()
            && self.egress_client.is_file()
            && self.addon_dns.is_file()
            && self.exit_report.is_file()
            && self.ping.is_file()
            && self.forward_proxy.is_file()
    }

    fn binaries(&self) -> RuntimeOverlayGuestBinaries {
        RuntimeOverlayGuestBinaries {
            agent: self.agent.clone(),
            netinit: self.netinit.clone(),
            seccomp_apply: self.seccomp_apply.clone(),
            runner: self.runner.clone(),
            egress_client: self.egress_client.clone(),
            addon_dns: self.addon_dns.clone(),
            exit_report: self.exit_report.clone(),
            ping: self.ping.clone(),
            forward_proxy: self.forward_proxy.clone(),
        }
    }
}

/// The musl target triple cargo-zigbuild cross-compiles to for `arch`.
/// Static musl so the binary runs in any guest userspace (no loader).
pub fn musl_target_triple(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Aarch64 => "aarch64-unknown-linux-musl",
        GuestArch::X86_64 => "x86_64-unknown-linux-musl",
    }
}

/// Spec for the `cargo zigbuild` invocation that produces the guest
/// binaries. Pure data; [`build_guest_binaries`] runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAgentBuildSpec {
    /// Workspace root (dir containing `Cargo.toml`, `crates/`).
    pub workspace_root: PathBuf,
    pub arch: GuestArch,
    /// Cargo target dir for the cross-compile. Cache-scoped, deliberately NOT
    /// `<workspace_root>/target`: a source-checkout guest build must never write
    /// into the invoking source tree (mirrors `mvm-cli/build.rs`'s OUT_DIR
    /// target). Set as `CARGO_TARGET_DIR` for the `cargo zigbuild` process.
    pub target_dir: PathBuf,
    /// Override the cargo binary (tests). `None` ⇒ `cargo` on `$PATH`.
    pub cargo: Option<PathBuf>,
}

impl GuestAgentBuildSpec {
    pub fn new(workspace_root: PathBuf, arch: GuestArch, target_dir: PathBuf) -> Self {
        Self {
            workspace_root,
            arch,
            target_dir,
            cargo: None,
        }
    }

    pub fn target_triple(&self) -> &'static str {
        musl_target_triple(self.arch)
    }

    /// `cargo zigbuild` argv. Builds the universal guest runtime bins with
    /// `addons` (the async loopback helper bins — `mvm-egress-client` here —
    /// require it).
    pub fn argv(&self) -> Vec<String> {
        let cargo = self
            .cargo
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "cargo".to_string());
        vec![
            cargo,
            "zigbuild".to_string(),
            "--release".to_string(),
            "--target".to_string(),
            self.target_triple().to_string(),
            "-p".to_string(),
            "mvm-agentd".to_string(),
            "--bin".to_string(),
            "mvm-guest-agent".to_string(),
            "--bin".to_string(),
            "mvm-guest-netinit".to_string(),
            "--bin".to_string(),
            "mvm-oci-entrypoint".to_string(),
            "--bin".to_string(),
            "mvm-egress-client".to_string(),
            "--features".to_string(),
            "mvm-agentd/addons".to_string(),
        ]
    }

    /// Paths the build drops the binaries at, under the cache-scoped
    /// `target_dir` (never the source tree's `target/`). Independent of any
    /// ambient `CARGO_TARGET_DIR` — [`build_guest_binaries`] pins the env to
    /// `target_dir`.
    pub fn output_dir(&self) -> PathBuf {
        self.target_dir.join(self.target_triple()).join("release")
    }
}

/// The worktree-isolated Cargo target dir for guest cross-compiles.
///
/// One checkout reuses dependency output across source edits; different
/// worktrees hash to different target dirs and cannot serve each other stale
/// workspace artifacts. Final guest binaries remain content-keyed separately.
pub fn guest_build_target_dir(cache_root: &Path, workspace_root: &Path) -> PathBuf {
    let stable_root =
        std::fs::canonicalize(workspace_root).unwrap_or_else(|_| workspace_root.to_path_buf());
    let digest = Sha256::digest(stable_root.to_string_lossy().as_bytes());
    cache_root
        .join("guest-agent-build")
        .join("targets")
        .join(&hex::encode(digest)[..16])
}

/// True when `dir` is the root of an mvm source checkout: it carries a top-level
/// `Cargo.toml` and the `crates/mvm-agentd/` crate. That pair uniquely names the
/// workspace root — the guest crate exists nowhere else in the tree.
pub fn is_source_workspace_root(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file() && dir.join("crates/mvm-agentd").is_dir()
}

/// Walk up from `start`, returning the first ancestor that is a source
/// workspace root, else `None`. Pure — no ambient state.
pub fn source_workspace_from(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| is_source_workspace_root(d))
        .map(Path::to_path_buf)
}

/// The mvm source workspace to build the legacy rootfs-injected guest runtime
/// from, or `None` for an installed binary with no source fallback.
///
/// Resolution: the running executable's checkout first, then the invoking
/// process's current checkout, then the compile-time `CARGO_MANIFEST_DIR`
/// ancestor. An explicitly invoked worktree binary must keep its host and guest
/// code from the same tree even when the caller's shell is in another checkout.
/// Installed binaries have no checkout ancestor and therefore retain the
/// current-directory source fallback.
pub fn detect_source_workspace() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok();
    let current_dir = std::env::current_dir().ok();
    source_workspace_for_channel(
        crate::artifact_acquisition::compiled_channel(),
        executable.as_deref(),
        current_dir.as_deref(),
        Path::new(env!("CARGO_MANIFEST_DIR")),
    )
}

#[cfg(test)]
fn source_workspace_for(
    executable: Option<&Path>,
    current_dir: Option<&Path>,
    compiled_manifest_dir: &Path,
) -> Option<PathBuf> {
    source_workspace_for_channel(
        crate::artifact_acquisition::DistributionChannel::Source,
        executable,
        current_dir,
        compiled_manifest_dir,
    )
}

fn source_workspace_for_channel(
    channel: crate::artifact_acquisition::DistributionChannel,
    executable: Option<&Path>,
    current_dir: Option<&Path>,
    compiled_manifest_dir: &Path,
) -> Option<PathBuf> {
    if !channel.permits_automatic_builds() {
        return None;
    }
    executable
        .and_then(source_workspace_from)
        .or_else(|| current_dir.and_then(source_workspace_from))
        .or_else(|| source_workspace_from(compiled_manifest_dir))
}

/// Cache-key segment for a source-checkout guest build: a `src-` prefixed
/// fingerprint of the guest crate sources. A changed guest source ⇒ a changed
/// key ⇒ a fresh build, so a contributor's local edit is never served a stale
/// version+arch-cached agent. The `src-` prefix keeps it from ever colliding
/// with a version-keyed (shipped-binary) cache entry.
pub fn source_cache_key(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    Ok(format!(
        "src-v{GUEST_SOURCE_CACHE_EPOCH}-{}",
        guest_source_fingerprint(workspace_root)?
    ))
}

/// Where the guest binaries come from on this host, and the cache key that
/// goes with it.
///
/// The two arms key differently — a source checkout on a fingerprint of the
/// guest sources, a shipped binary on the crate version — and which arm
/// applies is a property of the host, not of the caller. Returning both
/// together is what stops a caller from pairing one arm's key with the
/// other's assumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestBinarySource {
    /// An mvm source checkout: cross-compile from `workspace_root` on a miss.
    SourceCheckout {
        workspace_root: PathBuf,
        cache_key: String,
    },
    /// No checkout — the shipped binary's embedded bytes, keyed by version.
    EmbeddedVersion { cache_key: String },
}

impl GuestBinarySource {
    /// The cache-key segment [`GuestAgentLayout::under`] is addressed with.
    pub fn cache_key(&self) -> &str {
        match self {
            Self::SourceCheckout { cache_key, .. } | Self::EmbeddedVersion { cache_key } => {
                cache_key
            }
        }
    }
}

/// Resolve [`GuestBinarySource`] for this host.
///
/// Public because seeding the guest-binary cache and reading it must agree
/// on the key, and the only way to guarantee that is for both to derive it
/// here. A test that seeds the version key while the resolver reads the
/// source-fingerprint key does not fail — it silently misses and performs
/// a real cross-compile, which is how three `pull_core` unit tests came to
/// spend fifty-five seconds each building the guest agent.
pub fn guest_binary_source() -> Result<GuestBinarySource, GuestAgentBuildError> {
    match detect_source_workspace() {
        Some(workspace_root) => {
            let cache_key = source_cache_key(&workspace_root)?;
            Ok(GuestBinarySource::SourceCheckout {
                workspace_root,
                cache_key,
            })
        }
        None => Ok(GuestBinarySource::EmbeddedVersion {
            cache_key: env!("CARGO_PKG_VERSION").to_string(),
        }),
    }
}

/// Fingerprints already computed in this process, by workspace root.
///
/// Only successes are stored. An error can be transient — a file being written
/// as the walk passes it — and caching one would make a single unlucky moment
/// permanent for the rest of the run.
static SOURCE_FINGERPRINTS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, String>>,
> = std::sync::OnceLock::new();

/// A stable content fingerprint over every workspace input that can change the
/// OCI guest binaries: dependency lock, workspace manifest, shared core code,
/// guest code, and this build recipe. Host-only CLI edits are excluded.
///
/// Memoized for the lifetime of the process. Nine call sites across the boot
/// path ask for this, and a single `machine run` on a source checkout was
/// answering it **six times** — six walks over 416 files and ~7.2 MB, ~2500
/// file opens, for a value that cannot differ between them.
///
/// Process lifetime is the right scope because `mvmctl` is one-shot: every
/// caller runs inside a single command, within a few hundred milliseconds of
/// the others. A source tree edited inside that window would already produce
/// disagreeing answers at different call sites today, and disagreement is
/// worse than staleness — one leg would rebuild against a fingerprint another
/// leg had already recorded. The memo makes the answer consistent as well as
/// cheap. Anything long-running that later wants change detection needs a
/// watcher, not a repeated full-tree hash.
pub fn guest_source_fingerprint(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    let memo = SOURCE_FINGERPRINTS.get_or_init(Default::default);
    if let Ok(cache) = memo.lock()
        && let Some(hit) = cache.get(workspace_root)
    {
        return Ok(hit.clone());
    }
    let digest = compute_guest_source_fingerprint(workspace_root)?;
    if let Ok(mut cache) = memo.lock() {
        cache.insert(workspace_root.to_path_buf(), digest.clone());
    }
    Ok(digest)
}

/// A content fingerprint over the inputs to `libmvm_host_services.so` — the
/// SDK sidecar's cdylib, and the one file in that image a source change can
/// alter.
///
/// Separate from [`guest_source_fingerprint`] because the input sets differ:
/// the cdylib is `mvm-sdk`'s `[lib]` target, which the guest-binary set does
/// not build, while the shared crates underneath it are common to both. Folding
/// `mvm-sdk` into the guest fingerprint instead would invalidate every cached
/// guest binary on an SDK-only edit, which is a rebuild nobody asked for.
///
/// The sidecar's other members — the glibc loader, `libc.so.6`, `libgcc_s.so.1`
/// — come from nixpkgs and cannot change without the version changing, so they
/// are deliberately not inputs here.
pub fn sdk_cdylib_source_fingerprint(
    workspace_root: &Path,
) -> Result<String, GuestAgentBuildError> {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-sdk-cdylib-input-v1\0");
    hash_inputs(
        &mut hasher,
        workspace_root,
        &[
            "Cargo.lock",
            "Cargo.toml",
            "crates/mvm-contract/Cargo.toml",
            "crates/mvm-contract/src",
            "crates/mvm-core/Cargo.toml",
            "crates/mvm-core/src",
            "crates/mvm-agentd/Cargo.toml",
            "crates/mvm-agentd/src",
            "crates/mvm-sdk/Cargo.toml",
            "crates/mvm-sdk/src",
        ],
    )?;
    Ok(hex::encode(hasher.finalize()))
}

/// Fold each declared input into `hasher`, failing closed on one that is
/// missing. A fingerprint that quietly skipped an absent input would collide
/// with the tree that still has it.
fn hash_inputs(
    hasher: &mut Sha256,
    workspace_root: &Path,
    inputs: &[&str],
) -> Result<(), GuestAgentBuildError> {
    for rel in inputs {
        let path = workspace_root.join(rel);
        if path.is_dir() {
            hash_dir_recursive(hasher, rel, &path)?;
        } else if path.is_file() {
            hash_file(hasher, rel, &path)?;
        } else {
            return Err(GuestAgentBuildError::OutputMissing(path));
        }
    }
    Ok(())
}

/// The walk itself, split out so the memo above has something to wrap and a
/// test can measure the uncached cost directly.
fn compute_guest_source_fingerprint(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-oci-guest-build-input-v1\0");
    for rel in [
        "Cargo.lock",
        "Cargo.toml",
        "crates/mvm-contract/Cargo.toml",
        "crates/mvm-contract/src",
        "crates/mvm-core/Cargo.toml",
        "crates/mvm-core/src",
        "crates/mvm-agentd/Cargo.toml",
        "crates/mvm-agentd/src",
        "crates/mvm-build/src/guest_agent_build.rs",
    ] {
        let path = workspace_root.join(rel);
        if path.is_dir() {
            hash_dir_recursive(&mut hasher, rel, &path)?;
        } else if path.is_file() {
            hash_file(&mut hasher, rel, &path)?;
        } else {
            return Err(GuestAgentBuildError::OutputMissing(path));
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Resolve the guest binaries for `(cache_key, arch)`, building + caching them
/// from `workspace_root` on a cache miss. For a source checkout the caller
/// passes a [`source_cache_key`], so a changed guest source misses the cache and
/// rebuilds instead of serving a stale agent. The cross-compile writes to a
/// cache-scoped target dir, never into `workspace_root/target`.
pub fn resolve_or_build_guest_binaries(
    cache_root: &Path,
    cache_key: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, cache_key, arch);
    if layout.is_complete() {
        return Ok(layout.binaries());
    }
    let _build_lock = mvm_core::util::atomic_io::FileLock::acquire(&layout.dir.join("build"))
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("acquire guest runtime build lock: {e:#}"),
        })?;
    if layout.is_complete() {
        return Ok(layout.binaries());
    }
    let spec = GuestAgentBuildSpec::new(
        workspace_root.to_path_buf(),
        arch,
        guest_build_target_dir(cache_root, workspace_root),
    );
    let built = build_guest_binaries(&spec)?;
    install_into_cache(
        GuestRuntimeBinaryPaths {
            agent: &built.0,
            netinit: &built.1,
            egress_client: &built.2,
            entrypoint_runner: &built.3,
        },
        cache_root,
        cache_key,
        arch,
    )
}

/// Copy already-built guest binaries into the cache and return the
/// cached paths. Lets a caller that already has the binaries (e.g. a
/// prior `cargo zigbuild`) pre-warm the cache without rebuilding.
pub fn install_into_cache(
    src: GuestRuntimeBinaryPaths<'_>,
    cache_root: &Path,
    cache_key: &str,
    arch: GuestArch,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, cache_key, arch);
    std::fs::create_dir_all(&layout.dir)?;
    install_one(src.agent, &layout.agent)?;
    install_one(src.netinit, &layout.netinit)?;
    install_one(src.egress_client, &layout.egress_client)?;
    install_one(src.entrypoint_runner, &layout.entrypoint_runner)?;

    // Validate on the way into the cache — once per build, rather than on every
    // invocation. A wrong-architecture or dynamically linked artifact cached
    // here would otherwise be injected into a rootfs that has no dynamic
    // loader, and surface as a guest that boots to a silent PID 1.
    let binaries = layout.binaries();
    for (name, path) in binaries.artifacts() {
        let bytes = std::fs::read(path)?;
        crate::guest_elf::validate_static_guest_elf(&bytes, path, arch).map_err(|e| {
            GuestAgentBuildError::BuildFailed {
                reason: format!("{name}: {e}"),
            }
        })?;
    }
    Ok(binaries)
}

/// The cached guest binaries if a complete set is already present, else `None`.
/// Lets a caller check the cache without triggering a source-checkout build.
pub fn cached_guest_binaries(
    cache_root: &Path,
    cache_key: &str,
    arch: GuestArch,
) -> Option<MvmRuntimeBinaries> {
    let layout = GuestAgentLayout::under(cache_root, cache_key, arch);
    layout.is_complete().then(|| layout.binaries())
}

/// Whether resolving the guest runtime for `(cache_root, arch)` would trigger a
/// source-checkout cross-compile: a source workspace is detected and its
/// content-keyed cache is cold. Mirrors [`resolve_or_build_guest_binaries`]'s
/// build/no-build decision so a caller can announce the slow, output-silent
/// `cargo zigbuild` before it runs.
pub fn source_build_pending(cache_root: &Path, arch: GuestArch) -> bool {
    match detect_source_workspace() {
        Some(ws) => source_build_pending_for(cache_root, arch, &ws),
        None => false,
    }
}

fn source_build_pending_for(cache_root: &Path, arch: GuestArch, workspace_root: &Path) -> bool {
    match source_cache_key(workspace_root) {
        Ok(cache_key) => cached_guest_binaries(cache_root, &cache_key, arch).is_none(),
        Err(_) => false,
    }
}

/// Resolve the full runtime-overlay guest-binary set for `(version, arch)`,
/// building + caching it from `workspace_root` on a cache miss.
pub fn resolve_or_build_runtime_overlay_guest_binaries(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<RuntimeOverlayGuestBinaries, GuestAgentBuildError> {
    let fingerprint = runtime_overlay_source_checkout_fingerprint(workspace_root)?;
    let layout = RuntimeOverlayGuestLayout::under(cache_root, version, arch, &fingerprint);
    if layout.is_complete() {
        return Ok(layout.binaries());
    }
    let _build_lock = mvm_core::util::atomic_io::FileLock::acquire(&layout.dir.join("build"))
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("acquire runtime overlay guest build lock: {e:#}"),
        })?;
    if layout.is_complete() {
        return Ok(layout.binaries());
    }
    build_runtime_overlay_guest_binaries_into_cache(cache_root, &layout, workspace_root, arch)
}

pub fn runtime_overlay_source_checkout_fingerprint(
    workspace_root: &Path,
) -> Result<String, GuestAgentBuildError> {
    guest_source_fingerprint(workspace_root)
}

fn build_runtime_overlay_guest_binaries_into_cache(
    cache_root: &Path,
    layout: &RuntimeOverlayGuestLayout,
    workspace_root: &Path,
    arch: GuestArch,
) -> Result<RuntimeOverlayGuestBinaries, GuestAgentBuildError> {
    std::fs::create_dir_all(&layout.dir)?;
    let spec = GuestAgentBuildSpec::new(
        workspace_root.to_path_buf(),
        arch,
        guest_build_target_dir(cache_root, workspace_root),
    );
    let triple = spec.target_triple();
    let prod_args = vec![
        "zigbuild".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        triple.to_string(),
        "-p".to_string(),
        "mvm-agentd".to_string(),
        "--bin".to_string(),
        "mvm-guest-agent".to_string(),
        "--bin".to_string(),
        "mvm-guest-netinit".to_string(),
        "--bin".to_string(),
        "mvm-seccomp-apply".to_string(),
        "--bin".to_string(),
        "--bin".to_string(),
        "mvm-ping".to_string(),
        "--bin".to_string(),
        "mvm-runner".to_string(),
        "--bin".to_string(),
        "mvm-egress-client".to_string(),
        "--bin".to_string(),
        "mvm-addon-dns".to_string(),
        "--bin".to_string(),
        "mvm-exit-report".to_string(),
        "--bin".to_string(),
        "mvm-forward-proxy".to_string(),
        // mvm-egress-client + mvm-addon-dns are the async loopback helper
        // bins gated behind mvm-agentd's `addons` feature (see its
        // Cargo.toml) so the sealed agent's default build stays tokio-free.
        "--features".to_string(),
        "mvm-agentd/addons".to_string(),
    ];
    run_zigbuild(&spec, &prod_args)?;
    let output_dir = spec.output_dir();
    install_one(&output_dir.join("mvm-guest-agent"), &layout.agent)?;
    install_one(&output_dir.join("mvm-guest-netinit"), &layout.netinit)?;
    install_one(&output_dir.join("mvm-seccomp-apply"), &layout.seccomp_apply)?;
    install_one(&output_dir.join("mvm-ping"), &layout.ping)?;
    install_one(&output_dir.join("mvm-runner"), &layout.runner)?;
    install_one(&output_dir.join("mvm-egress-client"), &layout.egress_client)?;
    install_one(&output_dir.join("mvm-addon-dns"), &layout.addon_dns)?;
    install_one(&output_dir.join("mvm-exit-report"), &layout.exit_report)?;
    install_one(&output_dir.join("mvm-forward-proxy"), &layout.forward_proxy)?;

    Ok(layout.binaries())
}

fn run_zigbuild(spec: &GuestAgentBuildSpec, args: &[String]) -> Result<(), GuestAgentBuildError> {
    let started = std::time::Instant::now();
    let _zigbuild_lock = acquire_guest_zigbuild_lock(&spec.target_dir)?;
    let (cargo, rustc) = zigbuild_tools(spec)?;
    tracing::info!(
        ?args,
        workspace = %spec.workspace_root.display(),
        "cross-compiling guest runtime via cargo zigbuild (first build for this source checkout)"
    );
    let mut cmd = std::process::Command::new(&cargo);
    cmd.args(zigbuild_args_for_output(args))
        .current_dir(&spec.workspace_root);
    apply_zigbuild_env(&mut cmd, spec, rustc.as_deref())?;
    // Cargo inherits stdio. Quiet mode suppresses routine progress while still
    // surfacing compiler errors; the CLI's verbose mode preserves raw output.
    let status = cmd
        .status()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("spawn `{}`: {e}", cargo.display()),
        })?;
    if status.success() {
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "guest runtime build complete"
        );
        return Ok(());
    }
    Err(GuestAgentBuildError::BuildFailed {
        reason: format!(
            "`cargo zigbuild` args {args:?} exited {:?} (see the streamed build output above)",
            status.code()
        ),
    })
}

#[cfg(test)]
fn write_exec(dst: &Path, bytes: &[u8]) -> Result<(), GuestAgentBuildError> {
    let _ = std::fs::remove_file(dst);
    std::fs::write(dst, bytes)?;
    set_exec(dst)
}

fn install_one(src: &Path, dst: &Path) -> Result<(), GuestAgentBuildError> {
    if !src.is_file() {
        return Err(GuestAgentBuildError::OutputMissing(src.to_path_buf()));
    }
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)?;
    set_exec(dst)?;
    Ok(())
}

/// The four built guest binary paths, in the order `agent, netinit,
/// egress_client, entrypoint_runner`.
type BuiltGuestBinaries = (PathBuf, PathBuf, PathBuf, PathBuf);

/// Run `cargo zigbuild` for the spec, returning the built binary paths.
pub fn build_guest_binaries(
    spec: &GuestAgentBuildSpec,
) -> Result<BuiltGuestBinaries, GuestAgentBuildError> {
    // Reaching here means a guest cross-compile is about to run. A launch
    // measurement that hides a multi-minute build behind a "prepared" label is
    // worthless, so it is recorded at the one site that starts one.
    mvm_core::launch_trace::record_image_build();
    let started = std::time::Instant::now();
    let _zigbuild_lock = acquire_guest_zigbuild_lock(&spec.target_dir)?;
    let argv = spec.argv();
    let (cargo, rustc) = zigbuild_tools(spec)?;
    tracing::info!(
        bins = ?&argv[1..],
        workspace = %spec.workspace_root.display(),
        "cross-compiling guest runtime via cargo zigbuild (first build for this source checkout)"
    );
    let mut cmd = std::process::Command::new(&cargo);
    cmd.args(zigbuild_args_for_output(&argv[1..]))
        .current_dir(&spec.workspace_root);
    apply_zigbuild_env(&mut cmd, spec, rustc.as_deref())?;
    // Cargo inherits stdio. Quiet mode suppresses routine progress while still
    // surfacing compiler errors; the CLI's verbose mode preserves raw output.
    let status = cmd
        .status()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("spawn `{}`: {e}", cargo.display()),
        })?;
    if !status.success() {
        return Err(GuestAgentBuildError::BuildFailed {
            reason: format!(
                "`cargo zigbuild` exited {:?} (see the streamed build output above)",
                status.code()
            ),
        });
    }
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        "guest runtime build complete"
    );
    let dir = spec.output_dir();
    let agent = dir.join("mvm-guest-agent");
    let netinit = dir.join("mvm-guest-netinit");
    let egress_client = dir.join("mvm-egress-client");
    let entrypoint_runner = dir.join("mvm-oci-entrypoint");
    for p in [&agent, &netinit, &egress_client, &entrypoint_runner] {
        if !p.is_file() {
            return Err(GuestAgentBuildError::OutputMissing(p.clone()));
        }
    }
    Ok((agent, netinit, egress_client, entrypoint_runner))
}

fn zigbuild_args_for_output(args: &[String]) -> Vec<String> {
    if std::env::var_os(GUEST_BUILD_VERBOSE_ENV).is_some() || args.is_empty() {
        return args.to_vec();
    }
    let mut quiet = Vec::with_capacity(args.len() + 1);
    quiet.push(args[0].clone());
    quiet.push("--quiet".to_string());
    quiet.extend_from_slice(&args[1..]);
    quiet
}

fn apply_zigbuild_env(
    cmd: &mut std::process::Command,
    spec: &GuestAgentBuildSpec,
    rustc: Option<&Path>,
) -> Result<(), GuestAgentBuildError> {
    if let Some(rustc) = rustc {
        cmd.env("RUSTC", rustc);
    }
    cmd.env("CARGO_TARGET_DIR", &spec.target_dir)
        // These builds are reproducible guest artifacts, not part of the
        // contributor's outer compilation session. Do not inherit a nightly
        // frontend flag or host-global compiler wrapper.
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");

    // Keep cargo-zigbuild's own cache under the mvm cache root instead of
    // whatever platform-global default the host picks (for example
    // `~/Library/Caches/cargo-zigbuild` on macOS). This keeps the direct guest
    // binary path aligned with `MVM_HOME` / `~/.mvm/cache` and avoids
    // depending on unrelated host cache permissions.
    let zigbuild_cache_dir = zigbuild_cache_dir(&spec.target_dir);
    let zig_global_cache_dir = zig_global_cache_dir(&spec.target_dir);
    std::fs::create_dir_all(&zigbuild_cache_dir)?;
    std::fs::create_dir_all(&zig_global_cache_dir)?;
    cmd.env("CARGO_ZIGBUILD_CACHE_DIR", zigbuild_cache_dir);
    cmd.env("ZIG_GLOBAL_CACHE_DIR", zig_global_cache_dir);
    Ok(())
}

fn zigbuild_cache_dir(target_dir: &Path) -> PathBuf {
    scoped_tool_cache_dir("cargo-zigbuild", target_dir)
}

fn zig_global_cache_dir(target_dir: &Path) -> PathBuf {
    scoped_tool_cache_dir("zig", target_dir)
}

fn scoped_tool_cache_dir(tool: &str, target_dir: &Path) -> PathBuf {
    target_dir
        .parent()
        .unwrap_or(target_dir)
        .join("tool-cache")
        .join(tool)
}

fn acquire_guest_zigbuild_lock(
    target_dir: &Path,
) -> Result<mvm_core::util::atomic_io::FileLock, GuestAgentBuildError> {
    mvm_core::util::atomic_io::FileLock::acquire(&scoped_tool_cache_dir(
        "zigbuild-lock",
        target_dir,
    ))
    .map_err(|e| GuestAgentBuildError::BuildFailed {
        reason: format!("acquire guest zigbuild lock: {e:#}"),
    })
}

fn hash_dir_recursive(
    hasher: &mut Sha256,
    prefix: &str,
    dir: &Path,
) -> Result<(), GuestAgentBuildError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let rel = format!("{prefix}/{name}");
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            hash_dir_recursive(hasher, &rel, &path)?;
        } else if file_type.is_file() {
            hash_file(hasher, &rel, &path)?;
        }
    }
    Ok(())
}

fn hash_file(hasher: &mut Sha256, rel: &str, path: &Path) -> Result<(), GuestAgentBuildError> {
    let bytes = std::fs::read(path)?;
    hasher.update(rel.as_bytes());
    hasher.update(b"\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    hasher.update(b"\0");
    Ok(())
}

fn zigbuild_tools(
    spec: &GuestAgentBuildSpec,
) -> Result<(PathBuf, Option<PathBuf>), GuestAgentBuildError> {
    if let Some(cargo) = &spec.cargo {
        return Ok((cargo.clone(), None));
    }
    let toolchain = pinned_rust_toolchain(&spec.workspace_root)?;
    let cargo = rustup_tool(&toolchain, "cargo")?;
    let rustc = rustup_tool(&toolchain, "rustc")?;
    Ok((cargo, Some(rustc)))
}

fn pinned_rust_toolchain(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    let manifest = workspace_root.join("Cargo.toml");
    let contents = std::fs::read_to_string(&manifest)?;
    let value = contents
        .parse::<toml::Value>()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("parse {}: {e}", manifest.display()),
        })?;
    value
        .get("workspace")
        .and_then(|item| item.get("metadata"))
        .and_then(|item| item.get("mvm"))
        .and_then(|item| item.get("toolchain"))
        .and_then(|item| item.get("rust"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| GuestAgentBuildError::BuildFailed {
            reason: format!(
                "{} is missing workspace.metadata.mvm.toolchain.rust",
                manifest.display()
            ),
        })
}

fn rustup_tool(toolchain: &str, tool: &str) -> Result<PathBuf, GuestAgentBuildError> {
    let output = std::process::Command::new("rustup")
        .args(["which", tool, "--toolchain", toolchain])
        .output()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("resolve {tool} from Rust {toolchain}: {e}"),
        })?;
    if !output.status.success() {
        return Err(GuestAgentBuildError::BuildFailed {
            reason: format!(
                "Rust {toolchain} is required for guest binaries; install it with \
                 `rustup toolchain install {toolchain} --profile minimal` and add the required \
                 musl target"
            ),
        });
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("rustup returned a non-UTF-8 {tool} path: {e}"),
        })?
        .trim()
        .to_owned();
    if path.is_empty() {
        return Err(GuestAgentBuildError::BuildFailed {
            reason: format!("rustup returned an empty {tool} path for Rust {toolchain}"),
        });
    }
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
fn set_exec(path: &Path) -> Result<(), GuestAgentBuildError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_exec(_path: &Path) -> Result<(), GuestAgentBuildError> {
    Ok(())
}

/// A minimal static ELF64-LE fixture accepted by the production validator.
#[cfg(test)]
pub(crate) fn fake_static_elf(arch: GuestArch, tag: &[u8]) -> Vec<u8> {
    let machine: u16 = match arch {
        GuestArch::X86_64 => 0x3E,
        GuestArch::Aarch64 => 0xB7,
    };
    let mut bytes = vec![0u8; 64];
    bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes.extend_from_slice(tag);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn seed_complete_guest_cache(
        cache_root: &Path,
        cache_key: &str,
        arch: GuestArch,
        bytes: &[u8],
    ) {
        let layout = GuestAgentLayout::under(cache_root, cache_key, arch);
        std::fs::create_dir_all(&layout.dir).expect("create guest cache dir");
        for path in [
            &layout.agent,
            &layout.netinit,
            &layout.egress_client,
            &layout.entrypoint_runner,
        ] {
            write_exec(path, bytes).expect("seed guest cache binary");
        }
    }

    #[test]
    fn source_build_pending_flips_when_the_source_keyed_cache_is_seeded() {
        // A deterministic workspace root: this crate's manifest dir has the
        // workspace root as an ancestor, independent of the test's CWD.
        let ws = source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("workspace root resolves from the crate manifest dir");
        let cache = tempfile::tempdir().expect("tempdir");
        let arch = GuestArch::Aarch64;

        // Cold cache: resolving the guest runtime would cross-compile.
        assert!(source_build_pending_for(cache.path(), arch, &ws));

        // Seed the exact content-keyed slot the resolver would fill.
        let key = source_cache_key(&ws).expect("source cache key");
        seed_complete_guest_cache(cache.path(), &key, arch, b"x");

        // Warm cache: no cross-compile pending.
        assert!(!source_build_pending_for(cache.path(), arch, &ws));
    }

    /// The cache must not accept an artifact the guest could not execute.
    /// Without this, a wrong-architecture cross-compile is cached under a
    /// key that looks valid and surfaces as a guest that never reaches the
    /// agent.
    #[test]
    fn install_refuses_an_artifact_the_guest_could_not_run() {
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let arch = GuestArch::Aarch64;

        let paths: Vec<std::path::PathBuf> = [
            "mvm-guest-agent",
            "mvm-guest-netinit",
            "mvm-egress-client",
            "mvm-oci-entrypoint",
        ]
        .iter()
        .map(|n| {
            let p = source.path().join(n);
            std::fs::write(&p, fake_static_elf(arch, n.as_bytes())).unwrap();
            p
        })
        .collect();

        let install = |cache_root: &Path| {
            install_into_cache(
                GuestRuntimeBinaryPaths {
                    agent: &paths[0],
                    netinit: &paths[1],
                    egress_client: &paths[2],
                    entrypoint_runner: &paths[3],
                },
                cache_root,
                "test-key",
                arch,
            )
        };

        install(cache.path()).expect("a valid static set must install");

        // Now make one artifact the wrong architecture.
        std::fs::write(
            &paths[1],
            fake_static_elf(GuestArch::X86_64, b"mvm-guest-agent"),
        )
        .unwrap();
        let cache2 = tempfile::tempdir().unwrap();
        let err = install(cache2.path()).expect_err("a wrong-arch artifact must be refused");
        assert!(
            err.to_string().contains("agent"),
            "the refusal should name the artifact: {err}"
        );

        // And a plain script is not an ELF at all.
        std::fs::write(&paths[1], b"#!/bin/sh\necho hi\n").unwrap();
        let cache3 = tempfile::tempdir().unwrap();
        assert!(
            install(cache3.path()).is_err(),
            "a non-ELF artifact must be refused"
        );
    }

    #[test]
    fn install_paths_then_cached_round_trips() {
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let arch = GuestArch::Aarch64;
        let version = env!("CARGO_PKG_VERSION");

        // Nothing cached yet.
        assert!(cached_guest_binaries(cache.path(), version, arch).is_none());

        let agent = source.path().join("mvm-guest-agent");
        let netinit = source.path().join("mvm-guest-netinit");
        let egress_client = source.path().join("mvm-egress-client");
        let entrypoint_runner = source.path().join("mvm-oci-entrypoint");
        for (path, tag) in [
            (&agent, b"agent".as_slice()),
            (&netinit, b"netinit".as_slice()),
            (&egress_client, b"egress-client".as_slice()),
            (&entrypoint_runner, b"entrypoint-runner".as_slice()),
        ] {
            std::fs::write(path, fake_static_elf(arch, tag)).unwrap();
        }

        // Install artifact paths, then the cache lookup finds them.
        let bins = install_into_cache(
            GuestRuntimeBinaryPaths {
                agent: &agent,
                netinit: &netinit,
                egress_client: &egress_client,
                entrypoint_runner: &entrypoint_runner,
            },
            cache.path(),
            version,
            arch,
        )
        .expect("install artifact paths");
        assert!(bins.agent.is_file());
        assert!(bins.netinit.is_file());
        assert!(bins.egress_client.is_file());
        let layout = GuestAgentLayout::under(cache.path(), version, arch);
        assert!(layout.entrypoint_runner.is_file());
        assert_eq!(
            std::fs::read(&bins.agent).unwrap(),
            fake_static_elf(arch, b"agent")
        );
        assert_eq!(
            std::fs::read(&bins.egress_client).unwrap(),
            fake_static_elf(arch, b"egress-client")
        );
        assert_eq!(
            std::fs::read(&layout.entrypoint_runner).unwrap(),
            fake_static_elf(arch, b"entrypoint-runner")
        );

        let cached = cached_guest_binaries(cache.path(), version, arch).expect("now cached");
        assert_eq!(cached.agent, bins.agent);
        // Executable bit is set on the installed binary.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cached.agent)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "installed agent must be executable");
        }
    }

    #[test]
    fn musl_triple_per_arch() {
        assert_eq!(
            musl_target_triple(GuestArch::Aarch64),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            musl_target_triple(GuestArch::X86_64),
            "x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn layout_is_versioned_and_arched() {
        let version = env!("CARGO_PKG_VERSION");
        let l = GuestAgentLayout::under(Path::new("/c"), version, GuestArch::Aarch64);
        let expected_dir = PathBuf::from("/c")
            .join("guest-agent")
            .join(version)
            .join("aarch64");
        assert_eq!(l.dir, expected_dir);
        assert_eq!(l.agent, l.dir.join("mvm-guest-agent"));
        assert_eq!(l.netinit, l.dir.join("mvm-guest-netinit"));
        assert_eq!(l.egress_client, l.dir.join("mvm-egress-client"));
        assert_eq!(l.entrypoint_runner, l.dir.join("mvm-oci-entrypoint"));
    }

    #[test]
    fn build_argv_targets_musl_and_guest_bins() {
        let spec = GuestAgentBuildSpec::new(
            PathBuf::from("/ws"),
            GuestArch::Aarch64,
            PathBuf::from("/cache/guest-agent-build/target"),
        );
        let argv = spec.argv();
        assert_eq!(argv[0], "cargo");
        assert_eq!(argv[1], "zigbuild");
        assert!(argv.contains(&"aarch64-unknown-linux-musl".to_string()));
        let binaries: Vec<&str> = argv
            .windows(2)
            .filter_map(|pair| (pair[0] == "--bin").then_some(pair[1].as_str()))
            .collect();
        assert_eq!(
            binaries,
            vec![
                "mvm-guest-agent",
                "mvm-guest-netinit",
                "mvm-oci-entrypoint",
                "mvm-egress-client",
            ]
        );
        assert!(argv.contains(&"mvm-agentd".to_string()));
    }

    #[test]
    fn output_dir_is_cache_scoped_never_the_source_tree() {
        let mut env = TestEnv::new();
        env.set("CARGO_TARGET_DIR", "/tmp/ambient-should-be-ignored");
        let spec = GuestAgentBuildSpec::new(
            PathBuf::from("/ws"),
            GuestArch::Aarch64,
            PathBuf::from("/cache/guest-agent-build/target"),
        );
        assert_eq!(
            spec.output_dir(),
            PathBuf::from("/cache/guest-agent-build/target/aarch64-unknown-linux-musl/release")
        );
        assert!(!spec.output_dir().starts_with("/ws/target"));
    }

    #[test]
    fn guest_build_target_dir_reuses_dependencies_across_edits_in_one_checkout() {
        let first = guest_build_target_dir(Path::new("/c"), Path::new("/ws"));
        assert!(first.starts_with("/c/guest-agent-build/targets"));
        assert_eq!(
            first,
            guest_build_target_dir(Path::new("/c"), Path::new("/ws")),
            "source edits in one checkout must reuse Cargo dependency output"
        );
        assert_ne!(
            first,
            guest_build_target_dir(Path::new("/c"), Path::new("/other-ws")),
            "different worktrees must keep Cargo outputs isolated"
        );
    }

    #[test]
    fn quiet_is_default_and_verbose_preserves_raw_cargo_output() {
        let mut env = TestEnv::new();
        env.remove(GUEST_BUILD_VERBOSE_ENV);
        let args = vec!["zigbuild".to_string(), "--release".to_string()];
        assert_eq!(
            zigbuild_args_for_output(&args),
            ["zigbuild", "--quiet", "--release"]
        );

        env.set(GUEST_BUILD_VERBOSE_ENV, "1");
        assert_eq!(zigbuild_args_for_output(&args), args);
    }

    #[test]
    fn zigbuild_cache_dir_lives_under_guest_build_root() {
        let target_dir = Path::new("/tmp/mvm-cache-root/guest-agent-build/target");
        assert_eq!(
            zigbuild_cache_dir(target_dir),
            scoped_tool_cache_dir("cargo-zigbuild", target_dir)
        );
        assert_eq!(
            zig_global_cache_dir(target_dir),
            scoped_tool_cache_dir("zig", target_dir)
        );
    }

    #[test]
    fn apply_zigbuild_env_exports_explicit_cache_dir() {
        let spec = GuestAgentBuildSpec::new(
            PathBuf::from("/ws"),
            GuestArch::Aarch64,
            PathBuf::from("/tmp/mvm-cache-root/guest-agent-build/target"),
        );
        let mut cmd = std::process::Command::new("cargo");
        cmd.env("RUSTFLAGS", "-Zthreads=8")
            .env("CARGO_ENCODED_RUSTFLAGS", "-Zthreads=8")
            .env("RUSTC_WRAPPER", "sccache")
            .env("RUSTUP_TOOLCHAIN", "nightly");
        apply_zigbuild_env(&mut cmd, &spec, Some(Path::new("/pinned/rustc")))
            .expect("configure zigbuild env");

        let envs: std::collections::HashMap<_, _> = cmd
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string)))
            .collect();
        let expected_zigbuild_cache = scoped_tool_cache_dir(
            "cargo-zigbuild",
            Path::new("/tmp/mvm-cache-root/guest-agent-build/target"),
        );
        let expected_zig_cache = scoped_tool_cache_dir(
            "zig",
            Path::new("/tmp/mvm-cache-root/guest-agent-build/target"),
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("CARGO_ZIGBUILD_CACHE_DIR")),
            Some(&Some(expected_zigbuild_cache.into_os_string()))
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("ZIG_GLOBAL_CACHE_DIR")),
            Some(&Some(expected_zig_cache.into_os_string()))
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("CARGO_TARGET_DIR")),
            Some(&Some(std::ffi::OsString::from(
                "/tmp/mvm-cache-root/guest-agent-build/target"
            )))
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("RUSTC")),
            Some(&Some(std::ffi::OsString::from("/pinned/rustc")))
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("RUSTC_WRAPPER")),
            Some(&Some(std::ffi::OsString::new()))
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("RUSTC_WORKSPACE_WRAPPER")),
            Some(&Some(std::ffi::OsString::new()))
        );
        for removed in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
            assert_eq!(
                envs.get(std::ffi::OsStr::new(removed)),
                Some(&None),
                "{removed} must not leak into the pinned guest build"
            );
        }
    }

    #[test]
    fn reads_the_guest_rust_pin_from_workspace_metadata() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        std::fs::write(
            workspace.path().join("Cargo.toml"),
            r#"
[workspace.metadata.mvm.toolchain]
rust = "1.91.1"
"#,
        )
        .expect("write workspace manifest");

        assert_eq!(
            pinned_rust_toolchain(workspace.path()).expect("read embedded Rust pin"),
            "1.91.1"
        );
    }

    #[test]
    fn missing_guest_rust_pin_is_rejected() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        std::fs::write(workspace.path().join("Cargo.toml"), "[workspace]\n")
            .expect("write workspace manifest");

        let error = pinned_rust_toolchain(workspace.path())
            .expect_err("workspace without a Rust pin must fail");
        assert!(error.to_string().contains("toolchain.rust"));
    }

    #[test]
    fn install_and_resolve_round_trips_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let agent_src = tmp.path().join("a");
        let netinit_src = tmp.path().join("n");
        let egress_client_src = tmp.path().join("e");
        let entrypoint_runner_src = tmp.path().join("r");
        // Must match the arch this test installs under, not the build host:
        // `install_into_cache` validates each artifact against the arch it is
        // cached for. Using `GuestArch::host()` here passed on an arm64 macOS
        // developer machine and failed on x86_64 Linux CI, where the fixtures
        // were x86_64 but the install arch is aarch64.
        let elf_arch = GuestArch::Aarch64;
        for (path, tag) in [
            (&agent_src, b"AGENT".as_slice()),
            (&netinit_src, b"NETINIT".as_slice()),
            (&egress_client_src, b"EGRESS".as_slice()),
            (&entrypoint_runner_src, b"RUNNER".as_slice()),
        ] {
            std::fs::write(path, fake_static_elf(elf_arch, tag)).unwrap();
        }
        let cache = tmp.path().join("cache");

        let installed = install_into_cache(
            GuestRuntimeBinaryPaths {
                agent: &agent_src,
                netinit: &netinit_src,
                egress_client: &egress_client_src,
                entrypoint_runner: &entrypoint_runner_src,
            },
            &cache,
            version,
            GuestArch::Aarch64,
        )
        .expect("install");
        assert_eq!(
            std::fs::read(&installed.agent).unwrap(),
            fake_static_elf(elf_arch, b"AGENT")
        );
        assert_eq!(
            std::fs::read(&installed.egress_client).unwrap(),
            fake_static_elf(elf_arch, b"EGRESS")
        );
        let layout = GuestAgentLayout::under(&cache, version, GuestArch::Aarch64);
        assert_eq!(
            std::fs::read(&layout.entrypoint_runner).unwrap(),
            fake_static_elf(elf_arch, b"RUNNER")
        );

        // A subsequent resolve hits the cache and never builds (the
        // workspace path is bogus; if it built it would fail).
        let resolved = resolve_or_build_guest_binaries(
            &cache,
            version,
            GuestArch::Aarch64,
            Path::new("/nonexistent-workspace"),
        )
        .expect("resolve from cache");
        assert_eq!(resolved, installed);
    }

    #[test]
    fn install_rejects_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let err = install_into_cache(
            GuestRuntimeBinaryPaths {
                agent: &tmp.path().join("missing-agent"),
                netinit: &tmp.path().join("missing-netinit"),
                egress_client: &tmp.path().join("missing-egress-client"),
                entrypoint_runner: &tmp.path().join("missing-entrypoint-runner"),
            },
            &tmp.path().join("cache"),
            version,
            GuestArch::Aarch64,
        )
        .unwrap_err();
        assert!(matches!(err, GuestAgentBuildError::OutputMissing(_)));
    }

    /// Build a minimal fake source checkout under `root`: a workspace `Cargo.toml`
    /// plus a `crates/mvm-agentd/{Cargo.toml,src/main.rs}` carrying `agent_body`.
    fn make_fake_checkout(root: &Path, agent_body: &str) {
        std::fs::create_dir_all(root.join("crates/mvm-contract/src")).unwrap();
        std::fs::create_dir_all(root.join("crates/mvm-core/src")).unwrap();
        std::fs::create_dir_all(root.join("crates/mvm-agentd/src")).unwrap();
        std::fs::create_dir_all(root.join("crates/mvm-build/src")).unwrap();
        std::fs::write(root.join("Cargo.lock"), b"version = 4\n").unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\n").unwrap();
        std::fs::write(root.join("crates/mvm-contract/Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(
            root.join("crates/mvm-contract/src/lib.rs"),
            b"pub fn wire() {}\n",
        )
        .unwrap();
        std::fs::write(root.join("crates/mvm-core/Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(
            root.join("crates/mvm-core/src/lib.rs"),
            b"pub fn core() {}\n",
        )
        .unwrap();
        std::fs::write(root.join("crates/mvm-agentd/Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(root.join("crates/mvm-agentd/src/main.rs"), agent_body).unwrap();
        std::fs::write(
            root.join("crates/mvm-build/src/guest_agent_build.rs"),
            b"pub fn recipe() {}\n",
        )
        .unwrap();
    }

    #[test]
    fn is_source_workspace_root_requires_guest_crate_and_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        // Empty dir is not a workspace root.
        assert!(!is_source_workspace_root(tmp.path()));
        make_fake_checkout(tmp.path(), "fn main() {}");
        assert!(is_source_workspace_root(tmp.path()));
    }

    #[test]
    fn source_workspace_from_walks_up_to_root() {
        let tmp = tempfile::tempdir().unwrap();
        make_fake_checkout(tmp.path(), "fn main() {}");
        // Canonicalize: tempdir on macOS is under a `/var → /private/var` symlink.
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        // From a nested subdir the walk finds the root.
        let nested = root.join("crates/mvm-agentd/src");
        assert_eq!(source_workspace_from(&nested), Some(root.clone()));
        // From the root itself, the root.
        assert_eq!(source_workspace_from(&root), Some(root));
    }

    #[test]
    fn source_workspace_from_none_for_non_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(source_workspace_from(tmp.path()), None);
    }

    #[test]
    fn executable_checkout_wins_over_an_unrelated_current_checkout() {
        let executable_checkout = tempfile::tempdir().unwrap();
        let current_checkout = tempfile::tempdir().unwrap();
        make_fake_checkout(executable_checkout.path(), "fn main() { /* executable */ }");
        make_fake_checkout(current_checkout.path(), "fn main() { /* current */ }");

        let executable = executable_checkout.path().join("target/debug/mvmctl");
        let current_dir = current_checkout.path().join("crates/mvm-agentd");
        let compiled_manifest = executable_checkout.path().join("crates/mvm-build");

        assert_eq!(
            source_workspace_for(Some(&executable), Some(&current_dir), &compiled_manifest),
            Some(executable_checkout.path().to_path_buf()),
            "an explicitly invoked worktree binary must inject guest code from that worktree"
        );
    }

    #[test]
    fn release_channel_ignores_every_checkout_hint() {
        let executable_checkout = tempfile::tempdir().unwrap();
        let current_checkout = tempfile::tempdir().unwrap();
        make_fake_checkout(executable_checkout.path(), "fn main() { /* executable */ }");
        make_fake_checkout(current_checkout.path(), "fn main() { /* current */ }");

        let executable = executable_checkout.path().join("target/release/mvmctl");
        let current_dir = current_checkout.path().join("crates/mvm-agentd");
        let compiled_manifest = executable_checkout.path().join("crates/mvm-build");

        assert_eq!(
            source_workspace_for_channel(
                crate::artifact_acquisition::DistributionChannel::Release,
                Some(&executable),
                Some(&current_dir),
                &compiled_manifest,
            ),
            None,
            "an official binary must not compile merely because it runs inside a checkout"
        );
    }

    #[test]
    #[cfg(not(feature = "release-channel"))]
    fn detect_source_workspace_resolves_this_repo() {
        // Running under nextest, cwd is `crates/mvm-build`; the walk up finds the
        // real workspace root, and it carries the guest crate.
        let ws = detect_source_workspace().expect("this is a source checkout");
        assert!(ws.join("crates/mvm-agentd").is_dir());
        assert!(ws.join("Cargo.toml").is_file());
    }

    #[cfg(feature = "release-channel")]
    #[test]
    fn official_build_does_not_detect_the_checkout_it_was_compiled_in() {
        assert_eq!(detect_source_workspace(), None);
        assert!(!source_build_pending(
            Path::new("/tmp/official-release-empty-cache"),
            GuestArch::host(),
        ));
    }

    #[test]
    fn fingerprint_changes_with_guest_source_and_is_stable() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let c = tempfile::tempdir().unwrap();
        make_fake_checkout(a.path(), "fn main() { println!(\"v1\"); }");
        make_fake_checkout(b.path(), "fn main() { println!(\"v2\"); }");
        make_fake_checkout(c.path(), "fn main() { println!(\"v1\"); }");

        let fa = guest_source_fingerprint(a.path()).unwrap();
        let fb = guest_source_fingerprint(b.path()).unwrap();
        let fc = guest_source_fingerprint(c.path()).unwrap();
        // A changed guest source yields a different fingerprint.
        assert_ne!(fa, fb, "source edit must change the fingerprint");
        // Identical source yields an identical fingerprint (a real cache hit).
        assert_eq!(fa, fc, "identical source must fingerprint identically");
        // The digest is lowercase hex.
        assert_eq!(fa.len(), 64);
        assert!(fa.bytes().all(|x| x.is_ascii_hexdigit()));
    }

    /// Six call sites on one `machine run` asked for this fingerprint, each
    /// walking 416 files. The memo makes the second and later asks free — and
    /// its cost is staleness within the process, asserted here rather than left
    /// for someone to discover.
    #[test]
    fn the_fingerprint_is_computed_once_per_workspace_per_process() {
        let dir = tempfile::tempdir().unwrap();
        make_fake_checkout(dir.path(), "fn main() { println!(\"v1\"); }");

        let first = guest_source_fingerprint(dir.path()).unwrap();

        // Edit a declared input. The uncached walk must see it — otherwise this
        // test would pass with a mutation that never happened.
        std::fs::write(
            dir.path().join("crates/mvm-agentd/src/main.rs"),
            "fn main() { println!(\"v2\"); }",
        )
        .unwrap();
        assert_ne!(
            compute_guest_source_fingerprint(dir.path()).unwrap(),
            first,
            "the uncached walk must see the edit, or this test proves nothing"
        );

        // The memoized entry is what every later caller in this process gets.
        assert_eq!(
            guest_source_fingerprint(dir.path()).unwrap(),
            first,
            "a second ask in the same process must not re-walk the tree"
        );
    }

    #[test]
    fn fingerprint_fails_closed_when_a_declared_input_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        make_fake_checkout(tmp.path(), "fn main() {}");
        std::fs::remove_file(tmp.path().join("Cargo.lock")).unwrap();

        assert!(matches!(
            guest_source_fingerprint(tmp.path()),
            Err(GuestAgentBuildError::OutputMissing(path))
                if path == tmp.path().join("Cargo.lock")
        ));
    }

    #[test]
    fn source_cache_key_is_src_prefixed() {
        let tmp = tempfile::tempdir().unwrap();
        make_fake_checkout(tmp.path(), "fn main() {}");
        let key = source_cache_key(tmp.path()).unwrap();
        assert!(key.starts_with("src-"), "key must be src-prefixed: {key}");
    }

    #[test]
    fn source_build_never_hits_a_stale_version_arch_cache() {
        // Reproduces the bug: a prior shipped-binary run populated the version+arch
        // cache with a STALE agent. A contributor's source checkout keys the cache
        // on the guest source content instead, so its lookup targets a different
        // dir and can never be served that stale entry.
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::Aarch64;
        let version = env!("CARGO_PKG_VERSION");

        // Populate the version+arch compatibility cache.
        seed_complete_guest_cache(cache.path(), version, arch, b"STALE");
        assert!(
            cached_guest_binaries(cache.path(), version, arch).is_some(),
            "version+arch cache is populated (stale)"
        );

        // A source checkout resolves to a src-fingerprint key, whose cache dir is
        // empty — no stale hit.
        let ws = tempfile::tempdir().unwrap();
        make_fake_checkout(ws.path(), "fn main() { /* edited */ }");
        let key = source_cache_key(ws.path()).unwrap();
        assert_ne!(key, version, "source key must differ from the version key");
        assert!(
            cached_guest_binaries(cache.path(), &key, arch).is_none(),
            "source-keyed lookup must not return the stale version+arch entry"
        );

        // And an edit produces yet another distinct key — never colliding.
        let ws2 = tempfile::tempdir().unwrap();
        make_fake_checkout(ws2.path(), "fn main() { /* different edit */ }");
        let key2 = source_cache_key(ws2.path()).unwrap();
        assert_ne!(key, key2, "distinct guest sources yield distinct keys");
    }

    #[test]
    fn runtime_overlay_layout_is_versioned_and_arched() {
        let layout =
            RuntimeOverlayGuestLayout::under(Path::new("/c"), "1.2.3", GuestArch::X86_64, "abc123");
        assert_eq!(
            layout.dir,
            PathBuf::from("/c/runtime-overlay-bins/1.2.3/x86_64/abc123")
        );
        assert_eq!(layout.agent, layout.dir.join("agent"));
        assert_eq!(layout.netinit, layout.dir.join("netinit"));
        assert_eq!(layout.seccomp_apply, layout.dir.join("seccomp-apply"));
        assert_eq!(layout.runner, layout.dir.join("runner"));
        assert_eq!(layout.egress_client, layout.dir.join("egress-client"));
        assert_eq!(layout.addon_dns, layout.dir.join("addon-dns"));
        assert_eq!(layout.exit_report, layout.dir.join("exit-report"));
    }

    #[test]
    fn guest_build_fingerprint_changes_when_shared_guest_dependency_changes() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        make_fake_checkout(root, "pub fn guest() {}\n");
        std::fs::create_dir_all(root.join("crates/mvm-cli/src")).expect("mkdir mvm-cli src");
        std::fs::write(
            root.join("crates/mvm-cli/src/lib.rs"),
            "pub fn host_only() {}\n",
        )
        .expect("write host-only src");

        // Against the uncached walk: what this pins is that `mvm-contract/src`
        // is one of the fingerprint's declared inputs, not how often the answer
        // is recomputed. The public entry memoizes per process, so asking it
        // twice about one path measures the memo instead of the input set.
        // `the_fingerprint_is_computed_once_per_workspace_per_process` covers
        // the memo itself.
        let before = compute_guest_source_fingerprint(root).expect("fingerprint before");
        std::fs::write(
            root.join("crates/mvm-contract/src/lib.rs"),
            "pub fn wire() { println!(\"changed\"); }\n",
        )
        .expect("rewrite mvm-contract src");
        let after = compute_guest_source_fingerprint(root).expect("fingerprint after");

        assert_ne!(before, after);
    }

    #[test]
    fn runtime_overlay_source_fingerprint_ignores_host_only_files() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        make_fake_checkout(root, "pub fn guest() {}\n");
        std::fs::create_dir_all(root.join("crates/mvm-cli/src")).expect("mkdir mvm-cli src");
        std::fs::write(
            root.join("crates/mvm-cli/src/lib.rs"),
            "pub fn host_only() {}\n",
        )
        .expect("write host-only src");

        let before = runtime_overlay_source_checkout_fingerprint(root).expect("fingerprint before");
        std::fs::write(
            root.join("crates/mvm-cli/src/lib.rs"),
            "pub fn host_only() { println!(\"host-only change\"); }\n",
        )
        .expect("rewrite host-only src");
        let after = runtime_overlay_source_checkout_fingerprint(root).expect("fingerprint after");

        assert_eq!(before, after);
    }
}
