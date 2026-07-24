//! Host-side source of the guest runtime binaries baked into an OCI rootfs
//! ([`crate::oci_runtime_inject`]).
//!
//! An mkGuest rootfs gets the agent from a nix build inside the builder
//! VM. An arbitrary OCI image has no nix build of its own, so for the
//! `run --image` path the host produces the binaries directly and bakes
//! them in. This module mirrors the existing host cross-compile pattern
//! (`crates/mvm-cli/build.rs` cross-compiles the host-vm bins with
//! `cargo-zigbuild` to a static musl target) and caches the result under
//! `~/.mvm/cache/guest-agent/<version>/<arch>/interactive/`.
//!
//! `cargo-zigbuild` is the single portable cross path: the agent pulls
//! `ring` (C), so a static musl build needs a musl C cross-compiler, and
//! zig supplies it without a system `<arch>-linux-musl-gcc`. The
//! source-checkout build ([`resolve_or_build_guest_binaries`]) is only
//! reachable with the workspace + zig; a **shipped mvmctl** embeds these
//! binaries at build time (`crates/mvm-cli/build.rs`) and installs the embedded
//! bytes via [`install_prebuilt_guest_binaries`]. The resolution order lives in
//! `run_image::inject_and_materialize`: embedded release bytes win for shipped
//! binaries, while source builds use an invoking-checkout content-keyed cache.

use mvm_core::arch::GuestArch;
use sha2::{Digest, Sha256};
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
    pub oci_init: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub egress_client: PathBuf,
    pub entrypoint_runner: PathBuf,
    pub verity_init: PathBuf,
}

/// Built guest runtime binary paths ready to install into the cache.
#[derive(Debug, Clone, Copy)]
pub struct GuestRuntimeBinaryPaths<'a> {
    pub oci_init: &'a Path,
    pub agent: &'a Path,
    pub netinit: &'a Path,
    pub egress_client: &'a Path,
    pub entrypoint_runner: &'a Path,
    pub verity_init: &'a Path,
}

/// Embedded guest runtime binary bytes ready to install into the cache.
#[derive(Debug, Clone, Copy)]
pub struct GuestRuntimeBinaryBytes<'a> {
    pub oci_init: &'a [u8],
    pub agent: &'a [u8],
    pub netinit: &'a [u8],
    pub egress_client: &'a [u8],
    pub entrypoint_runner: &'a [u8],
    pub verity_init: &'a [u8],
}

/// Cache segment keying the agent build variant. The `run --image` path needs
/// the interactive (exec-capable) agent, and this module always builds with it
/// (see [`GuestAgentBuildSpec`]); keying the cache by the variant means a stale,
/// same-version agent built *without* interactive (the old, segment-less layout)
/// is never reused for an exec-capable request — the cause of the
/// "guest agent built without interactive feature" exec failure on a cache hit.
const AGENT_VARIANT: &str = "interactive";

impl GuestAgentLayout {
    /// `cache_key` names the cache generation: the mvmctl `version` for an
    /// embedded/shipped build (content is fixed by the version), or a guest
    /// source fingerprint (`source_cache_key`) for a contributor checkout so a
    /// local edit lands in its own cache dir and never reuses a stale agent.
    pub fn under(cache_root: &Path, cache_key: &str, arch: GuestArch) -> Self {
        let dir = cache_root
            .join("guest-agent")
            .join(cache_key)
            .join(arch.to_string())
            .join(AGENT_VARIANT);
        Self {
            oci_init: dir.join("mvm-oci-init"),
            agent: dir.join("mvm-guest-agent"),
            netinit: dir.join("mvm-guest-netinit"),
            egress_client: dir.join("mvm-egress-client"),
            entrypoint_runner: dir.join("mvm-oci-entrypoint"),
            verity_init: dir.join("mvm-verity-init"),
            dir,
        }
    }

    fn is_complete(&self) -> bool {
        self.oci_init.is_file()
            && self.agent.is_file()
            && self.netinit.is_file()
            && self.egress_client.is_file()
            && self.entrypoint_runner.is_file()
            && self.verity_init.is_file()
    }

    fn binaries(&self) -> MvmRuntimeBinaries {
        MvmRuntimeBinaries {
            oci_init: self.oci_init.clone(),
            agent: self.agent.clone(),
            netinit: self.netinit.clone(),
            egress_client: self.egress_client.clone(),
            entrypoint_runner: self.entrypoint_runner.clone(),
            verity_init: self.verity_init.clone(),
        }
    }
}

/// Full guest-binary set that the read-only runtime overlay carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayGuestBinaries {
    pub agent: PathBuf,
    pub agent_interactive: PathBuf,
    pub netinit: PathBuf,
    pub seccomp_apply: PathBuf,
    pub verity_init: PathBuf,
    pub runner: PathBuf,
    pub egress_client: PathBuf,
    pub addon_dns: PathBuf,
    pub exit_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayGuestLayout {
    pub dir: PathBuf,
    pub agent: PathBuf,
    pub agent_interactive: PathBuf,
    pub netinit: PathBuf,
    pub seccomp_apply: PathBuf,
    pub verity_init: PathBuf,
    pub runner: PathBuf,
    pub egress_client: PathBuf,
    pub addon_dns: PathBuf,
    pub exit_report: PathBuf,
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
            agent_interactive: dir.join("agent-interactive"),
            netinit: dir.join("netinit"),
            seccomp_apply: dir.join("seccomp-apply"),
            verity_init: dir.join("verity-init"),
            runner: dir.join("runner"),
            egress_client: dir.join("egress-client"),
            addon_dns: dir.join("addon-dns"),
            exit_report: dir.join("exit-report"),
            dir,
        }
    }

    fn is_complete(&self) -> bool {
        self.agent.is_file()
            && self.agent_interactive.is_file()
            && self.netinit.is_file()
            && self.seccomp_apply.is_file()
            && self.verity_init.is_file()
            && self.runner.is_file()
            && self.egress_client.is_file()
            && self.addon_dns.is_file()
            && self.exit_report.is_file()
    }

    fn binaries(&self) -> RuntimeOverlayGuestBinaries {
        RuntimeOverlayGuestBinaries {
            agent: self.agent.clone(),
            agent_interactive: self.agent_interactive.clone(),
            netinit: self.netinit.clone(),
            seccomp_apply: self.seccomp_apply.clone(),
            verity_init: self.verity_init.clone(),
            runner: self.runner.clone(),
            egress_client: self.egress_client.clone(),
            addon_dns: self.addon_dns.clone(),
            exit_report: self.exit_report.clone(),
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

    /// `cargo zigbuild` argv. Builds the guest runtime bins with `interactive`
    /// (the `run --image` exec path uses the interactive-gated handler,
    /// matching `nix/packages/mvm-guest-agent.nix`) and `addons` (the
    /// async loopback helper bins — `mvm-egress-client` here — require it
    /// so the sealed agent's default build stays tokio-free).
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
            "mvm-oci-init".to_string(),
            "--bin".to_string(),
            "mvm-oci-entrypoint".to_string(),
            "--bin".to_string(),
            "mvm-verity-init".to_string(),
            "--bin".to_string(),
            "mvm-egress-client".to_string(),
            "--features".to_string(),
            "mvm-agentd/interactive".to_string(),
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

/// The cache-scoped cargo target dir for the guest cross-compile under
/// `cache_root`. Kept off the source tree so a contributor's `run --image`
/// guest build never writes into any checkout's `target/`.
pub fn guest_build_target_dir(cache_root: &Path) -> PathBuf {
    cache_root.join("guest-agent-build").join("target")
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

/// The mvm source workspace to cross-compile the guest binaries from, or `None`
/// for a shipped binary with no checkout (→ the caller uses the embedded bytes).
///
/// Resolution: the invoking process's `current_dir` first (so a contributor
/// running from any worktree/clone builds THAT tree's guest sources, not the
/// checkout mvmctl happened to be compiled in), walking up to the root; then the
/// compile-time `CARGO_MANIFEST_DIR` ancestor (preserves an in-place `cargo run`
/// whose cwd isn't the root); else `None`.
pub fn detect_source_workspace() -> Option<PathBuf> {
    if let Ok(cwd) = std::env::current_dir()
        && let Some(ws) = source_workspace_from(&cwd)
    {
        return Some(ws);
    }
    source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
}

/// Cache-key segment for a source-checkout guest build: a `src-` prefixed
/// fingerprint of the guest crate sources. A changed guest source ⇒ a changed
/// key ⇒ a fresh build, so a contributor's local edit is never served a stale
/// version+arch-cached agent. The `src-` prefix keeps it from ever colliding
/// with a version-keyed (shipped-binary) cache entry.
pub fn source_cache_key(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    Ok(format!("src-{}", guest_source_fingerprint(workspace_root)?))
}

/// A stable content fingerprint over the guest crate sources compiled into the
/// runtime binaries (`mvm-agentd`): each crate's
/// `Cargo.toml` plus every file under its `src/`. Hashes workspace-relative
/// paths and bytes in sorted order so the digest is deterministic.
pub fn guest_source_fingerprint(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    use sha2::{Digest, Sha256};

    let mut files: Vec<PathBuf> = Vec::new();
    let crate_dir = workspace_root.join("crates/mvm-agentd");
    let manifest = crate_dir.join("Cargo.toml");
    if manifest.is_file() {
        files.push(manifest);
    }
    collect_source_files(&crate_dir.join("src"), &mut files)?;
    files.sort();

    let mut h = Sha256::new();
    for f in &files {
        let rel = f.strip_prefix(workspace_root).unwrap_or(f);
        h.update(rel.to_string_lossy().as_bytes());
        h.update([0u8]);
        h.update(std::fs::read(f)?);
        h.update([0u8]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Collect every regular file under `dir` (recursively) into `out`. Skips a
/// `target` directory defensively; absent `dir` is a no-op.
fn collect_source_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), GuestAgentBuildError> {
    if !dir.exists() {
        return Ok(());
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            for entry in std::fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
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
        guest_build_target_dir(cache_root),
    );
    let built = build_guest_binaries(&spec)?;
    install_into_cache(
        GuestRuntimeBinaryPaths {
            oci_init: &built.0,
            agent: &built.1,
            netinit: &built.2,
            egress_client: &built.3,
            entrypoint_runner: &built.4,
            verity_init: &built.5,
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
    install_one(src.oci_init, &layout.oci_init)?;
    install_one(src.agent, &layout.agent)?;
    install_one(src.netinit, &layout.netinit)?;
    install_one(src.egress_client, &layout.egress_client)?;
    install_one(src.entrypoint_runner, &layout.entrypoint_runner)?;
    install_one(src.verity_init, &layout.verity_init)?;
    Ok(layout.binaries())
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
/// `cargo zigbuild` before it runs. A caller holding embedded guest binaries
/// installs those instead and must not consult this.
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
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-runtime-overlay-source-checkout-v1\0");
    for rel in [
        "Cargo.lock",
        "Cargo.toml",
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

/// Install guest binaries from in-memory bytes (embedded in the host binary at
/// build time) into the cache. The end-user path: a shipped mvmctl has no
/// source checkout to cross-compile from, so it writes the embedded bytes here.
pub fn install_prebuilt_guest_binaries(
    bytes: GuestRuntimeBinaryBytes<'_>,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, version, arch);
    std::fs::create_dir_all(&layout.dir)?;
    write_exec(&layout.oci_init, bytes.oci_init)?;
    write_exec(&layout.agent, bytes.agent)?;
    write_exec(&layout.netinit, bytes.netinit)?;
    write_exec(&layout.egress_client, bytes.egress_client)?;
    write_exec(&layout.entrypoint_runner, bytes.entrypoint_runner)?;
    write_exec(&layout.verity_init, bytes.verity_init)?;
    Ok(layout.binaries())
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
        guest_build_target_dir(cache_root),
    );
    let triple = spec.target_triple();
    let cargo = spec.cargo.clone().unwrap_or_else(|| "cargo".into());

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
        "mvm-verity-init".to_string(),
        "--bin".to_string(),
        "mvm-runner".to_string(),
        "--bin".to_string(),
        "mvm-egress-client".to_string(),
        "--bin".to_string(),
        "mvm-addon-dns".to_string(),
        "--bin".to_string(),
        "mvm-exit-report".to_string(),
        // mvm-egress-client + mvm-addon-dns are the async loopback helper
        // bins gated behind mvm-agentd's `addons` feature (see its
        // Cargo.toml) so the sealed agent's default build stays tokio-free.
        "--features".to_string(),
        "mvm-agentd/addons".to_string(),
    ];
    run_zigbuild(&spec, cargo.as_os_str(), &prod_args)?;
    let output_dir = spec.output_dir();
    install_one(&output_dir.join("mvm-guest-agent"), &layout.agent)?;
    install_one(&output_dir.join("mvm-guest-netinit"), &layout.netinit)?;
    install_one(&output_dir.join("mvm-seccomp-apply"), &layout.seccomp_apply)?;
    install_one(&output_dir.join("mvm-verity-init"), &layout.verity_init)?;
    install_one(&output_dir.join("mvm-runner"), &layout.runner)?;
    install_one(&output_dir.join("mvm-egress-client"), &layout.egress_client)?;
    install_one(&output_dir.join("mvm-addon-dns"), &layout.addon_dns)?;
    install_one(&output_dir.join("mvm-exit-report"), &layout.exit_report)?;

    let dev_agent_args = vec![
        "zigbuild".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        triple.to_string(),
        "-p".to_string(),
        "mvm-agentd".to_string(),
        "--bin".to_string(),
        "mvm-guest-agent".to_string(),
        "--features".to_string(),
        "mvm-agentd/interactive".to_string(),
    ];
    run_zigbuild(&spec, cargo.as_os_str(), &dev_agent_args)?;
    install_one(
        &output_dir.join("mvm-guest-agent"),
        &layout.agent_interactive,
    )?;

    Ok(layout.binaries())
}

fn run_zigbuild(
    spec: &GuestAgentBuildSpec,
    cargo: &std::ffi::OsStr,
    args: &[String],
) -> Result<(), GuestAgentBuildError> {
    let _zigbuild_lock = acquire_guest_zigbuild_lock(&spec.target_dir)?;
    tracing::info!(
        ?args,
        workspace = %spec.workspace_root.display(),
        "cross-compiling guest runtime via cargo zigbuild (first build for this source checkout)"
    );
    let mut cmd = std::process::Command::new(cargo);
    cmd.args(args).current_dir(&spec.workspace_root);
    apply_zigbuild_env(&mut cmd, spec)?;
    // Inherit stdio so cargo's own "Compiling …" progress streams to the user: a
    // multi-minute guest cross-compile must look alive, not like a silent hang.
    let status = cmd
        .status()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("spawn `{}`: {e}", PathBuf::from(cargo).display()),
        })?;
    if status.success() {
        return Ok(());
    }
    Err(GuestAgentBuildError::BuildFailed {
        reason: format!(
            "`cargo zigbuild` args {args:?} exited {:?} (see the streamed build output above)",
            status.code()
        ),
    })
}

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

/// The six built guest binary paths, in the order `oci_init, agent, netinit,
/// egress_client, entrypoint_runner, verity_init`.
type BuiltGuestBinaries = (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf);

/// Run `cargo zigbuild` for the spec, returning the built binary paths.
pub fn build_guest_binaries(
    spec: &GuestAgentBuildSpec,
) -> Result<BuiltGuestBinaries, GuestAgentBuildError> {
    let _zigbuild_lock = acquire_guest_zigbuild_lock(&spec.target_dir)?;
    let argv = spec.argv();
    tracing::info!(
        bins = ?&argv[1..],
        workspace = %spec.workspace_root.display(),
        "cross-compiling guest runtime via cargo zigbuild (first build for this source checkout)"
    );
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(&spec.workspace_root);
    apply_zigbuild_env(&mut cmd, spec)?;
    // Inherit stdio so cargo's own "Compiling …" progress streams to the user: a
    // multi-minute guest cross-compile must look alive, not like a silent hang.
    let status = cmd
        .status()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("spawn `{}`: {e}", argv[0]),
        })?;
    if !status.success() {
        return Err(GuestAgentBuildError::BuildFailed {
            reason: format!(
                "`cargo zigbuild` exited {:?} (see the streamed build output above)",
                status.code()
            ),
        });
    }
    let dir = spec.output_dir();
    let oci_init = dir.join("mvm-oci-init");
    let agent = dir.join("mvm-guest-agent");
    let netinit = dir.join("mvm-guest-netinit");
    let egress_client = dir.join("mvm-egress-client");
    let entrypoint_runner = dir.join("mvm-oci-entrypoint");
    let verity_init = dir.join("mvm-verity-init");
    for p in [
        &oci_init,
        &agent,
        &netinit,
        &egress_client,
        &entrypoint_runner,
        &verity_init,
    ] {
        if !p.is_file() {
            return Err(GuestAgentBuildError::OutputMissing(p.clone()));
        }
    }
    Ok((
        oci_init,
        agent,
        netinit,
        egress_client,
        entrypoint_runner,
        verity_init,
    ))
}

fn apply_zigbuild_env(
    cmd: &mut std::process::Command,
    spec: &GuestAgentBuildSpec,
) -> Result<(), GuestAgentBuildError> {
    // Pin RUSTC to the rustup toolchain when available — a Homebrew
    // `rustc` earlier on `$PATH` carries no cross-target std and fails
    // the musl build with E0463.
    if let Some(rustc) = rustup_rustc() {
        cmd.env("RUSTC", rustc);
    }
    cmd.env("CARGO_TARGET_DIR", &spec.target_dir);

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

/// `rustup which rustc` path, or `None` if rustup isn't installed.
fn rustup_rustc() -> Option<PathBuf> {
    let out = std::process::Command::new("rustup")
        .args(["which", "rustc"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

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
        install_prebuilt_guest_binaries(
            GuestRuntimeBinaryBytes {
                oci_init: b"x",
                agent: b"x",
                netinit: b"x",
                egress_client: b"x",
                entrypoint_runner: b"x",
                verity_init: b"x",
            },
            cache.path(),
            &key,
            arch,
        )
        .expect("seed the source-keyed guest cache");

        // Warm cache: no cross-compile pending.
        assert!(!source_build_pending_for(cache.path(), arch, &ws));
    }

    #[test]
    fn install_prebuilt_then_cached_round_trips() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::Aarch64;
        let version = env!("CARGO_PKG_VERSION");

        // Nothing cached yet.
        assert!(cached_guest_binaries(cache.path(), version, arch).is_none());

        // Install embedded-style bytes, then the cache lookup finds them.
        let bins = install_prebuilt_guest_binaries(
            GuestRuntimeBinaryBytes {
                oci_init: b"fake-oci-init-elf",
                agent: b"fake-agent-elf",
                netinit: b"fake-netinit-elf",
                egress_client: b"fake-egress-client-elf",
                entrypoint_runner: b"fake-entrypoint-runner-elf",
                verity_init: b"fake-verity-init-elf",
            },
            cache.path(),
            version,
            arch,
        )
        .expect("install prebuilt");
        assert!(bins.agent.is_file());
        assert!(bins.netinit.is_file());
        assert!(bins.egress_client.is_file());
        let layout = GuestAgentLayout::under(cache.path(), version, arch);
        assert!(layout.oci_init.is_file());
        assert!(layout.entrypoint_runner.is_file());
        assert_eq!(
            std::fs::read(&layout.oci_init).unwrap(),
            b"fake-oci-init-elf"
        );
        assert_eq!(std::fs::read(&bins.agent).unwrap(), b"fake-agent-elf");
        assert_eq!(
            std::fs::read(&bins.egress_client).unwrap(),
            b"fake-egress-client-elf"
        );
        assert_eq!(
            std::fs::read(&layout.entrypoint_runner).unwrap(),
            b"fake-entrypoint-runner-elf"
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
    fn layout_is_versioned_arched_and_variant_keyed() {
        let version = env!("CARGO_PKG_VERSION");
        let l = GuestAgentLayout::under(Path::new("/c"), version, GuestArch::Aarch64);
        let expected_dir = PathBuf::from("/c")
            .join("guest-agent")
            .join(version)
            .join("aarch64")
            .join("interactive");
        // The `interactive` segment keys the variant so a stale same-version agent
        // built without interactive is never reused for the exec-capable request.
        assert_eq!(l.dir, expected_dir);
        assert_eq!(l.oci_init, l.dir.join("mvm-oci-init"));
        assert_eq!(l.agent, l.dir.join("mvm-guest-agent"));
        assert_eq!(l.netinit, l.dir.join("mvm-guest-netinit"));
        assert_eq!(l.egress_client, l.dir.join("mvm-egress-client"));
        assert_eq!(l.entrypoint_runner, l.dir.join("mvm-oci-entrypoint"));
        assert_eq!(l.verity_init, l.dir.join("mvm-verity-init"));
    }

    #[test]
    fn build_argv_targets_musl_with_interactive_and_guest_bins() {
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
                "mvm-oci-init",
                "mvm-oci-entrypoint",
                "mvm-verity-init",
                "mvm-egress-client",
            ]
        );
        assert!(argv.contains(&"mvm-agentd".to_string()));
        assert!(argv.contains(&"mvm-agentd/interactive".to_string()));
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
    fn guest_build_target_dir_is_under_cache_root() {
        assert_eq!(
            guest_build_target_dir(Path::new("/c")),
            PathBuf::from("/c/guest-agent-build/target")
        );
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
        apply_zigbuild_env(&mut cmd, &spec).expect("configure zigbuild env");

        let envs: std::collections::HashMap<_, _> = cmd
            .get_envs()
            .filter_map(|(key, value)| {
                value.map(|value| (key.to_os_string(), value.to_os_string()))
            })
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
            Some(&expected_zigbuild_cache.into_os_string())
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("ZIG_GLOBAL_CACHE_DIR")),
            Some(&expected_zig_cache.into_os_string())
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("CARGO_TARGET_DIR")),
            Some(&std::ffi::OsString::from(
                "/tmp/mvm-cache-root/guest-agent-build/target"
            ))
        );
    }

    #[test]
    fn install_and_resolve_round_trips_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let oci_init_src = tmp.path().join("i");
        let agent_src = tmp.path().join("a");
        let netinit_src = tmp.path().join("n");
        let egress_client_src = tmp.path().join("e");
        let entrypoint_runner_src = tmp.path().join("r");
        let verity_init_src = tmp.path().join("v");
        std::fs::write(&oci_init_src, b"INIT").unwrap();
        std::fs::write(&agent_src, b"AGENT").unwrap();
        std::fs::write(&netinit_src, b"NETINIT").unwrap();
        std::fs::write(&egress_client_src, b"EGRESS").unwrap();
        std::fs::write(&entrypoint_runner_src, b"RUNNER").unwrap();
        std::fs::write(&verity_init_src, b"VERITY").unwrap();
        let cache = tmp.path().join("cache");

        let installed = install_into_cache(
            GuestRuntimeBinaryPaths {
                oci_init: &oci_init_src,
                agent: &agent_src,
                netinit: &netinit_src,
                egress_client: &egress_client_src,
                entrypoint_runner: &entrypoint_runner_src,
                verity_init: &verity_init_src,
            },
            &cache,
            version,
            GuestArch::Aarch64,
        )
        .expect("install");
        assert_eq!(std::fs::read(&installed.agent).unwrap(), b"AGENT");
        assert_eq!(std::fs::read(&installed.egress_client).unwrap(), b"EGRESS");
        let layout = GuestAgentLayout::under(&cache, version, GuestArch::Aarch64);
        assert_eq!(std::fs::read(&layout.oci_init).unwrap(), b"INIT");
        assert_eq!(std::fs::read(&layout.entrypoint_runner).unwrap(), b"RUNNER");

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
                oci_init: &tmp.path().join("missing-oci-init"),
                agent: &tmp.path().join("missing-agent"),
                netinit: &tmp.path().join("missing-netinit"),
                egress_client: &tmp.path().join("missing-egress-client"),
                entrypoint_runner: &tmp.path().join("missing-entrypoint-runner"),
                verity_init: &tmp.path().join("missing-verity-init"),
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
        std::fs::create_dir_all(root.join("crates/mvm-agentd/src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\n").unwrap();
        std::fs::write(root.join("crates/mvm-agentd/Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(root.join("crates/mvm-agentd/src/main.rs"), agent_body).unwrap();
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
    fn detect_source_workspace_resolves_this_repo() {
        // Running under nextest, cwd is `crates/mvm-build`; the walk up finds the
        // real workspace root, and it carries the guest crate.
        let ws = detect_source_workspace().expect("this is a source checkout");
        assert!(ws.join("crates/mvm-agentd").is_dir());
        assert!(ws.join("Cargo.toml").is_file());
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

        // Populate the version+arch cache (the embedded/shipped path).
        install_prebuilt_guest_binaries(
            GuestRuntimeBinaryBytes {
                oci_init: b"STALE",
                agent: b"STALE",
                netinit: b"STALE",
                egress_client: b"STALE",
                entrypoint_runner: b"STALE",
                verity_init: b"STALE",
            },
            cache.path(),
            version,
            arch,
        )
        .unwrap();
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
        assert_eq!(
            layout.agent_interactive,
            layout.dir.join("agent-interactive")
        );
        assert_eq!(layout.netinit, layout.dir.join("netinit"));
        assert_eq!(layout.seccomp_apply, layout.dir.join("seccomp-apply"));
        assert_eq!(layout.runner, layout.dir.join("runner"));
        assert_eq!(layout.egress_client, layout.dir.join("egress-client"));
        assert_eq!(layout.addon_dns, layout.dir.join("addon-dns"));
        assert_eq!(layout.exit_report, layout.dir.join("exit-report"));
    }

    #[test]
    fn runtime_overlay_source_fingerprint_changes_when_guest_source_changes() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("crates/mvm-core/src")).expect("mkdir mvm-core src");
        std::fs::create_dir_all(root.join("crates/mvm-agentd/src")).expect("mkdir mvm-agentd src");
        std::fs::create_dir_all(root.join("crates/mvm-build/src")).expect("mkdir mvm-build src");
        std::fs::create_dir_all(root.join("crates/mvm-cli/src")).expect("mkdir mvm-cli src");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("write workspace cargo");
        std::fs::write(root.join("Cargo.lock"), "version = 3\n").expect("write cargo lock");
        std::fs::write(
            root.join("crates/mvm-core/Cargo.toml"),
            "[package]\nname = \"mvm-core\"\nversion = \"0.1.0\"\n",
        )
        .expect("write mvm-core cargo");
        std::fs::write(
            root.join("crates/mvm-core/src/lib.rs"),
            "pub fn core() {}\n",
        )
        .expect("write mvm-core src");
        std::fs::write(
            root.join("crates/mvm-agentd/Cargo.toml"),
            "[package]\nname = \"mvm-agentd\"\nversion = \"0.1.0\"\n",
        )
        .expect("write mvm-agentd cargo");
        std::fs::write(
            root.join("crates/mvm-agentd/src/lib.rs"),
            "pub fn guest() {}\n",
        )
        .expect("write mvm-agentd src");
        std::fs::write(
            root.join("crates/mvm-build/src/guest_agent_build.rs"),
            "pub fn build_spec() {}\n",
        )
        .expect("write guest_agent_build src");
        std::fs::write(
            root.join("crates/mvm-cli/src/lib.rs"),
            "pub fn host_only() {}\n",
        )
        .expect("write host-only src");

        let before = runtime_overlay_source_checkout_fingerprint(root).expect("fingerprint before");
        std::fs::write(
            root.join("crates/mvm-agentd/src/lib.rs"),
            "pub fn guest() { println!(\"changed\"); }\n",
        )
        .expect("rewrite mvm-agentd src");
        let after = runtime_overlay_source_checkout_fingerprint(root).expect("fingerprint after");

        assert_ne!(before, after);
    }

    #[test]
    fn runtime_overlay_source_fingerprint_ignores_host_only_files() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("crates/mvm-core/src")).expect("mkdir mvm-core src");
        std::fs::create_dir_all(root.join("crates/mvm-agentd/src")).expect("mkdir mvm-agentd src");
        std::fs::create_dir_all(root.join("crates/mvm-build/src")).expect("mkdir mvm-build src");
        std::fs::create_dir_all(root.join("crates/mvm-cli/src")).expect("mkdir mvm-cli src");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("write workspace cargo");
        std::fs::write(root.join("Cargo.lock"), "version = 3\n").expect("write cargo lock");
        std::fs::write(
            root.join("crates/mvm-core/Cargo.toml"),
            "[package]\nname = \"mvm-core\"\nversion = \"0.1.0\"\n",
        )
        .expect("write mvm-core cargo");
        std::fs::write(
            root.join("crates/mvm-core/src/lib.rs"),
            "pub fn core() {}\n",
        )
        .expect("write mvm-core src");
        std::fs::write(
            root.join("crates/mvm-agentd/Cargo.toml"),
            "[package]\nname = \"mvm-agentd\"\nversion = \"0.1.0\"\n",
        )
        .expect("write mvm-agentd cargo");
        std::fs::write(
            root.join("crates/mvm-agentd/src/lib.rs"),
            "pub fn guest() {}\n",
        )
        .expect("write mvm-agentd src");
        std::fs::write(
            root.join("crates/mvm-build/src/guest_agent_build.rs"),
            "pub fn build_spec() {}\n",
        )
        .expect("write guest_agent_build src");
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
