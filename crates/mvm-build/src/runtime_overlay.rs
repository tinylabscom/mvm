//! Build, download, and install the mvm runtime overlay disk.
//!
//! Every microVM mvm boots — Nix-built rootfs and OCI-pulled rootfs alike —
//! attaches a second virtio-blk device carrying the guest agent + seccomp
//! shim + runner + per-language SDK runtime libraries. Picking a cached
//! artifact and validating it is the resolve half and lives in
//! [`mvm_fs::overlay`] (its main names are re-exported here); this module
//! owns how an artifact *lands* in the cache in the first place:
//!
//! 1. **Build from the flake.** [`build_overlay_with_nix`] shells out to
//!    `nix build` against `<workspace>/nix/images/runtime-overlay/` and
//!    returns paths into the nix store. Linux-only — host Nix is never used
//!    by mvmctl on macOS, so the function gates on `target_os = "linux"`;
//!    macOS builds run through the direct in-process assembler instead.
//! 2. **Download from a release.** [`download_runtime_overlay`] fetches the
//!    published per-arch tarball, verifies it, and installs it — the same
//!    integrity pattern the dev-image download uses.
//!
//! [`install_overlay_into_cache`] is the shared atomic cache installer both
//! producers hand off to, and [`resolve_or_seed_from_default_cache`] wraps
//! the fs resolver with a one-shot seed from the default cache so a
//! worktree-isolated cache root inherits an already-acquired artifact
//! instead of rebuilding or re-downloading it.

use mvm_core::arch::GuestArch;
use mvm_fs::parallel::par_map;
use std::path::{Path, PathBuf};
use thiserror::Error;

use mvm_fs::overlay::{
    CHECKSUM_MANIFEST_FILE, LOCAL_BUILD_EPOCH_FILE, OverlayError, compute_file_sha256,
    read_roothash_file, verify_overlay_dir_integrity,
};
pub use mvm_fs::overlay::{
    RuntimeOverlayArtifact, RuntimeOverlayArtifactNames, RuntimeOverlayLayout,
    RuntimeOverlayResolver, read_overlay_artifact_from_dir,
};

#[cfg(feature = "pure-mkfs")]
use crate::guest_agent_build::RuntimeOverlayGuestBinaries;

/// Failure building, downloading, installing, or resolving the runtime
/// overlay artifact.
#[derive(Debug, Error)]
pub enum RuntimeOverlayError {
    /// The resolve half rejected the artifact: missing files, version
    /// mismatch, malformed roothash, integrity drift, or incomplete payload.
    #[error(transparent)]
    Resolve(#[from] OverlayError),

    /// The published compatibility binaries could not be validated or cached.
    #[error(transparent)]
    GuestRuntime(#[from] crate::guest_agent_build::GuestAgentBuildError),

    /// `nix build` exited non-zero or couldn't be spawned by the
    /// orchestrator that drives `nix build` against the runtime-overlay
    /// flake. Includes the upstream stderr so failures are debuggable
    /// without re-running with `--verbose`.
    #[error("nix build failed: {reason}")]
    NixBuildFailed { reason: String },

    /// The runtime-overlay operation is unsupported on this host. `nix
    /// build` runs Linux-only; macOS callers route through the builder VM.
    #[error("host does not support {operation}: {reason}")]
    HostUnsupported {
        operation: &'static str,
        reason: &'static str,
    },

    /// Underlying io failure during a file read or copy.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// `curl` exited non-zero (or couldn't be spawned) while fetching one of
    /// the release artifacts. Carries the URL and the upstream stderr so a
    /// failed download is debuggable without re-running with `--verbose`.
    /// The download path mirrors the existing `download_builder_vm_image`
    /// shape.
    #[error("download failed for {url}: {reason}")]
    DownloadFailed { url: String, reason: String },

    /// A downloaded artifact's sha256 didn't match the entry in the
    /// per-release `checksums-sha256.txt`. The mismatched file is removed
    /// before this error is returned so a partial install can't be reused
    /// on retry.
    #[error(
        "checksum mismatch for {name}: \
         expected sha256 {expected}, computed {actual}"
    )]
    ChecksumMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    /// The fetched `checksums-sha256.txt` file didn't carry an entry for one
    /// of the artifacts we need. Refusing to download an artifact whose
    /// checksum we can't pre-commit is the fail-closed integrity contract.
    #[error("checksum manifest at {checksums_url} did not list an entry for {name}")]
    ChecksumMissing { name: String, checksums_url: String },

    /// The release published an archive with no signature bundle beside it.
    /// Refused rather than treated as unsigned: a digest fetched over the same
    /// channel as the archive authenticates the transport, not the publisher.
    #[error(
        "release archive {asset} has no signature bundle at {bundle_url} — \
         refusing to install an unsigned artifact"
    )]
    SignatureMissing {
        /// Published asset name that could not be authenticated.
        asset: String,
        /// Where the bundle was expected.
        bundle_url: String,
    },

    /// The archive did not verify under any accepted release signing identity.
    /// The reason is the verifier's own message; neither archive nor bundle
    /// bytes are echoed, so this is safe to surface verbatim.
    #[error("release archive {asset} failed signature verification: {reason}")]
    SignatureInvalid {
        /// Published asset name whose signature was rejected.
        asset: String,
        /// Verifier's description of the failure.
        reason: String,
    },

    /// A downloaded release tarball was malformed or unsafe to extract.
    /// Always fail closed — tar extraction is an attack surface.
    #[error("release archive invalid at {archive_path:?}: {reason}")]
    InvalidArchive {
        archive_path: PathBuf,
        reason: String,
    },

    /// The direct in-process overlay assembly failed.
    #[cfg(feature = "pure-mkfs")]
    #[error("direct runtime overlay build failed: {reason}")]
    DirectBuildFailed { reason: String },
}

#[cfg(feature = "pure-mkfs")]
const DIRECT_OVERLAY_VERITY_SALT: [u8; 32] = [0u8; 32];
#[cfg(feature = "pure-mkfs")]
const DIRECT_OVERLAY_DATA_BLOCK_SIZE: u32 = 4096;
#[cfg(feature = "pure-mkfs")]
const DIRECT_OVERLAY_HASH_BLOCK_SIZE: u32 = 4096;
// Bump whenever the packaging logic in this file changes in a way the source
// fingerprint doesn't cover (that hash only walks crate sources, not this
// file) — forces a locally cached overlay to rebuild instead of reusing
// stale staged content.
const LOCAL_BUILD_EPOCH: &str = "3";

/// Resolve `arch`'s overlay from `resolver`'s cache; on a miss with a
/// non-default cache root (e.g. a worktree-isolated `MVM_HOME`), seed
/// that cache by installing the default cache's artifact and retry once. A
/// default-cache miss surfaces the original resolve error unchanged. This is
/// still a pure cache operation — no build, no download.
pub fn resolve_or_seed_from_default_cache(
    resolver: &RuntimeOverlayResolver,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let arch_dir = arch.to_string();
    match resolver.resolve(&arch_dir) {
        Ok(artifact) => Ok(artifact),
        Err(initial_error) => {
            if seed_from_default_cache(resolver, &arch_dir)? {
                return Ok(resolver.resolve(&arch_dir)?);
            }
            Err(initial_error.into())
        }
    }
}

fn seed_from_default_cache(
    resolver: &RuntimeOverlayResolver,
    arch_dir: &str,
) -> Result<bool, RuntimeOverlayError> {
    let version = resolver.expected_version().to_string();
    crate::cache_install::seed_on_miss(
        resolver.cache_root(),
        &crate::cache_install::default_cache_root(),
        |root| {
            RuntimeOverlayResolver::new(root.to_path_buf(), version.clone())
                .resolve(arch_dir)
                .ok()
        },
        |source| {
            install_overlay_into_cache(&source, resolver.cache_root(), &InstallOptions::default())
                .map(|_| ())
        },
    )
}

#[cfg(feature = "pure-mkfs")]
pub fn build_runtime_overlay_from_guest_binaries(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    bins: &RuntimeOverlayGuestBinaries,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let staging = tempfile::tempdir()?;
    let root = staging.path().join("overlay-root");
    std::fs::create_dir_all(&root)?;

    let binaries = [
        (&bins.agent, root.join("agent")),
        (&bins.netinit, root.join("netinit")),
        (&bins.ping, root.join("ping")),
        (&bins.seccomp_apply, root.join("seccomp-apply")),
        (&bins.runner, root.join("runner")),
        (&bins.egress_client, root.join("egress-client")),
        (&bins.addon_dns, root.join("addon-dns")),
        (&bins.exit_report, root.join("exit-report")),
        (&bins.forward_proxy, root.join("forward-proxy")),
    ];
    par_map(binaries.to_vec(), |(src, dst)| {
        stage_runtime_overlay_binary(src, &dst)
    })
    .into_iter()
    .collect::<Result<(), _>>()?;
    std::fs::write(root.join("VERSION"), format!("{version}\n"))?;

    let image = mvm_fs::ext4::build_image(collect_overlay_nodes(&root)?).map_err(|e| {
        RuntimeOverlayError::DirectBuildFailed {
            reason: format!("build ext4 image: {e}"),
        }
    })?;
    let verity = mvm_fs::ext4::verity::format(
        &image,
        &DIRECT_OVERLAY_VERITY_SALT,
        DIRECT_OVERLAY_DATA_BLOCK_SIZE as usize,
        DIRECT_OVERLAY_HASH_BLOCK_SIZE as usize,
    );
    let roothash = mvm_fs::ext4::verity::to_hex(&verity.root_hash);

    let artifact_dir = staging.path().join("artifact");
    std::fs::create_dir_all(&artifact_dir)?;
    let roothash_body = format!("{roothash}\n");
    let version_body = format!("{version}\n");
    let artifact_writes = [
        ("overlay.ext4", image.as_slice()),
        ("overlay.verity", verity.hash_tree.as_slice()),
        ("overlay.roothash", roothash_body.as_bytes()),
        ("VERSION", version_body.as_bytes()),
    ];
    par_map(artifact_writes.to_vec(), |(name, bytes)| {
        std::fs::write(artifact_dir.join(name), bytes)
    })
    .into_iter()
    .collect::<Result<(), _>>()?;

    let built = read_overlay_artifact_from_dir(&artifact_dir, &arch.to_string())?;
    install_overlay_into_cache(&built, cache_root, &InstallOptions { overwrite: true })?;
    resolve_or_seed_from_default_cache(
        &RuntimeOverlayResolver::new(cache_root.to_path_buf(), version.to_string()),
        arch,
    )
}

#[cfg(feature = "pure-mkfs")]
fn stage_runtime_overlay_binary(src: &Path, dst: &Path) -> Result<(), RuntimeOverlayError> {
    if !src.is_file() {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: format!(
                "required runtime-overlay binary missing at {}",
                src.display()
            ),
        });
    }
    std::fs::copy(src, dst)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

#[cfg(feature = "pure-mkfs")]
fn collect_overlay_nodes(root: &Path) -> Result<Vec<mvm_fs::ext4::Node>, RuntimeOverlayError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                let target = std::fs::read_link(&path)?;
                out.push(mvm_fs::ext4::Node::Symlink {
                    path: overlay_guest_path(root, &path),
                    target: target.to_string_lossy().into_owned(),
                });
            } else if file_type.is_dir() {
                out.push(mvm_fs::ext4::Node::Dir {
                    path: overlay_guest_path(root, &path),
                    mode: overlay_mode_of(&path, 0o755),
                    xattrs: Vec::new(),
                });
                stack.push(path);
            } else if file_type.is_file() {
                out.push(mvm_fs::ext4::Node::File {
                    path: overlay_guest_path(root, &path),
                    mode: overlay_mode_of(&path, 0o644),
                    data: std::fs::read(&path)?,
                    xattrs: Vec::new(),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "pure-mkfs")]
fn overlay_guest_path(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => format!("/{}", path.to_string_lossy()),
    }
}

#[cfg(feature = "pure-mkfs")]
fn overlay_mode_of(path: &Path, default: u16) -> u16 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => (metadata.permissions().mode() & 0o7777) as u16,
            Err(_) => default,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        default
    }
}

/// Resolve a local runtime overlay for the current source checkout, rebuilding
/// it into the cache when the cached artifact is missing or invalid.
pub fn resolve_or_build_local_runtime_overlay(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let resolver = RuntimeOverlayResolver::new(cache_root.to_path_buf(), version.to_string());
    let Some(workspace_root) = runtime_overlay_source_checkout_root() else {
        return resolve_or_seed_from_default_cache(&resolver, arch);
    };
    let expected_fingerprint =
        crate::guest_agent_build::runtime_overlay_source_checkout_fingerprint(&workspace_root)
            .map_err(|e| RuntimeOverlayError::NixBuildFailed {
                reason: format!("compute runtime-overlay source fingerprint: {e}"),
            })?;
    match resolve_or_seed_from_default_cache(&resolver, arch) {
        Ok(artifact)
            if local_source_cache_is_fresh(
                &resolver.layout(&arch.to_string()),
                &expected_fingerprint,
            )? =>
        {
            Ok(artifact)
        }
        Ok(_) => {
            tracing::info!(
                cache_root = %cache_root.display(),
                version,
                arch = %arch,
                "runtime overlay source-built cache is stale; rebuilding from source checkout"
            );
            build_runtime_overlay_from_source_checkout(cache_root, version, arch, &workspace_root)
        }
        Err(initial_error) => {
            tracing::info!(
                cache_root = %cache_root.display(),
                version,
                arch = %arch,
                error = %initial_error,
                "runtime overlay cache miss or invalid payload; rebuilding from source checkout"
            );
            build_runtime_overlay_from_source_checkout(cache_root, version, arch, &workspace_root)
        }
    }
}

#[cfg(any(feature = "pure-mkfs", target_os = "linux"))]
fn write_local_source_fingerprint(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    fingerprint: &str,
) -> Result<(), RuntimeOverlayError> {
    let layout = RuntimeOverlayLayout::under(cache_root, version, &arch.to_string());
    std::fs::write(
        layout.local_source_fingerprint_file,
        format!("{fingerprint}\n"),
    )?;
    Ok(())
}

#[cfg(any(feature = "pure-mkfs", target_os = "linux"))]
fn write_local_build_epoch(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<(), RuntimeOverlayError> {
    let layout = RuntimeOverlayLayout::under(cache_root, version, &arch.to_string());
    std::fs::write(
        layout.local_build_epoch_file,
        format!("{LOCAL_BUILD_EPOCH}\n"),
    )?;
    Ok(())
}

fn local_source_cache_is_fresh(
    layout: &RuntimeOverlayLayout,
    expected: &str,
) -> Result<bool, RuntimeOverlayError> {
    let Ok(found) = std::fs::read_to_string(&layout.local_source_fingerprint_file) else {
        return Ok(false);
    };
    let Ok(epoch) = std::fs::read_to_string(&layout.local_build_epoch_file) else {
        return Ok(false);
    };
    Ok(found.trim() == expected && epoch.trim() == LOCAL_BUILD_EPOCH)
}

// =================================================================
// Build orchestrator
// =================================================================

/// Spec for `nix build` of the runtime-overlay flake at
/// `<workspace>/nix/images/runtime-overlay/`. Pure data; the
/// actual invocation lives in [`build_overlay_with_nix`].
///
/// The spec exposes its argv + env separately so callers that
/// drive `nix build` *inside* the builder VM (rather than on the
/// host) can plumb the same shape through without reaching for an
/// external command.
#[derive(Debug, Clone)]
pub struct OverlayBuildSpec {
    /// Workspace root — the dir containing `nix/`, `crates/`,
    /// `Cargo.toml`. The flake reads
    /// `<workspace_root>/nix/images/runtime-overlay/flake.nix`.
    pub workspace_root: PathBuf,
    /// Which target arch to build for. Maps to the Nix
    /// `system` attribute on the flake's `packages` output.
    pub arch: GuestArch,
    /// Where the resulting result-symlink should live. Typically
    /// a tempdir or a staging location under
    /// `~/.mvm/cache/runtime-overlay/<version>/<arch>/.work/` —
    /// the install-to-cache step is the caller's responsibility.
    pub out_link: PathBuf,
    /// Override the `nix` binary location. Default `None` ⇒
    /// resolved via `$PATH`. Tests use this to substitute a stub.
    pub nix_binary: Option<PathBuf>,
}

impl OverlayBuildSpec {
    /// Construct a spec for the given (workspace, arch, out_link).
    pub fn new(workspace_root: PathBuf, arch: GuestArch, out_link: PathBuf) -> Self {
        Self {
            workspace_root,
            arch,
            out_link,
            nix_binary: None,
        }
    }

    /// Nix `system` attribute string corresponding to `self.arch`.
    /// The runtime-overlay flake exposes outputs at
    /// `packages.<system>.default` for these two systems.
    pub fn system(&self) -> &'static str {
        self.arch.nix_system()
    }

    /// Absolute path to the flake directory (the dir containing
    /// `flake.nix`). Nix's `path:` URI scheme consumes the dir,
    /// not the `flake.nix` file.
    pub fn flake_path(&self) -> PathBuf {
        self.workspace_root
            .join("nix")
            .join("images")
            .join("runtime-overlay")
    }

    /// The Nix flake reference used by `nix build`. Pinned to
    /// the workspace-local path so we don't accidentally fetch
    /// a published flake when building from source.
    pub fn flake_reference(&self) -> String {
        format!(
            "path:{}#packages.{}.default",
            self.flake_path().display(),
            self.system()
        )
    }

    /// `nix build` argv, ready to hand to `Command::new` plus
    /// `.args(argv[1..])`. The orchestrator manages its own
    /// symlink position via `--out-link <path>`. The build always
    /// includes `--impure` because the flake's workspace-root
    /// contract relies on `MVM_WORKSPACE_PATH`.
    pub fn argv(&self) -> Vec<String> {
        let nix = self
            .nix_binary
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "nix".to_string());
        vec![
            nix,
            "build".to_string(),
            "--extra-experimental-features".to_string(),
            "nix-command flakes".to_string(),
            "--impure".to_string(),
            "--out-link".to_string(),
            self.out_link.display().to_string(),
            self.flake_reference(),
        ]
    }

    /// Environment variables to thread through to `nix build`.
    /// `MVM_WORKSPACE_PATH` is the override the flake reads when
    /// running inside the builder VM's sandbox where `..`
    /// resolution against the store copy doesn't reach the
    /// workspace — same mechanism the builder-vm flake uses.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![(
            "MVM_WORKSPACE_PATH".to_string(),
            self.workspace_root.display().to_string(),
        )]
    }
}

/// Drive `nix build` from a spec. Linux-only at runtime — host
/// Nix is never used by mvmctl on macOS, and even if the binary
/// is installed it can't cross-compile to `aarch64-linux` /
/// `x86_64-linux` without a remote builder. Non-Linux callers
/// get `HostUnsupported`; those calls route through the builder
/// VM.
///
/// On success the function:
///
/// 1. Verifies the four required files exist at
///    `<out_link>/{overlay.ext4, overlay.verity, overlay.roothash,
///    VERSION}`. The runtime-overlay flake's `runCommand`
///    produces exactly these names.
/// 2. Reads `VERSION` + `overlay.roothash` and validates them.
/// 3. Returns a [`RuntimeOverlayArtifact`] pointing at the
///    nix-store paths the result-symlink resolves to.
pub fn build_overlay_with_nix(
    spec: &OverlayBuildSpec,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    #[cfg(target_os = "linux")]
    {
        run_nix_build(spec)?;
        validate_built_artifact(spec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Suppress "unused" on non-Linux while keeping a single
        // public signature across hosts.
        let _ = spec;
        Err(RuntimeOverlayError::HostUnsupported {
            operation: "runtime-overlay nix build",
            reason: "nix build runs Linux-only; non-Linux callers route through the libkrun builder VM (W1.4b.3b)",
        })
    }
}

#[cfg(target_os = "linux")]
fn run_nix_build(spec: &OverlayBuildSpec) -> Result<(), RuntimeOverlayError> {
    let argv = spec.argv();
    let binary = argv.first().cloned().unwrap_or_else(|| "nix".to_string());
    let mut cmd = std::process::Command::new(&binary);
    cmd.args(&argv[1..]);
    for (k, v) in spec.env() {
        cmd.env(k, v);
    }
    let exec = cmd
        .output()
        .map_err(|e| RuntimeOverlayError::NixBuildFailed {
            reason: format!("spawn `{binary}`: {e}"),
        })?;
    if !exec.status.success() {
        let stderr = String::from_utf8_lossy(&exec.stderr).into_owned();
        return Err(RuntimeOverlayError::NixBuildFailed {
            reason: format!("exit {:?}; stderr={stderr}", exec.status.code()),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_built_artifact(
    spec: &OverlayBuildSpec,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    Ok(read_overlay_artifact_from_dir(
        &spec.out_link,
        &spec.arch.to_string(),
    )?)
}

fn runtime_overlay_source_checkout_root() -> Option<PathBuf> {
    if !crate::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        return None;
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    workspace_root
        .join("nix")
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix")
        .is_file()
        .then(|| workspace_root.to_path_buf())
}

fn build_runtime_overlay_from_source_checkout(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    #[cfg(any(feature = "pure-mkfs", target_os = "linux"))]
    let source_fingerprint =
        crate::guest_agent_build::runtime_overlay_source_checkout_fingerprint(workspace_root)
            .map_err(|e| RuntimeOverlayError::NixBuildFailed {
                reason: format!("compute runtime-overlay source fingerprint: {e}"),
            })?;
    #[cfg(feature = "pure-mkfs")]
    {
        let bins = crate::guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
            cache_root,
            version,
            arch,
            workspace_root,
        )
        .map_err(|e| RuntimeOverlayError::DirectBuildFailed {
            reason: format!("build guest binaries for runtime overlay: {e}"),
        })?;
        let artifact = build_runtime_overlay_from_guest_binaries(cache_root, version, arch, &bins)?;
        write_local_source_fingerprint(cache_root, version, arch, &source_fingerprint)?;
        write_local_build_epoch(cache_root, version, arch)?;
        Ok(artifact)
    }
    #[cfg(all(not(feature = "pure-mkfs"), target_os = "linux"))]
    {
        let temp = tempfile::tempdir()?;
        let spec = OverlayBuildSpec::new(
            workspace_root.to_path_buf(),
            arch,
            temp.path().join("result"),
        );
        let built = build_overlay_with_nix(&spec)?;
        let _installed =
            install_overlay_into_cache(&built, cache_root, &InstallOptions { overwrite: true })?;
        write_local_source_fingerprint(cache_root, version, arch, &source_fingerprint)?;
        write_local_build_epoch(cache_root, version, arch)?;
        resolve_or_seed_from_default_cache(
            &RuntimeOverlayResolver::new(cache_root.to_path_buf(), version.to_string()),
            arch,
        )
    }
    #[cfg(all(not(feature = "pure-mkfs"), not(target_os = "linux")))]
    {
        let _ = (cache_root, version, arch, workspace_root);
        Err(RuntimeOverlayError::HostUnsupported {
            operation: "runtime overlay local rebuild",
            reason: "direct runtime-overlay rebuild requires either the pure-mkfs feature or a Linux nix build path",
        })
    }
}

// =================================================================
// Cache-install step
// =================================================================

/// Options for [`install_overlay_into_cache`].
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Overwrite any existing artifact at the target cache
    /// directory. Default `false` — if every required file is
    /// already present at the target path, the function is a
    /// no-op (the install short-circuits and returns the
    /// resolver-view of the existing artifact). Set `true` for
    /// "force re-install" semantics, e.g. after a build whose
    /// content the caller knows is fresher than what's cached.
    pub overwrite: bool,
}

/// Copy `source`'s runtime overlay files into the canonical cache
/// layout under `cache_root`:
///
/// ```text
/// <cache_root>/runtime-overlay/<version>/<arch>/{overlay.ext4,
///   overlay.verity, overlay.roothash, VERSION}
/// ```
///
/// The install is atomic on the same-filesystem case: each
/// file is staged into a sibling `.tmp.<pid>/` directory, then
/// the whole tmp dir is renamed into the final location. A
/// failure mid-way leaves only the `.tmp.<pid>/` behind (which
/// can be safely cleaned up by a future call) — the existing
/// cache content is never partially overwritten.
///
/// Permissions: copied files are chmod'd to `0644` so the cache
/// stays readable+overwritable across installs, even if the
/// source files (from a Nix store path) are mode `0444`.
pub fn install_overlay_into_cache(
    source: &RuntimeOverlayArtifact,
    cache_root: &Path,
    options: &InstallOptions,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    // The source VERSION file sits next to overlay.ext4 in the
    // build orchestrator's output. The `RuntimeOverlayArtifact`
    // type doesn't carry it as a separate path, so we derive it.
    let source_dir = source
        .overlay_ext4
        .parent()
        .ok_or_else(|| {
            RuntimeOverlayError::from(OverlayError::ArtifactIncomplete {
                artifact_dir: PathBuf::new(),
                missing: source.overlay_ext4.clone(),
                version: source.version.clone(),
                arch: source.arch.clone(),
            })
        })?
        .to_path_buf();
    let source_version_file = source_dir.join("VERSION");

    for required in [
        &source.overlay_ext4,
        &source.sidecar,
        &source.roothash_file,
        &source_version_file,
    ] {
        if !required.is_file() {
            return Err(OverlayError::ArtifactIncomplete {
                artifact_dir: source_dir.clone(),
                missing: (*required).clone(),
                version: source.version.clone(),
                arch: source.arch.clone(),
            }
            .into());
        }
    }

    let layout = RuntimeOverlayLayout::under(cache_root, &source.version, &source.arch);

    // Idempotency: if every file at the target already exists
    // and the caller hasn't asked to overwrite, short-circuit.
    // The resolver does the validation; we just construct the
    // resolver-shape artifact pointing at the cache paths.
    if !options.overwrite && all_required_files_present(&layout) {
        return Ok(RuntimeOverlayArtifact {
            overlay_ext4: layout.overlay_ext4,
            sidecar: layout.sidecar,
            roothash_file: layout.roothash_file,
            roothash: source.roothash.clone(),
            arch: source.arch.clone(),
            version: source.version.clone(),
        });
    }

    let parent = layout.artifact_dir.parent().ok_or_else(|| {
        RuntimeOverlayError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "computed artifact dir has no parent",
        ))
    })?;
    std::fs::create_dir_all(parent)?;

    // Stage to a sibling temp directory whose name carries the
    // PID + a small random suffix. Multiple concurrent installs
    // for the same (version, arch) get distinct staging dirs and
    // the last rename wins atomically.
    let staging = parent.join(crate::cache_install::staging_dir_name(&source.arch));
    // Belt-and-braces: if a previous interrupted install left a
    // staging dir at the same name, blow it away.
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    // A run killed between here and the rename below orphans its staging dir
    // under another pid, which nothing else would ever clean up.
    crate::cache_install::reap_stale_staging(parent, &source.arch);
    std::fs::create_dir(&staging)?;

    let cache_copies = [
        (&source.overlay_ext4, staging.join("overlay.ext4")),
        (&source.sidecar, staging.join("overlay.verity")),
        (&source.roothash_file, staging.join("overlay.roothash")),
        (&source_version_file, staging.join("VERSION")),
    ];
    par_map(cache_copies.to_vec(), |(src, dst)| {
        install_file_with_perms(src, &dst)
    })
    .into_iter()
    .collect::<Result<(), _>>()?;
    write_checksum_manifest(&staging)?;
    std::fs::write(
        staging.join(LOCAL_BUILD_EPOCH_FILE),
        format!("{LOCAL_BUILD_EPOCH}\n"),
    )?;

    // Replace the existing artifact dir, if any. Two-phase
    // (remove old, then rename new) — not strictly atomic across
    // the gap, but the only window during which the cache lacks
    // a complete artifact is microsecond-scale. Acceptable for
    // an offline-cache-install operation; admission re-reads on
    // each microVM start anyway.
    if layout.artifact_dir.exists() {
        std::fs::remove_dir_all(&layout.artifact_dir)?;
    }
    std::fs::rename(&staging, &layout.artifact_dir)?;

    Ok(RuntimeOverlayArtifact {
        overlay_ext4: layout.overlay_ext4,
        sidecar: layout.sidecar,
        roothash_file: layout.roothash_file,
        roothash: source.roothash.clone(),
        arch: source.arch.clone(),
        version: source.version.clone(),
    })
}

fn all_required_files_present(layout: &RuntimeOverlayLayout) -> bool {
    layout.overlay_ext4.is_file()
        && layout.sidecar.is_file()
        && layout.roothash_file.is_file()
        && layout.version_file.is_file()
        && layout.checksum_manifest_file.is_file()
}

fn install_file_with_perms(src: &Path, dst: &Path) -> Result<(), RuntimeOverlayError> {
    std::fs::copy(src, dst)?;
    set_cache_perms(dst)?;
    Ok(())
}

fn write_checksum_manifest(dir: &Path) -> Result<(), RuntimeOverlayError> {
    let entries = [
        ("overlay.ext4", dir.join("overlay.ext4")),
        ("overlay.verity", dir.join("overlay.verity")),
        ("overlay.roothash", dir.join("overlay.roothash")),
        ("VERSION", dir.join("VERSION")),
    ];
    let mut body = String::new();
    for (name, path) in entries {
        let digest = compute_file_sha256(&path)?;
        body.push_str(&format!("{digest}  {name}\n"));
    }
    std::fs::write(dir.join(CHECKSUM_MANIFEST_FILE), body)?;
    set_cache_perms(&dir.join(CHECKSUM_MANIFEST_FILE))?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_cache_perms(p: &Path) -> Result<(), RuntimeOverlayError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_cache_perms(_p: &Path) -> Result<(), RuntimeOverlayError> {
    // Windows mvmctl is a non-goal for the boot path; the cache
    // exists for completeness but permission semantics are
    // platform-defined. No-op.
    Ok(())
}

// ============================================================================
// Download the published runtime overlay (consumer side)
// ============================================================================

/// Default GitHub Releases base URL the release pipeline
/// (`runtime-overlay-image` job in `.github/workflows/release.yml`)
/// uploads to. Override via the `MVM_OVERLAY_BASE_URL` env var for
/// hermetic tests or a private mirror — the env path doesn't accept
/// the `v` prefix or trailing slash; we append `/v<version>` ourselves
/// so the test can pin to a `file://...` fixture dir.
const DEFAULT_RELEASE_BASE: &str = "https://github.com/tinylabscom/mvm/releases/download";

/// Documented escape hatch — bypass the SHA-256
/// integrity check when an emergency rotation requires it. Never set
/// in CI. Matches the env var name used by `download_dev_image` and
/// `download_builder_vm_image` so the operator runbook covers all
/// three.
pub(crate) const SKIP_HASH_VERIFY_ENV: &str = "MVM_SKIP_HASH_VERIFY";

/// Construct the per-version release base URL the four artifacts
/// live under. Production-shape:
/// `https://github.com/tinylabscom/mvm/releases/download/v<version>`.
/// Honors `MVM_OVERLAY_BASE_URL` for tests + private mirrors —
/// callers pass the *prefix*, this function appends `/v<version>`.
pub fn release_base_url(version: &str) -> String {
    let base =
        std::env::var("MVM_OVERLAY_BASE_URL").unwrap_or_else(|_| DEFAULT_RELEASE_BASE.to_string());
    format!("{}/v{version}", base.trim_end_matches('/'))
}

/// Download the runtime overlay tarball for `version` + `arch` from the
/// published GitHub Release, SHA-256-verify the archive, safely extract it,
/// re-verify each inner artifact against the archive's embedded
/// `checksums-sha256.txt`, and install into `cache_root` under the canonical layout
/// `<cache_root>/runtime-overlay/<version>/<arch>/`.
///
/// Mirrors the integrity pattern of `download_dev_image` /
/// `download_builder_vm_image`: fetch the archive checksum first; reject
/// downloads whose hash isn't pre-committed there; honor
/// `MVM_SKIP_HASH_VERIFY=1` only as a documented emergency
/// rotation escape (never set in CI).
///
/// Returns the installed `RuntimeOverlayArtifact` so the caller
/// can hand it straight to the backend.
pub fn download_runtime_overlay(
    version: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let names = RuntimeOverlayArtifactNames::for_arch(&arch.to_string());
    let base = release_base_url(version);
    let archive_checksum_url = format!("{base}/{}", names.archive_checksum);

    // Step 1: fetch the archive checksum sidecar before touching the tarball.
    // The archive is the transport unit; a missing checksum aborts before we
    // spend bandwidth on the payload.
    let expected = fetch_expected_hashes(&archive_checksum_url, &[&names.archive])?;

    // Step 2: download the tarball into a temp dir, prove it against both the
    // digest and the release signing identity, then safely extract it into
    // canonical filenames so `install_overlay_into_cache` can consume the
    // extracted directory directly. The signature rung sits before extraction
    // so an unauthenticated tar is never parsed.
    let tmp = tempfile::tempdir()?;
    let stage = tmp.path();
    let archive_local = stage.join(&names.archive);
    curl_download(&format!("{base}/{}", names.archive), &archive_local)?;
    verify_file_sha256(&archive_local, &names.archive, expected.get(&names.archive))?;
    crate::release_signature::verify_release_archive_signature(
        &crate::release_signature::ReleaseSignatureRequest {
            base_url: &base,
            asset: &names.archive,
            archive_path: &archive_local,
            version,
            // Unchanged: this path still resolves its base URL from the CLI
            // version, so its signature train must stay the CLI one. Splitting
            // its download tag from its cache key is a separate change.
            train: crate::release_signature::ReleaseTrain::Cli,
        },
    )?;
    extract_release_archive(&archive_local, stage, &OVERLAY_ARCHIVE_MEMBERS)?;
    verify_overlay_dir_integrity(stage)?;
    verify_release_guest_runtime(stage)?;

    crate::guest_agent_build::install_into_cache(
        crate::guest_agent_build::GuestRuntimeBinaryPaths {
            oci_init: &stage.join("mvm-oci-init"),
            agent: &stage.join("mvm-guest-agent"),
            netinit: &stage.join("mvm-guest-netinit"),
            egress_client: &stage.join("mvm-egress-client"),
            entrypoint_runner: &stage.join("mvm-oci-entrypoint"),
            verity_init: &stage.join("mvm-verity-init"),
        },
        &cache_root.join("oci"),
        version,
        arch,
    )?;

    // Step 3: read the roothash text so the returned
    // `RuntimeOverlayArtifact` carries the value the backend
    // bakes into the kernel cmdline (`mvm.runtime_roothash=…`).
    let ext4_local = stage.join("overlay.ext4");
    let verity_local = stage.join("overlay.verity");
    let roothash_local = stage.join("overlay.roothash");
    let roothash = read_roothash_file(&roothash_local)?;

    // Step 4: hand off to the existing atomic installer. It
    // copies into a staging dir under `cache_root` and renames
    // into the canonical artifact dir on success — so a
    // mid-install crash leaves only a `.tmp.<pid>` behind, never
    // a partially-overwritten cache entry.
    let staged_artifact = RuntimeOverlayArtifact {
        overlay_ext4: ext4_local,
        sidecar: verity_local,
        roothash_file: roothash_local,
        roothash,
        arch: arch.to_string(),
        version: version.to_string(),
    };
    install_overlay_into_cache(
        &staged_artifact,
        cache_root,
        &InstallOptions { overwrite: true },
    )
}

/// Exactly the members the overlay's release tarball may carry. Doubles as the
/// extraction allow-list and the completeness check — an archive carrying
/// anything else, or missing any of these, is refused.
const RELEASE_GUEST_RUNTIME_FILES: [&str; 6] =
    crate::guest_agent_build::OCI_GUEST_RUNTIME_BINARY_NAMES;

const OVERLAY_ARCHIVE_MEMBERS: [&str; 11] = [
    "overlay.ext4",
    "overlay.verity",
    "overlay.roothash",
    "VERSION",
    "mvm-oci-init",
    "mvm-guest-agent",
    "mvm-guest-netinit",
    "mvm-egress-client",
    "mvm-oci-entrypoint",
    "mvm-verity-init",
    CHECKSUM_MANIFEST_FILE,
];

fn verify_release_guest_runtime(stage: &Path) -> Result<(), RuntimeOverlayError> {
    let manifest_path = stage.join(CHECKSUM_MANIFEST_FILE);
    let body = std::fs::read_to_string(&manifest_path)?;
    let expected = mvm_fs::overlay::parse_checksums_manifest(&body);
    for name in RELEASE_GUEST_RUNTIME_FILES {
        let expected_hash =
            expected
                .get(name)
                .ok_or_else(|| RuntimeOverlayError::ChecksumMissing {
                    name: name.to_string(),
                    checksums_url: manifest_path.display().to_string(),
                })?;
        verify_file_sha256(&stage.join(name), name, Some(expected_hash))?;
    }
    Ok(())
}

/// Safely extract a published release tarball into `stage`, flattening it to the
/// canonical filenames in `expected`.
///
/// Shared by every release-artifact downloader so there is one set of refusals
/// rather than one per artifact: a member whose path escapes `stage` (traversal
/// or absolute), a member outside `expected`, a nested path, a non-regular entry
/// type, or a missing required member all fail closed. `expected` is both the
/// allow-list and the required set — a release artifact set is complete or it is
/// not installed at all.
pub(crate) fn extract_release_archive(
    archive_path: &Path,
    stage: &Path,
    expected: &[&'static str],
) -> Result<(), RuntimeOverlayError> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = std::collections::BTreeSet::new();

    for entry in archive
        .entries()
        .map_err(|e| RuntimeOverlayError::InvalidArchive {
            archive_path: archive_path.to_path_buf(),
            reason: format!("read tar entries: {e}"),
        })?
    {
        let mut entry = entry.map_err(|e| RuntimeOverlayError::InvalidArchive {
            archive_path: archive_path.to_path_buf(),
            reason: format!("read tar entry: {e}"),
        })?;
        let path = entry
            .path()
            .map_err(|e| RuntimeOverlayError::InvalidArchive {
                archive_path: archive_path.to_path_buf(),
                reason: format!("read tar path: {e}"),
            })?
            .into_owned();
        let Some(name) = canonical_archive_member_name(&path, expected) else {
            return Err(RuntimeOverlayError::InvalidArchive {
                archive_path: archive_path.to_path_buf(),
                reason: format!("unsafe or unexpected path {:?}", path.display()),
            });
        };
        match entry.header().entry_type() {
            tar::EntryType::Regular => {
                let dest = stage.join(name);
                let mut out = std::fs::File::create(&dest)?;
                std::io::copy(&mut entry, &mut out)?;
                set_cache_perms(&dest)?;
                seen.insert(name.to_string());
            }
            tar::EntryType::Directory => {}
            other => {
                return Err(RuntimeOverlayError::InvalidArchive {
                    archive_path: archive_path.to_path_buf(),
                    reason: format!(
                        "unsupported tar entry type {other:?} for {:?}",
                        path.display()
                    ),
                });
            }
        }
    }

    for required in expected {
        if !seen.contains(*required) && !stage.join(required).is_file() {
            return Err(RuntimeOverlayError::InvalidArchive {
                archive_path: archive_path.to_path_buf(),
                reason: format!("missing required archive member {required}"),
            });
        }
    }
    Ok(())
}

/// Map a tar member path to the canonical filename it may be written as, or
/// `None` when it must be refused. Only a single unprefixed component that
/// appears in `expected` is accepted, so `../x`, `/x`, and `dir/x` are all
/// rejected by construction rather than by string inspection.
fn canonical_archive_member_name(path: &Path, expected: &[&'static str]) -> Option<&'static str> {
    let mut components = path.components();
    let component = match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(name)), None) => name,
        _ => return None,
    };
    let name = component.to_str()?;
    expected
        .iter()
        .copied()
        .find(|candidate| *candidate == name)
}

/// HTTP GET the per-release `sha256sum`-format checksums file and
/// return a `name -> hex-digest` map for the artifacts we need.
/// Filenames that aren't in `wanted` are dropped; any name in
/// `wanted` that's absent from the manifest is a hard failure.
pub(crate) fn fetch_expected_hashes(
    checksums_url: &str,
    wanted: &[&str],
) -> Result<std::collections::HashMap<String, String>, RuntimeOverlayError> {
    let tmp = tempfile::NamedTempFile::new()?;
    curl_download(checksums_url, tmp.path())?;
    let body = std::fs::read_to_string(tmp.path())?;
    let map = mvm_fs::overlay::parse_checksums_manifest(&body);

    for w in wanted {
        if !map.contains_key(*w) {
            return Err(RuntimeOverlayError::ChecksumMissing {
                name: (*w).to_string(),
                checksums_url: checksums_url.to_string(),
            });
        }
    }
    Ok(map)
}

/// Stream `path` through SHA-256 and compare to `expected`. On
/// mismatch, delete the file (so retry can't pick up tainted
/// bytes) and return a `ChecksumMismatch`. Honors
/// `MVM_SKIP_HASH_VERIFY=1`.
pub(crate) fn verify_file_sha256(
    path: &Path,
    name: &str,
    expected: Option<&String>,
) -> Result<(), RuntimeOverlayError> {
    if std::env::var_os(SKIP_HASH_VERIFY_ENV).is_some() {
        tracing::warn!(
            "{SKIP_HASH_VERIFY_ENV} set — skipping integrity check on {name}. \
             ADR-002 §W5.1 documents this as an emergency-rotation escape hatch."
        );
        return Ok(());
    }
    let Some(expected) = expected else {
        // `fetch_expected_hashes` already enforces presence —
        // surface a clear internal-error message if a refactor
        // ever decouples the two.
        return Err(RuntimeOverlayError::ChecksumMissing {
            name: name.to_string(),
            checksums_url: "(internal: missing expected hash)".to_string(),
        });
    };

    let actual = compute_file_sha256(path)?;

    if actual != *expected {
        let _ = std::fs::remove_file(path);
        return Err(RuntimeOverlayError::ChecksumMismatch {
            name: name.to_string(),
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

/// Shell out to `curl -fSL` to download `url` to `dest`. Mirrors
/// the existing `download_file` helper in
/// `mvm-cli::commands::env::artifact_verify` so operator
/// expectations stay uniform across the three downloaders
/// (dev image, builder VM image, runtime overlay).
pub(crate) fn curl_download(url: &str, dest: &Path) -> Result<(), RuntimeOverlayError> {
    let output = std::process::Command::new("curl")
        .args(["-fSL", "--silent", "--show-error", "-o"])
        .arg(dest)
        .arg(url)
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let _ = std::fs::remove_file(dest);
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            let code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string());
            Err(RuntimeOverlayError::DownloadFailed {
                url: url.to_string(),
                reason: format!("curl exited {code}; stderr={stderr}"),
            })
        }
        Err(e) => {
            let _ = std::fs::remove_file(dest);
            Err(RuntimeOverlayError::DownloadFailed {
                url: url.to_string(),
                reason: format!("spawn curl failed: {e}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use mvm_fs::ext4::Node;
    use tempfile::TempDir;

    const FAKE_ROOTHASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[cfg(feature = "release-channel")]
    #[test]
    fn official_build_does_not_detect_the_compiled_in_runtime_overlay_flake() {
        assert_eq!(runtime_overlay_source_checkout_root(), None);
    }

    fn valid_overlay_ext4_bytes() -> Vec<u8> {
        let paths: &[&str] = &[
            "/agent",
            "/netinit",
            "/ping",
            "/seccomp-apply",
            "/runner",
            "/egress-client",
            "/forward-proxy",
            "/addon-dns",
            "/exit-report",
        ];
        let mut nodes: Vec<Node> = paths
            .iter()
            .map(|path| Node::File {
                path: (*path).to_string(),
                mode: 0o555,
                data: path.as_bytes().to_vec(),
                xattrs: Vec::new(),
            })
            .collect();
        nodes.push(Node::File {
            path: "/VERSION".into(),
            mode: 0o444,
            data: b"0.14.0\n".to_vec(),
            xattrs: Vec::new(),
        });
        mvm_fs::ext4::build_image(nodes).expect("build valid overlay ext4 fixture")
    }

    #[test]
    fn arch_display_matches_kernel_naming() {
        assert_eq!(GuestArch::Aarch64.to_string(), "aarch64");
        assert_eq!(GuestArch::X86_64.to_string(), "x86_64");
    }

    #[test]
    fn arch_host_returns_one_of_the_supported_arches() {
        // The const fn must compile and produce a value; the
        // exact value depends on the test binary's target arch.
        let host = GuestArch::host();
        assert!(matches!(host, GuestArch::Aarch64 | GuestArch::X86_64));
    }

    // =================================================================
    // Build-spec tests
    // =================================================================

    #[test]
    fn build_spec_system_maps_arch_to_nix_system_string() {
        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::Aarch64,
            PathBuf::from("/tmp/result"),
        );
        assert_eq!(spec.system(), "aarch64-linux");

        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::X86_64,
            PathBuf::from("/tmp/result"),
        );
        assert_eq!(spec.system(), "x86_64-linux");
    }

    #[test]
    fn build_spec_flake_path_points_at_runtime_overlay_dir() {
        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::Aarch64,
            PathBuf::from("/tmp/result"),
        );
        assert_eq!(
            spec.flake_path(),
            PathBuf::from("/workspace/nix/images/runtime-overlay")
        );
    }

    #[test]
    fn build_spec_flake_reference_pins_path_uri_and_system_default() {
        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::X86_64,
            PathBuf::from("/tmp/result"),
        );
        // Pinned to the workspace-local path so we don't fetch
        // a published flake on the rare host where nix is happy
        // to resolve a bare attribute against `nixpkgs`.
        assert_eq!(
            spec.flake_reference(),
            "path:/workspace/nix/images/runtime-overlay#packages.x86_64-linux.default"
        );
    }

    #[test]
    fn build_spec_argv_defaults_to_path_lookup_nix_and_includes_required_flags() {
        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::Aarch64,
            PathBuf::from("/tmp/result"),
        );
        let argv = spec.argv();
        // Default nix binary is `nix` (resolved via $PATH).
        assert_eq!(argv[0], "nix");
        assert_eq!(argv[1], "build");
        // Experimental features enable nix-command + flakes
        // without requiring a contributor's `~/.config/nix/nix.conf`.
        let pair = argv
            .windows(2)
            .find(|w| w[0] == "--extra-experimental-features");
        assert!(
            pair.is_some(),
            "argv must enable nix-command + flakes: {argv:?}"
        );
        assert_eq!(pair.unwrap()[1], "nix-command flakes");
        assert!(
            argv.iter().any(|arg| arg == "--impure"),
            "argv must opt into the MVM_WORKSPACE_PATH override: {argv:?}"
        );
        // --out-link <path>
        let out = argv.windows(2).find(|w| w[0] == "--out-link");
        assert!(out.is_some(), "argv must specify --out-link: {argv:?}");
        assert_eq!(out.unwrap()[1], "/tmp/result");
        assert!(
            argv.iter().any(|arg| arg == "--impure"),
            "argv must opt into impure evaluation so MVM_WORKSPACE_PATH is visible: {argv:?}"
        );
        // Final positional is the flake reference.
        assert_eq!(
            argv.last().unwrap(),
            "path:/workspace/nix/images/runtime-overlay#packages.aarch64-linux.default"
        );
    }

    #[test]
    fn build_spec_argv_respects_nix_binary_override() {
        let spec = OverlayBuildSpec {
            workspace_root: PathBuf::from("/workspace"),
            arch: GuestArch::Aarch64,
            out_link: PathBuf::from("/tmp/result"),
            nix_binary: Some(PathBuf::from("/custom/nix-stub")),
        };
        let argv = spec.argv();
        assert_eq!(argv[0], "/custom/nix-stub");
    }

    #[test]
    fn build_spec_env_sets_workspace_path_for_sandbox_resolution() {
        // `MVM_WORKSPACE_PATH` is the env override the
        // runtime-overlay flake reads so the `..` resolution
        // against a store copy lands at the right tree when nix
        // runs inside the builder VM sandbox.
        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::Aarch64,
            PathBuf::from("/tmp/result"),
        );
        let env = spec.env();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "MVM_WORKSPACE_PATH");
        assert_eq!(env[0].1, "/workspace");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn build_overlay_with_nix_returns_host_unsupported_on_non_linux() {
        let spec = OverlayBuildSpec::new(
            PathBuf::from("/workspace"),
            GuestArch::Aarch64,
            PathBuf::from("/tmp/result"),
        );
        let err = build_overlay_with_nix(&spec).unwrap_err();
        match err {
            RuntimeOverlayError::HostUnsupported { operation, .. } => {
                assert!(
                    operation.contains("runtime-overlay") || operation.contains("nix"),
                    "expected runtime-overlay or nix in operation; got {operation:?}"
                );
            }
            other => panic!("expected HostUnsupported, got {other:?}"),
        }
    }

    // =================================================================
    // install_overlay_into_cache tests
    // =================================================================

    /// Build a "source" artifact in a tempdir whose layout
    /// mimics the runtime-overlay flake's `$out/`: four files at
    /// the same level. Returns `(tempdir_keep_alive, artifact)`.
    fn make_source_artifact(
        version: &str,
        arch: GuestArch,
        roothash: &str,
    ) -> (TempDir, RuntimeOverlayArtifact) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("overlay.ext4"), valid_overlay_ext4_bytes()).unwrap();
        std::fs::write(dir.join("overlay.verity"), b"source-verity-bytes").unwrap();
        std::fs::write(
            dir.join("overlay.roothash"),
            format!("{roothash}\n").as_bytes(),
        )
        .unwrap();
        std::fs::write(dir.join("VERSION"), format!("{version}\n").as_bytes()).unwrap();

        let artifact = RuntimeOverlayArtifact {
            overlay_ext4: dir.join("overlay.ext4"),
            sidecar: dir.join("overlay.verity"),
            roothash_file: dir.join("overlay.roothash"),
            roothash: roothash.to_string(),
            arch: arch.to_string(),
            version: version.to_string(),
        };
        (tmp, artifact)
    }

    #[test]
    fn install_copies_all_four_files_into_canonical_cache_layout() {
        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();
        let source_ext4 = std::fs::read(&source.overlay_ext4).unwrap();
        let source_sidecar = std::fs::read(&source.sidecar).unwrap();

        let installed =
            install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
                .expect("install");

        let expected_dir = cache
            .path()
            .join("runtime-overlay")
            .join("0.14.0")
            .join("aarch64");
        assert!(
            expected_dir.is_dir(),
            "artifact dir must exist at {expected_dir:?}"
        );
        assert_eq!(installed.overlay_ext4, expected_dir.join("overlay.ext4"));
        assert_eq!(installed.sidecar, expected_dir.join("overlay.verity"));
        assert_eq!(
            installed.roothash_file,
            expected_dir.join("overlay.roothash")
        );
        assert_eq!(installed.version, "0.14.0");
        assert_eq!(installed.arch, "aarch64");

        // Content matches the source verbatim.
        assert_eq!(std::fs::read(&installed.overlay_ext4).unwrap(), source_ext4);
        assert_eq!(std::fs::read(&installed.sidecar).unwrap(), source_sidecar);
        let roothash_text = std::fs::read_to_string(&installed.roothash_file).unwrap();
        assert_eq!(roothash_text.trim(), FAKE_ROOTHASH);
        let version_text = std::fs::read_to_string(expected_dir.join("VERSION")).unwrap();
        assert_eq!(version_text.trim(), "0.14.0");
        let build_epoch =
            std::fs::read_to_string(expected_dir.join(LOCAL_BUILD_EPOCH_FILE)).unwrap();
        assert_eq!(build_epoch.trim(), LOCAL_BUILD_EPOCH);
        let checksums = std::fs::read_to_string(expected_dir.join(CHECKSUM_MANIFEST_FILE)).unwrap();
        assert!(checksums.contains("overlay.ext4"));
        assert!(checksums.contains("overlay.verity"));
        assert!(checksums.contains("overlay.roothash"));
        assert!(checksums.contains("VERSION"));
    }

    #[test]
    fn install_returns_artifact_resolvable_by_runtime_overlay_resolver() {
        // End-to-end: install → resolve must succeed. Closes the
        // producer → cache → consumer loop in a unit test (the real
        // build pipeline has its own Linux integration test).
        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::X86_64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();

        install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .expect("install");

        let resolver =
            RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".to_string());
        let resolved = resolver.resolve("x86_64").expect("resolve");
        assert_eq!(resolved.version, "0.14.0");
        assert_eq!(resolved.arch, "x86_64");
        assert_eq!(resolved.roothash, FAKE_ROOTHASH);
    }

    #[test]
    fn local_source_cache_requires_current_build_epoch_marker() {
        let cache = TempDir::new().unwrap();
        let layout = RuntimeOverlayLayout::under(cache.path(), "0.14.0", "aarch64");
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        std::fs::write(&layout.local_source_fingerprint_file, b"abc\n").unwrap();
        assert!(
            !local_source_cache_is_fresh(&layout, "abc").expect("stale without build epoch"),
            "source-built overlay cache must be invalidated when the host-side build epoch marker is missing"
        );
        std::fs::write(
            &layout.local_build_epoch_file,
            format!("{LOCAL_BUILD_EPOCH}\n"),
        )
        .unwrap();
        assert!(
            local_source_cache_is_fresh(&layout, "abc").expect("fresh with build epoch"),
            "matching fingerprint plus current build epoch must keep the source-built overlay cache hot"
        );
    }

    #[test]
    fn install_is_idempotent_under_default_options() {
        // Second install with overwrite=false short-circuits and
        // returns the cache-view artifact without re-copying.
        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();
        let original_ext4 = std::fs::read(&source.overlay_ext4).unwrap();

        let first = install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .expect("first install");

        // Mutate the source bytes; second install must NOT pick
        // them up under overwrite=false.
        std::fs::write(&source.overlay_ext4, b"mutated-source-bytes").unwrap();

        let second = install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .expect("second install");

        assert_eq!(first.overlay_ext4, second.overlay_ext4);
        let cached_bytes = std::fs::read(&second.overlay_ext4).unwrap();
        assert_eq!(
            cached_bytes, original_ext4,
            "idempotent install must NOT overwrite existing cache content"
        );
    }

    #[test]
    fn install_overwrite_replaces_existing_cache_content() {
        let (keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();

        install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .expect("first install");

        // Rewrite source content; second install with
        // overwrite=true must update the cache.
        std::fs::write(&source.overlay_ext4, b"updated-source-bytes").unwrap();
        std::fs::write(&source.sidecar, b"updated-verity-bytes").unwrap();
        // Keep VERSION + roothash matching to keep the resolver happy.

        let opts = InstallOptions { overwrite: true };
        let installed =
            install_overlay_into_cache(&source, cache.path(), &opts).expect("overwrite install");

        let cached_bytes = std::fs::read(&installed.overlay_ext4).unwrap();
        assert_eq!(cached_bytes, b"updated-source-bytes");
        let cached_sidecar = std::fs::read(&installed.sidecar).unwrap();
        assert_eq!(cached_sidecar, b"updated-verity-bytes");
        drop(keep);
    }

    #[test]
    fn install_fails_when_source_overlay_ext4_missing() {
        let (keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        // Remove the source file but keep the artifact metadata
        // — simulates a half-built artifact handed to the
        // installer.
        std::fs::remove_file(&source.overlay_ext4).unwrap();

        let cache = TempDir::new().unwrap();
        let err = install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .unwrap_err();
        assert!(
            matches!(
                err,
                RuntimeOverlayError::Resolve(OverlayError::ArtifactIncomplete { .. })
            ),
            "{err:?}"
        );
        drop(keep);
    }

    #[test]
    fn install_fails_when_source_version_file_missing() {
        let (keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let source_dir = source.overlay_ext4.parent().unwrap();
        std::fs::remove_file(source_dir.join("VERSION")).unwrap();

        let cache = TempDir::new().unwrap();
        let err = install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .unwrap_err();
        match err {
            RuntimeOverlayError::Resolve(OverlayError::ArtifactIncomplete { missing, .. }) => {
                assert!(
                    missing.ends_with("VERSION"),
                    "expected VERSION missing; got {missing:?}"
                );
            }
            other => panic!("expected ArtifactIncomplete, got {other:?}"),
        }
        drop(keep);
    }

    #[test]
    fn install_creates_intermediate_directories() {
        // Cache root is fresh — no `runtime-overlay/<version>/<arch>/`
        // structure exists. The installer must mkdir -p the path.
        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();

        install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
            .expect("install on empty cache");

        assert!(cache.path().join("runtime-overlay").is_dir());
        assert!(cache.path().join("runtime-overlay/0.14.0").is_dir());
        assert!(cache.path().join("runtime-overlay/0.14.0/aarch64").is_dir());
    }

    #[test]
    fn install_separates_arches_within_the_same_version() {
        let (_keep_a, source_a) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let (_keep_b, source_b) = make_source_artifact("0.14.0", GuestArch::X86_64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();

        install_overlay_into_cache(&source_a, cache.path(), &InstallOptions::default())
            .expect("install aarch64");
        install_overlay_into_cache(&source_b, cache.path(), &InstallOptions::default())
            .expect("install x86_64");

        assert!(
            cache
                .path()
                .join("runtime-overlay/0.14.0/aarch64/overlay.ext4")
                .is_file()
        );
        assert!(
            cache
                .path()
                .join("runtime-overlay/0.14.0/x86_64/overlay.ext4")
                .is_file()
        );
    }

    #[test]
    fn install_separates_versions_within_the_same_arch() {
        let (_keep_a, source_a) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let (_keep_b, source_b) = make_source_artifact("0.15.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();

        install_overlay_into_cache(&source_a, cache.path(), &InstallOptions::default())
            .expect("install 0.14.0");
        install_overlay_into_cache(&source_b, cache.path(), &InstallOptions::default())
            .expect("install 0.15.0");

        assert!(
            cache
                .path()
                .join("runtime-overlay/0.14.0/aarch64/overlay.ext4")
                .is_file()
        );
        assert!(
            cache
                .path()
                .join("runtime-overlay/0.15.0/aarch64/overlay.ext4")
                .is_file()
        );
    }

    #[test]
    fn resolve_seeds_missing_worktree_cache_from_default_cache() {
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path().join("isolated-cache"));

        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let default_cache_root = crate::cache_install::default_cache_root();
        install_overlay_into_cache(&source, &default_cache_root, &InstallOptions::default())
            .expect("install source into default cache");

        let resolver = RuntimeOverlayResolver::new(
            scratch.path().join("isolated-cache"),
            "0.14.0".to_string(),
        );
        let artifact = resolve_or_seed_from_default_cache(&resolver, GuestArch::Aarch64)
            .expect("seeded resolve should succeed");

        let seeded_dir = scratch
            .path()
            .join("isolated-cache")
            .join("runtime-overlay")
            .join("0.14.0")
            .join("aarch64");
        assert_eq!(artifact.overlay_ext4, seeded_dir.join("overlay.ext4"));
        assert!(artifact.overlay_ext4.is_file());
        assert_eq!(
            std::fs::read(seeded_dir.join("overlay.ext4")).unwrap(),
            std::fs::read(default_cache_root.join("runtime-overlay/0.14.0/aarch64/overlay.ext4"))
                .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_chmods_files_to_0644() {
        use std::os::unix::fs::PermissionsExt;
        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);

        // Make source files read-only (0444) to simulate
        // Nix-store paths. The installer must override to 0644
        // so the cache stays overwritable on future installs.
        for p in [&source.overlay_ext4, &source.sidecar, &source.roothash_file] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o444)).unwrap();
        }

        let cache = TempDir::new().unwrap();
        let installed =
            install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
                .expect("install");

        for p in [
            &installed.overlay_ext4,
            &installed.sidecar,
            &installed.roothash_file,
            &installed
                .overlay_ext4
                .parent()
                .expect("artifact dir")
                .join(CHECKSUM_MANIFEST_FILE),
        ] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "cache file {p:?} must be 0644 (got {mode:o})");
        }
    }

    #[test]
    fn install_cleans_up_stale_staging_dir_from_a_previous_crash() {
        // Pre-create a staging dir that the next install will
        // collide with. The installer must remove it and proceed.
        let (_keep, source) = make_source_artifact("0.14.0", GuestArch::Aarch64, FAKE_ROOTHASH);
        let cache = TempDir::new().unwrap();
        let parent = cache.path().join("runtime-overlay/0.14.0");
        std::fs::create_dir_all(&parent).unwrap();
        let staging = parent.join(crate::cache_install::staging_dir_name("aarch64"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("garbage"), b"left over from a crash").unwrap();

        let installed =
            install_overlay_into_cache(&source, cache.path(), &InstallOptions::default())
                .expect("install should clean up staging");
        assert!(installed.overlay_ext4.is_file());
        // The leftover garbage file must not appear in the final
        // artifact dir; only the four expected files are there.
        let final_entries: Vec<_> = std::fs::read_dir(parent.join("aarch64"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !final_entries.iter().any(|n| n == "garbage"),
            "stale staging content must not leak into final cache: {final_entries:?}"
        );
    }

    // ====================================================================
    // download_runtime_overlay tests
    // ====================================================================

    /// `release_base_url` honors `MVM_OVERLAY_BASE_URL`. Pinned via a
    /// mutex so concurrent tests don't fight over the env var.
    #[test]
    fn release_base_url_honors_env_override() {
        // `TestEnv` serializes env-mutating tests in this process behind a
        // shared lock and restores the prior value on drop.
        let mut env = TestEnv::new();
        env.set("MVM_OVERLAY_BASE_URL", "https://mirror.example.com/mvm");
        let url = release_base_url("9.9.9");
        assert_eq!(url, "https://mirror.example.com/mvm/v9.9.9");
        env.remove("MVM_OVERLAY_BASE_URL");
    }

    #[test]
    fn release_base_url_falls_back_to_default_without_env() {
        let mut env = TestEnv::new();
        env.remove("MVM_OVERLAY_BASE_URL");
        let url = release_base_url("0.14.0");
        assert_eq!(
            url,
            "https://github.com/tinylabscom/mvm/releases/download/v0.14.0"
        );
    }

    #[test]
    fn release_base_url_strips_trailing_slash_on_override() {
        let mut env = TestEnv::new();
        env.set("MVM_OVERLAY_BASE_URL", "https://mirror.example.com/mvm/");
        let url = release_base_url("9.9.9");
        assert_eq!(url, "https://mirror.example.com/mvm/v9.9.9");
        env.remove("MVM_OVERLAY_BASE_URL");
    }

    /// End-to-end download flow against a `file://` fixture: stage
    /// a tarball + archive checksum sidecar under names matching the
    /// release-pipeline layout, point
    /// `MVM_OVERLAY_BASE_URL` at the fixture dir, and assert the
    /// installer materializes everything correctly into the cache.
    /// Exercises every code path except the actual GitHub network
    /// hop — same wire format, same archive verification, same
    /// inner-manifest verification, same atomic install.
    ///
    /// `file://` URLs work with curl (`-fSL`) the same way HTTP
    /// URLs do, so the test exercises the exact code path
    /// production hits.
    #[test]
    fn download_runtime_overlay_end_to_end_against_file_url_fixture() {
        // SAFETY: must serialize against other env-touching tests
        // in this module.
        let mut env = TestEnv::new();

        let upstream = TempDir::new().unwrap();
        let release_dir = upstream.path().join("v9.9.9");
        std::fs::create_dir_all(&release_dir).unwrap();

        // Fixture bytes — the actual contents don't matter for the
        // download path, only their checksums.
        let ext4_bytes = b"fake-ext4-bytes";
        let verity_bytes = b"fake-verity-sidecar";
        let roothash_text = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        let version_text = "9.9.9\n";
        let archive_bytes = runtime_overlay_archive_bytes(
            ext4_bytes,
            verity_bytes,
            roothash_text.as_bytes(),
            version_text.as_bytes(),
        );
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz",
            &archive_bytes,
        );
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz.sha256",
            format!(
                "{}  runtime-overlay-aarch64.tar.gz\n",
                sha256_hex(&archive_bytes)
            )
            .as_bytes(),
        );

        let base_url = format!("file://{}", upstream.path().display());
        env.set("MVM_OVERLAY_BASE_URL", &base_url);
        // A valid Sigstore signature cannot be minted offline, and this test is
        // about the digest, extraction, and install rungs. The signature rung
        // has its own witnesses in `crate::release_signature` and below.
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");

        let cache = TempDir::new().unwrap();
        let result = download_runtime_overlay("9.9.9", GuestArch::Aarch64, cache.path());

        env.remove("MVM_OVERLAY_BASE_URL");

        let installed = result.expect("download + install must succeed against fixture");
        assert_eq!(installed.arch, "aarch64");
        assert_eq!(installed.version, "9.9.9");
        assert_eq!(
            installed.roothash,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert!(installed.overlay_ext4.is_file());
        assert!(installed.sidecar.is_file());
        assert!(installed.roothash_file.is_file());
        // Canonical names in the cache (no `runtime-overlay-` prefix).
        let cache_dir = cache.path().join("runtime-overlay/9.9.9/aarch64");
        assert!(cache_dir.join("overlay.ext4").is_file());
        assert!(cache_dir.join("overlay.verity").is_file());
        assert!(cache_dir.join("overlay.roothash").is_file());
        assert!(cache_dir.join("VERSION").is_file());
        assert!(
            crate::guest_agent_build::cached_guest_binaries(
                &cache.path().join("oci"),
                "9.9.9",
                GuestArch::Aarch64,
            )
            .is_some(),
            "the published overlay must seed OCI materialization shims"
        );
        assert_eq!(
            std::fs::read(cache_dir.join("overlay.ext4")).unwrap(),
            ext4_bytes
        );
    }

    /// The overlay carries the same signature rung the sidecar does: a release
    /// that publishes an archive with no signature beside it is refused, and
    /// nothing lands in the cache — even though its digest matches.
    #[test]
    fn download_runtime_overlay_refuses_an_unsigned_archive() {
        let mut env = TestEnv::new();
        let upstream = TempDir::new().unwrap();
        let release_dir = upstream.path().join("v9.9.9");
        std::fs::create_dir_all(&release_dir).unwrap();

        let archive_bytes = b"not-even-a-real-archive".to_vec();
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz",
            &archive_bytes,
        );
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz.sha256",
            format!(
                "{}  runtime-overlay-aarch64.tar.gz\n",
                sha256_hex(&archive_bytes)
            )
            .as_bytes(),
        );

        env.set(
            "MVM_OVERLAY_BASE_URL",
            format!("file://{}", upstream.path().display()),
        );
        env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);

        let cache = TempDir::new().unwrap();
        let err = download_runtime_overlay("9.9.9", GuestArch::Aarch64, cache.path())
            .expect_err("an unsigned overlay archive must not install");

        let rendered = err.to_string();
        assert!(
            rendered.contains("signature") || rendered.contains("bundle"),
            "the refusal must be about the signature: {rendered}"
        );
        assert!(
            !cache.path().join("runtime-overlay/9.9.9/aarch64").exists(),
            "a refused download must cache nothing"
        );
    }

    /// A tampered artifact whose sha doesn't match the manifest
    /// must be rejected, the bad file deleted, and the cache left
    /// unchanged. This is the fail-closed integrity contract.
    #[test]
    fn download_runtime_overlay_rejects_checksum_mismatch() {
        let mut env = TestEnv::new();

        let upstream = TempDir::new().unwrap();
        let release_dir = upstream.path().join("v9.9.9");
        std::fs::create_dir_all(&release_dir).unwrap();

        let expected_archive_bytes = runtime_overlay_archive_bytes(
            b"the-real-ext4-bytes",
            b"v",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            b"9.9.9\n",
        );
        let tampered_archive_bytes = runtime_overlay_archive_bytes(
            b"tampered!",
            b"v",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            b"9.9.9\n",
        );
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz",
            &tampered_archive_bytes,
        );
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz.sha256",
            format!(
                "{}  runtime-overlay-aarch64.tar.gz\n",
                sha256_hex(&expected_archive_bytes)
            )
            .as_bytes(),
        );

        let base_url = format!("file://{}", upstream.path().display());
        env.set("MVM_OVERLAY_BASE_URL", &base_url);
        let cache = TempDir::new().unwrap();
        let result = download_runtime_overlay("9.9.9", GuestArch::Aarch64, cache.path());
        env.remove("MVM_OVERLAY_BASE_URL");

        let err = result.expect_err("tampered ext4 must reject");
        match err {
            RuntimeOverlayError::ChecksumMismatch { name, .. } => {
                assert_eq!(name, "runtime-overlay-aarch64.tar.gz");
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
        // The cache must NOT have been populated.
        assert!(!cache.path().join("runtime-overlay/9.9.9/aarch64").exists());
    }

    /// An archive checksum sidecar missing the tarball entry aborts before the
    /// archive is fetched.
    #[test]
    fn download_runtime_overlay_rejects_missing_checksum_entry() {
        let mut env = TestEnv::new();

        let upstream = TempDir::new().unwrap();
        let release_dir = upstream.path().join("v9.9.9");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Sidecar lists the wrong name, not the archive we need.
        let checksums = "\
0000000000000000000000000000000000000000000000000000000000000001  runtime-overlay-aarch64-not-it.tar.gz
";
        write_fixture(
            &release_dir,
            "runtime-overlay-aarch64.tar.gz.sha256",
            checksums.as_bytes(),
        );

        let base_url = format!("file://{}", upstream.path().display());
        env.set("MVM_OVERLAY_BASE_URL", &base_url);
        let cache = TempDir::new().unwrap();
        let result = download_runtime_overlay("9.9.9", GuestArch::Aarch64, cache.path());
        env.remove("MVM_OVERLAY_BASE_URL");

        let err = result.expect_err("missing archive checksum entry must reject");
        match err {
            RuntimeOverlayError::ChecksumMissing { name, .. } => {
                assert_eq!(name, "runtime-overlay-aarch64.tar.gz");
            }
            other => panic!("expected ChecksumMissing, got {other:?}"),
        }
    }

    #[test]
    fn published_guest_runtime_requires_an_inner_checksum_for_every_binary() {
        let stage = TempDir::new().unwrap();
        for name in RELEASE_GUEST_RUNTIME_FILES {
            std::fs::write(
                stage.path().join(name),
                crate::guest_agent_build::fake_static_elf(GuestArch::Aarch64, name.as_bytes()),
            )
            .unwrap();
        }
        std::fs::write(stage.path().join(CHECKSUM_MANIFEST_FILE), "").unwrap();

        let err = verify_release_guest_runtime(stage.path())
            .expect_err("unsigned inner guest binaries must be refused");
        match err {
            RuntimeOverlayError::ChecksumMissing { name, .. } => {
                assert_eq!(name, "mvm-oci-init");
            }
            other => panic!("expected ChecksumMissing, got {other:?}"),
        }
    }

    fn runtime_overlay_archive_bytes(
        ext4_bytes: &[u8],
        verity_bytes: &[u8],
        roothash_bytes: &[u8],
        version_bytes: &[u8],
    ) -> Vec<u8> {
        let guest_files: Vec<(&str, Vec<u8>)> = RELEASE_GUEST_RUNTIME_FILES
            .iter()
            .map(|name| {
                (
                    *name,
                    crate::guest_agent_build::fake_static_elf(GuestArch::Aarch64, name.as_bytes()),
                )
            })
            .collect();
        let mut checksums = format!(
            "{}  overlay.ext4\n{}  overlay.verity\n{}  overlay.roothash\n{}  VERSION\n",
            sha256_hex(ext4_bytes),
            sha256_hex(verity_bytes),
            sha256_hex(roothash_bytes),
            sha256_hex(version_bytes),
        );
        for (name, bytes) in &guest_files {
            checksums.push_str(&format!("{}  {name}\n", sha256_hex(bytes)));
        }
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        append_archive_file(&mut tar, "overlay.ext4", ext4_bytes);
        append_archive_file(&mut tar, "overlay.verity", verity_bytes);
        append_archive_file(&mut tar, "overlay.roothash", roothash_bytes);
        append_archive_file(&mut tar, "VERSION", version_bytes);
        for (name, bytes) in &guest_files {
            append_archive_file(&mut tar, name, bytes);
        }
        append_archive_file(&mut tar, CHECKSUM_MANIFEST_FILE, checksums.as_bytes());
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn append_archive_file<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }

    fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(dir.join(name), bytes).expect("write fixture");
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn direct_overlay_build_writes_cache_layout() {
        let cache = TempDir::new().unwrap();
        let src = TempDir::new().unwrap();
        let make_bin = |name: &str| {
            let path = src.path().join(name);
            std::fs::write(&path, format!("fake-{name}")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            path
        };
        let bins = RuntimeOverlayGuestBinaries {
            agent: make_bin("agent"),
            netinit: make_bin("netinit"),
            ping: make_bin("ping"),
            seccomp_apply: make_bin("seccomp-apply"),
            runner: make_bin("runner"),
            egress_client: make_bin("egress-client"),
            addon_dns: make_bin("addon-dns"),
            exit_report: make_bin("exit-report"),
            forward_proxy: make_bin("forward-proxy"),
            verity_init: make_bin("verity-init"),
            forward_proxy: make_bin("forward-proxy"),
        };

        let artifact = build_runtime_overlay_from_guest_binaries(
            cache.path(),
            "1.2.3",
            GuestArch::X86_64,
            &bins,
        )
        .expect("build direct overlay");

        assert!(artifact.overlay_ext4.is_file());
        assert!(artifact.sidecar.is_file());
        assert_eq!(artifact.version, "1.2.3");
        assert_eq!(artifact.roothash.len(), 64);

        mvm_fs::overlay::validate_overlay_payload(&artifact.overlay_ext4)
            .expect("direct overlay carries all required guest paths");
    }

    /// The overlay's per-file mode is copied from the staged file, masked
    /// to the permission bits. Nothing asserted that, and the mutants it
    /// admitted are not cosmetic: turning the mask `&` into `|` yields
    /// 0o7777 for *every* file in the overlay — world-writable, setuid,
    /// setgid, sticky — and `^` inverts whatever the real mode was.
    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn overlay_mode_is_the_files_own_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");

        for mode in [0o644u32, 0o755, 0o600] {
            let f = tmp.path().join(format!("f{mode:o}"));
            std::fs::write(&f, b"x").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            let got = overlay_mode_of(&f, 0o400);
            assert_eq!(
                u32::from(got),
                mode,
                "the overlay mode must be the file's own permission bits"
            );
            // The masked-widening mutant lands here: 0o7777 is every
            // permission bit including setuid and setgid.
            assert_ne!(got, 0o7777, "the overlay must never widen a file to 0o7777");
        }

        // An absent path falls back to the caller's default rather than
        // inventing a mode.
        let absent = tmp.path().join("not-there");
        assert_eq!(overlay_mode_of(&absent, 0o644), 0o644);
        assert_eq!(overlay_mode_of(&absent, 0o755), 0o755);
    }

    /// The guest path is the staged path made absolute relative to the
    /// overlay root. A constant here silently collapses every file in the
    /// overlay onto one guest path.
    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn overlay_guest_path_is_rooted_and_distinct_per_file() {
        let root = Path::new("/stage/overlay");
        assert_eq!(
            overlay_guest_path(root, Path::new("/stage/overlay/usr/bin/agent")),
            "/usr/bin/agent"
        );
        assert_eq!(
            overlay_guest_path(root, Path::new("/stage/overlay/init")),
            "/init"
        );
        // Two different staged files must not map to the same guest path.
        assert_ne!(
            overlay_guest_path(root, Path::new("/stage/overlay/a")),
            overlay_guest_path(root, Path::new("/stage/overlay/b"))
        );
        // A path outside the root is still rooted rather than dropped.
        assert_eq!(
            overlay_guest_path(root, Path::new("elsewhere")),
            "/elsewhere"
        );
    }

    /// Completeness is a conjunction: every one of the five artifacts has
    /// to be there. Weakened to a disjunction, a cache holding one file
    /// reads as a complete overlay and the resolver serves it.
    #[test]
    fn a_cache_is_complete_only_when_every_artifact_is_present() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Build the layout the way production does, so the test cannot
        // drift from the real artifact names.
        let layout = RuntimeOverlayLayout::under(tmp.path(), "1.2.3", "aarch64");
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let every = [
            &layout.overlay_ext4,
            &layout.sidecar,
            &layout.roothash_file,
            &layout.version_file,
            &layout.checksum_manifest_file,
        ];

        assert!(
            !all_required_files_present(&layout),
            "an empty cache dir is not a complete overlay"
        );

        // Each artifact alone is still incomplete.
        for present in every {
            std::fs::write(present, b"x").unwrap();
            assert!(
                !all_required_files_present(&layout),
                "{} alone is not a complete overlay",
                present.display()
            );
            std::fs::remove_file(present).unwrap();
        }

        // Every artifact but one. This is the case a single-file fixture
        // cannot reach: weakening any `&&` to `||` splits the chain into
        // two groups, and a one-file cache leaves both groups false, so
        // the result is unchanged. Only a cache that satisfies one whole
        // group while missing a member of the other tells them apart.
        for missing in every {
            for f in every {
                std::fs::write(f, b"x").unwrap();
            }
            std::fs::remove_file(missing).unwrap();
            assert!(
                !all_required_files_present(&layout),
                "a cache missing only {} is not complete",
                missing.display()
            );
            for f in every {
                let _ = std::fs::remove_file(f);
            }
        }

        for f in every {
            std::fs::write(f, b"x").unwrap();
        }
        assert!(
            all_required_files_present(&layout),
            "all five artifacts present is a complete overlay"
        );
    }
}
