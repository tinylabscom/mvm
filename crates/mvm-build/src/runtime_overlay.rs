//! Build, download, and install the mvm runtime overlay disk.
//!
//! Every microVM mvm boots — Nix-built rootfs and OCI-pulled rootfs alike —
//! attaches a second virtio-blk device carrying the guest agent + seccomp
//! shim + runner + per-language SDK runtime libraries. Picking a cached
//! artifact and validating it is the resolve half and lives in
//! [`mvm_fs::overlay`] (its main names are re-exported here); this module
//! owns how an artifact *lands* in the cache in the first place:
//!
//! 1. **Build from a source checkout.** A contributor acquires one verified
//!    guest-runtime tree shared with initramfs and SDK sidecar assembly, then
//!    [`build_runtime_overlay_from_guest_runtime`] assembles the ext4 and
//!    its verity sidecar in-process. No image flake is involved.
//! 2. **Download from the image set.** [`download_runtime_overlay`] fetches
//!    the per-arch tarball as a member of the signed image set this build
//!    pins, holds it to the digest the verified root declares, and installs
//!    it.
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
    verify_overlay_dir_integrity,
};
pub use mvm_fs::overlay::{
    RuntimeOverlayArtifact, RuntimeOverlayArtifactNames, RuntimeOverlayLayout,
    RuntimeOverlayResolver, read_overlay_artifact_from_dir,
};

use crate::guest_agent_build::RuntimeOverlayGuestBinaries;
use crate::published_image_set::{MemberVersion, PublishedImageSet, SetMemberCache};
use mvm_core::image_set::{ImageSetRole, MemberTarget};

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

    /// An io failure that knows the operation and the path it failed on.
    #[error("{op} {}: {source}", .path.display())]
    IoAt {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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
    #[error("direct runtime overlay build failed: {reason}")]
    DirectBuildFailed { reason: String },

    /// The image set this build pins could not be acquired and verified, so
    /// no member of it can be trusted.
    #[error("{0:#}")]
    ImageSet(anyhow::Error),

    /// The verified image set could not deliver the member asked for: it
    /// declares none, or the bytes served are not the ones it declares.
    /// Boxed so the rare refusal does not widen every `Result` this crate
    /// returns.
    #[error(transparent)]
    ImageSetMember(Box<crate::published_image_set::ImageSetMemberError>),

    /// No usable member of the pinned image set is installed in the cache, or
    /// the one delivered carries a `VERSION` that cannot name a cache entry.
    #[error(transparent)]
    ImageSetCache(#[from] crate::published_image_set::SetMemberCacheError),
}

impl From<crate::published_image_set::ImageSetMemberError> for RuntimeOverlayError {
    fn from(error: crate::published_image_set::ImageSetMemberError) -> Self {
        Self::ImageSetMember(Box::new(error))
    }
}

const DIRECT_OVERLAY_VERITY_SALT: [u8; 32] = [0u8; 32];
const DIRECT_OVERLAY_DATA_BLOCK_SIZE: u32 = 4096;
const DIRECT_OVERLAY_HASH_BLOCK_SIZE: u32 = 4096;
// Bump whenever the packaging logic in this file changes in a way the source
// fingerprint doesn't cover (that hash only walks crate sources, not this
// file) — forces a locally cached overlay to rebuild instead of reusing
// stale staged content.
const LOCAL_BUILD_EPOCH: &str = "5";

const GUEST_RUNTIME_OVERLAY_BINARIES: [(&str, &str); 9] = [
    ("mvm-guest-agent", "agent"),
    ("mvm-guest-netinit", "netinit"),
    ("mvm-ping", "ping"),
    ("mvm-seccomp-apply", "seccomp-apply"),
    ("mvm-display-bridge", "display-bridge"),
    ("mvm-runner", "runner"),
    ("mvm-egress-client", "egress-client"),
    ("mvm-addon-dns", "addon-dns"),
    ("mvm-exit-report", "exit-report"),
];
const GPU_SHIM_SONAMES: [&str; 3] = ["libcuda.so.1", "libcudart.so", "libnvidia-ml.so.1"];

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

/// Resolve `arch`'s overlay installed from the image set `set`, a pure cache
/// read.
///
/// The entry's resolver expects the `VERSION` recorded when the member was
/// installed from its digest-verified bytes, not the running CLI's version:
/// the member belongs to the pinned root, and a CLI version bump does not
/// change which root is pinned. Every other check the resolver makes applies
/// unchanged.
pub fn resolve_image_set_runtime_overlay(
    cache_root: &Path,
    set: &SetMemberCache,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let version = set.installed_version(
        cache_root,
        ImageSetRole::RuntimeOverlay,
        MemberTarget::Arch(arch),
    )?;
    Ok(
        RuntimeOverlayResolver::new(set.cache_root(cache_root), version.into())
            .resolve(&arch.to_string())?,
    )
}

/// Resolve the overlay a boot of this host would attach, from cache alone:
/// the entry matching `resolver`'s version (seeded from the default cache on a
/// miss), and otherwise the one installed from the image set this build pins.
/// A miss in both surfaces the version-matched resolve error.
pub fn resolve_cached_runtime_overlay(
    resolver: &RuntimeOverlayResolver,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    resolve_or_seed_from_default_cache(resolver, arch).or_else(|version_matched| {
        resolve_image_set_runtime_overlay(resolver.cache_root(), &SetMemberCache::locked(), arch)
            .map_err(|_| version_matched)
    })
}

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
        (&bins.display_bridge, root.join("display-bridge")),
        (&bins.runner, root.join("runner")),
        (&bins.egress_client, root.join("egress-client")),
        (&bins.addon_dns, root.join("addon-dns")),
        (&bins.exit_report, root.join("exit-report")),
    ];
    par_map(binaries.to_vec(), |(src, dst)| {
        stage_runtime_overlay_binary(src, &dst)
    })
    .into_iter()
    .collect::<Result<(), _>>()?;
    assemble_runtime_overlay(cache_root, version, arch, &root, &staging)
}

/// Assemble the runtime overlay from one verified guest-runtime tree. The
/// archive member names are the only source of files admitted to the image;
/// the staging tree does not inherit unrelated files from a source checkout.
pub fn build_runtime_overlay_from_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    runtime: &crate::guest_runtime::GuestRuntime,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    if runtime.manifest.version != version {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: format!(
                "guest runtime version {} does not match overlay version {version}",
                runtime.manifest.version
            ),
        });
    }
    let resolver = RuntimeOverlayResolver::new(cache_root.to_path_buf(), version.to_string());
    if local_source_cache_is_fresh(&resolver.layout(&arch.to_string()), &runtime.digest)?
        && let Ok(cached) = resolver.resolve(&arch.to_string())
        && verify_guest_runtime_overlay_verity(&cached).is_ok()
    {
        return Ok(cached);
    }
    let staging = tempfile::tempdir()?;
    let root = staging.path().join("overlay-root");
    std::fs::create_dir_all(&root)?;
    stage_guest_runtime_overlay_tree(runtime, arch, &root)?;
    let artifact = assemble_runtime_overlay(cache_root, version, arch, &root, &staging)?;
    verify_guest_runtime_overlay_verity(&artifact)?;
    write_local_source_fingerprint(cache_root, version, arch, &runtime.digest)?;
    write_local_build_epoch(cache_root, version, arch)?;
    Ok(artifact)
}

fn stage_guest_runtime_overlay_tree(
    runtime: &crate::guest_runtime::GuestRuntime,
    arch: GuestArch,
    root: &Path,
) -> Result<(), RuntimeOverlayError> {
    for (archive_name, overlay_name) in GUEST_RUNTIME_OVERLAY_BINARIES {
        let member = format!("{arch}/bin/{archive_name}");
        stage_guest_runtime_member(runtime, &member, &root.join(overlay_name), 0o555)?;
    }
    for libc in [
        crate::guest_libc::GuestLibc::Glibc,
        crate::guest_libc::GuestLibc::Musl,
    ] {
        for soname in GPU_SHIM_SONAMES {
            let member = format!("{arch}/lib/{libc}/{soname}");
            stage_guest_runtime_member(
                runtime,
                &member,
                &root.join("gpu").join(libc.as_str()).join(soname),
                0o555,
            )?;
        }
    }
    let sdk_prefix = "sdk-py/mvm/";
    let sdk_members: Vec<&String> = runtime
        .manifest
        .files
        .keys()
        .filter(|member| member.starts_with(sdk_prefix))
        .collect();
    if !sdk_members
        .iter()
        .any(|member| member.as_str() == "sdk-py/mvm/__init__.py")
    {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: "guest runtime contains no Python SDK package initializer".into(),
        });
    }
    for member in sdk_members {
        let parsed = crate::guest_bins::GuestBinsMember::parse(member).map_err(|e| {
            RuntimeOverlayError::DirectBuildFailed {
                reason: format!("invalid Python SDK archive member {member:?}: {e}"),
            }
        })?;
        if !matches!(parsed, crate::guest_bins::GuestBinsMember::PythonSdk { .. }) {
            return Err(RuntimeOverlayError::DirectBuildFailed {
                reason: format!("archive member {member:?} is not a Python SDK file"),
            });
        }
        stage_guest_runtime_member(runtime, member, &root.join(member), 0o644)?;
    }
    Ok(())
}

fn stage_guest_runtime_member(
    runtime: &crate::guest_runtime::GuestRuntime,
    member: &str,
    destination: &Path,
    mode: u32,
) -> Result<(), RuntimeOverlayError> {
    let Some(expected_digest) = runtime.manifest.files.get(member) else {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: format!("guest runtime manifest does not contain {member}"),
        });
    };
    let source = runtime.root.join(member);
    if !std::fs::symlink_metadata(&source).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: format!("guest runtime member is not a regular file: {member}"),
        });
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(&source, destination)?;
    if compute_file_sha256(destination)? != *expected_digest {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: format!("guest runtime member changed while staging: {member}"),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

fn assemble_runtime_overlay(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    root: &Path,
    staging: &tempfile::TempDir,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    std::fs::write(root.join("VERSION"), format!("{version}\n"))?;

    let image = mvm_fs::ext4::build_image(collect_overlay_nodes(root)?, &Default::default())
        .map_err(|e| RuntimeOverlayError::DirectBuildFailed {
            reason: format!("build ext4 image: {e}"),
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

fn verify_guest_runtime_overlay_verity(
    artifact: &RuntimeOverlayArtifact,
) -> Result<(), RuntimeOverlayError> {
    let image = std::fs::read(&artifact.overlay_ext4)?;
    let tree = std::fs::read(&artifact.sidecar)?;
    let expected = mvm_fs::ext4::verity::format(
        &image,
        &DIRECT_OVERLAY_VERITY_SALT,
        DIRECT_OVERLAY_DATA_BLOCK_SIZE as usize,
        DIRECT_OVERLAY_HASH_BLOCK_SIZE as usize,
    );
    if expected.hash_tree != tree
        || mvm_fs::ext4::verity::to_hex(&expected.root_hash) != artifact.roothash
    {
        return Err(RuntimeOverlayError::DirectBuildFailed {
            reason: "runtime overlay ext4, verity tree, and roothash disagree".into(),
        });
    }
    Ok(())
}

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
                    owner: mvm_fs::ext4::Owner::ROOT,
                });
            } else if file_type.is_dir() {
                out.push(mvm_fs::ext4::Node::Dir {
                    path: overlay_guest_path(root, &path),
                    mode: overlay_mode_of(&path, 0o755),
                    xattrs: Vec::new(),
                    owner: mvm_fs::ext4::Owner::ROOT,
                });
                stack.push(path);
            } else if file_type.is_file() {
                out.push(mvm_fs::ext4::Node::File {
                    path: overlay_guest_path(root, &path),
                    mode: overlay_mode_of(&path, 0o644),
                    data: std::fs::read(&path)?,
                    xattrs: Vec::new(),
                    owner: mvm_fs::ext4::Owner::ROOT,
                });
            }
        }
    }
    Ok(out)
}

fn overlay_guest_path(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => format!("/{}", path.to_string_lossy()),
    }
}

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
        return resolve_cached_runtime_overlay(&resolver, arch);
    };
    let runtime = crate::guest_runtime::resolve_or_build_source_guest_runtime(
        cache_root,
        version,
        arch,
        &workspace_root,
    )
    .map_err(|e| RuntimeOverlayError::DirectBuildFailed {
        reason: format!("acquire guest runtime for overlay: {e}"),
    })?;
    // Seeding is best-effort; the assembler owns the single cache-admission
    // decision, including source freshness and verification of the verity tree.
    if let Err(error) = resolve_or_seed_from_default_cache(&resolver, arch) {
        tracing::info!(
            cache_root = %cache_root.display(),
            version,
            arch = %arch,
            %error,
            "runtime overlay cache miss or invalid payload; rebuilding from source checkout"
        );
    }
    build_runtime_overlay_from_guest_runtime(cache_root, version, arch, &runtime)
}

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

fn runtime_overlay_source_checkout_root() -> Option<PathBuf> {
    crate::image_source::guest_runtime_source_checkout()
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
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).map_err(|source| {
        RuntimeOverlayError::IoAt {
            op: "setting cache permissions on",
            path: p.to_path_buf(),
            source,
        }
    })
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

/// Documented escape hatch — bypass the SHA-256
/// integrity check when an emergency rotation requires it. Never set
/// in CI. Matches the env var name honoured by `verify_artifact_hash` on the
/// CLI's download path, so the operator runbook covers both.
pub(crate) const SKIP_HASH_VERIFY_ENV: &str = "MVM_SKIP_HASH_VERIFY";

/// Download the runtime overlay tarball for `arch` as a member of the image
/// set this build pins, safely extract it, re-verify each inner artifact
/// against the archive's embedded `checksums-sha256.txt`, and install it as a
/// member of that set (see [`install_image_set_runtime_overlay_archive`]).
///
/// The archive is trusted only through the set: the root manifest is held to
/// its locked digest and its publisher's signature, and the archive to the
/// size and digest that root declares, all before extraction.
///
/// `guest_runtime_key` is the key the OCI guest runtime binaries the archive
/// also carries are cached under — the running CLI's guest-binary source key.
///
/// Returns the installed `RuntimeOverlayArtifact` so the caller
/// can hand it straight to the backend.
pub fn download_runtime_overlay(
    guest_runtime_key: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let image_set = PublishedImageSet::acquire().map_err(RuntimeOverlayError::ImageSet)?;
    download_runtime_overlay_from(&image_set, guest_runtime_key, arch, cache_root)
}

/// [`download_runtime_overlay`] from a set that has already been acquired.
pub fn download_runtime_overlay_from(
    image_set: &PublishedImageSet,
    guest_runtime_key: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let names = RuntimeOverlayArtifactNames::for_arch(&arch.to_string());
    let tmp = tempfile::tempdir()?;
    let archive_local = tmp.path().join(&names.archive);
    image_set.fetch_member_artifact(
        ImageSetRole::RuntimeOverlay,
        arch,
        &names.archive,
        &archive_local,
    )?;
    install_image_set_runtime_overlay_archive(
        &archive_local,
        &image_set.member_cache(),
        guest_runtime_key,
        arch,
        cache_root,
    )
}

/// Fetch `asset` from the per-version directory `release_url` of a CLI
/// release, the way clients that predate the image set acquire it: its
/// `.sha256` sidecar first, then the archive held to that digest, then the
/// archive held to the CLI release workflow's signing identity.
///
/// The CLI release still publishes these archives for those clients, and its
/// workflow proves each one survives this path before publishing.
pub fn fetch_cli_release_archive(
    release_url: &str,
    version: &str,
    asset: &str,
    dest: &Path,
) -> Result<(), RuntimeOverlayError> {
    let expected = fetch_expected_hashes(&format!("{release_url}/{asset}.sha256"), &[asset])?;
    curl_download(&format!("{release_url}/{asset}"), dest)?;
    verify_file_sha256(dest, asset, expected.get(asset))?;
    crate::release_signature::verify_release_archive_signature(
        &crate::release_signature::ReleaseSignatureRequest {
            base_url: release_url,
            asset,
            archive_path: dest,
            version,
            train: crate::release_signature::ReleaseTrain::Cli,
        },
    )
    .map(|_| ())
}

/// Install an authenticated runtime overlay archive published per CLI
/// version: safely extract it, re-verify each inner artifact against the
/// archive's own manifest, seed the OCI guest runtime from it, and install the
/// overlay atomically under `<cache_root>/runtime-overlay/<version>/<arch>/`,
/// where a resolver expecting `version` will find it.
///
/// The caller must have authenticated `archive` already — tar extraction is
/// an attack surface, and an unauthenticated archive is never parsed.
pub fn install_runtime_overlay_archive(
    archive: &Path,
    version: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let tmp = tempfile::tempdir()?;
    let staged = stage_runtime_overlay_archive(archive, tmp.path(), version, arch, cache_root)?;
    install_overlay_into_cache(
        &RuntimeOverlayArtifact {
            version: version.to_string(),
            ..staged
        },
        cache_root,
        &InstallOptions { overwrite: true },
    )
}

/// Install an authenticated runtime overlay archive delivered as a member of
/// the image set `set`, filed under that set's root rather than any CLI
/// version.
///
/// The entry is labelled with the member's own `VERSION`, read from the
/// verified bytes, and that version is recorded as what the entry's resolver
/// must expect. The record is written only once the overlay is in place, so
/// an interrupted install reads as a miss and is acquired again.
pub fn install_image_set_runtime_overlay_archive(
    archive: &Path,
    set: &SetMemberCache,
    guest_runtime_key: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    let tmp = tempfile::tempdir()?;
    let staged =
        stage_runtime_overlay_archive(archive, tmp.path(), guest_runtime_key, arch, cache_root)?;
    let version = MemberVersion::parse(&staged.version)?;
    let installed = install_overlay_into_cache(
        &RuntimeOverlayArtifact {
            version: version.as_str().to_string(),
            ..staged
        },
        &set.cache_root(cache_root),
        &InstallOptions { overwrite: true },
    )?;
    set.record(
        cache_root,
        ImageSetRole::RuntimeOverlay,
        MemberTarget::Arch(arch),
        &version,
    )?;
    Ok(installed)
}

/// Extract an authenticated overlay archive into `stage`, re-verify it against
/// its own manifest, and seed the OCI guest runtime it carries under
/// `guest_runtime_key`. Returns the staged overlay labelled with its own
/// `VERSION` and a validated roothash — the value the backend bakes into the
/// kernel cmdline (`mvm.runtime_roothash=…`).
fn stage_runtime_overlay_archive(
    archive: &Path,
    stage: &Path,
    guest_runtime_key: &str,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<RuntimeOverlayArtifact, RuntimeOverlayError> {
    extract_release_archive(archive, stage, &OVERLAY_ARCHIVE_MEMBERS)?;
    verify_overlay_dir_integrity(stage)?;
    verify_release_guest_runtime(stage)?;

    crate::guest_agent_build::install_into_cache(
        crate::guest_agent_build::GuestRuntimeBinaryPaths {
            agent: &stage.join("mvm-guest-agent"),
            netinit: &stage.join("mvm-guest-netinit"),
            egress_client: &stage.join("mvm-egress-client"),
            entrypoint_runner: &stage.join("mvm-oci-entrypoint"),
        },
        &cache_root.join("oci"),
        guest_runtime_key,
        arch,
    )?;

    Ok(read_overlay_artifact_from_dir(stage, &arch.to_string())?)
}

/// Exactly the members the overlay's release tarball may carry. Doubles as the
/// extraction allow-list and the completeness check — an archive carrying
/// anything else, or missing any of these, is refused.
const RELEASE_GUEST_RUNTIME_FILES: [&str; 4] =
    crate::guest_agent_build::OCI_GUEST_RUNTIME_BINARY_NAMES;

const OVERLAY_ARCHIVE_MEMBERS: [&str; 9] = [
    "overlay.ext4",
    "overlay.verity",
    "overlay.roothash",
    "VERSION",
    "mvm-guest-agent",
    "mvm-guest-netinit",
    "mvm-egress-client",
    "mvm-oci-entrypoint",
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
    // Release bundles contain several executables, unlike the single initramfs
    // image. Bound expansion while leaving room for larger runtime binaries.
    extract_release_archive_with_limits(
        archive_path,
        stage,
        expected,
        ExpandedArchiveLimits {
            file_bytes: 128 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
        },
    )
}

#[derive(Clone, Copy)]
pub(crate) struct ExpandedArchiveLimits {
    pub(crate) file_bytes: u64,
    pub(crate) total_bytes: u64,
}

impl ExpandedArchiveLimits {
    // Canonical bundles have only a handful of flat files. 64 KiB covers
    // their headers, block padding and optional GNU/PAX metadata generously.
    const TAR_FRAMING_BYTES: u64 = 64 * 1024;

    pub(crate) fn archive_reader<R: std::io::Read>(&self, reader: R) -> std::io::Take<R> {
        reader.take(self.total_bytes.saturating_add(Self::TAR_FRAMING_BYTES))
    }

    /// Account for bytes after tar's end marker too. `Take` bounds metadata
    /// consumed internally by tar; probing its underlying reader distinguishes
    /// a real EOF from a stream truncated at the expansion ceiling.
    pub(crate) fn finish_archive<R: std::io::Read>(
        mut reader: std::io::Take<R>,
    ) -> std::io::Result<()> {
        std::io::copy(&mut reader, &mut std::io::sink())?;
        if reader.limit() == 0 && reader.get_mut().read(&mut [0u8; 1])? != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expanded tar stream budget exceeded",
            ));
        }
        Ok(())
    }

    /// Copy at most the per-file and remaining aggregate budgets. The probe
    /// reads one extra byte but never writes it, including at an exact fit.
    pub(crate) fn copy_entry(
        &self,
        entry: &mut impl std::io::Read,
        out: &mut impl std::io::Write,
        remaining: &mut u64,
    ) -> std::io::Result<()> {
        let copied = std::io::copy(
            &mut std::io::Read::take(&mut *entry, self.file_bytes.min(*remaining)),
            out,
        )?;
        *remaining -= copied;
        if entry.read(&mut [0u8; 1])? != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expanded archive budget exceeded",
            ));
        }
        Ok(())
    }
}

fn extract_release_archive_with_limits(
    archive_path: &Path,
    stage: &Path,
    expected: &[&'static str],
    limits: ExpandedArchiveLimits,
) -> Result<(), RuntimeOverlayError> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(limits.archive_reader(decoder));
    let mut seen = std::collections::BTreeSet::new();
    let mut remaining = limits.total_bytes;

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
                if !seen.insert(name.to_string()) {
                    return Err(RuntimeOverlayError::InvalidArchive {
                        archive_path: archive_path.to_path_buf(),
                        reason: format!("duplicate archive member {name}"),
                    });
                }
                let dest = stage.join(name);
                let mut out = std::fs::File::create(&dest)?;
                limits
                    .copy_entry(&mut entry, &mut out, &mut remaining)
                    .map_err(|e| RuntimeOverlayError::InvalidArchive {
                        archive_path: archive_path.to_path_buf(),
                        reason: format!("extract {name}: {e}"),
                    })?;
                set_cache_perms(&dest)?;
            }
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

    ExpandedArchiveLimits::finish_archive(archive.into_inner()).map_err(|e| {
        RuntimeOverlayError::InvalidArchive {
            archive_path: archive_path.to_path_buf(),
            reason: format!("finish tar stream: {e}"),
        }
    })?;
    for required in expected {
        if !seen.contains(*required) {
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
    let output = mvm_core::env_hygiene::helper_command("curl")
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
    #[test]
    fn tar_stream_budget_bounds_hidden_metadata_and_trailing_bytes() {
        let limits = super::ExpandedArchiveLimits {
            file_bytes: 16,
            total_bytes: 32,
        };
        let cap = limits.total_bytes + super::ExpandedArchiveLimits::TAR_FRAMING_BYTES;
        for kind in [tar::EntryType::GNULongName, tar::EntryType::XHeader] {
            let mut builder = tar::Builder::new(Vec::new());
            let bytes = vec![b'a'; 1024 * 1024];
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "metadata", bytes.as_slice())
                .unwrap();
            let mut cursor = std::io::Cursor::new(builder.into_inner().unwrap());
            {
                let mut archive = tar::Archive::new(limits.archive_reader(&mut cursor));
                assert!(archive.entries().unwrap().next().unwrap().is_err());
            }
            assert_eq!(
                cursor.position(),
                cap,
                "metadata cannot read beyond the raw cap"
            );
        }

        let mut cursor = std::io::Cursor::new(vec![0; 1024 * 1024]);
        let mut archive = tar::Archive::new(limits.archive_reader(&mut cursor));
        assert!(
            archive.entries().unwrap().next().is_none(),
            "tar stops at its end marker"
        );
        let error = super::ExpandedArchiveLimits::finish_archive(archive.into_inner()).unwrap_err();
        assert!(error.to_string().contains("stream budget"), "{error}");
        assert_eq!(cursor.position(), cap + 1, "only one excess byte is probed");

        let cursor = std::io::Cursor::new(vec![0; cap as usize]);
        super::ExpandedArchiveLimits::finish_archive(limits.archive_reader(cursor)).unwrap();
    }

    #[test]
    fn release_archive_rejects_redundant_directory_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("directories.tar.gz");
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let mut tar = tar::Builder::new(gzip);
        for _ in 0..1024 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, "VERSION", std::io::empty())
                .unwrap();
        }
        std::fs::write(&archive, tar.into_inner().unwrap().finish().unwrap()).unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir(&stage).unwrap();
        let error = super::extract_release_archive_with_limits(
            &archive,
            &stage,
            &["VERSION"],
            super::ExpandedArchiveLimits {
                file_bytes: 16,
                total_bytes: 32,
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported tar entry type Directory"),
            "{error}"
        );
        assert_eq!(std::fs::read_dir(stage).unwrap().count(), 0);
    }

    #[test]
    fn expanded_archive_copy_accepts_exact_limits_and_bounds_actual_writes() {
        let limits = super::ExpandedArchiveLimits {
            file_bytes: 4,
            total_bytes: 6,
        };
        let mut remaining = limits.total_bytes;
        let mut out = Vec::new();
        limits
            .copy_entry(&mut b"1234".as_slice(), &mut out, &mut remaining)
            .unwrap();
        assert_eq!(remaining, 2);
        limits
            .copy_entry(&mut b"56".as_slice(), &mut out, &mut remaining)
            .unwrap();
        assert_eq!(remaining, 0);
        assert!(
            limits
                .copy_entry(&mut b"7".as_slice(), &mut out, &mut remaining)
                .is_err()
        );
        assert_eq!(out, b"123456");
        let mut remaining = limits.total_bytes;
        let mut out = Vec::new();
        assert!(
            limits
                .copy_entry(&mut b"12345".as_slice(), &mut out, &mut remaining)
                .is_err()
        );
        assert_eq!(out, b"1234");
    }

    #[test]
    fn release_archive_rejects_duplicate_members_and_expansion_over_budget() {
        for (entries, expected_error) in [
            (vec![b"first".as_slice(), b"second".as_slice()], "duplicate"),
            (vec![&[0; 4096][..]], "budget"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let archive = tmp.path().join("release.tar.gz");
            let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            let mut tar = tar::Builder::new(gzip);
            for bytes in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, "VERSION", bytes).unwrap();
            }
            std::fs::write(&archive, tar.into_inner().unwrap().finish().unwrap()).unwrap();
            let stage = tmp.path().join("stage");
            std::fs::create_dir(&stage).unwrap();
            let error = super::extract_release_archive_with_limits(
                &archive,
                &stage,
                &["VERSION"],
                super::ExpandedArchiveLimits {
                    file_bytes: 16,
                    total_bytes: 32,
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected_error), "{error}");
            assert!(std::fs::metadata(stage.join("VERSION")).unwrap().len() <= 16);
        }
    }

    use super::*;
    use crate::published_image_set::ImageSetMemberError;
    use crate::published_image_set::fixture::ImageSetFixture;
    use mvm_core::util::test_env::TestEnv;
    use tempfile::TempDir;

    const FAKE_ROOTHASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn guest_runtime_fixture() -> (TempDir, crate::guest_runtime::GuestRuntime) {
        use mvm_core::image_set::{GitCommit, WorktreeState};
        use sha2::{Digest, Sha256};
        let dir = TempDir::new().unwrap();
        let arch = GuestArch::X86_64;
        let mut files = std::collections::BTreeMap::new();
        for (name, _) in GUEST_RUNTIME_OVERLAY_BINARIES {
            let member = format!("{arch}/bin/{name}");
            let bytes = format!("binary:{name}");
            let path = dir.path().join(&member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes.as_bytes()).unwrap();
            files.insert(member, hex::encode(Sha256::digest(bytes.as_bytes())));
        }
        for libc in [
            crate::guest_libc::GuestLibc::Glibc,
            crate::guest_libc::GuestLibc::Musl,
        ] {
            for soname in GPU_SHIM_SONAMES {
                let member = format!("{arch}/lib/{libc}/{soname}");
                let bytes = format!("{libc}:{soname}");
                let path = dir.path().join(&member);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, bytes.as_bytes()).unwrap();
                files.insert(member, hex::encode(Sha256::digest(bytes.as_bytes())));
            }
        }
        for (member, bytes) in [
            ("sdk-py/mvm/__init__.py", b"".as_slice()),
            ("sdk-py/mvm/host.py", b"def time(): pass\n".as_slice()),
        ] {
            let path = dir.path().join(member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            files.insert(member.to_string(), hex::encode(Sha256::digest(bytes)));
        }
        let runtime = crate::guest_runtime::GuestRuntime {
            root: dir.path().to_path_buf(),
            digest: "d".repeat(64),
            manifest: crate::guest_bins::GuestBinsManifest {
                schema_version: crate::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
                version: "1.2.3".into(),
                guest_source_fingerprint: "g".repeat(64),
                sdk_cdylib_source_fingerprint: "s".repeat(64),
                source: crate::image_source::RepoIdentity {
                    commit: GitCommit::new("a".repeat(40)).unwrap(),
                    worktree: WorktreeState::Clean,
                },
                files,
            },
        };
        (dir, runtime)
    }

    #[test]
    fn guest_runtime_overlay_stages_exact_guest_tree_and_is_deterministic() {
        let (_source, runtime) = guest_runtime_fixture();
        let cache_a = TempDir::new().unwrap();
        let cache_b = TempDir::new().unwrap();
        let a = build_runtime_overlay_from_guest_runtime(
            cache_a.path(),
            "1.2.3",
            GuestArch::X86_64,
            &runtime,
        )
        .unwrap();
        let fs = ext4_view::Ext4::load_from_path(&a.overlay_ext4).unwrap();
        let names_in = |path: &str| {
            let mut names: Vec<Vec<u8>> = fs
                .read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().as_ref().to_vec())
                .filter(|name| name != b"." && name != b"..")
                .collect();
            names.sort();
            names
        };
        let mut expected_root: Vec<Vec<u8>> = GUEST_RUNTIME_OVERLAY_BINARIES
            .iter()
            .map(|(_, overlay_name)| overlay_name.as_bytes().to_vec())
            .chain([b"gpu".to_vec(), b"sdk-py".to_vec(), b"VERSION".to_vec()])
            .collect();
        expected_root.sort();
        assert_eq!(names_in("/"), expected_root);
        assert_eq!(names_in("/gpu"), vec![b"glibc".to_vec(), b"musl".to_vec()]);
        assert_eq!(names_in("/sdk-py"), vec![b"mvm".to_vec()]);
        assert_eq!(
            names_in("/sdk-py/mvm"),
            vec![b"__init__.py".to_vec(), b"host.py".to_vec()]
        );
        for (archive_name, overlay_name) in GUEST_RUNTIME_OVERLAY_BINARIES {
            let guest_path = format!("/{overlay_name}");
            assert_eq!(
                fs.read(guest_path.as_str()).unwrap(),
                std::fs::read(runtime.root.join(format!("x86_64/bin/{archive_name}"))).unwrap()
            );
            assert_eq!(
                fs.metadata(guest_path.as_str()).unwrap().mode() & 0o777,
                0o555
            );
        }
        for libc in ["glibc", "musl"] {
            let mut expected_gpu: Vec<Vec<u8>> = GPU_SHIM_SONAMES
                .iter()
                .map(|name| name.as_bytes().to_vec())
                .collect();
            expected_gpu.sort();
            assert_eq!(names_in(&format!("/gpu/{libc}")), expected_gpu);
            for soname in GPU_SHIM_SONAMES {
                let guest_path = format!("/gpu/{libc}/{soname}");
                assert_eq!(
                    fs.read(guest_path.as_str()).unwrap(),
                    std::fs::read(runtime.root.join(format!("x86_64/lib/{libc}/{soname}")))
                        .unwrap()
                );
                assert_eq!(
                    fs.metadata(guest_path.as_str()).unwrap().mode() & 0o777,
                    0o555
                );
            }
        }
        for member in ["sdk-py/mvm/__init__.py", "sdk-py/mvm/host.py"] {
            let guest_path = format!("/{member}");
            assert_eq!(
                fs.read(guest_path.as_str()).unwrap(),
                std::fs::read(runtime.root.join(member)).unwrap()
            );
            assert_eq!(
                fs.metadata(guest_path.as_str()).unwrap().mode() & 0o777,
                0o644
            );
        }
        let b = build_runtime_overlay_from_guest_runtime(
            cache_b.path(),
            "1.2.3",
            GuestArch::X86_64,
            &runtime,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&a.overlay_ext4).unwrap(),
            std::fs::read(&b.overlay_ext4).unwrap()
        );
        assert_eq!(
            std::fs::read(&a.sidecar).unwrap(),
            std::fs::read(&b.sidecar).unwrap()
        );
        assert_eq!(a.roothash, b.roothash);
        assert_eq!(
            std::fs::read_to_string(
                RuntimeOverlayLayout::under(cache_a.path(), "1.2.3", "x86_64")
                    .local_source_fingerprint_file
            )
            .unwrap()
            .trim(),
            runtime.digest,
        );
    }

    #[test]
    fn guest_runtime_overlay_requires_sdk_initializer_not_just_other_sdk_files() {
        let (_source, mut runtime) = guest_runtime_fixture();
        runtime.manifest.files.remove("sdk-py/mvm/__init__.py");
        let staging = TempDir::new().unwrap();
        let error = stage_guest_runtime_overlay_tree(&runtime, GuestArch::X86_64, staging.path())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no Python SDK package initializer"),
            "{error}"
        );
    }

    #[test]
    fn guest_runtime_overlay_reuses_only_fresh_verified_cache() {
        for stale in [false, true] {
            for tampered in [false, true] {
                let (_source, runtime) = guest_runtime_fixture();
                let cache = TempDir::new().unwrap();
                let build = || {
                    build_runtime_overlay_from_guest_runtime(
                        cache.path(),
                        "1.2.3",
                        GuestArch::X86_64,
                        &runtime,
                    )
                };
                let artifact = build().unwrap();
                if stale {
                    write_local_source_fingerprint(
                        cache.path(),
                        "1.2.3",
                        GuestArch::X86_64,
                        "old-runtime",
                    )
                    .unwrap();
                }
                if tampered {
                    let mut tree = std::fs::read(&artifact.sidecar).unwrap();
                    tree[0] ^= 1;
                    std::fs::write(&artifact.sidecar, tree).unwrap();
                    // The local checksum manifest is not a verity proof:
                    // even internally consistent file hashes must not admit
                    // a tree that disagrees with the image and root hash.
                    write_checksum_manifest(artifact.sidecar.parent().unwrap()).unwrap();
                    RuntimeOverlayResolver::new(cache.path().to_path_buf(), "1.2.3".into())
                        .resolve("x86_64")
                        .expect("tampering must reach verity verification, not fail resolution");
                }
                // A cache hit must not stage again. A stale or corrupt entry
                // must try to rebuild and detect the changed source member.
                let member = runtime.root.join("sdk-py/mvm/__init__.py");
                std::fs::write(&member, b"changed").unwrap();
                if stale || tampered {
                    let error = build().unwrap_err();
                    assert!(
                        error.to_string().contains("changed while staging"),
                        "{error}"
                    );
                    std::fs::write(&member, b"").unwrap();
                    let repaired = build().unwrap();
                    verify_guest_runtime_overlay_verity(&repaired).unwrap();
                    assert!(
                        local_source_cache_is_fresh(
                            &RuntimeOverlayLayout::under(cache.path(), "1.2.3", "x86_64"),
                            &runtime.digest,
                        )
                        .unwrap()
                    );
                } else {
                    let reused = build().expect("fresh verified cache must not restage");
                    assert_eq!(reused.roothash, artifact.roothash);
                }
            }
        }
    }

    #[test]
    fn guest_runtime_overlay_refuses_missing_or_changed_member_and_tampered_verity() {
        let (_source, mut runtime) = guest_runtime_fixture();
        let cache = TempDir::new().unwrap();
        let member = "x86_64/lib/musl/libcuda.so.1";
        let digest = runtime.manifest.files.remove(member).unwrap();
        let error = build_runtime_overlay_from_guest_runtime(
            cache.path(),
            "1.2.3",
            GuestArch::X86_64,
            &runtime,
        )
        .unwrap_err();
        assert!(error.to_string().contains(member), "{error}");
        runtime.manifest.files.insert(member.into(), digest);
        std::fs::write(runtime.root.join(member), b"changed").unwrap();
        let error = build_runtime_overlay_from_guest_runtime(
            cache.path(),
            "1.2.3",
            GuestArch::X86_64,
            &runtime,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("changed while staging"),
            "{error}"
        );

        let (_source, runtime) = guest_runtime_fixture();
        let artifact = build_runtime_overlay_from_guest_runtime(
            cache.path(),
            "1.2.3",
            GuestArch::X86_64,
            &runtime,
        )
        .unwrap();
        std::fs::write(&artifact.sidecar, b"wrong tree").unwrap();
        assert!(verify_guest_runtime_overlay_verity(&artifact).is_err());
        std::fs::write(&artifact.roothash_file, format!("{}\n", "f".repeat(64))).unwrap();
        let wrong_root = RuntimeOverlayArtifact {
            roothash: "f".repeat(64),
            ..artifact
        };
        assert!(verify_guest_runtime_overlay_verity(&wrong_root).is_err());
    }

    #[cfg(feature = "release-channel")]
    #[test]
    fn official_build_does_not_detect_the_compiled_in_source_checkout() {
        assert_eq!(runtime_overlay_source_checkout_root(), None);
    }

    #[cfg(not(feature = "release-channel"))]
    #[test]
    fn contributor_build_detects_its_source_checkout_by_the_workspace_manifest() {
        let mut env = TestEnv::new();
        env.remove(crate::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV);
        let workspace_root = runtime_overlay_source_checkout_root()
            .expect("a contributor build must detect its source checkout");
        assert!(
            workspace_root.is_absolute(),
            "source root must not depend on the working directory"
        );
        assert!(
            workspace_root.join("Cargo.toml").is_file(),
            "detected workspace root must be the mvm workspace"
        );
    }

    fn valid_overlay_ext4_bytes() -> Vec<u8> {
        crate::boot_asset_fixture::valid_overlay_ext4_bytes()
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

    const OVERLAY_ARCHIVE: &str = "runtime-overlay-aarch64.tar.gz";

    fn fixture_overlay_archive() -> Vec<u8> {
        runtime_overlay_archive_bytes(
            b"fake-ext4-bytes",
            b"fake-verity-sidecar",
            format!("{FAKE_ROOTHASH}\n").as_bytes(),
            b"9.9.9\n",
        )
    }

    fn with_overlay(archive: Vec<u8>) -> ImageSetFixture {
        ImageSetFixture::complete().publish(
            mvm_core::image_set::ImageSetRole::RuntimeOverlay,
            mvm_core::image_set::MemberTarget::Arch(GuestArch::Aarch64),
            OVERLAY_ARCHIVE,
            archive,
        )
    }

    /// Acquire `fixture` as the verified set. A fixture carries no publisher
    /// signature; that rung has its own witnesses in
    /// `crate::published_image_set`.
    fn acquire(fixture: &ImageSetFixture, served: &Path, env: &mut TestEnv) -> PublishedImageSet {
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        PublishedImageSet::acquire_from(fixture.serve_from(served))
            .expect("the fixture root must be accepted")
    }

    /// The member the signed root names is fetched, extracted, re-verified
    /// against its own manifest and installed under the canonical layout.
    /// `file://` URLs go through the same `curl -fSL` a release URL does, so
    /// only the network hop is missing.
    #[test]
    fn download_runtime_overlay_installs_the_member_the_signed_root_names() {
        let mut env = TestEnv::new();
        let served = TempDir::new().unwrap();
        let set = acquire(
            &with_overlay(fixture_overlay_archive()),
            served.path(),
            &mut env,
        );

        let cache = TempDir::new().unwrap();
        let installed =
            download_runtime_overlay_from(&set, "9.9.9", GuestArch::Aarch64, cache.path())
                .expect("download + install must succeed against the fixture set");

        assert_eq!(installed.arch, "aarch64");
        assert_eq!(installed.version, "9.9.9");
        assert_eq!(installed.roothash, FAKE_ROOTHASH);
        let cache_dir = set
            .member_cache()
            .cache_root(cache.path())
            .join("runtime-overlay/9.9.9/aarch64");
        for file in [
            "overlay.ext4",
            "overlay.verity",
            "overlay.roothash",
            "VERSION",
        ] {
            assert!(cache_dir.join(file).is_file(), "{file} must be installed");
        }
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
            b"fake-ext4-bytes"
        );
    }

    /// Bytes other than the ones the signed root declares are refused at the
    /// digest, before extraction, and nothing reaches the cache. The served
    /// archive differs in its gzip trailer only, so had it been extracted the
    /// failure would have been a gzip error rather than a digest mismatch.
    #[test]
    fn download_runtime_overlay_rejects_checksum_mismatch() {
        let mut env = TestEnv::new();
        let archive = fixture_overlay_archive();
        let mut tampered = archive.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let served = TempDir::new().unwrap();
        let fixture = with_overlay(archive).serve_instead(OVERLAY_ARCHIVE, tampered);
        let set = acquire(&fixture, served.path(), &mut env);

        let cache = TempDir::new().unwrap();
        let err = download_runtime_overlay_from(&set, "9.9.9", GuestArch::Aarch64, cache.path())
            .expect_err("tampered archive must be refused");
        match err {
            RuntimeOverlayError::ImageSetMember(member) => match *member {
                ImageSetMemberError::DigestMismatch { name, .. } => {
                    assert_eq!(name, OVERLAY_ARCHIVE)
                }
                other => panic!("expected a digest mismatch, got {other:?}"),
            },
            other => panic!("expected a digest mismatch, got {other:?}"),
        }
        assert!(!cache.path().join("runtime-overlay").exists());
        assert!(!set.member_cache().cache_root(cache.path()).exists());
    }

    /// A member cut from a workspace at another version than this CLI's.
    const MEMBER_VERSION: &str = "0.0.1-member";

    fn member_overlay_archive(version: &str) -> Vec<u8> {
        runtime_overlay_archive_bytes(
            &valid_overlay_ext4_bytes(),
            b"fake-verity-sidecar",
            format!("{FAKE_ROOTHASH}\n").as_bytes(),
            format!("{version}\n").as_bytes(),
        )
    }

    /// The set's identity is its signed root, so a member whose `VERSION` is
    /// not this CLI's installs, and a later boot resolves it from the cache
    /// without the set being acquired again.
    #[test]
    fn a_set_member_at_another_version_installs_and_resolves_from_cache() {
        assert_ne!(MEMBER_VERSION, env!("CARGO_PKG_VERSION"));
        let mut env = TestEnv::new();
        let served = TempDir::new().unwrap();
        let set = acquire(
            &with_overlay(member_overlay_archive(MEMBER_VERSION)),
            served.path(),
            &mut env,
        );
        let cache = TempDir::new().unwrap();

        let installed = download_runtime_overlay_from(
            &set,
            env!("CARGO_PKG_VERSION"),
            GuestArch::Aarch64,
            cache.path(),
        )
        .expect("a member at another version must install");
        assert_eq!(installed.version, MEMBER_VERSION);

        // Nothing is served any more: a resolve that reached for the set would
        // fail, so success proves a pure cache hit.
        std::fs::remove_dir_all(served.path()).unwrap();
        let resolved = resolve_image_set_runtime_overlay(
            cache.path(),
            &set.member_cache(),
            GuestArch::Aarch64,
        )
        .expect("the installed member must resolve from the cache");
        assert_eq!(resolved, installed);
    }

    /// An entry installed from another root is not this root's member, even
    /// when its bytes are intact: the lock moved, so it is acquired again.
    #[test]
    fn a_set_member_installed_from_another_root_is_not_reused() {
        let mut env = TestEnv::new();
        let served = TempDir::new().unwrap();
        let set = acquire(
            &with_overlay(member_overlay_archive(MEMBER_VERSION)),
            served.path(),
            &mut env,
        );
        let cache = TempDir::new().unwrap();
        download_runtime_overlay_from(&set, "9.9.9", GuestArch::Aarch64, cache.path()).unwrap();

        let moved = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"next"));
        let err = resolve_image_set_runtime_overlay(cache.path(), &moved, GuestArch::Aarch64)
            .expect_err("another root's member must not resolve");
        assert!(
            matches!(
                err,
                RuntimeOverlayError::ImageSetCache(
                    crate::published_image_set::SetMemberCacheError::NotInstalled { .. }
                )
            ),
            "{err:?}"
        );
    }

    /// A member whose `VERSION` could not name a cache entry is refused before
    /// anything is installed.
    #[test]
    fn a_set_member_with_an_unusable_version_is_refused() {
        let mut env = TestEnv::new();
        let served = TempDir::new().unwrap();
        let set = acquire(
            &with_overlay(member_overlay_archive("../escape")),
            served.path(),
            &mut env,
        );
        let cache = TempDir::new().unwrap();

        let err = download_runtime_overlay_from(&set, "9.9.9", GuestArch::Aarch64, cache.path())
            .expect_err("a traversal VERSION must be refused");
        assert!(
            matches!(err, RuntimeOverlayError::ImageSetCache(_)),
            "{err:?}"
        );
        assert!(!set.member_cache().cache_root(cache.path()).exists());
    }

    /// Every cache-only consumer — the builder VM, the in-process boot, the
    /// bootstrap readiness probe — finds the pinned set's member when the
    /// version-matched entry is absent.
    #[test]
    fn a_cache_only_resolve_falls_back_to_the_pinned_sets_member() {
        // The version-matched arm seeds from the default cache; point that at
        // an empty home so only the pinned set's member can answer.
        let mut env = TestEnv::new();
        let home = TempDir::new().unwrap();
        env.isolate_mvm_home(home.path());
        let cache = TempDir::new().unwrap();
        let archive_dir = TempDir::new().unwrap();
        let archive = archive_dir.path().join(OVERLAY_ARCHIVE);
        std::fs::write(&archive, member_overlay_archive(MEMBER_VERSION)).unwrap();
        install_image_set_runtime_overlay_archive(
            &archive,
            &SetMemberCache::locked(),
            "9.9.9",
            GuestArch::Aarch64,
            cache.path(),
        )
        .unwrap();

        let resolver = RuntimeOverlayResolver::new(
            cache.path().to_path_buf(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        let artifact = resolve_cached_runtime_overlay(&resolver, GuestArch::Aarch64)
            .expect("the pinned set's member must satisfy a cache-only resolve");
        assert_eq!(artifact.version, MEMBER_VERSION);
    }

    /// The version-matched cache keeps exact equality with the running CLI: a
    /// set member in the cache does not satisfy a resolver asking for another
    /// version, and an overlay whose `VERSION` disagrees with its version key
    /// is still refused.
    #[test]
    fn the_version_matched_cache_still_refuses_a_mismatched_version() {
        let cache = TempDir::new().unwrap();
        let archive_dir = TempDir::new().unwrap();
        let archive = archive_dir.path().join(OVERLAY_ARCHIVE);
        std::fs::write(&archive, member_overlay_archive(MEMBER_VERSION)).unwrap();
        install_runtime_overlay_archive(&archive, "9.9.9", GuestArch::Aarch64, cache.path())
            .unwrap();

        let err = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "9.9.9".to_string())
            .resolve("aarch64")
            .expect_err("a VERSION other than the key's must be refused");
        assert!(
            matches!(err, OverlayError::VersionMismatch { .. }),
            "{err:?}"
        );
    }

    /// The current train requires an overlay for every arch, so a root without
    /// one is refused at acquisition — naming the role and arch — before any
    /// member is requested.
    #[test]
    fn download_runtime_overlay_refuses_a_set_without_an_overlay_for_the_arch() {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let served = TempDir::new().unwrap();
        let fixture = ImageSetFixture::complete().without_member(
            mvm_core::image_set::ImageSetRole::RuntimeOverlay,
            mvm_core::image_set::MemberTarget::Arch(GuestArch::Aarch64),
        );

        let err = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
            .err()
            .expect("a set without the overlay member must be refused");
        assert!(
            format!("{err:#}").contains("runtime_overlay/aarch64"),
            "{err:#}"
        );
    }

    /// A member that exists but does not carry this arch's archive name is
    /// refused by name before any download.
    #[test]
    fn download_runtime_overlay_refuses_a_member_without_the_archive() {
        let mut env = TestEnv::new();
        let served = TempDir::new().unwrap();
        let fixture = ImageSetFixture::complete().publish(
            mvm_core::image_set::ImageSetRole::RuntimeOverlay,
            mvm_core::image_set::MemberTarget::Arch(GuestArch::Aarch64),
            "runtime-overlay-renamed.tar.gz",
            fixture_overlay_archive(),
        );
        let set = acquire(&fixture, served.path(), &mut env);

        let cache = TempDir::new().unwrap();
        let err = download_runtime_overlay_from(&set, "9.9.9", GuestArch::Aarch64, cache.path())
            .expect_err("an undeclared archive must be refused");
        assert!(
            matches!(
                &err,
                RuntimeOverlayError::ImageSetMember(member)
                    if matches!(**member, ImageSetMemberError::NoArtifact { .. })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("runtime_overlay/aarch64"), "{err}");
    }

    /// Stage a CLI release directory the way `release.yml` publishes one: the
    /// archive and a `.sha256` sidecar pinning `checksum_over`.
    fn stage_cli_release(root: &Path, archive: &[u8], checksum_over: &[u8]) -> String {
        let release_dir = root.join("v9.9.9");
        std::fs::create_dir_all(&release_dir).unwrap();
        write_fixture(&release_dir, OVERLAY_ARCHIVE, archive);
        write_fixture(
            &release_dir,
            &format!("{OVERLAY_ARCHIVE}.sha256"),
            format!("{}  {OVERLAY_ARCHIVE}\n", sha256_hex(checksum_over)).as_bytes(),
        );
        format!("file://{}", release_dir.display())
    }

    #[test]
    fn a_cli_release_archive_installs_through_the_shared_install_half() {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let archive = fixture_overlay_archive();
        let upstream = TempDir::new().unwrap();
        let release_url = stage_cli_release(upstream.path(), &archive, &archive);

        let stage = TempDir::new().unwrap();
        let local = stage.path().join(OVERLAY_ARCHIVE);
        fetch_cli_release_archive(&release_url, "9.9.9", OVERLAY_ARCHIVE, &local).unwrap();
        let cache = TempDir::new().unwrap();
        let installed =
            install_runtime_overlay_archive(&local, "9.9.9", GuestArch::Aarch64, cache.path())
                .unwrap();
        assert_eq!(installed.roothash, FAKE_ROOTHASH);
    }

    /// A CLI release archive with no signature beside it is refused even
    /// though its digest matches its sidecar.
    #[test]
    fn a_cli_release_archive_without_a_signature_is_refused() {
        let mut env = TestEnv::new();
        env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let archive = b"not-even-a-real-archive".to_vec();
        let upstream = TempDir::new().unwrap();
        let release_url = stage_cli_release(upstream.path(), &archive, &archive);

        let stage = TempDir::new().unwrap();
        let err = fetch_cli_release_archive(
            &release_url,
            "9.9.9",
            OVERLAY_ARCHIVE,
            &stage.path().join(OVERLAY_ARCHIVE),
        )
        .expect_err("an unsigned archive must not be accepted");
        let rendered = err.to_string();
        assert!(
            rendered.contains("signature") || rendered.contains("bundle"),
            "the refusal must be about the signature: {rendered}"
        );
    }

    /// A CLI release archive whose bytes are not the ones its sidecar pins is
    /// refused and deleted.
    #[test]
    fn a_cli_release_archive_that_misses_its_sidecar_digest_is_refused() {
        let mut env = TestEnv::new();
        env.remove(SKIP_HASH_VERIFY_ENV);
        let upstream = TempDir::new().unwrap();
        let release_url = stage_cli_release(upstream.path(), b"tampered!", b"the-real-bytes");

        let stage = TempDir::new().unwrap();
        let local = stage.path().join(OVERLAY_ARCHIVE);
        let err = fetch_cli_release_archive(&release_url, "9.9.9", OVERLAY_ARCHIVE, &local)
            .expect_err("a digest mismatch must be refused");
        assert!(
            matches!(err, RuntimeOverlayError::ChecksumMismatch { .. }),
            "{err:?}"
        );
        assert!(!local.exists(), "refused bytes must not stay on disk");
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
                assert_eq!(name, "mvm-guest-agent");
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
        crate::boot_asset_fixture::runtime_overlay_archive_bytes(
            GuestArch::Aarch64,
            ext4_bytes,
            verity_bytes,
            roothash_bytes,
            version_bytes,
        )
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
            display_bridge: make_bin("display-bridge"),
            runner: make_bin("runner"),
            egress_client: make_bin("egress-client"),
            addon_dns: make_bin("addon-dns"),
            exit_report: make_bin("exit-report"),
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
