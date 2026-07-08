use super::*;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DevStatusImage {
    pub(super) kernel_path: Option<String>,
    pub(super) rootfs_path: String,
}

pub(super) fn resolve_dev_status_image() -> Option<DevStatusImage> {
    let version = env!("CARGO_PKG_VERSION");
    for dir in [
        format!("{}/dev/current", mvm_core::config::mvm_data_dir()),
        format!(
            "{}/dev/prebuilt/v{version}",
            mvm_core::config::mvm_data_dir()
        ),
        format!("{}/dev", mvm_core::config::mvm_cache_dir()),
    ] {
        let rootfs_path = format!("{dir}/rootfs.ext4");
        if !std::path::Path::new(&rootfs_path).exists() {
            continue;
        }
        let kernel_path = format!("{dir}/vmlinux");
        return Some(DevStatusImage {
            kernel_path: std::path::Path::new(&kernel_path)
                .exists()
                .then_some(kernel_path),
            rootfs_path,
        });
    }

    None
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum BuilderVmCacheState {
    Ready,
    Stale,
}

impl BuilderVmCacheState {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct BuilderVmCacheStatusSummary {
    pub(super) cache_kind: &'static str,
    pub(super) state: BuilderVmCacheState,
    pub(super) reason_code: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct DevImageCacheSummary {
    pub(super) state: &'static str,
    pub(super) kernel: &'static str,
    pub(super) rootfs: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct DevCacheInspectSummary {
    pub(super) dev_image: DevImageCacheSummary,
    pub(super) builder_cache: BuilderVmCacheStatusSummary,
}

/// Prepare `~/.mvm/dev/current/` for a fresh dev-image build.
///
/// Replaces a stale symlink (the nix-darwin `linux-builder` legacy
/// pointed `current` at a root-owned `/nix/store/…-mvm-dev` path)
/// with a real, writable directory. `create_dir_all` is a no-op
/// against an existing symlink, so without this the libkrun
/// virtio-fs `/out` mount lands on the read-only Nix store path
/// and Apple Container fails with EACCES.
///
/// Only reachable under the libkrun-dispatch branch of `ensure_dev_image`,
/// which itself is gated on `builder-vm`.
#[cfg(feature = "builder-vm")]
pub(super) fn prepare_dev_image_out_dir(out_dir: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(out_dir).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating dev-image out parent {}", parent.display()))?;
    }
    if std::path::Path::new(out_dir)
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        std::fs::remove_file(out_dir)
            .with_context(|| format!("removing stale dev-image symlink at {out_dir}"))?;
    }
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating dev-image out dir {out_dir}"))?;
    Ok(())
}

/// Resolve the dev image (kernel + rootfs) to absolute paths.
pub(in crate::commands) fn ensure_dev_image() -> Result<(String, String)> {
    #[cfg(feature = "builder-vm")]
    if let Ok(flake_dir) = find_builder_vm_flake() {
        let out_dir = format!("{}/dev/current", mvm_core::config::mvm_data_dir());
        let out_path = std::path::Path::new(&out_dir);

        if let Ok(fingerprint) = builder_vm_source_fingerprint(&flake_dir) {
            let status = builder_vm_source_cache_status(out_path, &fingerprint);
            if status.is_ready() {
                ui::success(&format!(
                    "Dev image cache hit (fingerprint {}); skipping builder VM.",
                    stage0_fingerprint_prefix(&fingerprint),
                ));
                return Ok((
                    format!("{out_dir}/vmlinux"),
                    format!("{out_dir}/rootfs.ext4"),
                ));
            }
            ui::progress(&format!(
                "Dev image cache decision: {}",
                status.reason_code()
            ));
        }

        prepare_dev_image_out_dir(&out_dir)?;
        return build_image_via_libkrun(&out_dir);
    }

    ui::info("No local builder-vm flake found; downloading published prebuilt.");
    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_root = format!("{}/dev/prebuilt", mvm_core::config::mvm_data_dir());
    let prebuilt_dir = format!("{prebuilt_root}/v{version}");
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    let kernel_path = format!("{prebuilt_dir}/vmlinux");
    let rootfs_path = format!("{prebuilt_dir}/rootfs.ext4");
    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        match validate_dev_image_artifacts(&kernel_path, &rootfs_path) {
            Ok(()) => {
                prune_old_prebuilts(&prebuilt_root, version);
                return Ok((kernel_path, rootfs_path));
            }
            Err(e) => {
                ui::warn(&format!(
                    "Cached dev image at {prebuilt_dir} failed sanity check ({e}); \
                     deleting and rebuilding."
                ));
                let _ = std::fs::remove_file(&kernel_path);
                let _ = std::fs::remove_file(&rootfs_path);
            }
        }
    }
    if let Some((src_kernel, src_rootfs, source_label)) = find_vendored_dev_image() {
        validate_dev_image_artifacts(&src_kernel, &src_rootfs).with_context(|| {
            format!(
                "vendored dev image at {source_label} failed sanity check — \
                 refusing to copy garbage into the prebuilt cache"
            )
        })?;
        ui::info(&format!(
            "Using vendored dev image from source checkout ({source_label})."
        ));
        std::fs::copy(&src_kernel, &kernel_path)
            .with_context(|| format!("copying vendored kernel {src_kernel:?} → {kernel_path}"))?;
        std::fs::copy(&src_rootfs, &rootfs_path)
            .with_context(|| format!("copying vendored rootfs {src_rootfs:?} → {rootfs_path}"))?;
        return Ok((kernel_path, rootfs_path));
    }
    match download_dev_image(&kernel_path, &rootfs_path) {
        Ok(result) => {
            prune_old_prebuilts(&prebuilt_root, version);
            Ok(result)
        }
        Err(download_err) => {
            ui::warn(&format!(
                "Could not download dev image for v{version}: {download_err}\n\
                 Searching for a local fallback under ~/.mvm/dev/."
            ));
            if let Some((src_kernel, src_rootfs, source_label)) = find_local_fallback_image() {
                ui::warn(&format!(
                    "Using local fallback from {source_label}. \
                     This is not the published v{version} image — boot it knowing the \
                     versions differ. Publish v{version} assets or restore the local \
                     builder flake to make this go away."
                ));
                std::fs::copy(&src_kernel, &kernel_path).with_context(|| {
                    format!("copying fallback kernel {src_kernel:?} → {kernel_path}")
                })?;
                std::fs::copy(&src_rootfs, &rootfs_path).with_context(|| {
                    format!("copying fallback rootfs {src_rootfs:?} → {rootfs_path}")
                })?;
                Ok((kernel_path, rootfs_path))
            } else {
                Err(download_err.context(
                    "no local fallback found under ~/.mvm/dev/current/, \
                     ~/.mvm/dev/prebuilt/v*/, or ~/.mvm/dev/builds/*/",
                ))
            }
        }
    }
}

pub(super) fn find_local_fallback_image() -> Option<(std::path::PathBuf, std::path::PathBuf, String)>
{
    find_local_fallback_image_with(|_| true)
}

fn find_local_fallback_image_with(
    accepts_rootfs: impl Fn(&std::path::Path) -> bool,
) -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    let dev_root = format!("{}/dev", mvm_core::config::mvm_data_dir());

    let mut candidates: Vec<(std::time::SystemTime, std::path::PathBuf, String)> = Vec::new();
    let mut consider = |dir: std::path::PathBuf, label: String| {
        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        if !kernel.is_file() || !rootfs.is_file() {
            return;
        }
        if validate_dev_image_artifacts(&kernel, &rootfs).is_err() {
            return;
        }
        if !accepts_rootfs(&rootfs) {
            return;
        }
        let mtime = std::fs::metadata(&rootfs)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        candidates.push((mtime, dir, label));
    };

    consider(
        std::path::Path::new(&dev_root).join("current"),
        "current".to_string(),
    );
    for sub in ["prebuilt", "builds"] {
        let parent = std::path::Path::new(&dev_root).join(sub);
        let Ok(entries) = std::fs::read_dir(&parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let label = format!("{sub}/{}", entry.file_name().to_string_lossy());
            consider(dir, label);
        }
    }

    candidates.sort_by_key(|(mtime, ..)| *mtime);
    let (_, dir, label) = candidates.into_iter().next_back()?;
    Some((dir.join("vmlinux"), dir.join("rootfs.ext4"), label))
}

#[cfg(feature = "builder-vm")]
pub(super) fn verify_stage0_rootfs_has_init(rootfs: &std::path::Path) -> Result<()> {
    let fs = ext4_view::Ext4::load_from_path(rootfs)
        .with_context(|| format!("opening {} as ext4", rootfs.display()))?;
    let present = fs.exists(HOST_VM_INIT_ROOTFS_PATH).with_context(|| {
        format!(
            "looking up {HOST_VM_INIT_ROOTFS_PATH} in {}",
            rootfs.display()
        )
    })?;
    if !present {
        anyhow::bail!(
            "Stage 0 builder VM rootfs {} is missing {HOST_VM_INIT_ROOTFS_PATH}",
            rootfs.display()
        );
    }
    Ok(())
}

pub(super) fn validate_dev_image_artifacts(
    kernel: impl AsRef<std::path::Path>,
    rootfs: impl AsRef<std::path::Path>,
) -> Result<()> {
    const KERNEL_MIN_BYTES: u64 = 1024 * 1024;
    const ROOTFS_MIN_BYTES: u64 = 4 * 1024 * 1024;
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 56;
    const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

    let kernel = kernel.as_ref();
    let rootfs = rootfs.as_ref();

    let kernel_size = std::fs::metadata(kernel)
        .with_context(|| format!("stat {}", kernel.display()))?
        .len();
    if kernel_size < KERNEL_MIN_BYTES {
        anyhow::bail!(
            "kernel at {} is only {} bytes (expected ≥ {})",
            kernel.display(),
            kernel_size,
            KERNEL_MIN_BYTES,
        );
    }

    let rootfs_size = std::fs::metadata(rootfs)
        .with_context(|| format!("stat {}", rootfs.display()))?
        .len();
    if rootfs_size < ROOTFS_MIN_BYTES {
        anyhow::bail!(
            "rootfs at {} is only {} bytes (expected ≥ {})",
            rootfs.display(),
            rootfs_size,
            ROOTFS_MIN_BYTES,
        );
    }

    use std::io::{Read, Seek, SeekFrom};
    let mut f =
        std::fs::File::open(rootfs).with_context(|| format!("open {}", rootfs.display()))?;
    f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET))
        .with_context(|| format!("seek to ext4 magic in {}", rootfs.display()))?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)
        .with_context(|| format!("read ext4 magic from {}", rootfs.display()))?;
    if magic != EXT4_MAGIC {
        anyhow::bail!(
            "rootfs at {} does not have ext4 magic at offset {} (got {magic:02x?})",
            rootfs.display(),
            EXT4_MAGIC_OFFSET,
        );
    }

    Ok(())
}

fn find_vendored_dev_image() -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir).parent()?.parent()?;
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let dir = workspace_root
        .join("nix")
        .join("images")
        .join("dev-prebuilt")
        .join(arch);
    let kernel = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    if !kernel.is_file() || !rootfs.is_file() {
        return None;
    }
    let label = format!("vendored {}", dir.display());
    Some((kernel, rootfs, label))
}

fn prune_old_prebuilts(prebuilt_root: &str, current_version: &str) {
    let current = format!("v{current_version}");
    let Ok(entries) = std::fs::read_dir(prebuilt_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == current {
            continue;
        }
        let path = entry.path();
        match std::fs::remove_dir_all(&path) {
            Ok(()) => ui::info(&format!("Pruned stale prebuilt cache: {name_str}")),
            Err(e) => tracing::warn!("Could not prune {}: {e}", path.display()),
        }
    }
}

fn download_dev_image(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    let verify_start = std::time::Instant::now();
    let result = download_dev_image_inner(kernel_path, rootfs_path);
    let elapsed_ms = verify_start.elapsed().as_millis() as u64;
    let metrics = mvm_core::observability::metrics::global();
    metrics
        .dev_image_verify_duration_ms
        .store(elapsed_ms, std::sync::atomic::Ordering::Relaxed);
    if result.is_ok() {
        metrics
            .dev_image_verify_ok
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    result
}

fn download_dev_image_inner(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let kernel_name = format!("dev-vmlinux-{arch}");
    let rootfs_name = format!("dev-rootfs-{arch}.ext4");
    let kernel_url = format!("{base_url}/{kernel_name}");
    let rootfs_url = format!("{base_url}/{rootfs_name}");

    ui::info(&format!(
        "Downloading dev image (v{version}) — one-time setup. \
         Subsequent runs reuse the cached image and start in seconds."
    ));

    let expected = match try_fetch_signed_manifest(&base_url, version, arch, "dev")? {
        Some(manifest) => {
            ui::success(&format!(
                "  ✓ cosign-verified manifest for v{} (built {} UTC, valid until {} UTC)",
                manifest.version,
                manifest.built_at.format("%Y-%m-%d"),
                manifest.not_after.format("%Y-%m-%d"),
            ));
            manifest
                .artifacts
                .iter()
                .map(|a| (a.name.clone(), a.sha256.to_ascii_lowercase()))
                .collect::<std::collections::HashMap<_, _>>()
        }
        None => {
            ui::warn(
                "No cosign-signed manifest found for this release. Falling back to \
                 the legacy unsigned checksum file path.",
            );
            let checksums_name = format!("dev-image-{arch}-checksums-sha256.txt");
            let checksums_url = format!("{base_url}/{checksums_name}");
            fetch_expected_hashes(&checksums_url, &[&kernel_name, &rootfs_name])?
        }
    };

    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!("Failed to download kernel from {kernel_url}"))
    })?;
    verify_artifact_hash(
        kernel_path,
        &kernel_name,
        expected.get(kernel_name.as_str()),
    )?;

    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!("Failed to download rootfs from {rootfs_url}"))
    })?;
    verify_artifact_hash(
        rootfs_path,
        &rootfs_name,
        expected.get(rootfs_name.as_str()),
    )?;

    ui::success("Dev image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

fn try_fetch_signed_manifest(
    base_url: &str,
    version: &str,
    arch: &str,
    variant: &str,
) -> Result<Option<mvm_core::crypto::image_verify::SignedManifest>> {
    use mvm_core::crypto::image_verify;

    let manifest_name = format!("{variant}-image-{arch}.manifest.json");
    let manifest_url = format!("{base_url}/{manifest_name}");
    let bundle_url = format!("{manifest_url}.bundle");

    if !url_exists(&manifest_url)? {
        return Ok(None);
    }

    let manifest_tmp = tempfile::NamedTempFile::new().context("creating manifest tempfile")?;
    let bundle_tmp = tempfile::NamedTempFile::new().context("creating bundle tempfile")?;
    let manifest_path = manifest_tmp.path().to_string_lossy().into_owned();
    let bundle_path = bundle_tmp.path().to_string_lossy().into_owned();

    download_file(&manifest_url, &manifest_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download signed manifest from {manifest_url}"
        ))
    })?;
    download_file(&bundle_url, &bundle_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download cosign bundle from {bundle_url}. The release \
             pipeline requires a manifest's signature to be present alongside \
             the manifest body — refusing to trust an unsigned manifest."
        ))
    })?;

    let manifest_bytes =
        std::fs::read(&manifest_path).context("reading downloaded manifest body")?;
    let bundle_bytes = std::fs::read(&bundle_path).context("reading downloaded cosign bundle")?;

    let expected_identity = format!(
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"
    );
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        tracing::warn!(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest body. \
             This is an emergency-rotation escape hatch only."
        );
        image_verify::parse_manifest(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("manifest parse failed: {e}"))?
    } else {
        image_verify::verify_manifest(
            &manifest_bytes,
            &bundle_bytes,
            &expected_identity,
            expected_issuer,
        )
        .map_err(|e| {
            bump_verify_outcome("sig_invalid");
            anyhow::anyhow!("Cosign verification failed for {manifest_name}: {e}")
        })?
    };

    image_verify::check_version_pin(&manifest, version).map_err(|e| {
        bump_verify_outcome("version_skew");
        anyhow::anyhow!("manifest version pin failed: {e}")
    })?;

    let now = chrono::Utc::now();
    if let Err(e) = image_verify::check_not_after(&manifest, now) {
        bump_verify_outcome("expired");
        ui::warn(&format!(
            "Dev image manifest is past its max-age ({e}). Consider upgrading \
             the CLI — older signed images are still cryptographically valid but \
             may carry unpatched vulnerabilities."
        ));
    }

    if let Some(revocations) = try_fetch_revocation_list()? {
        image_verify::check_revocation(&manifest, &revocations).map_err(|e| {
            bump_verify_outcome("revoked");
            anyhow::anyhow!("Dev image manifest is on the project's revocation list: {e}")
        })?;
    }

    Ok(Some(manifest))
}

fn try_fetch_revocation_list() -> Result<Option<mvm_core::crypto::image_verify::RevocationList>> {
    use mvm_core::crypto::image_verify;
    use std::time::{Duration, SystemTime};

    let cache_dir = format!("{}/revocations", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating revocations cache dir {cache_dir}"))?;
    let cache_json = format!("{cache_dir}/revoked-versions.json");
    let cache_bundle = format!("{cache_dir}/revoked-versions.json.bundle");

    let cache_age = std::fs::metadata(&cache_json)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or(Duration::from_secs(u64::MAX));

    let twenty_four_hours = Duration::from_secs(24 * 60 * 60);
    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);

    if cache_age > twenty_four_hours {
        let base = "https://github.com/tinylabscom/mvm/releases/download/revocations";
        let json_url = format!("{base}/revoked-versions.json");
        let bundle_url = format!("{base}/revoked-versions.json.bundle");

        match url_exists(&json_url) {
            Ok(true) => {
                let tmp_json =
                    tempfile::NamedTempFile::new().context("creating revocations tempfile")?;
                let tmp_bundle = tempfile::NamedTempFile::new()
                    .context("creating revocations bundle tempfile")?;
                let tmp_json_path = tmp_json.path().to_string_lossy().into_owned();
                let tmp_bundle_path = tmp_bundle.path().to_string_lossy().into_owned();
                let download_result = download_file(&json_url, &tmp_json_path)
                    .and_then(|()| download_file(&bundle_url, &tmp_bundle_path));
                match download_result {
                    Ok(()) => {
                        std::fs::copy(&tmp_json_path, &cache_json)
                            .context("caching revoked-versions.json")?;
                        std::fs::copy(&tmp_bundle_path, &cache_bundle)
                            .context("caching revoked-versions.json.bundle")?;
                    }
                    Err(e) if cache_age <= seven_days => {
                        ui::warn(&format!(
                            "Could not refresh revocation list ({e}); using cached copy \
                             (last refreshed {} hours ago).",
                            cache_age.as_secs() / 3600
                        ));
                    }
                    Err(e) => {
                        ui::warn(&format!(
                            "Could not refresh revocation list ({e}) and no fresh cache \
                             is available; proceeding without recall enforcement."
                        ));
                        return Ok(None);
                    }
                }
            }
            Ok(false) => return Ok(None),
            Err(e) if cache_age <= seven_days => {
                ui::warn(&format!(
                    "Could not probe revocation list ({e}); using cached copy."
                ));
            }
            Err(e) => {
                ui::warn(&format!(
                    "Could not probe revocation list ({e}) and no fresh cache \
                     is available; proceeding without recall enforcement."
                ));
                return Ok(None);
            }
        }
    }

    if !std::path::Path::new(&cache_json).exists() {
        return Ok(None);
    }

    let json_bytes = std::fs::read(&cache_json).context("reading cached revocations.json")?;
    let bundle_bytes =
        std::fs::read(&cache_bundle).context("reading cached revocations.json.bundle")?;

    let expected_identity = "https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocations";
    let expected_issuer = "https://token.actions.githubusercontent.com";

    if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        let list: image_verify::RevocationList = serde_json::from_slice(&json_bytes)
            .context("parsing revocations JSON without signature verification")?;
        return Ok(Some(list));
    }

    image_verify::verify_signed_payload(
        &json_bytes,
        &bundle_bytes,
        expected_identity,
        expected_issuer,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "Revocation list signature verification failed: {e}. Refusing to \
             trust an unverified recall."
        )
    })?;
    let list: image_verify::RevocationList =
        serde_json::from_slice(&json_bytes).context("parsing verified revocations JSON")?;
    Ok(Some(list))
}

pub fn cmd_dev_import_image(
    manifest_path: &str,
    bundle_path: &str,
    vmlinux_path: &str,
    rootfs_path: &str,
) -> Result<()> {
    use mvm_core::crypto::image_verify;

    let version = env!("CARGO_PKG_VERSION");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    ui::info(&format!(
        "Importing dev image (v{version}, {arch}) from local files..."
    ));

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("reading manifest file at {manifest_path}"))?;
    let bundle_bytes = std::fs::read(bundle_path)
        .with_context(|| format!("reading cosign bundle at {bundle_path}"))?;

    let expected_identity = format!(
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"
    );
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        ui::warn(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest. \
             This is an emergency-rotation escape only.",
        );
        image_verify::parse_manifest(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("manifest parse failed: {e}"))?
    } else {
        image_verify::verify_manifest(
            &manifest_bytes,
            &bundle_bytes,
            &expected_identity,
            expected_issuer,
        )
        .map_err(|e| {
            bump_verify_outcome("sig_invalid");
            anyhow::anyhow!("Cosign verification failed for the imported manifest: {e}")
        })?
    };

    image_verify::check_version_pin(&manifest, version).map_err(|e| {
        bump_verify_outcome("version_skew");
        anyhow::anyhow!("Imported manifest is for a different CLI version: {e}")
    })?;

    let now = chrono::Utc::now();
    if let Err(e) = image_verify::check_not_after(&manifest, now) {
        bump_verify_outcome("expired");
        ui::warn(&format!(
            "Imported manifest is past its max-age ({e}). Sideloaded images \
             from older releases remain cryptographically valid but may \
             carry unpatched vulnerabilities."
        ));
    }

    if let Some(revocations) = try_fetch_revocation_list()? {
        image_verify::check_revocation(&manifest, &revocations).map_err(|e| {
            bump_verify_outcome("revoked");
            anyhow::anyhow!("Imported manifest is on the project's revocation list: {e}")
        })?;
    }

    if manifest.arch != arch {
        anyhow::bail!(
            "Manifest is for arch {} but this host is {arch}. Wrong-arch image \
             would not boot.",
            manifest.arch
        );
    }

    let kernel_name = format!("dev-vmlinux-{arch}");
    let rootfs_name = format!("dev-rootfs-{arch}.{}", manifest.rootfs_format);

    let kernel_digest = manifest
        .artifact(&kernel_name)
        .ok_or_else(|| anyhow::anyhow!("manifest does not list {kernel_name}"))?;
    let rootfs_digest = manifest
        .artifact(&rootfs_name)
        .ok_or_else(|| anyhow::anyhow!("manifest does not list {rootfs_name}"))?;

    image_verify::verify_artifact(std::path::Path::new(vmlinux_path), kernel_digest).map_err(
        |e| {
            bump_verify_outcome("digest_mismatch");
            anyhow::anyhow!("kernel SHA-256 mismatch: {e}")
        },
    )?;
    image_verify::verify_artifact(std::path::Path::new(rootfs_path), rootfs_digest).map_err(
        |e| {
            bump_verify_outcome("digest_mismatch");
            anyhow::anyhow!("rootfs SHA-256 mismatch: {e}")
        },
    )?;

    let prebuilt_dir = format!(
        "{}/dev/prebuilt/v{version}",
        mvm_core::config::mvm_data_dir()
    );
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    let target_kernel = format!("{prebuilt_dir}/vmlinux");
    let target_rootfs = format!("{prebuilt_dir}/rootfs.ext4");
    std::fs::copy(vmlinux_path, &target_kernel)
        .with_context(|| format!("copying kernel to {target_kernel}"))?;
    std::fs::copy(rootfs_path, &target_rootfs)
        .with_context(|| format!("copying rootfs to {target_rootfs}"))?;

    mvm_core::observability::metrics::global()
        .dev_image_verify_ok
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    ui::success(&format!(
        "Imported and verified dev image v{version} into {prebuilt_dir}. \
         Run `mvmctl dev up` to boot the dev VM from the cached artifacts."
    ));
    Ok(())
}
