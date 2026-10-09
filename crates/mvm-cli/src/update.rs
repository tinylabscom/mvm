use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::http;
use crate::ui;
use mvm_build::published_image_set::github_download_base;
use mvm_core::release_version::{ReleaseVersion, VersionSyntax};

const GITHUB_REPO: &str = "tinylabscom/mvm";

/// Current version compiled into the binary (from Cargo.toml).
pub(crate) fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Detect the target triple for the current platform at compile time.
/// Returns strings matching the release artifact naming from release.yml.
fn detect_target() -> Result<&'static str> {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return Ok("aarch64-apple-darwin");

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return Ok("x86_64-apple-darwin");

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return Ok("x86_64-unknown-linux-gnu");

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    return Ok("aarch64-unknown-linux-gnu");

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
    )))]
    anyhow::bail!(
        "Unsupported platform: {} / {}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
}

/// Base URL for the GitHub releases query.
///
/// Defaults to `https://api.github.com`. `MVM_UPDATE_API_URL` overrides
/// for hermetic tests — the env-var supplies the bare host
/// (e.g. `http://127.0.0.1:8080`) and the existing path suffix
/// `/repos/<repo>/releases/latest` is appended. The override path
/// emits a warning so the bypass is visible in stderr.
fn github_api_base() -> String {
    if let Ok(base) = std::env::var("MVM_UPDATE_API_URL")
        && !base.trim().is_empty()
    {
        eprintln!("[mvm] MVM_UPDATE_API_URL set; using {base} (test path).");
        return base.trim().trim_end_matches('/').to_string();
    }
    String::from("https://api.github.com")
}

/// Query the GitHub releases API for the latest release tag name.
pub(crate) fn fetch_latest_version() -> Result<String> {
    let url = format!(
        "{}/repos/{}/releases/latest",
        github_api_base(),
        GITHUB_REPO
    );

    let json = http::fetch_json(&url)
        .context("Failed to query GitHub releases API. Check your network connection.")?;

    let tag = json["tag_name"]
        .as_str()
        .context("GitHub API response missing 'tag_name' field")?;

    Ok(tag.to_string())
}

/// Strip the "v" prefix from a version tag.
fn strip_v_prefix(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Download a release checksum manifest and prove the publisher signed it
/// before any of its bytes are read.
///
/// The manifest decides which artifact bytes are acceptable, so whoever can
/// serve one picks the artifact; TLS says nothing about who wrote it. Refuses
/// on a missing, unparseable, or foreign-signed bundle — the shared release
/// verifier does the deciding.
/// Download a GitHub release asset.
///
/// Release asset URLs always answer `302` and redirect to blob storage, and
/// `mvm_http` deliberately does not follow redirects ("no HTTP/2, no redirect
/// following ..." — every one of its other callers has already disabled them).
/// So a release fetch routed through it fails on the redirect no matter how
/// correct the URL is. Reuses the curl downloader the working release paths
/// already use, whose `-fSL` follows the redirect and fails on HTTP error.
fn download_release_asset(url: &str, dest: &Path) -> Result<()> {
    let dest_str = dest
        .to_str()
        .with_context(|| format!("release asset destination is not UTF-8: {}", dest.display()))?;
    crate::commands::env::artifact_verify::download_file(url, dest_str)
}

/// The boot image release every published guest artifact is fetched from, as
/// `(tag, bare-semver)`.
///
/// Deliberately *not* the CLI's own version. Those are separate counters: the
/// CLI ships from `v<crate version>` and the images from `boot-image/vN`, so a
/// kernel fix does not wait for a CLI release. Deriving the image URL from
/// `CARGO_PKG_VERSION` meant every build between two CLI releases pointed at a
/// tag nobody had published — a 404 on the first boot of a fresh install, for
/// most of the CLI's life rather than at its edges.
///
/// The bare semver is what `release_trust`'s boot image identity template
/// interpolates, so it is derived here rather than re-split at each call site.
#[cfg(test)]
pub(crate) fn boot_image_release() -> Result<(String, String)> {
    let tag = mvm_core::config::default_boot_image_tag();
    let version = tag.rsplit_once("/v").map(|(_, v)| v).with_context(|| {
        format!("image set tag {tag:?} is not of the form `image-set/v<semver>`")
    })?;
    Ok((tag.to_string(), version.to_string()))
}

/// Asset and checksum-manifest names for a kernel variant in the image set.
///
/// The image set publishes each kernel *inside* the image it belongs to, so a
/// variant maps to the image that carries it: the workload kernel is the
/// default tenant's, the builder kernel the builder VM's. mvm-images builds
/// both from one shared kernel definition, so the mapping is a rename, not a
/// substitution.
fn boot_image_kernel_assets(arch: &str, variant: &str) -> Result<(String, String)> {
    let image = match variant {
        "workload" => "default-microvm",
        "builder" => "builder-vm",
        other => anyhow::bail!(
            "unknown kernel variant {other:?}: the boot image publishes only the \
             workload (default-microvm) and builder (builder-vm) kernels"
        ),
    };
    Ok((
        format!("{image}-vmlinux-{arch}"),
        format!("{image}-{arch}-checksums-sha256.txt"),
    ))
}

/// Parse a hex-encoded SHA256 digest from a `checksums-sha256.txt` entry.
///
/// Each line is: `<64 hex chars>  <filename>`  (two spaces, shasum format).
/// Returns the raw 32-byte digest.
fn parse_checksum_line(line: &str) -> Result<[u8; 32]> {
    let hex = line
        .split_whitespace()
        .next()
        .context("Empty checksum line")?;
    if hex.len() != 64 {
        anyhow::bail!("Expected 64 hex chars in checksum, got {}", hex.len());
    }
    let mut digest = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).context("Non-UTF8 in checksum hex")?;
        digest[i] =
            u8::from_str_radix(s, 16).with_context(|| format!("Invalid hex byte: {}", s))?;
    }
    Ok(digest)
}

/// Verify the SHA256 digest of a downloaded archive against `checksums-sha256.txt`.
///
/// Downloads the combined checksum file, finds the line for `archive_name`,
/// and confirms it matches the digest of the file at `archive_path`.
fn verify_checksum(version: &str, archive_name: &str, archive_path: &Path) -> Result<()> {
    let checksum_url = format!(
        "{}/{}/releases/download/{}/checksums-sha256.txt",
        github_download_base(),
        GITHUB_REPO,
        version
    );

    let checksum_text = http::fetch_text(&checksum_url)
        .context("Failed to download checksum file — cannot verify integrity")?;

    // Find the line that corresponds to this archive.
    let expected_digest = checksum_text
        .lines()
        .find(|line| line.contains(archive_name))
        .with_context(|| {
            format!(
                "Checksum for '{}' not found in checksums-sha256.txt",
                archive_name
            )
        })
        .and_then(parse_checksum_line)?;

    // Compute the SHA256 of the downloaded file.
    let bytes = std::fs::read(archive_path).with_context(|| {
        format!(
            "Failed to read archive for checksum: {}",
            archive_path.display()
        )
    })?;
    let actual_digest: [u8; 32] = Sha256::digest(&bytes).into();

    if actual_digest != expected_digest {
        anyhow::bail!(
            "Checksum mismatch for {}!\n  expected: {}\n  actual:   {}\nThe download may be corrupted or tampered with.",
            archive_name,
            hex_encode(&expected_digest),
            hex_encode(&actual_digest),
        );
    }

    ui::success("Checksum verified.");
    Ok(())
}

/// Hex-encode a byte slice for display.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Download the release archive into the given temp directory.
fn download_release(version: &str, target: &str, tmp_dir: &Path) -> Result<()> {
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let download_url = format!(
        "{}/{}/releases/download/{}/{}",
        github_download_base(),
        GITHUB_REPO,
        version,
        archive_name
    );
    let dest = tmp_dir.join(&archive_name);

    let sp = ui::spinner(&format!("Downloading {}...", download_url));

    download_release_asset(&download_url, &dest).with_context(|| {
        format!(
            "Download failed. Check that {} has a release for {}.",
            version, target
        )
    })?;

    sp.finish_and_clear();
    ui::success("Download complete.");
    Ok(())
}

/// Whether a release with this tag exists at all.
///
/// Only ever called on the error path, so the extra request costs nothing in
/// The advice to print when a kernel download 404s.
///
/// A missing asset and a missing release are the same HTTP status and
/// different problems. An in-development build always hits the second — the
/// crate version runs ahead of the last tag, by construction — and telling
/// that user to "cut a release that publishes kernels" points them at
/// something that is not broken, when what they want is to compile.
#[cfg(test)]
fn kernel_fetch_hint(tag: &str, asset: &str, release_exists: bool) -> String {
    if release_exists {
        format!(
            "release {tag} exists but publishes no kernel asset {asset}. Build it \
             locally with `--source compile`, or cut a release that publishes kernels."
        )
    } else {
        format!(
            "there is no release {tag} to download {asset} from. This mvmctl was \
             built from a version that has not been released — a source checkout \
             compiles instead: `--source compile`."
        )
    }
}

/// Download a workload or builder kernel from the signed image set pinned by
/// this build. The root digest, exact publisher identity, compatibility and
/// member digest are all established before the staged file is published.
pub(crate) fn download_kernel(arch: &str, variant: &str, dest: &Path) -> Result<()> {
    let (asset, _) = boot_image_kernel_assets(arch, variant)?;
    let arch = arch.parse::<mvm_core::arch::GuestArch>()?;
    let role = match variant {
        "workload" => mvm_core::image_set::ImageSetRole::WorkloadKernel(
            mvm_core::image_set::WorkloadImageProfile::DefaultTenant,
        ),
        "builder" => mvm_core::image_set::ImageSetRole::BuilderVm,
        other => bail!("unknown kernel variant {other:?}"),
    };

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating kernel cache dir {}", parent.display()))?;
    }

    let parent = dest
        .parent()
        .with_context(|| format!("kernel destination has no parent: {}", dest.display()))?;
    let download = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| {
            format!(
                "creating kernel download staging file in {}",
                parent.display()
            )
        })?
        .into_temp_path();
    let image_set = crate::commands::env::artifact_verify::acquire_image_set()?;
    let artifact =
        image_set.artifact(role, mvm_core::image_set::MemberTarget::Arch(arch), &asset)?;
    let tag = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str();
    let sp = ui::spinner(&format!("Downloading {asset} ({tag})..."));
    let dl = image_set.fetch_artifact(artifact, &download);
    sp.finish_and_clear();
    dl.with_context(|| format!("download {asset} from the locked image set"))?;
    ui::success(&format!("Verified {asset}."));
    publish_downloaded_kernel(download, dest)?;
    Ok(())
}

/// Record the fetched kernel's digest beside it so the *read* path can check
/// it later.
///
/// The checksum-manifest comparison above happens once, at fetch. Nothing
/// re-derived it afterwards, so a kernel that rotted, was truncated, or was
/// replaced on disk was served on the strength of its filename. The staged
/// download is renamed into place only after checksum verification, and a
/// sidecar failure evicts it rather than leaving an unservable cache entry.
fn publish_downloaded_kernel(download: tempfile::TempPath, dest: &Path) -> Result<()> {
    download
        .persist(dest)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing downloaded kernel to {}", dest.display()))?;
    if let Err(error) = mvm_build::kernel_fetch::record_kernel_digest(dest) {
        let _ = std::fs::remove_file(dest);
        let _ = std::fs::remove_file(mvm_build::kernel_fetch::kernel_digest_sidecar(dest));
        return Err(error).context("recording downloaded kernel digest");
    }
    Ok(())
}

/// Refuse to update a binary the system package manager owns. Replacing
/// `/usr/bin/mvmctl` behind dpkg's or rpm's back leaves its database recording
/// files and digests that are no longer on disk, and the next package upgrade
/// or removal acts on that stale record.
fn refuse_package_install(current_exe: &Path) -> Result<()> {
    match crate::install_layout::package_install_of(current_exe) {
        Some(install) => bail!(package_install_refusal(&install)),
        None => Ok(()),
    }
}

/// Validate the running binary only when this invocation may replace it.
///
/// `--check` is deliberately read-only: package ownership and install layout
/// affect replacement, not whether a newer release can be reported.
fn validate_install_target(check_only: bool, current_exe: &Path) -> Result<()> {
    if check_only {
        return Ok(());
    }
    refuse_package_install(current_exe)
}

/// What to tell a user whose mvmctl came from a distribution package.
fn package_install_refusal(install: &crate::install_layout::PackageInstall) -> String {
    use crate::install_layout::PackageFormat;
    let releases = format!("https://github.com/{GITHUB_REPO}/releases");
    let (origin, upgrade) = match install.format {
        Some(PackageFormat::Deb) => (
            "the mvmctl .deb package, so dpkg owns it".to_string(),
            format!(
                "download the new .deb from {releases} and run: \
                 sudo apt install ./mvmctl_<version>-1_<arch>.deb"
            ),
        ),
        Some(PackageFormat::Rpm) => (
            "the mvmctl .rpm package, so rpm owns it".to_string(),
            format!(
                "download the new .rpm from {releases} and run: \
                 sudo dnf install ./mvmctl-<version>-1.<arch>.rpm"
            ),
        ),
        None => (
            "a system package, so its package manager owns it".to_string(),
            "upgrade it with the package manager that installed it".to_string(),
        ),
    };
    format!(
        "this mvmctl was installed from {origin} (marker: {marker}). Replacing it here \
         would leave the package database describing files that are no longer on disk. \
         To upgrade, {upgrade}",
        marker = install.marker.display(),
    )
}

/// Extract only the authenticated installer, never archive-controlled paths.
/// Validate every entry before executing anything, including entries after it.
fn extract_release_installer(archive_path: &Path, target: &str) -> Result<tempfile::NamedTempFile> {
    let file = std::fs::File::open(archive_path).context("Opening release archive")?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let expected = format!("mvmctl-{target}/install.sh");
    let mut installer = None;
    for entry in archive.entries().context("Reading release archive")? {
        let mut entry = entry.context("Reading release archive entry")?;
        let raw = entry.path_bytes();
        let path = std::str::from_utf8(&raw).context("Non-UTF-8 release archive path")?;
        // Release tarballs may use a single conventional leading ./.
        let path = path.strip_prefix("./").unwrap_or(path);
        if path.is_empty() && entry.header().entry_type().is_dir() {
            continue;
        }
        mvm_core::plan::bundle::ensure_safe_path(path)?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            bail!("Refusing non-regular release archive entry: {path}");
        }
        if path == expected {
            if !kind.is_file() || installer.is_some() {
                bail!("Release archive must contain exactly one regular {expected}");
            }
            let mut script = tempfile::NamedTempFile::new().context("Staging release installer")?;
            std::io::copy(&mut entry, &mut script).context("Extracting release installer")?;
            installer = Some(script);
        }
    }
    installer.with_context(|| {
        format!(
            "Release archive is missing {expected}; refusing to change the existing installation"
        )
    })
}

/// Delegate the whole CLI/helper/guest-runtime transaction to the installer
/// shipped inside the signed release, rather than duplicating its rollback.
fn extract_and_install(
    version: &str,
    target: &str,
    tmp_dir: &Path,
    current_exe: &Path,
) -> Result<()> {
    let archive_path = tmp_dir.join(format!("mvmctl-{target}.tar.gz"));
    let installer = extract_release_installer(&archive_path, target)?;
    // Pin the installer's redownload to the bytes authenticated above.
    let archive_digest = mvm_core::crypto::image_verify::sha256_file(&archive_path)
        .context("Hashing authenticated release archive")?;
    let lib_dir = crate::install_layout::versioned_lib_dir_of(current_exe);
    let install_dir = if let Some(lib) = &lib_dir {
        let marker = std::fs::read_to_string(lib.join(crate::install_layout::LIB_MARKER))
            .context("Reading versioned installation marker")?;
        let dirs: Vec<_> = marker
            .lines()
            .filter_map(|line| line.strip_prefix("install_dir="))
            .collect();
        if dirs.len() != 1 || !Path::new(dirs[0]).is_absolute() {
            bail!(
                "Versioned installation marker must record one absolute install_dir; re-run install.sh with the original installation paths"
            );
        }
        std::path::PathBuf::from(dirs[0])
    } else {
        current_exe
            .parent()
            .context("Cannot determine install directory")?
            .to_path_buf()
    };
    let mut command = mvm_core::env_hygiene::helper_command("sh");
    command
        .arg(installer.path())
        .env("MVM_VERSION", version)
        .env("MVM_INSTALL_DIR", &install_dir)
        .env("MVM_TRUSTED_ARCHIVE_SHA256", archive_digest)
        .env("MVM_SKIP_BOOTSTRAP", "1")
        .env_remove("MVM_INSTALL_LIB_DIR")
        .env_remove("MVM_SKIP_VERIFY")
        .env_remove("MVM_SKIP_COSIGN_VERIFY")
        .env_remove("MVM_SKIP_HASH_VERIFY")
        .env_remove("MVM_SKIP_CODESIGN")
        .env_remove("MVM_TRUSTED_COSIGN_SHA256")
        .env_remove("MVM_COSIGN_DOWNLOAD_URL");
    if let Some(lib) = lib_dir {
        command.env("MVM_INSTALL_LIB_DIR", lib);
    }
    let status = command
        .status()
        .context("Running authenticated release installer")?;
    if !status.success() {
        bail!("Release installer failed ({status}); update was not completed");
    }
    Ok(())
}

/// Verify a downloaded release archive against the release workflow's signing
/// identity before anything extracts it.
///
/// The Sigstore bundle published beside the archive is checked in-process
/// against the embedded trust root, so a host without `cosign` gets the same
/// verdict as one with it. A missing, unparseable, or foreign-signed bundle
/// refuses the update; the SHA-256 checked before this comes from a manifest
/// fetched over the same channel, so on its own it says nothing about who
/// published the archive.
fn install_verified_release(
    version: &str,
    target: &str,
    tmp_dir: &Path,
    current_exe: &Path,
) -> Result<()> {
    let release_base = format!(
        "{}/{}/releases/download/{}",
        github_download_base(),
        GITHUB_REPO,
        version
    );
    ui::info("Verifying release signature...");
    install_verified_release_at(&release_base, version, target, tmp_dir, current_exe)
}

fn install_verified_release_at(
    release_base: &str,
    version: &str,
    target: &str,
    tmp_dir: &Path,
    current_exe: &Path,
) -> Result<()> {
    let archive_name = format!("mvmctl-{target}.tar.gz");
    verify_archive_signature_at(
        release_base,
        version,
        &archive_name,
        &tmp_dir.join(&archive_name),
    )?;
    ui::success("Signature verified.");
    extract_and_install(version, target, tmp_dir, current_exe)
}

fn verify_signature_if_required(
    skip_verify: bool,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if skip_verify {
        bail!(
            "--skip-verify is not supported for self-update: the release installer must be authenticated"
        );
    }
    verify()
}

/// Verify `archive_name` against the bundle published under `release_base`,
/// accepting only the CLI release workflow at `tag`.
fn verify_archive_signature_at(
    release_base: &str,
    tag: &str,
    archive_name: &str,
    archive_path: &Path,
) -> Result<()> {
    if std::env::var_os(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV).is_some() {
        bail!(
            "Unset MVM_SKIP_COSIGN_VERIFY before self-update; release authentication is mandatory"
        );
    }
    mvm_build::release_signature::verify_release_archive_signature(
        &mvm_build::release_signature::ReleaseSignatureRequest {
            base_url: release_base,
            asset: archive_name,
            archive_path,
            version: strip_v_prefix(tag),
            train: mvm_build::release_signature::ReleaseTrain::Cli,
        },
    )
    .with_context(|| {
        format!(
            "refusing to install {archive_name}: it is not signed by the {tag} release workflow"
        )
    })
}

/// What `update` should do about the release it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateAction {
    /// The running binary is already the resolved release.
    UpToDate,
    /// Install the resolved release over the running one.
    Install,
    /// The resolved release is older than the running one. Refused, because a
    /// user who ran `update` asked to move forward and would not be told
    /// otherwise: the old code called this "New version available" and
    /// installed it.
    RefuseDowngrade,
}

/// Decide without performing any I/O, so every branch is testable.
///
/// `--force` overrides both refusals — reinstalling the same version and
/// deliberately moving back to an older one are both things a user can mean.
pub(crate) fn decide_update(latest: &str, current: &str, force: bool) -> UpdateAction {
    use std::cmp::Ordering;

    let ordered = ReleaseVersion::parse(latest, VersionSyntax::Lenient)
        .zip(ReleaseVersion::parse(current, VersionSyntax::Lenient))
        .map(|(latest, running)| latest.cmp(&running));

    match ordered {
        Some(Ordering::Less) if !force => UpdateAction::RefuseDowngrade,
        Some(Ordering::Equal) if !force => UpdateAction::UpToDate,
        // Unparseable on either side: fall back to the equality test this used
        // before there was an ordering at all. Not a guess, just no worse.
        None if latest == current && !force => UpdateAction::UpToDate,
        _ => UpdateAction::Install,
    }
}

/// Main entry point: check for updates and optionally install.
/// Tag prefix for the boot-image release line. Images version on their own
/// counter, so `v0.18.0` (binaries) and `boot-image/v0.1.0` (images) name
/// different things and neither ordering means anything to the other.
pub(crate) const BOOT_IMAGE_TAG_PREFIX: &str = "image-set/v";

/// A `major.minor.patch` triple, parsed so two tags can be ordered.
///
/// Ordering tags as strings puts `v0.10.0` before `v0.9.0`, which would report
/// a newer image as older — the one wrong answer this whole comparison exists
/// to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BootImageVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl BootImageVersion {
    /// Parse the version out of a full `boot-image/vX.Y.Z` tag. Anything that
    /// is not that shape returns `None` rather than a guess — a tag we cannot
    /// order is one we must not claim to have ordered.
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        Self::parse(tag.strip_prefix(BOOT_IMAGE_TAG_PREFIX)?)
    }

    fn parse(version: &str) -> Option<Self> {
        // A pre-release or build suffix does not participate in the ordering
        // this command needs; drop it rather than refuse the whole tag.
        let core = version
            .split(['-', '+'])
            .next()
            .unwrap_or(version)
            .trim_end();
        let mut parts = core.split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let major = next()?;
        let minor = next()?;
        let patch = next()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

/// Pick the highest `image-set/v*` tag from a set of tag names.
///
/// Split from the fetch so the ordering can be tested without a server.
pub(crate) fn highest_boot_image_tag<'a>(tags: impl Iterator<Item = &'a str>) -> Option<String> {
    tags.filter_map(|tag| BootImageVersion::from_tag(tag).map(|v| (v, tag)))
        .max_by_key(|(v, _)| *v)
        .map(|(_, tag)| tag.to_string())
}

/// Which install line `update` announces once `decide_update` has settled on
/// `Install`. Pure, and therefore unit-testable at its boundaries, because the
/// three cases differ only in wording — and wording that drifts (a downgrade
/// announced as an upgrade) is the bug this classification exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallAnnouncement {
    /// `latest == current`: reachable only with `--force`, which alone turns
    /// "already current" from `UpToDate` into `Install`.
    ForceReinstall,
    /// `latest < current` in the lenient ordering: reachable only under
    /// `--force`.
    DowngradeOverNewer,
    /// A strictly newer release, or a pair whose versions cannot be ordered.
    NewVersion,
}

fn install_announcement(current: &str, latest: &str) -> InstallAnnouncement {
    if latest == current {
        return InstallAnnouncement::ForceReinstall;
    }
    if ReleaseVersion::parse(latest, VersionSyntax::Lenient)
        .zip(ReleaseVersion::parse(current, VersionSyntax::Lenient))
        .is_some_and(|(latest, running)| latest < running)
    {
        return InstallAnnouncement::DowngradeOverNewer;
    }
    InstallAnnouncement::NewVersion
}

pub fn update(check_only: bool, force: bool, skip_verify: bool) -> Result<()> {
    // An install this command must not touch is refused before any network
    // traffic: the answer does not depend on what the latest release is.
    let current_exe =
        std::env::current_exe().context("Failed to determine path of current executable")?;
    validate_install_target(check_only, &current_exe)?;

    let current = current_version();
    ui::info(&format!("Current version: {}", current));

    let sp = ui::spinner("Checking for updates...");
    let latest_tag = fetch_latest_version()?;
    let latest_version = strip_v_prefix(&latest_tag);
    sp.finish_and_clear();

    match decide_update(latest_version, current, force) {
        UpdateAction::UpToDate => {
            ui::success(&format!("Already up to date ({}).", current));
            return Ok(());
        }
        UpdateAction::RefuseDowngrade => {
            ui::warn(&format!(
                "The latest release is {}, which is older than the running {}.",
                latest_version, current
            ));
            ui::info("Not downgrading. Re-run with --force to install it anyway.");
            return Ok(());
        }
        UpdateAction::Install => {}
    }

    match install_announcement(current, latest_version) {
        InstallAnnouncement::ForceReinstall => {
            ui::info(&format!(
                "Already at {} but --force specified, reinstalling.",
                current
            ));
        }
        InstallAnnouncement::DowngradeOverNewer => {
            // Reachable only under --force. Announcing a downgrade as a "new
            // version" is what this whole change is about.
            ui::info(&format!(
                "Installing {} over the newer {} (--force).",
                latest_version, current
            ));
        }
        InstallAnnouncement::NewVersion => {
            ui::info(&format!(
                "New version available: {} -> {}",
                current, latest_version
            ));
        }
    }

    if check_only {
        return Ok(());
    }

    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    let target = detect_target()?;
    ui::info(&format!("Platform: {}", target));

    let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    download_release(&latest_tag, target, tmp_dir.path())?;
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let archive_path = tmp_dir.path().join(&archive_name);
    verify_checksum(&latest_tag, &archive_name, &archive_path)?;
    verify_signature_if_required(skip_verify, || {
        install_verified_release(&latest_tag, target, tmp_dir.path(), &current_exe)
    })?;

    ui::success(&format!("\nSuccessfully updated to {}!", latest_tag));
    ui::info("The CLI and matching guest runtime have been installed together.");
    ui::info("To verify: Open a new shell and run 'mvmctl --version'");
    ui::info("Or run: hash -r  (to clear your shell's command cache)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UpdateAction, decide_update};

    /// The bug, stated as the behaviour: an rc user's latest is the stable
    /// release, because the rc is published as a prerelease and deliberately is
    /// not latest. Installing it walks them backwards.
    #[test]
    fn an_rc_is_not_walked_back_to_stable_by_a_plain_update() {
        assert_eq!(
            decide_update("0.17.0", "0.18.0-rc.1", false),
            UpdateAction::RefuseDowngrade
        );
        // Deliberately moving back is something a user can mean.
        assert_eq!(
            decide_update("0.17.0", "0.18.0-rc.1", true),
            UpdateAction::Install
        );
    }

    #[test]
    fn moving_forward_and_standing_still_are_unchanged() {
        assert_eq!(
            decide_update("0.18.0", "0.17.0", false),
            UpdateAction::Install
        );
        assert_eq!(
            decide_update("0.18.0", "0.18.0-rc.1", false),
            UpdateAction::Install,
            "the rc's own final release is a real upgrade"
        );
        assert_eq!(
            decide_update("0.18.0", "0.18.0", false),
            UpdateAction::UpToDate
        );
        assert_eq!(
            decide_update("0.18.0", "0.18.0", true),
            UpdateAction::Install,
            "--force reinstalls the same version"
        );
    }

    /// A version neither side can order must not become a silent downgrade.
    /// The equality test is what this did before an ordering existed, and
    /// falling back to it is no worse than it ever was.
    #[test]
    fn an_unorderable_version_falls_back_to_the_equality_test() {
        assert_eq!(
            decide_update("nightly", "nightly", false),
            UpdateAction::UpToDate
        );
        assert_eq!(
            decide_update("nightly", "0.18.0", false),
            UpdateAction::Install,
            "unparseable is not evidence of a downgrade, so it must not refuse"
        );
    }

    /// The image counter and the CLI counter are different numbers, and the
    /// fetch URL has to follow the image one.
    #[test]
    fn the_boot_image_release_is_not_the_cli_version() {
        let (tag, version) = boot_image_release().expect("a well-formed pinned tag");
        assert!(
            tag.starts_with("image-set/v"),
            "images ship on their own counter: {tag}"
        );
        assert_eq!(tag, format!("image-set/v{version}"));
        assert_ne!(
            tag,
            format!("v{}", current_version()),
            "deriving the image tag from the CLI version is the bug this fixes"
        );
    }

    /// The bare semver is what the boot image identity template interpolates,
    /// so a tag that does not split cleanly would silently accept no identity.
    #[test]
    fn the_image_version_matches_the_signing_identity_template() {
        let (_tag, version) = boot_image_release().expect("tag");
        let identities = mvm_core::release_trust::accepted_image_set_identities(&version);
        assert!(
            identities
                .iter()
                .any(|i| i.ends_with(&format!("refs/tags/image-set/v{version}"))),
            "identity must bind the published tag: {identities:?}"
        );
    }

    /// The two release trains name the same kernel differently; this is the
    /// rename, and getting it wrong would fetch the *other* kernel.
    #[test]
    fn kernel_variants_map_to_their_published_image_assets() {
        assert_eq!(
            boot_image_kernel_assets("aarch64", "workload").unwrap(),
            (
                "default-microvm-vmlinux-aarch64".to_string(),
                "default-microvm-aarch64-checksums-sha256.txt".to_string()
            )
        );
        assert_eq!(
            boot_image_kernel_assets("x86_64", "builder").unwrap(),
            (
                "builder-vm-vmlinux-x86_64".to_string(),
                "builder-vm-x86_64-checksums-sha256.txt".to_string()
            )
        );
    }

    #[test]
    fn an_unknown_kernel_variant_is_refused_rather_than_guessed() {
        let err = boot_image_kernel_assets("aarch64", "initramfs")
            .expect_err("only workload and builder kernels are published");
        assert!(format!("{err}").contains("unknown kernel variant"), "{err}");
    }

    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    // --- install.sh layout ---

    #[test]
    fn update_accepts_a_binary_in_an_install_sh_release_directory() {
        use crate::install_layout::{LIB_MARKER, RELEASE_MARKER};
        let root = tempfile::tempdir().unwrap();
        let release = root.path().join("lib").join("2-v0.18.0");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(root.path().join("lib").join(LIB_MARKER), "").unwrap();
        std::fs::write(release.join(RELEASE_MARKER), "complete\n").unwrap();
        std::fs::write(release.join("mvmctl"), "").unwrap();

        validate_install_target(false, &release.join("mvmctl")).unwrap();
    }

    #[test]
    fn check_only_does_not_refuse_an_install_sh_release_directory() {
        use crate::install_layout::{LIB_MARKER, RELEASE_MARKER};
        let root = tempfile::tempdir().unwrap();
        let release = root.path().join("lib").join("2-v0.18.0");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(root.path().join("lib").join(LIB_MARKER), "").unwrap();
        std::fs::write(release.join(RELEASE_MARKER), "complete\n").unwrap();
        let executable = release.join("mvmctl");
        std::fs::write(&executable, "").unwrap();

        validate_install_target(true, &executable)
            .expect("checking for updates never replaces the managed binary");
        assert!(
            validate_install_target(false, &executable).is_ok(),
            "an actual update delegates to the atomic installer"
        );
    }

    #[test]
    fn update_proceeds_for_a_binary_outside_an_install_sh_release() {
        let root = tempfile::tempdir().unwrap();
        let loose = root.path().join("bin").join("mvmctl");
        std::fs::create_dir_all(loose.parent().unwrap()).unwrap();
        std::fs::write(&loose, "").unwrap();
        assert!(validate_install_target(false, &loose).is_ok());
    }

    // --- distribution packages ---

    /// `<root>/usr/bin/mvmctl` with the package marker holding `content`.
    fn packaged_binary(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use crate::install_layout::PACKAGE_MARKER;
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr");
        std::fs::create_dir_all(usr.join("bin")).unwrap();
        std::fs::write(usr.join("bin/mvmctl"), "").unwrap();
        let marker = usr.join(PACKAGE_MARKER);
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(marker, content).unwrap();
        let exe = usr.join("bin/mvmctl");
        (root, exe)
    }

    #[test]
    fn update_refuses_a_binary_a_deb_installed_and_names_apt() {
        let (_root, exe) = packaged_binary("deb\n");
        let error = refuse_package_install(&exe).unwrap_err().to_string();
        assert!(error.contains("mvmctl .deb package"), "{error}");
        assert!(error.contains("dpkg owns it"), "{error}");
        assert!(
            error.contains("sudo apt install ./mvmctl_<version>-1_<arch>.deb"),
            "{error}"
        );
        assert!(error.contains("share/mvmctl/package-managed"), "{error}");
        assert!(
            error.contains("https://github.com/tinylabscom/mvm/releases"),
            "{error}"
        );
    }

    #[test]
    fn update_refuses_a_binary_an_rpm_installed_and_names_dnf() {
        let (_root, exe) = packaged_binary("rpm\n");
        let error = refuse_package_install(&exe).unwrap_err().to_string();
        assert!(error.contains("rpm owns it"), "{error}");
        assert!(
            error.contains("sudo dnf install ./mvmctl-<version>-1.<arch>.rpm"),
            "{error}"
        );
        assert!(!error.contains("apt"), "{error}");
    }

    #[test]
    fn update_refuses_an_unrecognised_package_marker_without_guessing_the_tool() {
        let (_root, exe) = packaged_binary("something-else\n");
        let error = refuse_package_install(&exe).unwrap_err().to_string();
        assert!(
            error.contains("package manager that installed it"),
            "{error}"
        );
        assert!(!error.contains("apt") && !error.contains("dnf"), "{error}");
    }

    #[test]
    fn update_proceeds_for_a_binary_no_package_owns() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("usr/bin/mvmctl");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "").unwrap();
        assert!(refuse_package_install(&exe).is_ok());
    }

    // --- signature verification ---

    /// Stage a release directory holding `archive` and, optionally, a bundle.
    fn stage_release(archive: &[u8], bundle: Option<&[u8]>) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SIGNED_ASSET), archive).unwrap();
        if let Some(bundle) = bundle {
            let name = mvm_build::release_signature::bundle_asset_name(SIGNED_ASSET);
            std::fs::write(dir.path().join(name), bundle).unwrap();
        }
        let base = format!("file://{}", dir.path().display());
        (dir, base)
    }

    const SIGNED_ASSET: &str = "mvmctl-aarch64-apple-darwin.tar.gz";

    #[test]
    fn an_archive_without_a_bundle_is_refused() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let (dir, base) = stage_release(b"archive", None);

        let err = verify_archive_signature_at(
            &base,
            "v9.9.9",
            SIGNED_ASSET,
            &dir.path().join(SIGNED_ASSET),
        )
        .expect_err("an unsigned archive must not install");

        let msg = format!("{err:#}");
        assert!(msg.contains(SIGNED_ASSET), "names the asset: {msg}");
        assert!(msg.contains("v9.9.9"), "names the release: {msg}");
    }

    #[test]
    fn an_archive_with_a_garbage_bundle_is_refused() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let (dir, base) = stage_release(b"archive", Some(b"not a sigstore bundle"));

        verify_archive_signature_at(
            &base,
            "v9.9.9",
            SIGNED_ASSET,
            &dir.path().join(SIGNED_ASSET),
        )
        .expect_err("a bundle that does not parse must not admit the archive");
    }

    #[test]
    fn signature_verification_is_mandatory_even_with_the_legacy_skip_flag() {
        let mut called = false;
        let error = verify_signature_if_required(false, || {
            called = true;
            anyhow::bail!("signature refused")
        })
        .expect_err("verification failures must refuse the update")
        .to_string();
        assert!(called);
        assert!(error.contains("signature refused"), "{error}");

        verify_signature_if_required(true, || panic!("skip verification must not install"))
            .expect_err("the explicit skip must refuse self-update");
    }

    /// The tag carries a `v`; the identity template adds its own. A real
    /// release bundle verifying under its real tag proves the two are not
    /// doubled, which no refusal test can show.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn a_real_release_bundle_verifies_under_its_tag() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let asset = "builder-vm-aarch64-checksums-sha256.txt";
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1");

        verify_archive_signature_at(
            &format!("file://{}", dir.display()),
            "v0.18.0-rc.1",
            asset,
            &dir.join(asset),
        )
        .expect("the v0.18.0-rc.1 release workflow's own signature must verify");

        let err = verify_archive_signature_at(
            &format!("file://{}", dir.display()),
            "v0.18.0",
            asset,
            &dir.join(asset),
        )
        .expect_err("a signature from another release's workflow must not verify");
        assert!(format!("{err:#}").contains("v0.18.0"));
    }

    // --- checksum verification ---

    fn sha256_of(data: &[u8]) -> String {
        let digest: [u8; 32] = Sha256::digest(data).into();
        hex_encode(&digest)
    }

    #[test]
    fn test_parse_checksum_line_valid() {
        let hex = "a".repeat(64);
        let line = format!("{}  mvmctl-aarch64-apple-darwin.tar.gz", hex);
        let digest = parse_checksum_line(&line).unwrap();
        assert_eq!(digest, [0xaa; 32]);
    }

    #[test]
    fn test_parse_checksum_line_wrong_length() {
        let err = parse_checksum_line("abc  file.tar.gz").unwrap_err();
        assert!(err.to_string().contains("64 hex chars"));
    }

    #[test]
    fn test_checksum_correct_digest_passes() {
        let data = b"hello binary";
        let hash = sha256_of(data);

        // Write the "archive" to a temp file
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();

        // Build a checksums-sha256.txt line that matches
        let checksum_line = format!("{}  mvmctl-test.tar.gz\n", hash);

        // parse_checksum_line + manual comparison (verify_checksum needs HTTP)
        let expected = parse_checksum_line(checksum_line.trim()).unwrap();
        let actual: [u8; 32] = Sha256::digest(data).into();
        assert_eq!(expected, actual, "Correct digest should match");
    }

    #[test]
    fn test_checksum_tampered_bytes_fail() {
        let data = b"hello binary";
        let tampered = b"TAMPERED!!!!";
        let hash_of_original = sha256_of(data);
        let checksum_line = format!("{}  mvmctl-test.tar.gz", hash_of_original);

        let expected = parse_checksum_line(&checksum_line).unwrap();
        let actual: [u8; 32] = Sha256::digest(tampered).into();
        assert_ne!(
            expected, actual,
            "Tampered bytes should produce different digest"
        );
    }

    // --- Existing tests ---

    #[test]
    fn test_current_version_non_empty() {
        let v = current_version();
        assert!(!v.is_empty());
        assert!(v.contains('.'), "Version should contain dots: {}", v);
    }

    #[test]
    fn test_strip_v_prefix() {
        assert_eq!(strip_v_prefix("v0.1.0"), "0.1.0");
        assert_eq!(strip_v_prefix("0.1.0"), "0.1.0");
        assert_eq!(strip_v_prefix("v1.2.3-beta"), "1.2.3-beta");
    }

    #[test]
    fn test_detect_target_succeeds() {
        let target = detect_target().unwrap();
        let valid_targets = [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        ];
        assert!(
            valid_targets.contains(&target),
            "Unexpected target: {}",
            target
        );
    }

    #[test]
    fn downloaded_kernel_publish_replaces_atomically_and_records_digest() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("vmlinux");
        std::fs::write(&dest, b"old kernel").unwrap();
        let mut download = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        download.write_all(b"new verified kernel").unwrap();
        download.flush().unwrap();

        publish_downloaded_kernel(download.into_temp_path(), &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new verified kernel");
        let recorded =
            std::fs::read_to_string(mvm_build::kernel_fetch::kernel_digest_sidecar(&dest)).unwrap();
        assert_eq!(
            recorded.trim(),
            mvm_fs::overlay::compute_file_sha256(&dest).unwrap()
        );
    }

    /// The two 404s are different problems and must not read the same. A
    /// missing release means "this build was never released, compile"; a
    /// missing asset means "this release ships no kernels". Sending a
    /// developer to cut a release, or a user to compile on a host with no
    /// toolchain, is the failure this split exists to prevent.
    #[test]
    fn a_missing_release_and_a_missing_asset_give_different_advice() {
        let no_release = kernel_fetch_hint("v0.18.0", "vmlinux-aarch64-workload", false);
        let no_asset = kernel_fetch_hint("v0.17.0", "vmlinux-aarch64-workload", true);
        assert_ne!(no_release, no_asset);

        assert!(
            no_release.contains("no release v0.18.0"),
            "must name the absent release: {no_release}"
        );
        assert!(
            !no_release.contains("cut a release"),
            "a build that predates its own release is not fixed by cutting one: {no_release}"
        );

        assert!(
            no_asset.contains("exists but publishes no kernel asset"),
            "must say the release is present and the asset is not: {no_asset}"
        );
    }

    /// Both arms name the asset and offer `--source compile`, since that is
    /// the way forward either way.
    #[test]
    fn both_hints_name_the_asset_and_the_compile_escape() {
        for hint in [
            kernel_fetch_hint("v0.18.0", "vmlinux-x86_64-builder", false),
            kernel_fetch_hint("v0.18.0", "vmlinux-x86_64-builder", true),
        ] {
            assert!(hint.contains("vmlinux-x86_64-builder"), "{hint}");
            assert!(hint.contains("--source compile"), "{hint}");
        }
    }

    // --- release-fetch seam tests ---
    //
    // `github_api_base`/`github_download_base` read `MVM_UPDATE_API_URL` and
    // `MVM_UPDATE_DOWNLOAD_URL`, so a loopback HTTP server is the hermetic
    // stand-in for the release host. These tests are the owning crate's
    // witnesses that a tampered fetch, digest comparison, or install step is
    // detected; without them a mutant that returns a canned version, inverts a
    // digest comparison, or skips a failure bail passes the whole suite.

    /// Answer `requests` HTTP GETs with bodies chosen from the request line,
    /// then go quiet. Returns the base URL the loopback listener ended up on.
    fn loopback_release_server(
        requests: usize,
        body: impl Fn(&str) -> Vec<u8> + Send + 'static,
    ) -> String {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().expect("listener addr"));
        std::thread::spawn(move || {
            for stream in listener.incoming().take(requests) {
                let mut stream = stream.expect("accept");
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while head.len() < 16 * 1024 {
                    if stream.read(&mut byte).expect("read request") == 0 {
                        break;
                    }
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&head);
                let line = request.lines().next().unwrap_or_default();
                let payload = body(line);
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    payload.len()
                );
                stream.write_all(header.as_bytes()).expect("write head");
                stream.write_all(&payload).expect("write body");
            }
        });
        base
    }

    #[test]
    fn fetch_latest_version_reads_the_tag_the_api_returned() {
        let server = loopback_release_server(1, |line| {
            assert!(
                line.contains("/releases/latest"),
                "the query must hit the latest-release endpoint: {line}"
            );
            br#"{"tag_name":"v9.9.9","draft":false}"#.to_vec()
        });
        let mut env = TestEnv::new();
        env.set("MVM_UPDATE_API_URL", &server);

        assert_eq!(
            fetch_latest_version().expect("fetch the latest tag"),
            "v9.9.9"
        );
    }

    #[test]
    fn verify_checksum_holds_the_archive_to_the_manifest_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("mvmctl-unit.tar.gz");
        std::fs::write(&archive, b"release bytes").unwrap();
        let matching = hex_encode(&Sha256::digest(b"release bytes"));

        let mut env = TestEnv::new();
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            loopback_release_server(1, {
                let matching = matching.clone();
                move |_| format!("{matching}  mvmctl-unit.tar.gz\n").into_bytes()
            }),
        );
        verify_checksum("v9.9.9", "mvmctl-unit.tar.gz", &archive)
            .expect("a matching digest verifies");

        let wrong = "0".repeat(64);
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            loopback_release_server(1, {
                let wrong = wrong.clone();
                move |_| format!("{wrong}  mvmctl-unit.tar.gz\n").into_bytes()
            }),
        );
        let error = verify_checksum("v9.9.9", "mvmctl-unit.tar.gz", &archive)
            .expect_err("a mismatched digest must refuse the archive")
            .to_string();
        assert!(error.contains("Checksum mismatch"), "{error}");
    }

    #[test]
    fn download_kernel_refuses_a_manifest_digest_that_does_not_match() {
        let (asset, _) = boot_image_kernel_assets("aarch64", "workload").expect("known assets");
        let server = loopback_release_server(1, move |line| {
            assert!(
                line.contains("/image-set.json"),
                "the first and only request must be the signed root: {line}"
            );
            b"not the locked image-set root".to_vec()
        });
        let mut env = TestEnv::new();
        env.set("MVM_UPDATE_DOWNLOAD_URL", &server);

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out").join(&asset);
        let error = download_kernel("aarch64", "workload", &dest)
            .expect_err("a mismatched manifest digest must refuse the kernel")
            .to_string();
        assert!(error.contains("manifest digest mismatch"), "{error}");
        assert!(
            !dest.exists(),
            "a rejected download must never be published into the cache"
        );
    }

    fn installer_archive(root: &Path, entries: &[(&str, tar::EntryType, &[u8])]) {
        let file = std::fs::File::create(root.join("mvmctl-unit-test.tar.gz")).unwrap();
        let gzip = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(gzip);
        for (name, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            // Raw names allow malicious traversal fixtures rejected by set_path.
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*kind);
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append(&header, *bytes).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }

    fn old_install(root: &Path) -> std::path::PathBuf {
        let exe = root.join("bin/mvmctl");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"old CLI").unwrap();
        std::fs::write(root.join("bin/guest-runtime"), b"old runtime").unwrap();
        exe
    }

    #[test]
    fn unsigned_or_tampered_installer_is_never_invoked() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let root = tempfile::tempdir().unwrap();
        let exe = old_install(root.path());
        installer_archive(
            root.path(),
            &[(
                "mvmctl-unit-test/install.sh",
                tar::EntryType::Regular,
                b"printf invoked > \"$MVM_INSTALL_DIR/invoked\"\n",
            )],
        );
        let base = format!("file://{}", root.path().display());
        assert!(
            install_verified_release_at(&base, "v0.18.0-rc.1", "unit-test", root.path(), &exe)
                .is_err()
        );
        assert!(!root.path().join("bin/invoked").exists());

        // A genuine release signature cannot authenticate different archive bytes.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1/builder-vm-aarch64-checksums-sha256.txt.bundle");
        std::fs::copy(fixture, root.path().join("mvmctl-unit-test.tar.gz.bundle")).unwrap();
        assert!(
            install_verified_release_at(&base, "v0.18.0-rc.1", "unit-test", root.path(), &exe)
                .is_err()
        );
        assert!(!root.path().join("bin/invoked").exists());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old CLI");

        env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let error =
            install_verified_release_at(&base, "v0.18.0-rc.1", "unit-test", root.path(), &exe)
                .unwrap_err();
        assert!(error.to_string().contains("authentication is mandatory"));
        assert!(!root.path().join("bin/invoked").exists());
    }

    #[test]
    fn missing_or_malformed_installer_leaves_old_install_untouched() {
        let root = tempfile::tempdir().unwrap();
        let exe = old_install(root.path());
        installer_archive(
            root.path(),
            &[("mvmctl-unit-test/mvmctl", tar::EntryType::Regular, b"new")],
        );
        let error = extract_and_install("v9.9.9", "unit-test", root.path(), &exe).unwrap_err();
        assert!(error.to_string().contains("missing"), "{error}");
        std::fs::write(root.path().join("mvmctl-unit-test.tar.gz"), b"invalid").unwrap();
        assert!(extract_and_install("v9.9.9", "unit-test", root.path(), &exe).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old CLI");
        assert_eq!(
            std::fs::read(root.path().join("bin/guest-runtime")).unwrap(),
            b"old runtime"
        );
    }

    #[test]
    fn installer_extraction_refuses_traversal_links_and_duplicate_scripts() {
        for (path, kind) in [
            ("../install.sh", tar::EntryType::Regular),
            ("/install.sh", tar::EntryType::Regular),
            ("mvmctl-unit-test/../../install.sh", tar::EntryType::Regular),
            ("mvmctl-unit-test\\install.sh", tar::EntryType::Regular),
            ("mvmctl-unit-test/link", tar::EntryType::Symlink),
            ("mvmctl-unit-test/link", tar::EntryType::Link),
            ("mvmctl-unit-test/install.sh", tar::EntryType::Regular),
        ] {
            let root = tempfile::tempdir().unwrap();
            installer_archive(
                root.path(),
                &[
                    (
                        "mvmctl-unit-test/install.sh",
                        tar::EntryType::Regular,
                        b"exit 0",
                    ),
                    (path, kind, b""),
                ],
            );
            assert!(
                extract_release_installer(
                    &root.path().join("mvmctl-unit-test.tar.gz"),
                    "unit-test"
                )
                .is_err(),
                "{path}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_installer_receives_exact_version_and_standalone_destination() {
        let root = tempfile::tempdir().unwrap();
        let exe = old_install(root.path());
        installer_archive(
            root.path(),
            &[(
                "./mvmctl-unit-test/install.sh",
                tar::EntryType::Regular,
                br#"set -eu
[ "$MVM_VERSION" = v9.9.9-rc.2 ]
[ "$MVM_SKIP_BOOTSTRAP" = 1 ]
[ -z "${MVM_INSTALL_LIB_DIR+x}" ]
[ -z "${MVM_SKIP_VERIFY+x}" ]
[ -z "${MVM_SKIP_COSIGN_VERIFY+x}" ]
[ -z "${MVM_SKIP_HASH_VERIFY+x}" ]
[ -z "${MVM_SKIP_CODESIGN+x}" ]
[ -z "${MVM_TRUSTED_COSIGN_SHA256+x}" ]
[ -z "${MVM_COSIGN_DOWNLOAD_URL+x}" ]
printf '%s' "$MVM_VERSION" > "$MVM_INSTALL_DIR/invoked"
printf '%s' "$MVM_TRUSTED_ARCHIVE_SHA256" > "$MVM_INSTALL_DIR/digest"
"#,
            )],
        );
        let mut env = TestEnv::new();
        env.set("MVM_VERSION", "wrong");
        env.set("MVM_INSTALL_DIR", "/wrong");
        env.set("MVM_INSTALL_LIB_DIR", "/wrong");
        env.set("MVM_SKIP_VERIFY", "1");
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        env.set("MVM_SKIP_HASH_VERIFY", "1");
        env.set("MVM_SKIP_CODESIGN", "1");
        env.set("MVM_SKIP_BOOTSTRAP", "0");
        env.set("MVM_TRUSTED_ARCHIVE_SHA256", "wrong");
        env.set("MVM_TRUSTED_COSIGN_SHA256", "wrong");
        env.set("MVM_COSIGN_DOWNLOAD_URL", "file:///wrong");
        extract_and_install("v9.9.9-rc.2", "unit-test", root.path(), &exe).unwrap();
        assert_eq!(
            std::fs::read(root.path().join("bin/invoked")).unwrap(),
            b"v9.9.9-rc.2"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("bin/digest")).unwrap(),
            sha256_of(&std::fs::read(root.path().join("mvmctl-unit-test.tar.gz")).unwrap())
        );
    }

    #[cfg(unix)]
    #[test]
    fn installer_failure_preserves_old_cli_and_runtime() {
        let root = tempfile::tempdir().unwrap();
        let exe = old_install(root.path());
        installer_archive(
            root.path(),
            &[(
                "mvmctl-unit-test/install.sh",
                tar::EntryType::Regular,
                b"exit 23\n",
            )],
        );
        let error = extract_and_install("v9.9.9", "unit-test", root.path(), &exe).unwrap_err();
        assert!(error.to_string().contains("Release installer failed"));
        assert_eq!(std::fs::read(&exe).unwrap(), b"old CLI");
        assert_eq!(
            std::fs::read(root.path().join("bin/guest-runtime")).unwrap(),
            b"old runtime"
        );
    }

    #[cfg(unix)]
    #[test]
    fn versioned_update_uses_marker_paths_and_refuses_ambiguous_legacy_marker() {
        use crate::install_layout::{LIB_MARKER, RELEASE_MARKER};
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("custom bin");
        let lib = root.path().join("custom lib");
        let release = lib.join("1-v0.1.0");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(release.join(RELEASE_MARKER), "complete\n").unwrap();
        let exe = release.join("mvmctl");
        std::fs::write(&exe, b"old CLI").unwrap();
        installer_archive(
            root.path(),
            &[(
                "mvmctl-unit-test/install.sh",
                tar::EntryType::Regular,
                b"set -eu\nprintf '%s' \"$MVM_INSTALL_LIB_DIR\" > \"$MVM_INSTALL_DIR/invoked\"\n",
            )],
        );
        for marker in [
            "".to_string(),
            "install_dir=relative\n".to_string(),
            format!("install_dir={0}\ninstall_dir={0}\n", bin.display()),
        ] {
            std::fs::write(lib.join(LIB_MARKER), marker).unwrap();
            assert!(extract_and_install("v9.9.9", "unit-test", root.path(), &exe).is_err());
            assert!(!bin.join("invoked").exists());
        }
        std::fs::write(
            lib.join(LIB_MARKER),
            format!("install_dir={}\n", bin.display()),
        )
        .unwrap();
        extract_and_install("v9.9.9", "unit-test", root.path(), &exe).unwrap();
        assert_eq!(
            std::fs::read_to_string(bin.join("invoked")).unwrap(),
            lib.canonicalize().unwrap().to_str().unwrap()
        );
        assert_eq!(std::fs::read(exe).unwrap(), b"old CLI");
    }

    #[test]
    fn install_announcement_classifies_equal_downgrade_and_upgrade() {
        use super::InstallAnnouncement::*;
        assert_eq!(
            install_announcement("0.18.0", "0.18.0"),
            ForceReinstall,
            "only --force reaches Install at equality"
        );
        assert_eq!(
            install_announcement("0.18.0", "0.17.0"),
            DowngradeOverNewer,
            "installing an older release over a newer one is a downgrade and must say so"
        );
        assert_eq!(install_announcement("0.18.0", "0.19.0"), NewVersion);
        assert_eq!(
            install_announcement("0.18.0", "nightly"),
            NewVersion,
            "an unorderable latest must not read as a downgrade"
        );
        assert_eq!(
            install_announcement("nightly", "0.18.0"),
            NewVersion,
            "an unorderable current must not read as a downgrade either"
        );
        assert_eq!(
            install_announcement("0.18.0+running", "0.18.0+published"),
            NewVersion,
            "semver-equivalent but textually distinct releases are not downgrades"
        );
    }
}
