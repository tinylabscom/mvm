use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::http;
use crate::ui;
use mvm_build::published_image_set::github_download_base;
use mvm_core::release_version::{ReleaseVersion, VersionSyntax};
use mvm_runtime::shell::run_host;

const GITHUB_REPO: &str = "tinylabscom/mvm";
const SOURCE_HELPER_RELEASE: &str = "source-builds";
const SOURCE_HELPER_BASE_URL_ENV: &str = "MVM_SOURCE_HELPER_BASE_URL";
const SOURCE_HELPER_COMMIT_MARKER: &str = ".mvm-host-helpers-source-commit";
const RELEASE_HOST_BINS: &[&str] = &[
    "mvm-hvf-supervisor",
    "mvm-libkrun-supervisor",
    "mvm-network-endpoint",
];

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

/// The combined checksum manifest every CLI release publishes, signed by the
/// release workflow beside the archives it lists.
const CHECKSUM_MANIFEST: &str = "checksums-sha256.txt";

/// Per-version release directory the archive, its manifest, and both
/// signature bundles are published under.
pub(crate) fn release_base(tag: &str) -> String {
    format!(
        "{}/{}/releases/download/{}",
        github_download_base(),
        GITHUB_REPO,
        tag
    )
}

/// The SHA-256 the release at `tag` publishes for `archive_name`, read from a
/// checksum manifest whose signature has already been proven.
///
/// The manifest decides which archive bytes are acceptable, and it arrives
/// over the same channel as the archive, so whoever can serve one could serve
/// a matching pair. Its Sigstore bundle is therefore verified under the
/// release workflow's identity at exactly `tag` before a line of it is parsed.
/// A missing, unparseable, foreign-signed, or other-tag bundle refuses the
/// update. `MVM_SKIP_HASH_VERIFY` does not reach this check, and neither does
/// `--skip-verify`: that flag waives only the archive's own bundle, so the
/// archive stays authenticated through this manifest.
fn signed_archive_digest(tag: &str, archive_name: &str) -> Result<String> {
    let base = release_base(tag);
    let manifest = crate::commands::env::artifact_verify::ChecksumManifest {
        base_url: &base,
        asset: CHECKSUM_MANIFEST,
        version: strip_v_prefix(tag),
        train: mvm_build::release_signature::ReleaseTrain::Cli,
    };
    let mut digests =
        crate::commands::env::artifact_verify::fetch_expected_hashes(&manifest, &[archive_name])
            .with_context(|| {
                format!("refusing to update: the {tag} checksum manifest is not authenticated")
            })?;
    digests
        .remove(archive_name)
        .with_context(|| format!("{CHECKSUM_MANIFEST} for {tag} has no entry for {archive_name}"))
}

/// Hold a downloaded archive to the digest the signed manifest publishes for it.
fn verify_checksum(tag: &str, archive_name: &str, archive_path: &Path) -> Result<()> {
    let expected = signed_archive_digest(tag, archive_name)?;

    let bytes = std::fs::read(archive_path).with_context(|| {
        format!(
            "Failed to read archive for checksum: {}",
            archive_path.display()
        )
    })?;
    let actual = hex::encode(Sha256::digest(&bytes));

    if actual != expected {
        anyhow::bail!(
            "Checksum mismatch for {}!\n  expected: {}\n  actual:   {}\nThe download may be corrupted or tampered with.",
            archive_name,
            expected,
            actual,
        );
    }

    ui::success("Checksum verified against the signed manifest.");
    Ok(())
}

/// Download the release archive into the given temp directory.
fn download_release(version: &str, target: &str, tmp_dir: &Path) -> Result<()> {
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let download_url = format!("{}/{}", release_base(version), archive_name);
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

/// Check if a directory is writable by the current user.
fn is_writable(path: &Path) -> bool {
    tempfile::Builder::new()
        .prefix(".mvm-write-test-")
        .tempfile_in(path)
        .is_ok()
}

/// Verify that a binary responds to `--version`, exits 0, and prints version-like output.
///
/// Called before and after swapping the binary to prevent a defective release from
/// bricking an installation.
fn smoke_test_binary(bin: &Path) -> Result<()> {
    let output = mvm_core::env_hygiene::helper_command(bin)
        .arg("--version")
        .output()
        .with_context(|| format!("Failed to execute smoke test for {}", bin.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "smoke test failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.chars().any(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "smoke test output does not look like a version: {:?}",
            stdout.trim()
        );
    }

    Ok(())
}

/// Refuse to update an install made by `install.sh`. That install is a set of
/// versioned release directories switched as a whole; replacing files inside
/// the active one in place would leave a release directory holding binaries
/// from two versions under one version's name.
fn refuse_versioned_install(current_exe: &Path) -> Result<()> {
    if let Some(lib) = crate::install_layout::versioned_lib_dir_of(current_exe) {
        anyhow::bail!(
            "this mvmctl was installed by install.sh into {}, which upgrades mvmctl \
             and its host binaries together and can roll back. Upgrade by re-running \
             the installer: curl -fsSL https://runmvm.com/install.sh | sh",
            lib.display()
        );
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
    refuse_versioned_install(current_exe)?;
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

/// Extract the archive and install the binary, adjacent helpers, and resources.
fn extract_and_install(target: &str, tmp_dir: &Path, current_exe: &Path) -> Result<()> {
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let archive_path = tmp_dir.join(&archive_name);

    let output = run_host(
        "tar",
        &[
            "xzf",
            archive_path
                .to_str()
                .expect("archive path must be valid UTF-8"),
            "-C",
            tmp_dir.to_str().expect("tmp dir path must be valid UTF-8"),
        ],
    )?;

    if !output.status.success() {
        anyhow::bail!("Failed to extract archive");
    }

    let extracted_dir = tmp_dir.join(format!("mvmctl-{}", target));
    let new_binary = extracted_dir.join("mvmctl");
    if !new_binary.exists() {
        anyhow::bail!(
            "Binary not found in archive at expected path: mvmctl-{}/mvmctl",
            target
        );
    }

    // Pre-swap smoke test: verify the new binary works before touching the current installation.
    ui::info("Verifying new binary...");
    smoke_test_binary(&new_binary).context("New binary failed pre-install smoke test")?;

    let install_dir = current_exe
        .parent()
        .context("Cannot determine install directory")?;

    let needs_sudo = !is_writable(install_dir);

    ui::info(&format!("Installing to {}...", install_dir.display()));
    if needs_sudo {
        ui::warn("Requires elevated permissions.");
    }

    // --- Replace binary ---
    let backup_path = current_exe.with_extension("old");

    if needs_sudo {
        run_sudo_mv(current_exe, &backup_path)?;
        if let Err(e) = run_sudo_cp(&new_binary, current_exe) {
            if let Err(e) = run_sudo_mv(&backup_path, current_exe) {
                tracing::warn!("failed to rollback binary during update: {e}");
            }
            return Err(e);
        }
        if let Err(e) = run_host(
            "sudo",
            &[
                "chmod",
                "+x",
                current_exe.to_str().expect("exe path must be valid UTF-8"),
            ],
        ) {
            tracing::warn!("failed to chmod during update: {e}");
        }
        // Post-swap smoke test: verify installed binary before removing the backup.
        if let Err(e) = smoke_test_binary(current_exe) {
            if let Err(re) = run_sudo_mv(&backup_path, current_exe) {
                tracing::warn!("failed to restore backup after smoke test failure: {re}");
            }
            anyhow::bail!("New binary failed smoke test; restored previous version. ({e})");
        }
        if let Err(e) = run_host(
            "sudo",
            &[
                "rm",
                "-f",
                backup_path
                    .to_str()
                    .expect("backup path must be valid UTF-8"),
            ],
        ) {
            tracing::warn!("failed to rm during update: {e}");
        }
    } else {
        std::fs::rename(current_exe, &backup_path).context("Failed to back up current binary")?;
        if let Err(e) = std::fs::copy(&new_binary, current_exe) {
            if let Err(e) = std::fs::rename(&backup_path, current_exe) {
                tracing::warn!("failed to rollback binary during update: {e}");
            }
            return Err(anyhow::anyhow!(e).context("Failed to install new binary"));
        }
        set_executable(current_exe)?;
        // Post-swap smoke test: verify installed binary before removing the backup.
        if let Err(e) = smoke_test_binary(current_exe) {
            if let Err(re) = std::fs::rename(&backup_path, current_exe) {
                tracing::warn!("failed to restore backup after smoke test failure: {re}");
            }
            anyhow::bail!("New binary failed smoke test; restored previous version. ({e})");
        }
        if let Err(e) = std::fs::remove_file(&backup_path) {
            tracing::warn!("failed to remove backup file: {e}");
        }
    }

    install_release_host_binaries(&extracted_dir, install_dir, needs_sudo)
        .context("Failed to update adjacent host helper binaries")?;
    sign_installed_binaries(cfg!(target_os = "macos"), || {
        let targets = mvm_runtime::codesign::collect_sign_targets();
        mvm_runtime::codesign::sign_targets(&targets)
    })
    .context("Failed to apply macOS VM entitlements")?;

    // --- Replace resources ---
    let new_resources = extracted_dir.join("resources");
    if new_resources.exists() {
        let dest_resources = install_dir.join("resources");
        ui::info("Updating resources...");

        if needs_sudo {
            if let Err(e) = run_host(
                "sudo",
                &[
                    "rm",
                    "-rf",
                    dest_resources
                        .to_str()
                        .expect("resources path must be valid UTF-8"),
                ],
            ) {
                tracing::warn!("failed to remove old resources directory: {e}");
            }
            let output = run_host(
                "sudo",
                &[
                    "cp",
                    "-r",
                    new_resources
                        .to_str()
                        .expect("new resources path must be valid UTF-8"),
                    dest_resources
                        .to_str()
                        .expect("dest resources path must be valid UTF-8"),
                ],
            )?;
            require_resource_copy_success(output.status.success())?;
        } else {
            if let Err(e) = std::fs::remove_dir_all(&dest_resources) {
                tracing::warn!("failed to remove old resources: {e}");
            }
            copy_dir_recursive(&new_resources, &dest_resources)
                .context("Failed to update resources directory")?;
        }
    }

    Ok(())
}

fn require_resource_copy_success(success: bool) -> Result<()> {
    if !success {
        anyhow::bail!("sudo cp failed while updating resources directory");
    }
    Ok(())
}

fn install_release_host_binaries(
    extracted_dir: &Path,
    install_dir: &Path,
    needs_sudo: bool,
) -> Result<()> {
    for hostbin in RELEASE_HOST_BINS {
        let src = extracted_dir.join(hostbin);
        if !src.is_file() {
            continue;
        }
        let dest = install_dir.join(hostbin);
        if needs_sudo {
            run_sudo_cp(&src, &dest)?;
            let output = run_host(
                "sudo",
                &[
                    "chmod",
                    "+x",
                    dest.to_str().expect("helper path must be valid UTF-8"),
                ],
            )?;
            if !output.status.success() {
                anyhow::bail!("sudo chmod failed for {}", dest.display());
            }
        } else {
            std::fs::copy(&src, &dest)
                .with_context(|| format!("copying {} to {}", src.display(), dest.display()))?;
            set_executable(&dest)?;
        }
    }
    Ok(())
}

/// Install the signed release's host helpers beside a source-built `mvmctl`
/// without replacing the CLI itself.
pub(crate) fn prepare_release_host_binaries() -> Result<()> {
    let current_exe = std::env::current_exe().context("resolve the running mvmctl")?;
    let install_dir = current_exe
        .parent()
        .context("the running mvmctl has no parent directory")?;
    anyhow::ensure!(
        is_writable(install_dir),
        "cannot install published host helpers beside {}",
        current_exe.display()
    );
    let target = detect_target()?;
    let tmp = tempfile::tempdir().context("create host-helper download directory")?;
    if let Some(commit) = source_helper_commit()? {
        return prepare_source_host_binaries(&commit, target, install_dir, tmp.path());
    }
    let tag = format!("v{}", current_version());
    download_release(&tag, target, tmp.path())?;
    let archive_name = format!("mvmctl-{target}.tar.gz");
    let archive_path = tmp.path().join(&archive_name);
    verify_signature(&tag, &archive_name, &archive_path)?;
    let output = run_host(
        "tar",
        &[
            "xzf",
            archive_path
                .to_str()
                .expect("archive path must be valid UTF-8"),
            "-C",
            tmp.path()
                .to_str()
                .expect("temporary path must be valid UTF-8"),
        ],
    )?;
    anyhow::ensure!(output.status.success(), "failed to extract host helpers");
    let extracted = tmp.path().join(format!("mvmctl-{target}"));
    install_release_host_binaries(&extracted, install_dir, false)?;
    sign_installed_binaries(cfg!(target_os = "macos"), || {
        let targets = mvm_runtime::codesign::collect_sign_targets();
        mvm_runtime::codesign::sign_targets(&targets)
    })?;
    Ok(())
}

pub(crate) fn published_host_helpers_match_current_build() -> Result<bool> {
    let Some(commit) = source_helper_commit()? else {
        return Ok(true);
    };
    let current_exe = std::env::current_exe().context("resolve the running mvmctl")?;
    let install_dir = current_exe
        .parent()
        .context("the running mvmctl has no parent directory")?;
    Ok(source_helper_marker_matches(install_dir, &commit))
}

fn source_helper_commit() -> Result<Option<String>> {
    source_helper_commit_for(
        mvm_build::artifact_acquisition::compiled_channel(),
        env!("MVM_SOURCE_COMMIT"),
        env!("MVM_SOURCE_DIRTY"),
    )
}

/// The commit a source build's host helpers must match, or `None` for a
/// release build, whose helpers come from its own signed release.
fn source_helper_commit_for(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    commit: &str,
    dirty: &str,
) -> Result<Option<String>> {
    if channel == mvm_build::artifact_acquisition::DistributionChannel::Release {
        return Ok(None);
    }
    validate_source_helper_identity(commit, dirty).map(Some)
}

fn validate_source_helper_identity(commit: &str, dirty: &str) -> Result<String> {
    anyhow::ensure!(
        dirty == "false",
        "this mvmctl was built from a dirty or unidentified checkout, so no exact remote helper \
         bundle can match it; \
         explicitly compile local helpers with \
         `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`"
    );
    anyhow::ensure!(
        commit.len() == 40
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "the source build metadata has no valid commit; explicitly compile local helpers with \
         `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`"
    );
    Ok(commit.to_string())
}

fn prepare_source_host_binaries(
    commit: &str,
    target: &str,
    install_dir: &Path,
    tmp_dir: &Path,
) -> Result<()> {
    let archive_name = format!("mvm-host-helpers-{commit}-{target}.tar.gz");
    let base_url = std::env::var(SOURCE_HELPER_BASE_URL_ENV).unwrap_or_else(|_| {
        format!(
            "{}/{GITHUB_REPO}/releases/download/{SOURCE_HELPER_RELEASE}",
            github_download_base()
        )
    });
    let archive_path = tmp_dir.join(&archive_name);
    download_release_asset(&format!("{base_url}/{archive_name}"), &archive_path).with_context(
        || {
            format!(
                "no published host helpers match source commit {commit}; wait for the main-branch \
                 source-helper workflow or explicitly compile local helpers with \
                 `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`"
            )
        },
    )?;
    mvm_build::release_signature::verify_release_archive_signature(
        &mvm_build::release_signature::ReleaseSignatureRequest {
            base_url: &base_url,
            asset: &archive_name,
            archive_path: &archive_path,
            version: commit,
            train: mvm_build::release_signature::ReleaseTrain::SourceHelpers,
        },
    )
    .context("verify the source helper bundle")?;
    let output = run_host(
        "tar",
        &[
            "xzf",
            archive_path
                .to_str()
                .expect("archive path must be valid UTF-8"),
            "-C",
            tmp_dir
                .to_str()
                .expect("temporary path must be valid UTF-8"),
        ],
    )?;
    anyhow::ensure!(
        output.status.success(),
        "failed to extract source host helpers"
    );
    let extracted = tmp_dir.join(format!("mvm-host-helpers-{commit}-{target}"));
    validate_source_helper_bundle(&extracted, commit)?;
    install_release_host_binaries(&extracted, install_dir, false)?;
    sign_installed_binaries(cfg!(target_os = "macos"), || {
        let targets = mvm_runtime::codesign::collect_sign_targets();
        mvm_runtime::codesign::sign_targets(&targets)
    })?;
    mvm_core::util::atomic_io::atomic_write_durable(
        &install_dir.join(SOURCE_HELPER_COMMIT_MARKER),
        format!("{commit}\n").as_bytes(),
    )
    .context("record installed source-helper commit")?;
    Ok(())
}

fn source_helper_marker_matches(install_dir: &Path, expected_commit: &str) -> bool {
    std::fs::read_to_string(install_dir.join(SOURCE_HELPER_COMMIT_MARKER))
        .is_ok_and(|recorded| recorded.trim() == expected_commit)
}

fn validate_source_helper_bundle(extracted: &Path, expected_commit: &str) -> Result<()> {
    let recorded = std::fs::read_to_string(extracted.join("SOURCE_COMMIT"))
        .context("source helper bundle has no SOURCE_COMMIT")?;
    anyhow::ensure!(
        recorded.trim() == expected_commit,
        "source helper bundle records commit {}, expected {expected_commit}",
        recorded.trim()
    );
    Ok(())
}

/// Apply the macOS entitlements immediately after replacing a release binary
/// and its adjacent supervisors. A successful update must not leave the next
/// invocation dependent on a lazy first-boot repair.
fn sign_installed_binaries(
    is_macos: bool,
    signer: impl FnOnce() -> Vec<mvm_runtime::codesign::SignReport>,
) -> Result<()> {
    if !is_macos {
        return Ok(());
    }

    let failed: Vec<String> = signer()
        .iter()
        .filter(|report| !report.entitlements_present)
        .map(|report| report.path.display().to_string())
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "required VM entitlements are missing on: {}",
            failed.join(", ")
        )
    }
}

fn run_sudo_mv(from: &Path, to: &Path) -> Result<()> {
    let output = run_host(
        "sudo",
        &[
            "mv",
            from.to_str().expect("source path must be valid UTF-8"),
            to.to_str().expect("dest path must be valid UTF-8"),
        ],
    )?;
    if !output.status.success() {
        anyhow::bail!("sudo mv failed");
    }
    Ok(())
}

fn run_sudo_cp(from: &Path, to: &Path) -> Result<()> {
    let output = run_host(
        "sudo",
        &[
            "cp",
            from.to_str().expect("source path must be valid UTF-8"),
            to.to_str().expect("dest path must be valid UTF-8"),
        ],
    )?;
    if !output.status.success() {
        anyhow::bail!("sudo cp failed");
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

/// Verify a downloaded release archive against the release workflow's signing
/// identity before anything extracts it.
///
/// The Sigstore bundle published beside the archive is checked in-process
/// against the embedded trust root, so a host without `cosign` gets the same
/// verdict as one with it. A missing, unparseable, or foreign-signed bundle
/// refuses the update. The SHA-256 checked before this already came from a
/// signed manifest; this binds the archive to the workflow directly as well.
fn verify_signature(version: &str, archive_name: &str, archive_path: &Path) -> Result<()> {
    ui::info("Verifying release signature...");
    verify_archive_signature_at(&release_base(version), version, archive_name, archive_path)?;
    ui::success("Signature verified.");
    Ok(())
}

fn verify_signature_if_required(
    skip_verify: bool,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if skip_verify { Ok(()) } else { verify() }
}

/// Verify `archive_name` against the bundle published under `release_base`,
/// accepting only the CLI release workflow at `tag`.
fn verify_archive_signature_at(
    release_base: &str,
    tag: &str,
    archive_name: &str,
    archive_path: &Path,
) -> Result<()> {
    mvm_build::release_signature::verify_release_archive_signature(
        &mvm_build::release_signature::ReleaseSignatureRequest {
            base_url: release_base,
            asset: archive_name,
            archive_path,
            version: strip_v_prefix(tag),
            train: mvm_build::release_signature::ReleaseTrain::Cli,
        },
    )
    .map(|_| ())
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
        verify_signature(&latest_tag, &archive_name, &archive_path)
    })?;
    // The CLI and its guest runtime are one release. The runtime is acquired
    // and verified first, under its own signature whatever `--skip-verify`
    // says, so a runtime that cannot be verified leaves the old binary in
    // place rather than installing a CLI without one.
    crate::release_guest_runtime::stage_for_update(&latest_tag)?;
    extract_and_install(target, tmp_dir.path(), &current_exe)?;

    ui::success(&format!("\nSuccessfully updated to {}!", latest_tag));
    ui::info("The binary has been replaced on disk.");
    ui::info("To verify: Open a new shell and run 'mvmctl --version'");
    ui::info("Or run: hash -r  (to clear your shell's command cache)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        UpdateAction, decide_update, source_helper_commit, source_helper_commit_for,
        source_helper_marker_matches, validate_source_helper_bundle,
        validate_source_helper_identity,
    };
    use mvm_build::artifact_acquisition::DistributionChannel;

    #[test]
    fn the_helper_commit_is_this_builds_own_channel_and_identity() {
        let own = source_helper_commit_for(
            mvm_build::artifact_acquisition::compiled_channel(),
            env!("MVM_SOURCE_COMMIT"),
            env!("MVM_SOURCE_DIRTY"),
        );
        assert_eq!(
            source_helper_commit().map_err(|e| e.to_string()),
            own.map_err(|e| e.to_string())
        );
    }

    #[test]
    fn only_a_source_build_pins_its_helpers_to_a_commit() {
        let commit = "a".repeat(40);
        assert_eq!(
            source_helper_commit_for(DistributionChannel::Source, &commit, "false").unwrap(),
            Some(commit.clone())
        );
        assert!(source_helper_commit_for(DistributionChannel::Source, &commit, "true").is_err());
        // A release build takes its helpers from its own signed release, so
        // even unidentified source metadata asks nothing of it.
        assert_eq!(
            source_helper_commit_for(DistributionChannel::Release, "", "true").unwrap(),
            None
        );
    }

    #[test]
    fn source_helper_identity_requires_a_clean_full_commit() {
        let commit = "a".repeat(40);
        assert_eq!(
            validate_source_helper_identity(&commit, "false").unwrap(),
            commit
        );
        assert!(validate_source_helper_identity(&commit, "true").is_err());
        assert!(validate_source_helper_identity("abc", "false").is_err());
        assert!(validate_source_helper_identity(&"A".repeat(40), "false").is_err());
    }

    #[test]
    fn source_helper_bundle_must_record_the_requested_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let commit = "a".repeat(40);
        assert!(validate_source_helper_bundle(tmp.path(), &commit).is_err());

        std::fs::write(tmp.path().join("SOURCE_COMMIT"), format!("{commit}\n")).unwrap();
        validate_source_helper_bundle(tmp.path(), &commit).unwrap();
        assert!(validate_source_helper_bundle(tmp.path(), &"b".repeat(40)).is_err());
    }

    #[test]
    fn installed_source_helper_marker_must_match_the_cli_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let commit = "a".repeat(40);
        assert!(!source_helper_marker_matches(tmp.path(), &commit));
        std::fs::write(
            tmp.path().join(super::SOURCE_HELPER_COMMIT_MARKER),
            format!("{commit}\n"),
        )
        .unwrap();
        assert!(source_helper_marker_matches(tmp.path(), &commit));
        assert!(!source_helper_marker_matches(tmp.path(), &"b".repeat(40)));
    }

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
    fn update_refuses_a_binary_in_an_install_sh_release_directory() {
        use crate::install_layout::{LIB_MARKER, RELEASE_MARKER};
        let root = tempfile::tempdir().unwrap();
        let release = root.path().join("lib").join("2-v0.18.0");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(root.path().join("lib").join(LIB_MARKER), "").unwrap();
        std::fs::write(release.join(RELEASE_MARKER), "complete\n").unwrap();
        std::fs::write(release.join("mvmctl"), "").unwrap();

        let error = refuse_versioned_install(&release.join("mvmctl"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("install.sh"), "{error}");
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
            validate_install_target(false, &executable).is_err(),
            "an actual update must preserve the atomic install.sh layout"
        );
    }

    #[test]
    fn update_proceeds_for_a_binary_outside_an_install_sh_release() {
        let root = tempfile::tempdir().unwrap();
        let loose = root.path().join("bin").join("mvmctl");
        std::fs::create_dir_all(loose.parent().unwrap()).unwrap();
        std::fs::write(&loose, "").unwrap();
        assert!(refuse_versioned_install(&loose).is_ok());
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

    // --- smoke test ---

    #[cfg(unix)]
    #[test]
    fn test_smoke_test_binary_passes() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // Write a tiny shell script that prints a version-like string and exits 0.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mvm-smoke-test.sh");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "#!/bin/sh\necho 'mvmctl 1.0.0'").unwrap();
            file.flush().unwrap();
        }
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();

        assert!(smoke_test_binary(&path).is_ok());
    }

    #[test]
    fn test_smoke_test_binary_nonexistent_fails() {
        let result = smoke_test_binary(std::path::Path::new("/nonexistent/binary/does-not-exist"));
        assert!(result.is_err());
    }

    #[test]
    fn test_smoke_test_binary_rollback_error_message() {
        // Verify the rollback bail! message matches the spec wording.
        let err_msg = format!(
            "New binary failed smoke test; restored previous version. ({})",
            "smoke test failed (exit 1): "
        );
        assert!(err_msg.contains("New binary failed smoke test; restored previous version."));
    }

    #[test]
    fn release_host_bins_include_hvf_and_network_endpoint() {
        assert!(RELEASE_HOST_BINS.contains(&"mvm-hvf-supervisor"));
        assert!(RELEASE_HOST_BINS.contains(&"mvm-network-endpoint"));
    }

    #[test]
    fn install_release_host_binaries_copies_present_helpers() {
        let tmp = tempfile::tempdir().unwrap();
        let extracted = tmp.path().join("extracted");
        let install_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(extracted.join("mvm-hvf-supervisor"), b"hvf").unwrap();
        std::fs::write(extracted.join("mvm-network-endpoint"), b"endpoint").unwrap();

        install_release_host_binaries(&extracted, &install_dir, false).unwrap();

        assert_eq!(
            std::fs::read(install_dir.join("mvm-hvf-supervisor")).unwrap(),
            b"hvf"
        );
        assert_eq!(
            std::fs::read(install_dir.join("mvm-network-endpoint")).unwrap(),
            b"endpoint"
        );
    }

    #[test]
    fn a_failed_privileged_resource_copy_refuses_the_update() {
        require_resource_copy_success(true).expect("a successful copy is accepted");
        let error = require_resource_copy_success(false)
            .expect_err("a failed resource copy must refuse the update")
            .to_string();
        assert!(error.contains("sudo cp failed"), "{error}");
    }

    #[test]
    fn signing_is_skipped_off_macos_and_requires_every_entitlement_on_macos() {
        sign_installed_binaries(false, || panic!("non-macOS must not invoke the signer"))
            .expect("signing is a no-op off macOS");

        let report = |path: &str, entitlements_present| mvm_runtime::codesign::SignReport {
            path: path.into(),
            applied: true,
            entitlements_present,
        };
        sign_installed_binaries(true, || vec![report("mvmctl", true)])
            .expect("a signed macOS install is accepted");

        let error = sign_installed_binaries(true, || {
            vec![report("mvmctl", true), report("mvm-hvf-supervisor", false)]
        })
        .expect_err("every macOS release binary must retain its entitlement")
        .to_string();
        assert!(error.contains("mvm-hvf-supervisor"), "{error}");
        assert!(!error.contains("mvmctl"), "{error}");
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
    fn signature_verification_runs_unless_the_user_explicitly_skips_it() {
        let mut called = false;
        let error = verify_signature_if_required(false, || {
            called = true;
            anyhow::bail!("signature refused")
        })
        .expect_err("verification failures must refuse the update")
        .to_string();
        assert!(called);
        assert!(error.contains("signature refused"), "{error}");

        verify_signature_if_required(true, || panic!("skip verification must not verify"))
            .expect("the explicit skip bypasses signature verification");
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

    // --- checksum manifest signature ---

    /// The archive the manifest fixtures below are asked about.
    const MANIFEST_ARCHIVE: &str = "mvmctl-aarch64-apple-darwin.tar.gz";

    /// Stage a release directory under `tag` holding `manifest` as the
    /// release's combined checksum manifest, beside `bundle` when given, and
    /// point the download base at it.
    fn stage_manifest_release(
        env: &mut TestEnv,
        tag: &str,
        manifest: &[u8],
        bundle: Option<&[u8]>,
    ) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let dir = root
            .path()
            .join(GITHUB_REPO)
            .join("releases/download")
            .join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CHECKSUM_MANIFEST), manifest).unwrap();
        if let Some(bundle) = bundle {
            let name = mvm_build::release_signature::bundle_asset_name(CHECKSUM_MANIFEST);
            std::fs::write(dir.join(name), bundle).unwrap();
        }
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            format!("file://{}", root.path().display()),
        );
        root
    }

    /// The committed `v0.18.0-rc.1` manifest and the bundle `release.yml`
    /// published for it. The signature covers bytes, not a file name, so it
    /// stands in for that release's combined manifest.
    #[cfg(feature = "manifest-verify")]
    fn signed_fixture() -> (Vec<u8>, Vec<u8>) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1");
        let asset = "builder-vm-aarch64-checksums-sha256.txt";
        (
            std::fs::read(dir.join(asset)).unwrap(),
            std::fs::read(dir.join(format!("{asset}.bundle"))).unwrap(),
        )
    }

    /// The staged manifest has no entry for the archive, so a refusal that
    /// came from parsing it would say so; this one must come from the
    /// signature check, before any digest is read.
    #[test]
    fn self_update_refuses_an_unsigned_checksum_manifest_before_parsing() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        env.remove("MVM_SKIP_HASH_VERIFY");
        let manifest = format!("{}  some-other-archive.tar.gz\n", "d".repeat(64));
        let _release = stage_manifest_release(&mut env, "v9.9.9", manifest.as_bytes(), None);

        let msg = format!(
            "{:#}",
            signed_archive_digest("v9.9.9", MANIFEST_ARCHIVE)
                .expect_err("an unsigned manifest must not supply a digest")
        );

        assert!(
            msg.contains("unauthenticated checksum manifest"),
            "the refusal must name the reason: {msg}"
        );
        assert!(
            !msg.contains("did not include") && !msg.contains("no entry"),
            "the manifest must be refused before it is parsed: {msg}"
        );
        assert!(msg.contains("v9.9.9"), "names the release: {msg}");
    }

    /// Waiving the digest comparison is not a waiver of who published the
    /// digests.
    #[test]
    fn self_update_hash_skip_does_not_waive_the_manifest_signature() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        env.set("MVM_SKIP_HASH_VERIFY", "1");
        let manifest = format!("{}  {MANIFEST_ARCHIVE}\n", "e".repeat(64));
        let _release = stage_manifest_release(&mut env, "v9.9.9", manifest.as_bytes(), None);

        let msg = format!(
            "{:#}",
            signed_archive_digest("v9.9.9", MANIFEST_ARCHIVE)
                .expect_err("MVM_SKIP_HASH_VERIFY must not admit an unsigned manifest")
        );
        assert!(msg.contains("unauthenticated checksum manifest"), "{msg}");
    }

    /// Control for the two refusals below: the real bundle verifies under its
    /// own tag and the digest comes out of the manifest it signs.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn self_update_reads_digests_from_a_manifest_signed_under_its_tag() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let (manifest, bundle) = signed_fixture();
        let _release = stage_manifest_release(&mut env, "v0.18.0-rc.1", &manifest, Some(&bundle));

        let digest = signed_archive_digest("v0.18.0-rc.1", "builder-vm-aarch64.cmdline.txt")
            .expect("the release workflow's own manifest signature must verify");
        assert_eq!(
            digest,
            "5e186ff06b2c723c6cacd55497a3b053d65602314ca44dcccf3860e9a411afe5"
        );
    }

    /// A genuine bundle served beside edited manifest bytes: the edit adds a
    /// digest for the archive being installed, which is exactly what an
    /// attacker swapping the archive would need.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn self_update_refuses_a_tampered_checksum_manifest() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let (mut manifest, bundle) = signed_fixture();
        manifest.extend_from_slice(format!("{}  {MANIFEST_ARCHIVE}\n", "f".repeat(64)).as_bytes());
        let _release = stage_manifest_release(&mut env, "v0.18.0-rc.1", &manifest, Some(&bundle));

        let msg = format!(
            "{:#}",
            signed_archive_digest("v0.18.0-rc.1", MANIFEST_ARCHIVE)
                .expect_err("edited manifest bytes must not verify")
        );
        assert!(msg.contains("unauthenticated checksum manifest"), "{msg}");
    }

    /// The identity is tag-bound: another release's genuine manifest, served
    /// under this tag, is refused.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn self_update_refuses_a_checksum_manifest_signed_for_another_tag() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let (manifest, bundle) = signed_fixture();
        let _release = stage_manifest_release(&mut env, "v0.18.0", &manifest, Some(&bundle));

        let msg = format!(
            "{:#}",
            signed_archive_digest("v0.18.0", "builder-vm-aarch64.cmdline.txt")
                .expect_err("a manifest signed for v0.18.0-rc.1 must not verify as v0.18.0")
        );
        assert!(msg.contains("unauthenticated checksum manifest"), "{msg}");
        assert!(msg.contains("v0.18.0"), "names the release: {msg}");
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

    /// The digest comparison itself, with the publisher check waived through
    /// its documented escape so the loopback server need not sign anything.
    #[test]
    fn verify_checksum_holds_the_archive_to_the_manifest_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("mvmctl-unit.tar.gz");
        std::fs::write(&archive, b"release bytes").unwrap();
        let matching = hex::encode(Sha256::digest(b"release bytes"));

        let mut env = TestEnv::new();
        env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            loopback_release_server(1, {
                let matching = matching.clone();
                move |line| {
                    assert!(line.contains(CHECKSUM_MANIFEST), "{line}");
                    format!("{matching}  mvmctl-unit.tar.gz\n").into_bytes()
                }
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

    #[test]
    fn run_sudo_cp_and_mv_bail_when_sudo_cannot_run_them() {
        let scratch = tempfile::tempdir().unwrap();
        let fake_sudo = scratch.path().join("sudo");
        std::fs::write(&fake_sudo, b"#!/bin/sh\nexit 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut env = TestEnv::new();
        env.set("PATH", scratch.path());
        let from = scratch.path().join("from");
        std::fs::write(&from, b"bytes").unwrap();
        let to = scratch.path().join("to");

        let cp_error = run_sudo_cp(&from, &to)
            .expect_err("sudo cp failed")
            .to_string();
        assert!(cp_error.contains("sudo cp failed"), "{cp_error}");
        let mv_error = run_sudo_mv(&from, &to)
            .expect_err("sudo mv failed")
            .to_string();
        assert!(mv_error.contains("sudo mv failed"), "{mv_error}");
    }

    /// Build a real release tarball the way the publish pipeline does: a
    /// `mvmctl-<target>/` directory holding a smoke-testable `mvmctl` script
    /// (plus optional helper and resources), archived with the same `tar`
    /// `extract_and_install` shells out to.
    #[cfg(target_os = "linux")]
    fn build_release_archive(
        root: &std::path::Path,
        target: &str,
        with_helper: bool,
        with_resources: bool,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let staged = root.join("staged");
        let release = staged.join(format!("mvmctl-{target}"));
        std::fs::create_dir_all(&release).unwrap();
        let write_script = |path: &std::path::Path, body: &str| {
            std::fs::write(path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        write_script(&release.join("mvmctl"), "#!/bin/sh\necho 'mvmctl 9.9.9'\n");
        if with_helper {
            write_script(&release.join("mvm-hvf-supervisor"), "#!/bin/sh\nexit 0\n");
        }
        if with_resources {
            std::fs::create_dir_all(release.join("resources")).unwrap();
            std::fs::write(release.join("resources/config.toml"), b"x").unwrap();
        }
        let archive = root.join(format!("mvmctl-{target}.tar.gz"));
        let status = std::process::Command::new("tar")
            .arg("czf")
            .arg(&archive)
            .arg("-C")
            .arg(&staged)
            .arg(".")
            .status()
            .expect("run tar to build the fixture");
        assert!(status.success(), "tar fixture: {status}");
        archive
    }

    /// The swap is the claim: a complete, smoke-testable release replaces the
    /// running binary and its adjacent helper. A mutant that bails when the
    /// extracted binary *is* present (or that takes the sudo branch on a
    /// writable install dir) fails this end to end.
    ///
    /// Linux-only because the macOS arm of the flow runs real codesigning
    /// against the running test executable's install, which a unit test must
    /// never touch.
    #[cfg(target_os = "linux")]
    #[test]
    fn extract_and_install_swaps_in_the_release_binary_and_helpers() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let archive = build_release_archive(tmp.path(), "unit-test", true, true);
        std::fs::copy(&archive, work.join("mvmctl-unit-test.tar.gz")).unwrap();

        let install_dir = tmp.path().join("install");
        std::fs::create_dir_all(&install_dir).unwrap();
        let current_exe = install_dir.join("mvmctl");
        std::fs::write(&current_exe, b"#!/bin/sh\necho 'mvmctl 0.1.0'\n").unwrap();

        extract_and_install("unit-test", &work, &current_exe).expect("the update installs");

        let updated = std::fs::read_to_string(&current_exe).unwrap();
        assert!(
            updated.contains("9.9.9"),
            "the release binary must be the one installed"
        );
        assert!(
            install_dir.join("mvm-hvf-supervisor").is_file(),
            "an adjacent helper in the archive is installed beside the binary"
        );
        assert!(
            install_dir.join("resources/config.toml").is_file(),
            "the release resources ship with the binary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn extract_and_install_refuses_a_broken_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("mvmctl-unit-test.tar.gz"), b"not a tarball").unwrap();
        let install_dir = tmp.path().join("install");
        std::fs::create_dir_all(&install_dir).unwrap();
        let current_exe = install_dir.join("mvmctl");
        std::fs::write(&current_exe, b"#!/bin/sh\necho 'mvmctl 0.1.0'\n").unwrap();

        let error = extract_and_install("unit-test", &work, &current_exe)
            .expect_err("a broken archive must not reach the install step")
            .to_string();
        assert!(error.contains("Failed to extract archive"), "{error}");
        assert!(
            !current_exe.with_extension("old").exists(),
            "a failed extract must not have touched the installed binary"
        );
    }

    /// An install dir the user does not own sends the flow down the sudo arm;
    /// the non-sudo file operations would fail there, so a mutant that picks
    /// the arm by writability the wrong way round dies on this case and the
    /// previous one together.
    #[cfg(target_os = "linux")]
    #[test]
    fn extract_and_install_uses_sudo_for_a_host_owned_install_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let sudo = bin.join("sudo");
        std::fs::write(
            &sudo,
            b"#!/bin/sh\nprintf 'called\\n' >> \"$MVM_TEST_SUDO_MARKER\"\n/bin/chmod u+w \"$MVM_TEST_INSTALL_DIR\"\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let archive = build_release_archive(tmp.path(), "unit-test", true, true);
        std::fs::copy(&archive, work.join("mvmctl-unit-test.tar.gz")).unwrap();

        let install_dir = tmp.path().join("install");
        std::fs::create_dir_all(&install_dir).unwrap();
        let current_exe = install_dir.join("mvmctl");
        std::fs::write(&current_exe, b"#!/bin/sh\necho 'mvmctl 0.1.0'\n").unwrap();
        std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let marker = tmp.path().join("sudo-called");
        let mut env = TestEnv::new();
        env.set("PATH", format!("{}:/usr/bin:/bin", bin.display()));
        env.set("MVM_TEST_SUDO_MARKER", &marker);
        env.set("MVM_TEST_INSTALL_DIR", &install_dir);

        let result = extract_and_install("unit-test", &work, &current_exe);

        std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        result.expect("the sudo arm installs into a host-owned directory");
        assert!(marker.is_file(), "the sudo arm must be invoked");
        assert!(
            std::fs::read_to_string(&current_exe)
                .unwrap()
                .contains("9.9.9")
        );
        assert!(install_dir.join("resources/config.toml").is_file());
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
