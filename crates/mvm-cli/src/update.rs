use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::http;
use crate::ui;
use mvm_core::release_version::{ReleaseVersion, VersionSyntax};
use mvm_runtime::shell::run_host;

const GITHUB_REPO: &str = "tinylabscom/mvm";
const RELEASE_HOST_BINS: &[&str] = &[
    "mvm-hvf-supervisor",
    "mvm-libkrun-supervisor",
    "mvm-network-endpoint",
];

/// Current version compiled into the binary (from Cargo.toml).
fn current_version() -> &'static str {
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

/// Base URL for GitHub release-asset downloads.
///
/// Defaults to `https://github.com`. `MVM_UPDATE_DOWNLOAD_URL` overrides
/// for hermetic tests — same shape as `MVM_UPDATE_API_URL`.
fn github_download_base() -> String {
    if let Ok(base) = std::env::var("MVM_UPDATE_DOWNLOAD_URL")
        && !base.trim().is_empty()
    {
        eprintln!("[mvm] MVM_UPDATE_DOWNLOAD_URL set; using {base} (test path).");
        return base.trim().trim_end_matches('/').to_string();
    }
    String::from("https://github.com")
}

/// Query the GitHub releases API for the latest release tag name.
fn fetch_latest_version() -> Result<String> {
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
pub(crate) fn boot_image_release() -> Result<(String, String)> {
    let tag = mvm_core::config::default_boot_image_tag();
    let version = tag.rsplit_once("/v").map(|(_, v)| v).with_context(|| {
        format!("boot image tag {tag:?} is not of the form `boot-image/v<semver>`")
    })?;
    Ok((tag.to_string(), version.to_string()))
}

/// Asset and checksum-manifest names for a kernel variant on the boot image
/// release.
///
/// The two release trains name the same bytes differently: `kernel-build.yml`
/// publishes `vmlinux-<arch>-<variant>`, while `release-boot-image.yml`
/// publishes the kernel *inside* the image it belongs to. The workload kernel
/// is `nix/images/default-tenant`'s, whose flake states it is "the single
/// shared definition in `nix/images/kernel/`, identical to the one builder-vm
/// builds" — so the mapping is a rename, not a substitution.
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

fn fetch_signed_checksum_manifest(
    base_url: &str,
    asset: &str,
    version: &str,
    train: mvm_build::release_signature::ReleaseTrain,
) -> Result<String> {
    let staged = tempfile::NamedTempFile::new()
        .with_context(|| format!("creating staging file for {asset}"))?;
    download_release_asset(&format!("{base_url}/{asset}"), staged.path())
        .with_context(|| format!("downloading {asset} — cannot verify integrity"))?;
    mvm_build::release_signature::verify_release_archive_signature(
        &mvm_build::release_signature::ReleaseSignatureRequest {
            base_url,
            asset,
            archive_path: staged.path(),
            version,
            train,
        },
    )
    .with_context(|| format!("refusing to parse an unauthenticated checksum manifest ({asset})"))?;
    std::fs::read_to_string(staged.path()).with_context(|| format!("reading {asset}"))
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
/// the success case. An unreachable or rate-limited API answers `true`: the
/// point of the probe is to *sharpen* a message, and guessing "no release"
/// from a failed lookup would state something false with more confidence than
/// the vaguer wording it replaced.
fn release_exists(tag: &str) -> bool {
    let url = format!(
        "{}/repos/{}/releases/tags/{}",
        github_api_base(),
        GITHUB_REPO,
        tag
    );
    match http::fetch_json(&url) {
        Ok(v) => v.get("tag_name").is_some(),
        // Distinguishing "404, no such release" from "the network is down"
        // would need a status code this helper does not get. Both land here,
        // and both are better served by the asset-missing wording.
        Err(_) => true,
    }
}

/// The advice to print when a kernel download 404s.
///
/// A missing asset and a missing release are the same HTTP status and
/// different problems. An in-development build always hits the second — the
/// crate version runs ahead of the last tag, by construction — and telling
/// that user to "cut a release that publishes kernels" points them at
/// something that is not broken, when what they want is to compile.
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

/// Download a published kernel (`vmlinux-<arch>-<variant>`) from the
/// release matching this mvmctl's version, SHA-256-verify it against the
/// release's `kernel-<arch>-checksums-sha256.txt`, and write it to
/// `dest`. The `--source download` arm of `mvmctl kernel build`.
///
/// That manifest is itself signature-verified against the release identity
/// before it is read, so the digest the kernel is held to comes from the
/// publisher rather than from whoever answered the request.
///
/// Keyed by the mvmctl release tag: a given mvmctl can only ever fetch
/// the kernel that shipped with it — never a substitute for an in-tree
/// config edit (a source checkout compiles instead).
/// `MVM_SKIP_HASH_VERIFY` is the documented emergency escape for the digest
/// comparison — never set it in CI. It does not waive the manifest signature;
/// `MVM_SKIP_COSIGN_VERIFY` is that separate, larger concession.
///
/// Available without `builder-vm`: lean clients cannot compile kernels
/// locally, so downloading the release-matched kernel is their supported
/// acquisition path.
pub(crate) fn download_kernel(arch: &str, variant: &str, dest: &Path) -> Result<()> {
    let (tag, image_version) = boot_image_release()?;
    let (asset, checksums) = boot_image_kernel_assets(arch, variant)?;
    let base = github_download_base();

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating kernel cache dir {}", parent.display()))?;
    }

    let release_base = format!("{base}/{GITHUB_REPO}/releases/download/{tag}");
    let asset_url = format!("{release_base}/{asset}");
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
    let sp = ui::spinner(&format!("Downloading {asset} ({tag})..."));
    let dl = download_release_asset(&asset_url, &download);
    sp.finish_and_clear();
    dl.with_context(|| kernel_fetch_hint(&tag, &asset, release_exists(&tag)))?;

    // The signature rung runs even under MVM_SKIP_HASH_VERIFY: that hatch
    // waives comparing the digest, not the question of who published the
    // manifest the digest comes from. Waiving the publisher takes the separate
    // MVM_SKIP_COSIGN_VERIFY.
    let manifest = fetch_signed_checksum_manifest(
        &release_base,
        &checksums,
        &image_version,
        mvm_build::release_signature::ReleaseTrain::BootImage,
    )?;

    if std::env::var("MVM_SKIP_HASH_VERIFY").is_ok() {
        ui::warn("MVM_SKIP_HASH_VERIFY set — skipping kernel checksum verification (never in CI).");
        publish_downloaded_kernel(download, dest)?;
        return Ok(());
    }

    let expected = manifest
        .lines()
        .find(|l| l.contains(&asset))
        .with_context(|| format!("{asset} not found in {checksums}"))
        .and_then(parse_checksum_line)?;

    let bytes = std::fs::read(&download)
        .with_context(|| format!("reading {} for checksum", download.display()))?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != expected {
        anyhow::bail!(
            "Kernel checksum mismatch for {asset}!\n  expected: {}\n  actual:   {}\n\
             Staged download rejected; any existing cached kernel was preserved.",
            hex_encode(&expected),
            hex_encode(&actual),
        );
    }
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
    let output = std::process::Command::new(bin)
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
/// refuses the update; the SHA-256 checked before this comes from a manifest
/// fetched over the same channel, so on its own it says nothing about who
/// published the archive.
fn verify_signature(version: &str, archive_name: &str, archive_path: &Path) -> Result<()> {
    let release_base = format!(
        "{}/{}/releases/download/{}",
        github_download_base(),
        GITHUB_REPO,
        version
    );
    ui::info("Verifying release signature...");
    verify_archive_signature_at(&release_base, version, archive_name, archive_path)?;
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
pub(crate) const BOOT_IMAGE_TAG_PREFIX: &str = "boot-image/v";

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

/// The highest published `boot-image/v*` tag, or `None` when the line has
/// published nothing yet.
///
/// `/releases/latest` is the wrong endpoint here: it answers with the newest
/// release across *every* tag namespace, which for a repo whose binaries
/// release far more often is almost never a boot image. The full listing is
/// filtered instead, and an empty result is a clean answer — "no published
/// image line" is a real state, not a failure and not "behind".
pub(crate) fn fetch_latest_boot_image_tag() -> Result<Option<String>> {
    let url = format!("{}/repos/{}/releases", github_api_base(), GITHUB_REPO);
    let json = http::fetch_json(&url)
        .context("Failed to list GitHub releases. Check your network connection.")?;
    let releases = json
        .as_array()
        .context("GitHub releases listing was not a JSON array")?;
    Ok(highest_boot_image_tag(
        releases.iter().filter_map(|r| r["tag_name"].as_str()),
    ))
}

/// Pick the highest `boot-image/v*` tag from a set of tag names.
///
/// Split from the fetch so the ordering can be tested without a server.
pub(crate) fn highest_boot_image_tag<'a>(tags: impl Iterator<Item = &'a str>) -> Option<String> {
    tags.filter_map(|tag| BootImageVersion::from_tag(tag).map(|v| (v, tag)))
        .max_by_key(|(v, _)| *v)
        .map(|(_, tag)| tag.to_string())
}

/// Release-asset base URL for one boot-image tag.
///
/// Shares `MVM_UPDATE_DOWNLOAD_URL` with the binary updater so the network leg
/// is redirectable in a test without a second override to remember.
pub(crate) fn boot_image_asset_base_url(tag: &str) -> String {
    format!(
        "{}/{}/releases/download/{}",
        github_download_base(),
        GITHUB_REPO,
        tag
    )
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

    let current_exe =
        std::env::current_exe().context("Failed to determine path of current executable")?;
    refuse_versioned_install(&current_exe)?;
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
    extract_and_install(target, tmp_dir.path(), &current_exe)?;

    ui::success(&format!("\nSuccessfully updated to {}!", latest_tag));
    ui::info("The binary has been replaced on disk.");
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
            tag.starts_with("boot-image/v"),
            "images ship on their own counter: {tag}"
        );
        assert_eq!(tag, format!("boot-image/v{version}"));
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
        let identities = mvm_core::release_trust::accepted_boot_image_identities(&version);
        assert!(
            identities
                .iter()
                .any(|i| i.ends_with(&format!("refs/tags/boot-image/v{version}"))),
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
    fn update_proceeds_for_a_binary_outside_an_install_sh_release() {
        let root = tempfile::tempdir().unwrap();
        let loose = root.path().join("bin").join("mvmctl");
        std::fs::create_dir_all(loose.parent().unwrap()).unwrap();
        std::fs::write(&loose, "").unwrap();
        assert!(refuse_versioned_install(&loose).is_ok());
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

    #[cfg(feature = "builder-vm")]
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
        let kernel = b"kernel bytes for the unit test";
        // Deliberately not the digest of `kernel`.
        let wrong_digest = "ab".repeat(32);
        let (asset, checksums) =
            boot_image_kernel_assets("aarch64", "workload").expect("known assets");
        let closure_asset = asset.clone();
        let server = loopback_release_server(2, move |line| {
            if line.contains(&checksums) {
                format!("{wrong_digest}  {closure_asset}\n").into_bytes()
            } else {
                assert!(
                    line.contains(&closure_asset),
                    "the asset download must name the asset: {line}"
                );
                kernel.to_vec()
            }
        });
        let mut env = TestEnv::new();
        env.set("MVM_UPDATE_DOWNLOAD_URL", &server);
        // The manifest signature is a separate rung with its own tests; this
        // test pins the digest comparison below it.
        env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out").join(&asset);
        let error = download_kernel("aarch64", "workload", &dest)
            .expect_err("a mismatched manifest digest must refuse the kernel")
            .to_string();
        assert!(error.contains("checksum mismatch"), "{error}");
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
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let archive = build_release_archive(tmp.path(), "unit-test", true, true);
        std::fs::copy(&archive, work.join("mvmctl-unit-test.tar.gz")).unwrap();

        let install_dir = tmp.path().join("install");
        std::fs::create_dir_all(&install_dir).unwrap();
        let current_exe = install_dir.join("mvmctl");
        std::fs::write(&current_exe, b"#!/bin/sh\necho 'mvmctl 0.1.0'\n").unwrap();
        std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = extract_and_install("unit-test", &work, &current_exe);

        std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        result.expect("the sudo arm installs into a host-owned directory");
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
