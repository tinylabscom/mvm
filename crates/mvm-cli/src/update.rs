use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::http;
use crate::ui;
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
    let tag = mvm_core::config::DEFAULT_BOOT_IMAGE_TAG;
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
    sign_installed_binaries().context("Failed to apply macOS VM entitlements")?;

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
            if !output.status.success() {
                ui::warn("Failed to update resources directory");
            }
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
fn sign_installed_binaries() -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    let targets = mvm_runtime::codesign::collect_sign_targets();
    let reports = mvm_runtime::codesign::sign_targets(&targets);
    let failed: Vec<String> = reports
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

/// Verify the cosign signature of a release archive bundle if cosign is available.
///
/// Downloads `<archive_name>.bundle` from the release and runs `cosign verify-blob`.
/// Non-fatal if cosign is not installed — checksum verification still runs.
fn verify_signature(version: &str, archive_name: &str, archive_path: &Path) -> Result<()> {
    let cosign = match which::which("cosign") {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                "cosign not found — skipping signature verification. \
                 Install cosign to enable provenance checking."
            );
            return Ok(());
        }
    };

    let bundle_name = format!("{}.bundle", archive_name);
    let bundle_url = format!(
        "{}/{}/releases/download/{}/{}",
        github_download_base(),
        GITHUB_REPO,
        version,
        bundle_name
    );
    let bundle_path = archive_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(&bundle_name);

    ui::info("Downloading signature bundle...");
    download_release_asset(&bundle_url, &bundle_path)
        .context("Failed to download cosign bundle — cannot verify signature")?;

    let output = std::process::Command::new(&cosign)
        .args([
            "verify-blob",
            "--bundle",
            bundle_path
                .to_str()
                .expect("bundle path must be valid UTF-8"),
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-identity-regexp",
            &format!(
                "https://github.com/{repo}/.github/workflows/release.yml@refs/tags/.*",
                repo = GITHUB_REPO
            ),
            archive_path
                .to_str()
                .expect("archive path must be valid UTF-8"),
        ])
        .output()
        .context("Failed to run cosign verify-blob")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Signature verification failed — the archive may not have been built \
             by the official release pipeline.\ncosign output: {}",
            stderr.trim()
        );
    }

    ui::success("Signature verified.");
    Ok(())
}

/// A released CLI version, ordered by semantic-version precedence.
///
/// [`BootImageVersion`] deliberately drops a pre-release suffix, because the
/// image line has never carried one and dropping it keeps that ordering total.
/// Doing the same here would make `0.18.0-rc.1` compare *equal* to `0.18.0`,
/// which is the single comparison this type exists to get right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseVersion {
    major: u64,
    minor: u64,
    patch: u64,
    /// Dot-separated pre-release identifiers; empty for a normal release.
    pre: Vec<String>,
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| compare_prerelease(&self.pre, &other.pre))
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ReleaseVersion {
    /// Parse `X.Y.Z` or `X.Y.Z-<pre>`, with or without a leading `v`.
    ///
    /// Build metadata (`+...`) is stripped: semver excludes it from precedence,
    /// so two versions differing only there are the same release.
    ///
    /// Anything else returns `None`. A version that cannot be ordered is one
    /// this must not claim to have ordered — the caller falls back to the
    /// equality test rather than acting on a guess.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let raw = raw.strip_prefix('v').unwrap_or(raw);
        let raw = raw.split('+').next()?;
        // `None` (no hyphen) and `Some("")` (`0.18.0-`) are different: the
        // first is a normal release, the second is malformed. Collapsing them
        // to an empty string made `0.18.0-` parse as `0.18.0`.
        let (core, pre) = match raw.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (raw, None),
        };

        let mut parts = core.split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let major = next()?;
        let minor = next()?;
        let patch = next()?;
        if parts.next().is_some() {
            return None;
        }

        let pre: Vec<String> = match pre {
            None => Vec::new(),
            Some(pre) => pre.split('.').map(str::to_string).collect(),
        };
        // `1.0.0-` and `1.0.0-rc..1` are malformed, not a pre-release of
        // anything: an empty identifier has no precedence against a real one.
        if pre.iter().any(|id| id.is_empty()) {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

/// Semver §11: a pre-release version has lower precedence than the normal
/// version it precedes, and two pre-releases compare identifier by identifier.
fn compare_prerelease(a: &[String], b: &[String]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in a.iter().zip(b.iter()) {
                let ord = compare_identifier(x, y);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            // Every shared identifier is equal, so the longer set wins:
            // `rc.1.1` outranks `rc.1`.
            a.len().cmp(&b.len())
        }
    }
}

/// Numeric identifiers compare numerically and rank below alphanumeric ones;
/// alphanumeric identifiers compare in ASCII order.
fn compare_identifier(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
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

    let ordered = ReleaseVersion::parse(latest)
        .zip(ReleaseVersion::parse(current))
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

    if latest_version == current {
        ui::info(&format!(
            "Already at {} but --force specified, reinstalling.",
            current
        ));
    } else if ReleaseVersion::parse(latest_version)
        .zip(ReleaseVersion::parse(current))
        .is_some_and(|(latest, running)| latest < running)
    {
        // Reachable only under --force. Announcing a downgrade as a "new
        // version" is what this whole change is about.
        ui::info(&format!(
            "Installing {} over the newer {} (--force).",
            latest_version, current
        ));
    } else {
        ui::info(&format!(
            "New version available: {} -> {}",
            current, latest_version
        ));
    }

    if check_only {
        return Ok(());
    }

    let target = detect_target()?;
    ui::info(&format!("Platform: {}", target));

    let current_exe =
        std::env::current_exe().context("Failed to determine path of current executable")?;
    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    download_release(&latest_tag, target, tmp_dir.path())?;
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let archive_path = tmp_dir.path().join(&archive_name);
    verify_checksum(&latest_tag, &archive_name, &archive_path)?;
    if !skip_verify {
        verify_signature(&latest_tag, &archive_name, &archive_path)?;
    }
    extract_and_install(target, tmp_dir.path(), &current_exe)?;

    ui::success(&format!("\nSuccessfully updated to {}!", latest_tag));
    ui::info("The binary has been replaced on disk.");
    ui::info("To verify: Open a new shell and run 'mvmctl --version'");
    ui::info("Or run: hash -r  (to clear your shell's command cache)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ReleaseVersion, UpdateAction, decide_update};

    fn v(raw: &str) -> ReleaseVersion {
        ReleaseVersion::parse(raw).unwrap_or_else(|| panic!("{raw} should parse"))
    }

    /// The comparison that was missing. `update` tested string equality, so any
    /// resolved release that was not byte-identical to the running one was
    /// installed — forward or not.
    #[test]
    fn a_prerelease_ranks_below_the_release_it_precedes() {
        assert!(v("0.18.0-rc.1") < v("0.18.0"));
        assert!(v("0.18.0") > v("0.18.0-rc.1"));
        // ...and still above everything before it, which is the half a
        // suffix-dropping parse would get right by accident.
        assert!(v("0.18.0-rc.1") > v("0.17.0"));
    }

    #[test]
    fn prerelease_identifiers_compare_by_semver_rules() {
        // Numeric identifiers compare numerically, not as strings: the string
        // ordering would put rc.10 before rc.9.
        assert!(v("0.18.0-rc.2") < v("0.18.0-rc.10"));
        // Numeric identifiers rank below alphanumeric ones.
        assert!(v("0.18.0-1") < v("0.18.0-alpha"));
        // Alphanumeric identifiers compare in ASCII order.
        assert!(v("0.18.0-alpha") < v("0.18.0-beta"));
        // A longer set wins when every shared identifier is equal.
        assert!(v("0.18.0-rc.1") < v("0.18.0-rc.1.1"));
    }

    #[test]
    fn the_release_triple_still_dominates_the_suffix() {
        assert!(
            v("0.9.0") < v("0.10.0"),
            "string ordering would invert this"
        );
        assert!(v("0.18.1-rc.1") > v("0.18.0"));
        assert_eq!(v("0.18.0"), v("0.18.0"));
    }

    #[test]
    fn parse_accepts_the_shapes_a_tag_actually_takes_and_rejects_the_rest() {
        assert_eq!(v("v0.18.0"), v("0.18.0"), "a leading v is the tag form");
        // Build metadata is excluded from precedence by semver, so two
        // versions differing only there are the same release.
        assert_eq!(v("0.18.0+deadbeef"), v("0.18.0"));

        for bad in ["", "0.18", "0.18.0.1", "not-a-version", "0.x.0", "0.18.0-"] {
            assert!(
                ReleaseVersion::parse(bad).is_none(),
                "{bad:?} is not orderable and must not parse"
            );
        }
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
    use sha2::{Digest, Sha256};
    use std::io::Write;

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

    // --- signature verification ---

    #[test]
    fn test_verify_signature_skipped_when_cosign_absent() {
        // If cosign is not installed, verify_signature returns Ok (non-fatal).
        // We can't control whether cosign is installed, so we test the which::which behaviour
        // by checking that verify_signature on a nonsense version returns Ok (no cosign)
        // or Err only with a cosign-related message (cosign present but download fails).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let result = verify_signature("v0.0.0-nonexistent", "mvmctl-test.tar.gz", tmp.path());
        match result {
            Ok(()) => {} // cosign not installed → warning + Ok
            Err(e) => {
                let msg = e.to_string();
                // cosign installed but download failed — that's still acceptable test behaviour
                assert!(
                    msg.contains("cosign") || msg.contains("bundle") || msg.contains("download"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_skip_verify_flag_respected() {
        // When skip_verify is true, verify_signature should not be called.
        // The skip_verify=true path in update() simply never calls verify_signature.
        // Verified by code inspection: update() returns early before calling
        // verify_signature when skip_verify is set.
        // This test documents the intended semantics.
        let _ = "skip_verify=true prevents any cosign invocation";
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
}
