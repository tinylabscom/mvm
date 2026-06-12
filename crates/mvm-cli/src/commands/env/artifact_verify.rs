//! Artifact download + SHA-256 integrity verification for the dev-image
//! / builder-VM fetch paths.
//!
//! These are the generic "pull a file over curl and check it against the
//! published checksum manifest" helpers that back hash-verified downloads;
//! the dev-image and builder-VM download orchestration in
//! `dev_vz.rs` calls them.

use anyhow::{Context, Result};

use crate::ui;

/// Bump the dev_image_verify_<outcome> counter.
///
/// Caller passes the outcome name; centralising the lookup keeps the
/// counter set discoverable in one place. mvmd's reconciliation loop
/// will alert on attack-shaped spikes (sig_invalid, digest_mismatch,
/// revoked).
///
/// Security-relevant outcomes (everything except `network`, which is
/// operational) also emit a `LocalAuditKind::ImageVerifyFailed` event
/// so `mvmctl audit tail` shows the rejection. The counter is the
/// alerting channel; the audit line is the forensics channel.
pub(super) fn bump_verify_outcome(outcome: &str) {
    let m = mvm_core::observability::metrics::global();
    let counter = match outcome {
        "sig_invalid" => &m.dev_image_verify_sig_invalid,
        "digest_mismatch" => &m.dev_image_verify_digest_mismatch,
        "version_skew" => &m.dev_image_verify_version_skew,
        "revoked" => &m.dev_image_verify_revoked,
        "expired" => &m.dev_image_verify_expired,
        "network" => &m.dev_image_verify_network,
        // Defensive: an unknown outcome is itself a bug worth surfacing
        // — log a warning rather than silently swallowing the metric.
        _ => {
            tracing::warn!("bump_verify_outcome: unknown outcome '{outcome}'");
            return;
        }
    };
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if outcome != "network" {
        let mvmctl_version = env!("CARGO_PKG_VERSION");
        mvm_core::audit_emit!(
            ImageVerifyFailed,
            "outcome={outcome} mvmctl_version={mvmctl_version}"
        );
    }
}

/// HEAD-probe a URL. Returns Ok(true) when the resource is reachable
/// (HTTP 2xx), Ok(false) on 404, Err for transient failures.
pub(super) fn url_exists(url: &str) -> Result<bool> {
    let output = std::process::Command::new("curl")
        .args(["-fSI", "-o", "/dev/null", "-w", "%{http_code}", url])
        .output()
        .context("Failed to run curl HEAD probe")?;
    let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match code.as_str() {
        "200" | "302" => Ok(true),
        "404" => Ok(false),
        _ => {
            // Other status (5xx, network error, redirect chain failure)
            // — don't silently fall through to the unsigned path.
            anyhow::bail!(
                "HEAD probe of {url} returned status {code}; refusing to guess \
                 whether the signed manifest is missing or transiently unavailable. \
                 Retry, or investigate."
            )
        }
    }
}

/// Download the per-release `sha256sum`-format checksum file and parse it
/// into a `name -> hex-digest` map for the artifacts we plan to download.
///
/// The checksum file is the trust anchor for the hash-verified download.
/// It is fetched from the same GitHub release URL as the artifacts, over
/// TLS. Anyone
/// who can swap the artifact can also swap the checksum file, so the
/// real defence is end-to-end signing (cosign on the .tar.gz / SBOM
/// today, on the checksum file itself in a future iteration). What we
/// gain *now* is detection of mid-flight corruption and operator-error
/// substitution at the URL level — both of which are ruled out by a
/// matching hash.
///
/// Returns only entries for the artifacts in `wanted`; missing names
/// short-circuit to a clear error.
pub(super) fn fetch_expected_hashes(
    checksums_url: &str,
    wanted: &[&str],
) -> Result<std::collections::HashMap<String, String>> {
    let tmp = tempfile::NamedTempFile::new().context("Failed to create temp file")?;
    let tmp_path = tmp.path().to_string_lossy().to_string();
    download_file(checksums_url, &tmp_path).with_context(|| {
        format!(
            "Failed to download checksum manifest from {checksums_url}.\n\
             ADR-002 §W5.1 requires a hash-verified download; refusing to\n\
             proceed without the checksum file. To bypass for an emergency\n\
             rotation, set MVM_SKIP_HASH_VERIFY=1."
        )
    })?;
    let body = std::fs::read_to_string(&tmp_path)
        .with_context(|| format!("Failed to read checksum file at {tmp_path}"))?;

    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        // `sha256sum` output: `<64-hex>  <filename>`. Two-space gap is
        // canonical; a single space marks "text mode" but we accept
        // either rather than be picky about emitter conventions.
        let mut iter = line.splitn(2, char::is_whitespace);
        let Some(hash) = iter.next() else { continue };
        let Some(rest) = iter.next() else { continue };
        let name = rest.trim().trim_start_matches('*').to_string();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            map.insert(name, hash.to_ascii_lowercase());
        }
    }

    for w in wanted {
        if !map.contains_key(*w) {
            anyhow::bail!(
                "Checksum manifest at {checksums_url} did not include\n\
                 an entry for '{w}'. Refusing to download an unverifiable\n\
                 artifact. ADR-002 §W5.1."
            );
        }
    }
    Ok(map)
}

/// Stream `path` through SHA-256 and compare to `expected` (lowercase
/// hex). On mismatch, delete the file and bail with a clear message.
/// On `MVM_SKIP_HASH_VERIFY=1`, log a warning and accept — the env-var
/// is the documented escape hatch for emergency-rotation scenarios.
pub(super) fn verify_artifact_hash(
    path: &str,
    name: &str,
    expected: Option<&String>,
) -> Result<()> {
    if std::env::var_os("MVM_SKIP_HASH_VERIFY").is_some() {
        tracing::warn!(
            "MVM_SKIP_HASH_VERIFY set — skipping integrity check on {name}. \
             ADR-002 §W5.1 documents this as an emergency-rotation escape hatch."
        );
        return Ok(());
    }
    let Some(expected) = expected else {
        // fetch_expected_hashes already enforced presence, but defend
        // against a refactor that decouples the steps.
        anyhow::bail!("internal: no expected hash recorded for {name}");
    };

    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open downloaded artifact at {path}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("Failed to hash downloaded artifact at {path}"))?;
    let actual = format!("{:x}", hasher.finalize());

    if actual != *expected {
        let _ = std::fs::remove_file(path);
        bump_verify_outcome("digest_mismatch");
        anyhow::bail!(
            "Integrity check failed for {name}.\n\
             expected sha256: {expected}\n\
             actual   sha256: {actual}\n\
             \n\
             The downloaded artifact does not match the published checksum.\n\
             Refusing to use it. Possible causes:\n\
             - mid-flight corruption (retry the download);\n\
             - mirror/CDN cache poisoning (open an issue);\n\
             - the release was re-uploaded and the manifest is stale.\n\
             ADR-002 §W5.1."
        );
    }
    ui::info(&format!("  ✓ verified {name} sha256={}", &actual[..12]));
    Ok(())
}

/// Build the curl argv for a (resumable) download to `dest`.
/// `-C -` resumes from a partial `dest` if present; on a fresh or
/// already-complete file curl handles it gracefully. Corruption is
/// still caught downstream by the SHA-256 gate (`verify_artifact_hash`),
/// which deletes on mismatch so the next run restarts clean.
pub(super) fn curl_download_args(dest: &str, url: &str) -> Vec<String> {
    vec![
        "-fSL".to_string(),
        "--progress-bar".to_string(),
        "-C".to_string(),
        "-".to_string(),
        "-o".to_string(),
        dest.to_string(),
        url.to_string(),
    ]
}

/// Download a file from a URL using curl, resuming a partial `dest`.
pub(super) fn download_file(url: &str, dest: &str) -> Result<()> {
    let status = std::process::Command::new("curl")
        .args(curl_download_args(dest, url))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run curl")?;

    if !status.success() {
        // Keep any partial file: curl's `-C -` resumes it on the next
        // run. It's never hash-accepted while incomplete — verify runs
        // only after a successful download, and the SHA-256 gate deletes
        // on mismatch — so leaving it is safe and saves re-fetching.
        anyhow::bail!(
            "Download failed. Pre-built images for v{version} may not yet be\n\
             published — release tags are pushed before the artifact-build\n\
             matrix completes, so a 404 here often just means the build is\n\
             still in flight. Check the release page or retry in a few\n\
             minutes:\n\
             \n\
             \x20   https://github.com/tinylabscom/mvm/releases/tag/v{version}\n\
             \n\
             To build locally instead, set up a Nix Linux builder:\n\
             \n\
             \x20 Option 1 — Temporary (run in another terminal):\n\
             \x20   nix run 'nixpkgs#darwin.linux-builder'\n\
             \n\
             \x20 Option 2 — Permanent (add to /etc/nix/nix.conf):\n\
             \x20   builders = ssh-ng://builder@linux-builder aarch64-linux /etc/nix/builder_ed25519 4 1 kvm,big-parallel - -\n\
             \x20   builders-use-substitutes = true",
            version = env!("CARGO_PKG_VERSION")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::sync::Mutex;

    #[test]
    fn curl_download_args_request_resume() {
        let args = curl_download_args("/tmp/out", "https://example/x");
        assert!(
            args.contains(&"-C".to_string()),
            "must pass -C for resume: {args:?}"
        );
        assert!(
            args.windows(2).any(|w| w == ["-C", "-"]),
            "expected `-C -`: {args:?}"
        );
        assert!(args.contains(&"-fSL".to_string()));
        assert_eq!(args.last().unwrap(), "https://example/x");
    }

    /// Cargo test runs tests in parallel within a single binary. Two
    /// of these tests touch `MVM_SKIP_HASH_VERIFY` (the global env-var
    /// escape hatch), so they have to be serialised
    /// against each other and against any other test that hashes a
    /// real artifact. Static mutex held for the test's lifetime.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Compute the canonical lowercase-hex SHA-256 of a byte slice. Tests
    /// use this to derive matching expected values without rebuilding
    /// the production hash path.
    fn hex_sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn verify_hash_accepts_matching_artifact() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        let bytes = b"hello world\n";
        std::fs::write(&path, bytes).unwrap();
        let expected = hex_sha256(bytes);
        let result = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&expected));
        assert!(
            result.is_ok(),
            "matching hash should be accepted: {result:?}"
        );
        // File must still exist on success.
        assert!(
            path.exists(),
            "verified file must not be deleted on success"
        );
    }

    #[test]
    fn verify_hash_rejects_mismatched_artifact_and_deletes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"actual contents").unwrap();
        let expected = hex_sha256(b"different contents");
        let err = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&expected))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Integrity check failed"),
            "expected integrity-check error, got: {err}"
        );
        assert!(
            !path.exists(),
            "tampered file must be deleted to prevent reuse"
        );
    }

    #[test]
    fn verify_hash_skip_env_var_bypasses_check() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Ensure the file exists even though we'll set a "wrong" hash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"contents").unwrap();
        let wrong = hex_sha256(b"definitely not the contents");

        // SAFETY: ENV_LOCK serialises every test that touches this env
        // var, so no concurrent reader observes a half-set value. The
        // unsafe block is only required by edition-2024's set_var /
        // remove_var signatures; behaviour is unchanged.
        unsafe {
            std::env::set_var("MVM_SKIP_HASH_VERIFY", "1");
        }
        let result = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&wrong));
        unsafe {
            std::env::remove_var("MVM_SKIP_HASH_VERIFY");
        }
        assert!(result.is_ok(), "skip-env should bypass check: {result:?}");
    }

    #[test]
    fn fetch_expected_hashes_parses_sha256sum_format() {
        // Run a tiny in-process HTTP server? Overkill — the function
        // takes a URL and shells out to curl. Instead, we test the
        // parser by exercising it directly via a file:// URL: curl
        // accepts file:// and just copies the bytes.
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("checksums.txt");
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        // Two-space gap is canonical sha256sum output. Mix in a leading
        // '*' on one line (binary mode) to confirm we strip it.
        writeln!(f, "{}  dev-vmlinux-x86_64", "a".repeat(64)).unwrap();
        writeln!(f, "{} *dev-rootfs-x86_64.ext4", "b".repeat(64)).unwrap();
        writeln!(f, "garbage line that is not a hash").unwrap();
        drop(f);

        let url = format!("file://{}", manifest_path.display());
        let map = fetch_expected_hashes(&url, &["dev-vmlinux-x86_64", "dev-rootfs-x86_64.ext4"])
            .expect("manifest should parse");
        assert_eq!(map.get("dev-vmlinux-x86_64").unwrap(), &"a".repeat(64));
        assert_eq!(map.get("dev-rootfs-x86_64.ext4").unwrap(), &"b".repeat(64));
    }

    #[test]
    fn fetch_expected_hashes_errors_when_artifact_missing_from_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("checksums.txt");
        std::fs::write(
            &manifest_path,
            format!("{}  some-other-file\n", "c".repeat(64)),
        )
        .unwrap();

        let url = format!("file://{}", manifest_path.display());
        let err = fetch_expected_hashes(&url, &["dev-vmlinux-x86_64"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("did not include") && err.contains("dev-vmlinux-x86_64"),
            "expected missing-entry error, got: {err}"
        );
    }
}
