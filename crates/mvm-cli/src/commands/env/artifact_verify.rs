//! Artifact download + SHA-256 integrity verification for the dev-image
//! / builder-VM fetch paths.
//!
//! These are the generic "pull a file over curl and check it against the
//! published checksum manifest" helpers that back hash-verified downloads;
//! the dev-image and builder-VM download orchestration in
//! `builder_vm.rs` calls them.
//!
//! The manifest is itself signature-verified before it is parsed, so the
//! digests every artifact is held to come from the publisher rather than from
//! whoever answered the request.

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

/// A published checksum manifest, named the way the signature rung needs it.
///
/// The verifier fetches the Sigstore bundle from `<base_url>/<asset>.bundle`
/// and accepts only the identity bound to `version`'s tag, so a single joined
/// URL is not enough — splitting one back apart would have to guess where the
/// asset name starts. A params struct also stops three same-typed strings from
/// being transposed silently.
pub(crate) struct ChecksumManifest<'a> {
    /// Per-version release base URL, no trailing slash.
    pub base_url: &'a str,
    /// The manifest's published asset name, e.g. `kernel-aarch64-checksums-sha256.txt`.
    pub asset: &'a str,
    /// Release version whose signing identity is accepted for this manifest.
    pub version: &'a str,
    /// Which release train published the manifest, and therefore which
    /// workflow identity may have signed it.
    pub train: mvm_build::release_signature::ReleaseTrain,
}

impl ChecksumManifest<'_> {
    fn url(&self) -> String {
        format!("{}/{}", self.base_url, self.asset)
    }
}

/// Download the per-release `sha256sum`-format checksum file, prove it against
/// the release's Sigstore bundle, and parse it into a `name -> hex-digest` map
/// for the artifacts we plan to download.
///
/// The manifest is the trust anchor for every artifact digest beneath it, and
/// TLS authenticates only the transport: whoever can swap an artifact can swap
/// the digest published beside it. So the bytes are verified against the
/// release signing identity *before* a line of them is parsed — an unsigned,
/// mis-signed, or foreign-signed manifest is refused with nothing read out of
/// it.
///
/// `MVM_SKIP_HASH_VERIFY` does not reach this rung. Bypassing the publisher
/// check takes `MVM_SKIP_COSIGN_VERIFY`, a deliberately separate switch, since
/// waiving *who* published is a bigger concession than waiving *what* the bytes
/// hash to.
///
/// Returns only entries for the artifacts in `wanted`; missing names
/// short-circuit to a clear error.
pub(crate) fn fetch_expected_hashes(
    manifest: &ChecksumManifest<'_>,
    wanted: &[&str],
) -> Result<std::collections::HashMap<String, String>> {
    let checksums_url = manifest.url();
    let tmp = tempfile::NamedTempFile::new().context("Failed to create temp file")?;
    let tmp_path = tmp.path().to_string_lossy().to_string();
    download_file(&checksums_url, &tmp_path).with_context(|| {
        format!(
            "Failed to download checksum manifest from {checksums_url}.\n\
             ADR-002 §W5.1 requires a hash-verified download; refusing to\n\
             proceed without the checksum file."
        )
    })?;
    verify_manifest_signature(manifest, tmp.path())?;
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

/// Verify the downloaded manifest at `staged` against the release signing
/// identity, using the one shared release verifier.
///
/// A refusal here is attack-shaped, so it feeds the same counter and audit
/// line as a bad artifact signature rather than looking like a network blip.
pub(super) fn verify_manifest_signature(
    manifest: &ChecksumManifest<'_>,
    staged: &std::path::Path,
) -> Result<()> {
    mvm_build::release_signature::verify_release_archive_signature(
        &mvm_build::release_signature::ReleaseSignatureRequest {
            base_url: manifest.base_url,
            asset: manifest.asset,
            archive_path: staged,
            version: manifest.version,
            train: manifest.train,
        },
    )
    .map_err(|error| {
        bump_verify_outcome("sig_invalid");
        anyhow::Error::new(error).context(format!(
            "Refusing to parse an unauthenticated checksum manifest \
             ({}). Every artifact digest below it would inherit the \
             manifest's trust. ADR-002 §W5.1.",
            manifest.asset
        ))
    })
}

/// Stream `path` through SHA-256 and compare to `expected` (lowercase
/// hex). On mismatch, delete the file and bail with a clear message.
/// On `MVM_SKIP_HASH_VERIFY=1`, log a warning and accept — the env-var
/// is the documented escape hatch for emergency-rotation scenarios.
pub(crate) fn verify_artifact_hash(
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
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open downloaded artifact at {path}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("Failed to hash downloaded artifact at {path}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());

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

fn download_failure_message() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
        "Download failed. Published artifacts for v{version} may not yet be\n\
         available — release tags are pushed before the artifact-build matrix\n\
         completes, so a 404 often means publishing is still in progress.\n\
         Check the release page or retry in a few minutes:\n\
         \n\
         \x20   https://github.com/tinylabscom/mvm/releases/tag/v{version}\n\
         \n\
         mvm manages its own Linux builder; no host Nix configuration is required.\n\
         If you are developing from a source checkout, use the\n\
         mvmctl binary built from that checkout so it bootstraps the project\n\
         builder VM from the in-repo image source."
    )
}

/// Download a file from a URL using curl, resuming a partial `dest`.
pub(crate) fn download_file(url: &str, dest: &str) -> Result<()> {
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
        anyhow::bail!("{}", download_failure_message());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use sha2::{Digest, Sha256};

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

    #[test]
    fn download_failure_guidance_uses_mvm_managed_builder_without_sudo() {
        let message = download_failure_message();

        assert!(message.contains("mvm manages its own Linux builder"));
        assert!(message.contains("no host Nix configuration is required"));
        assert!(message.contains("https://github.com/tinylabscom/mvm/releases/tag/v"));
        for forbidden in ["sudo", "darwin.linux-builder", "/etc/nix"] {
            assert!(
                !message.contains(forbidden),
                "download recovery guidance must not recommend {forbidden}: {message}"
            );
        }
    }

    /// Compute the canonical lowercase-hex SHA-256 of a byte slice. Tests
    /// use this to derive matching expected values without rebuilding
    /// the production hash path.
    fn hex_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn verify_hash_accepts_matching_artifact() {
        let _env = TestEnv::new();
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
        let _env = TestEnv::new();
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
        let mut env = TestEnv::new();
        // Ensure the file exists even though we'll set a "wrong" hash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"contents").unwrap();
        let wrong = hex_sha256(b"definitely not the contents");

        env.set("MVM_SKIP_HASH_VERIFY", "1");
        let result = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&wrong));
        assert!(result.is_ok(), "skip-env should bypass check: {result:?}");
    }

    /// Stage a `sha256sum` manifest in its own dir and return the manifest
    /// params pointing at it. `file://` keeps the download path real — curl
    /// copies the bytes — without a network or a live release.
    fn stage_manifest(body: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MANIFEST_ASSET), body).unwrap();
        let base_url = format!("file://{}", dir.path().display());
        (dir, base_url)
    }

    const MANIFEST_ASSET: &str = "checksums.txt";
    const MANIFEST_VERSION: &str = "9.9.9";

    fn manifest<'a>(base_url: &'a str) -> ChecksumManifest<'a> {
        ChecksumManifest {
            base_url,
            asset: MANIFEST_ASSET,
            version: MANIFEST_VERSION,
            train: mvm_build::release_signature::ReleaseTrain::Cli,
        }
    }

    #[test]
    fn fetch_expected_hashes_parses_sha256sum_format() {
        let mut env = TestEnv::new();
        // This test is about the parser, so waive the publisher rung the way
        // an operator would; the rung itself has its own witnesses below.
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        // Two-space gap is canonical sha256sum output. Mix in a leading
        // '*' on one line (binary mode) to confirm we strip it.
        let body = format!(
            "{}  dev-vmlinux-x86_64\n{} *dev-rootfs-x86_64.ext4\ngarbage line that is not a hash\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        let (_dir, base_url) = stage_manifest(&body);

        let map = fetch_expected_hashes(
            &manifest(&base_url),
            &["dev-vmlinux-x86_64", "dev-rootfs-x86_64.ext4"],
        )
        .expect("manifest should parse");
        assert_eq!(map.get("dev-vmlinux-x86_64").unwrap(), &"a".repeat(64));
        assert_eq!(map.get("dev-rootfs-x86_64.ext4").unwrap(), &"b".repeat(64));
    }

    #[test]
    fn fetch_expected_hashes_errors_when_artifact_missing_from_manifest() {
        let mut env = TestEnv::new();
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        let (_dir, base_url) = stage_manifest(&format!("{}  some-other-file\n", "c".repeat(64)));

        let err = fetch_expected_hashes(&manifest(&base_url), &["dev-vmlinux-x86_64"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("did not include") && err.contains("dev-vmlinux-x86_64"),
            "expected missing-entry error, got: {err}"
        );
    }

    /// Read every `dev_image_verify_*` counter at once.
    ///
    /// The assertion that matters is not "the counter went up" but "that
    /// counter went up and no other did" — a misrouted outcome is invisible
    /// to the first and obvious to the second.
    fn verify_counters() -> [u64; 7] {
        let m = mvm_core::observability::metrics::global();
        let r = std::sync::atomic::Ordering::Relaxed;
        [
            m.dev_image_verify_sig_invalid.load(r),
            m.dev_image_verify_digest_mismatch.load(r),
            m.dev_image_verify_version_skew.load(r),
            m.dev_image_verify_revoked.load(r),
            m.dev_image_verify_expired.load(r),
            m.dev_image_verify_network.load(r),
            m.dev_image_verify_ok.load(r),
        ]
    }

    /// Each outcome bumps its own counter and nobody else's.
    ///
    /// These counters are the alerting channel: mvmd's reconciliation loop
    /// watches `sig_invalid`, `digest_mismatch` and `revoked` for
    /// attack-shaped spikes. An outcome routed to the wrong counter, or to no
    /// counter at all, does not make verification fail — it makes a rejection
    /// stop being visible, which is the failure this rung exists to prevent.
    ///
    /// Deleting any one arm of the match sends that outcome to the defensive
    /// `_` branch, which warns and bumps nothing. Every arm survived that
    /// deletion because nothing asserted the routing.
    #[test]
    fn each_verify_outcome_bumps_its_own_counter_and_no_other() {
        let _env = TestEnv::new();
        for (index, outcome) in [
            "sig_invalid",
            "digest_mismatch",
            "version_skew",
            "revoked",
            "expired",
            "network",
        ]
        .iter()
        .enumerate()
        {
            let before = verify_counters();
            bump_verify_outcome(outcome);
            let after = verify_counters();
            for (slot, (b, a)) in before.iter().zip(after.iter()).enumerate() {
                let expected = if slot == index { b + 1 } else { *b };
                assert_eq!(
                    *a, expected,
                    "outcome '{outcome}' moved counter slot {slot} from {b} to {a}"
                );
            }
        }
    }

    /// An unknown outcome bumps nothing rather than landing on a neighbour.
    ///
    /// The `_` arm is the reason a deleted match arm is silent, so it is also
    /// the thing that has to be checked directly: the guarantee is that an
    /// unroutable outcome is dropped, not that it is quietly counted as
    /// something else.
    #[test]
    fn an_unknown_verify_outcome_bumps_nothing() {
        let _env = TestEnv::new();
        let before = verify_counters();
        bump_verify_outcome("not_an_outcome");
        assert_eq!(verify_counters(), before);
    }

    /// Only security-relevant outcomes reach the audit log.
    ///
    /// The split is deliberate and the two channels are not interchangeable:
    /// the counter alerts, the audit line is the forensics record. `network`
    /// is operational — a flaky download is not evidence of anything — so it
    /// is counted and not recorded, while every other outcome is both.
    ///
    /// Inverting the guard survived, which would file every failed download as
    /// a security event and file no actual rejection at all.
    #[test]
    fn only_security_outcomes_are_written_to_the_audit_log() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let log = std::path::PathBuf::from(mvm_core::policy::audit::default_audit_log());

        bump_verify_outcome("network");
        let after_network = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            !after_network.contains("ImageVerifyFailed"),
            "an operational network failure is not a security event: {after_network}"
        );

        bump_verify_outcome("revoked");
        let after_revoked = std::fs::read_to_string(&log)
            .expect("a security-relevant rejection must be recorded for forensics");
        assert!(
            after_revoked.contains("outcome=revoked"),
            "the audit line must name the outcome: {after_revoked}"
        );
    }

    /// A manifest line is a digest only if it is 64 characters *and* hex.
    ///
    /// This map is the pin every downloaded artifact is then held to, so a
    /// line admitted into it is a digest mvm will trust. Relaxing the
    /// conjunction to a disjunction survived: it would admit a 64-character
    /// run of anything, and any length of hex, as a pinned SHA-256. A
    /// truncated digest that still "matches" a truncated computation is the
    /// shape that turns a hash pin into a formality.
    ///
    /// The valid line is present so the test cannot pass by rejecting
    /// everything.
    #[test]
    fn a_manifest_digest_needs_both_the_length_and_the_alphabet() {
        let mut env = TestEnv::new();
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        let good = "a".repeat(64);
        let body = format!(
            "{good}  well-formed\n\
             {}  right-length-wrong-alphabet\n\
             {}  right-alphabet-wrong-length\n",
            "z".repeat(64),
            "b".repeat(63),
        );
        let (_dir, base_url) = stage_manifest(&body);

        let map = fetch_expected_hashes(&manifest(&base_url), &["well-formed"])
            .expect("the well-formed line must be admitted");
        assert_eq!(map.get("well-formed"), Some(&good));

        for rejected in ["right-length-wrong-alphabet", "right-alphabet-wrong-length"] {
            assert!(
                !map.contains_key(rejected),
                "'{rejected}' is not a SHA-256 digest and must not become a pin"
            );
            let err = fetch_expected_hashes(&manifest(&base_url), &[rejected])
                .expect_err("asking for a malformed entry must refuse")
                .to_string();
            assert!(
                err.contains("did not include"),
                "the refusal must say the entry is absent: {err}"
            );
        }
    }

    /// The manifest is the trust anchor for every digest under it, so an
    /// unsigned one must be refused with nothing read out of it. The staged
    /// manifest is also missing the wanted entry: if the signature rung ever
    /// moves after the parse, this fails with a "did not include" error and
    /// says so.
    #[test]
    fn fetch_expected_hashes_refuses_an_unsigned_manifest_before_parsing() {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let (_dir, base_url) = stage_manifest(&format!("{}  some-other-file\n", "d".repeat(64)));

        let err = fetch_expected_hashes(&manifest(&base_url), &["dev-vmlinux-x86_64"])
            .unwrap_err()
            .to_string();

        assert!(
            !err.contains("did not include"),
            "the signature rung must refuse before the manifest is parsed: {err}"
        );
        assert!(
            err.contains("unauthenticated checksum manifest"),
            "the refusal must name the reason: {err}"
        );
    }

    /// The two hatches are independent by design: waiving the digest check is
    /// a smaller concession than waiving the publisher check, so it must not
    /// silently grant the larger one.
    #[test]
    fn skip_hash_verify_does_not_waive_the_manifest_signature() {
        let mut env = TestEnv::new();
        env.set("MVM_SKIP_HASH_VERIFY", "1");
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let (_dir, base_url) = stage_manifest(&format!("{}  dev-vmlinux-x86_64\n", "e".repeat(64)));

        let err = fetch_expected_hashes(&manifest(&base_url), &["dev-vmlinux-x86_64"])
            .expect_err("an unsigned manifest must be refused whatever the hash hatch says")
            .to_string();

        assert!(
            err.contains("unauthenticated checksum manifest"),
            "MVM_SKIP_HASH_VERIFY must not reach the signature rung: {err}"
        );
    }

    /// The converse: waiving the publisher check admits the manifest but
    /// leaves every digest in it binding.
    #[test]
    fn skip_cosign_verify_admits_the_manifest_but_keeps_the_hash_pin() {
        let mut env = TestEnv::new();
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        env.remove("MVM_SKIP_HASH_VERIFY");
        let artifact_name = "dev-vmlinux-x86_64";
        let pinned = hex_sha256(b"the published bytes");
        let (_dir, base_url) = stage_manifest(&format!("{pinned}  {artifact_name}\n"));

        let expected = fetch_expected_hashes(&manifest(&base_url), &[artifact_name])
            .expect("the escape hatch must admit an unsigned manifest");

        let local = tempfile::tempdir().unwrap();
        let path = local.path().join(artifact_name);
        std::fs::write(&path, b"substituted bytes").unwrap();
        let err = verify_artifact_hash(
            path.to_str().unwrap(),
            artifact_name,
            expected.get(artifact_name),
        )
        .expect_err("the digest pin must still bind")
        .to_string();
        assert!(err.contains("Integrity check failed"), "{err}");
    }
}
