//! How artifacts enter a cache root.
//!
//! Two conventions live here because both are shared by every cached
//! artifact (the builder VM image, the runtime overlay, the universal
//! initramfs) and both were previously reimplemented per artifact:
//!
//! 1. **The cross-root seed.** An isolated session (a worktree pointing
//!    `MVM_HOME` at a tempdir) can populate its own cache root from the
//!    host's shared one instead of rebuilding an expensive artifact. This
//!    module owns the only derivation of that shared root, so the set of
//!    places that can read `$HOME` while `MVM_HOME` is set stays exactly
//!    one — see the `check-test-home-isolation` gate.
//! 2. **The staging convention.** Installs stage into a sibling
//!    `<arch>.tmp.<pid>` directory and rename it into place, so a crash
//!    never leaves a half-written artifact where a resolver can find it.
//!    The flip side is that a killed install orphans its staging dir, so
//!    installers reap abandoned ones as they go.
//! 3. **Digest manifests.** Artifacts carry a `sha256sum`-format sidecar.
//!    Checking it belongs at admission — the one moment bytes cross into a
//!    cache root — and not on resolve, which runs on every VM start where
//!    re-hashing a multi-hundred-megabyte image is not affordable.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// The cache root of the *default* mvm home (`$HOME/.mvm/cache`),
/// deliberately ignoring the `MVM_HOME` override.
///
/// This is the single call site for that resolver in the whole workspace.
/// Keeping it here means a new cross-root seed is a visible change to this
/// module rather than a fresh `$HOME` read buried in an artifact module —
/// which matters because a test that isolates only `MVM_HOME` still reads
/// the developer's real cache through this path.
pub(crate) fn default_cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::default_mvm_cache_dir())
}

/// Populate `target_root` from `default_root` after a resolve miss.
///
/// Returns whether anything was installed, so the caller can retry its
/// resolve exactly once and otherwise surface its original error unchanged.
///
/// A miss in the *default* root is not an error — seeding is opportunistic,
/// and a host that has never built the artifact simply has nothing to give.
/// That is why `resolve_default` yields an `Option` rather than a `Result`:
/// the "nothing to seed" outcome is in the type instead of relying on every
/// caller to remember to swallow it. An `install` failure, by contrast, means
/// the target cache may be half-populated and does propagate.
pub(crate) fn seed_on_miss<S, E>(
    target_root: &Path,
    default_root: &Path,
    resolve_default: impl FnOnce(&Path) -> Option<S>,
    install: impl FnOnce(S) -> Result<(), E>,
) -> Result<bool, E> {
    if target_root == default_root {
        return Ok(false);
    }
    let Some(source) = resolve_default(default_root) else {
        return Ok(false);
    };
    install(source)?;
    Ok(true)
}

/// The `sha256sum`-format sidecar covering [`BUILDER_VM_CACHE_ARTIFACTS`].
pub const BUILDER_VM_ARTIFACT_DIGEST_FILE: &str = ".mvm-artifacts.sha256";

/// The artifacts a builder-VM cache directory must carry, and which the digest
/// sidecar commits to.
///
/// This lives here, rather than beside the builder code, because both sides of
/// a feature boundary need it: the seed in `libkrun_builder` is gated on
/// `builder-vm`, while the bootstrap readiness check also compiles under a
/// bare `test` cfg. One ungated list is the only way the two cannot disagree
/// about what a complete cache dir contains.
pub const BUILDER_VM_CACHE_ARTIFACTS: &[&str] =
    &["vmlinux", "rootfs.ext4", "cmdline.txt", "manifest.json"];

/// Integrity/provenance sidecars written next to the artifacts. Copied along
/// with them so a seeded cache stays verifiable, and so the bootstrap
/// readiness check recognises the seeded copy instead of rebuilding over it.
pub const BUILDER_VM_CACHE_SIDECARS: &[&str] = &[
    BUILDER_VM_ARTIFACT_DIGEST_FILE,
    ".mvm-provenance.json",
    ".mvm-source.sha256",
];

/// Recompute the `sha256sum`-format manifest covering `names` in `dir`.
///
/// Hashing streams via `mvm_fs`'s helper rather than reading each file whole:
/// one of these artifacts is a multi-hundred-megabyte rootfs.
pub fn digest_manifest(dir: &Path, names: &[&str]) -> std::io::Result<String> {
    let mut lines = Vec::with_capacity(names.len());
    for name in names {
        let digest = mvm_fs::overlay::compute_file_sha256(&dir.join(name))?;
        lines.push(format!("{digest}  {name}"));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

/// What comparing a recorded digest manifest against the bytes on disk found.
///
/// An enum rather than a bool because the two callers need different
/// branches: a seed treats a missing manifest as "nothing to check here" but
/// a drifted digest as "refuse", while the bootstrap readiness check reports
/// those as distinct reason codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestManifestCheck {
    /// Every named file matches the digest recorded for it.
    Match,
    /// No manifest exists at the expected path.
    ManifestAbsent,
    /// The manifest exists but records nothing for a required name.
    EntryAbsent { name: String },
    /// A file's bytes drifted from the digest the manifest committed to.
    Mismatch {
        name: String,
        expected: String,
        actual: String,
    },
    /// A named file could not be read to hash it.
    Unreadable { name: String, reason: String },
}

/// Compare `names` in `dir` against the manifest at `dir/manifest_file`.
///
/// Never returns `Err`: every failure mode is a variant the caller has to
/// decide about, and collapsing them into an io error loses the distinction
/// between "this cache predates the sidecar" and "these bytes changed".
pub fn verify_digest_manifest(
    dir: &Path,
    manifest_file: &str,
    names: &[&str],
) -> DigestManifestCheck {
    let Ok(body) = std::fs::read_to_string(dir.join(manifest_file)) else {
        return DigestManifestCheck::ManifestAbsent;
    };
    let recorded = mvm_fs::overlay::parse_checksums_manifest(&body);
    for name in names {
        let Some(expected) = recorded.get(*name) else {
            return DigestManifestCheck::EntryAbsent {
                name: (*name).to_string(),
            };
        };
        // Compare per-entry rather than whole-manifest strings so a reordered
        // or differently-terminated manifest is not mistaken for tampering.
        let actual = match mvm_fs::overlay::compute_file_sha256(&dir.join(name)) {
            Ok(actual) => actual,
            Err(e) => {
                return DigestManifestCheck::Unreadable {
                    name: (*name).to_string(),
                    reason: e.to_string(),
                };
            }
        };
        if &actual != expected {
            return DigestManifestCheck::Mismatch {
                name: (*name).to_string(),
                expected: expected.clone(),
                actual,
            };
        }
    }
    DigestManifestCheck::Match
}

/// Name of this process's staging directory for `arch`.
///
/// The pid disambiguates concurrent installs. Two installs in the same
/// process race on the post-staging rename, where the second one wins —
/// the same semantics as installing twice.
pub(crate) fn staging_dir_name(arch: &str) -> String {
    format!("{}.tmp.{}", arch, std::process::id())
}

/// How long an abandoned staging directory must sit before an install reaps
/// it. Staging is a handful of file copies, so anything this old belongs to a
/// process that died before its rename.
const STALE_STAGING_AGE: Duration = Duration::from_secs(6 * 60 * 60);

/// Remove staging directories for `arch` under `parent` that a previous run
/// abandoned.
///
/// Age is the liveness signal rather than the pid embedded in the name: a
/// portable pid check needs `libc` or `/proc`, and pid reuse makes it
/// unreliable in the one direction that matters. Judging by age can only ever
/// be wrong by leaving litter one cycle longer, never by deleting a live
/// install's staging directory.
///
/// Best-effort by design — reaping litter must never fail an install, so
/// every error here is dropped.
pub(crate) fn reap_stale_staging(parent: &Path, arch: &str) {
    reap_staging_older_than(parent, arch, STALE_STAGING_AGE);
}

/// The age threshold is a parameter so tests can drive the real selection
/// logic without backdating filesystem timestamps.
fn reap_staging_older_than(parent: &Path, arch: &str, max_age: Duration) {
    let ours = staging_dir_name(arch);
    let prefix = format!("{arch}.tmp.");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == ours || !name.starts_with(&prefix) {
            continue;
        }
        let abandoned = entry
            .metadata()
            .ok()
            .filter(|meta| meta.is_dir())
            .and_then(|meta| meta.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= max_age);
        if abandoned {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_on_miss_declines_when_target_is_the_default_root() {
        let mut installed = false;
        let seeded = seed_on_miss(
            Path::new("/same"),
            Path::new("/same"),
            |_| Some(()),
            |()| {
                installed = true;
                Ok::<(), ()>(())
            },
        )
        .unwrap();
        assert!(!seeded);
        assert!(!installed, "must not install into the root it reads from");
    }

    #[test]
    fn seed_on_miss_declines_when_the_default_root_has_nothing() {
        let seeded = seed_on_miss(
            Path::new("/target"),
            Path::new("/default"),
            |_| None::<()>,
            |()| Ok::<(), ()>(()),
        )
        .unwrap();
        assert!(!seeded, "a default-root miss is not an error");
    }

    #[test]
    fn seed_on_miss_installs_and_reports_success() {
        let mut seen = None;
        let seeded = seed_on_miss(
            Path::new("/target"),
            Path::new("/default"),
            |root| Some(root.to_path_buf()),
            |root| {
                seen = Some(root);
                Ok::<(), ()>(())
            },
        )
        .unwrap();
        assert!(seeded);
        assert_eq!(seen.as_deref(), Some(Path::new("/default")));
    }

    #[test]
    fn seed_on_miss_propagates_install_failure() {
        let result = seed_on_miss(
            Path::new("/target"),
            Path::new("/default"),
            |_| Some(()),
            |()| Err::<(), &str>("disk full"),
        );
        assert_eq!(result.unwrap_err(), "disk full");
    }

    fn artifact_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for (name, bytes) in files {
            std::fs::write(tmp.path().join(name), bytes).unwrap();
        }
        tmp
    }

    #[test]
    fn digest_manifest_emits_sha256sum_format_for_each_name() {
        let tmp = artifact_dir(&[("a", b"alpha"), ("b", b"beta")]);
        let manifest = digest_manifest(tmp.path(), &["a", "b"]).unwrap();

        let lines: Vec<&str> = manifest.trim_end().lines().collect();
        assert_eq!(lines.len(), 2);
        for (line, name) in lines.iter().zip(["a", "b"]) {
            let (hash, listed) = line.split_once("  ").expect("two-space separator");
            assert_eq!(listed, name);
            assert_eq!(hash.len(), 64, "{line}");
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "{line}");
        }
        assert!(manifest.ends_with('\n'));
    }

    #[test]
    fn verify_accepts_a_directory_matching_its_manifest() {
        let tmp = artifact_dir(&[("a", b"alpha"), ("b", b"beta")]);
        let manifest = digest_manifest(tmp.path(), &["a", "b"]).unwrap();
        std::fs::write(tmp.path().join("sums"), &manifest).unwrap();

        assert_eq!(
            verify_digest_manifest(tmp.path(), "sums", &["a", "b"]),
            DigestManifestCheck::Match
        );
    }

    #[test]
    fn verify_tolerates_a_reordered_manifest() {
        // The previous implementation compared whole manifest strings, so a
        // reordered-but-correct manifest read as tampering.
        let tmp = artifact_dir(&[("a", b"alpha"), ("b", b"beta")]);
        let forward = digest_manifest(tmp.path(), &["a", "b"]).unwrap();
        let reversed: Vec<&str> = forward.trim_end().lines().rev().collect();
        std::fs::write(
            tmp.path().join("sums"),
            format!("{}\n", reversed.join("\n")),
        )
        .unwrap();

        assert_eq!(
            verify_digest_manifest(tmp.path(), "sums", &["a", "b"]),
            DigestManifestCheck::Match
        );
    }

    #[test]
    fn verify_reports_an_absent_manifest_distinctly_from_drift() {
        let tmp = artifact_dir(&[("a", b"alpha")]);
        assert_eq!(
            verify_digest_manifest(tmp.path(), "sums", &["a"]),
            DigestManifestCheck::ManifestAbsent,
            "a cache predating the sidecar is not evidence of tampering"
        );
    }

    #[test]
    fn verify_detects_drifted_bytes() {
        let tmp = artifact_dir(&[("a", b"alpha")]);
        let manifest = digest_manifest(tmp.path(), &["a"]).unwrap();
        std::fs::write(tmp.path().join("sums"), &manifest).unwrap();
        std::fs::write(tmp.path().join("a"), b"tampered").unwrap();

        match verify_digest_manifest(tmp.path(), "sums", &["a"]) {
            DigestManifestCheck::Mismatch {
                name,
                expected,
                actual,
            } => {
                assert_eq!(name, "a");
                assert_ne!(expected, actual);
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_reports_a_name_the_manifest_does_not_cover() {
        let tmp = artifact_dir(&[("a", b"alpha"), ("b", b"beta")]);
        let manifest = digest_manifest(tmp.path(), &["a"]).unwrap();
        std::fs::write(tmp.path().join("sums"), &manifest).unwrap();

        assert_eq!(
            verify_digest_manifest(tmp.path(), "sums", &["a", "b"]),
            DigestManifestCheck::EntryAbsent {
                name: "b".to_string()
            }
        );
    }

    #[test]
    fn verify_reports_an_artifact_that_vanished() {
        let tmp = artifact_dir(&[("a", b"alpha")]);
        let manifest = digest_manifest(tmp.path(), &["a"]).unwrap();
        std::fs::write(tmp.path().join("sums"), &manifest).unwrap();
        std::fs::remove_file(tmp.path().join("a")).unwrap();

        assert!(matches!(
            verify_digest_manifest(tmp.path(), "sums", &["a"]),
            DigestManifestCheck::Unreadable { name, .. } if name == "a"
        ));
    }

    #[test]
    fn staging_dir_name_is_arch_scoped_and_pid_scoped() {
        let name = staging_dir_name("aarch64");
        assert!(name.starts_with("aarch64.tmp."));
        assert!(name.ends_with(&std::process::id().to_string()));
    }

    #[test]
    fn reap_leaves_fresh_and_foreign_dirs_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let ours = tmp.path().join(staging_dir_name("aarch64"));
        let fresh_other = tmp.path().join("aarch64.tmp.999999");
        let other_arch = tmp.path().join("x86_64.tmp.999999");
        let real = tmp.path().join("aarch64");
        for dir in [&ours, &fresh_other, &other_arch, &real] {
            std::fs::create_dir_all(dir).unwrap();
        }

        reap_stale_staging(tmp.path(), "aarch64");

        assert!(ours.is_dir(), "our own staging dir must survive");
        assert!(fresh_other.is_dir(), "a fresh orphan may still be in use");
        assert!(other_arch.is_dir(), "another arch is not ours to reap");
        assert!(
            real.is_dir(),
            "the installed artifact must never be touched"
        );
    }

    #[test]
    fn reap_removes_an_abandoned_staging_dir_with_its_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let stale = tmp.path().join("aarch64.tmp.999999");
        let ours = tmp.path().join(staging_dir_name("aarch64"));
        let real = tmp.path().join("aarch64");
        std::fs::create_dir_all(stale.join("nested")).unwrap();
        std::fs::write(stale.join("nested").join("overlay.ext4"), b"partial").unwrap();
        std::fs::create_dir_all(&ours).unwrap();
        std::fs::create_dir_all(&real).unwrap();

        // Everything is newly created, so a zero threshold makes every
        // candidate eligible — proving selection is by name, not by age alone.
        reap_staging_older_than(tmp.path(), "aarch64", Duration::ZERO);

        assert!(!stale.exists(), "an abandoned staging dir must be reaped");
        assert!(ours.is_dir(), "our own staging dir is never eligible");
        assert!(
            real.is_dir(),
            "the installed artifact must never be touched"
        );
    }

    #[test]
    fn the_shipped_threshold_spares_a_dir_that_was_just_created() {
        let tmp = tempfile::tempdir().unwrap();
        let fresh = tmp.path().join("aarch64.tmp.999999");
        std::fs::create_dir_all(&fresh).unwrap();

        reap_stale_staging(tmp.path(), "aarch64");

        assert!(
            fresh.is_dir(),
            "a concurrent install's staging dir must survive the real threshold"
        );
    }
}
