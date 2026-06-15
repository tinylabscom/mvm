//! Host-side workload-flake build cache.
//!
//! `mvmctl up --flake` runs `nix build` inside a builder VM on every
//! invocation. Even when the resulting image is byte-identical to the
//! previous run, the build leg pays the full builder-VM boot + nix
//! evaluation (~tens of seconds) just to rediscover the cache hit —
//! because the cache key is the nix revision, and the revision is only
//! knowable *after* the eval produces a store path.
//!
//! This module computes a **host-side input fingerprint** so an
//! unchanged build can be short-circuited before the builder VM is ever
//! booted: map `fingerprint -> revision_hash`, and on the next `up`
//! resolve the fingerprint host-side and reuse the already-materialised
//! `~/.mvm/dev/builds/<revision>/` artifacts.
//!
//! ## Soundness (the stale-image footgun)
//!
//! A missed input means a contributor's change is silently ignored and a
//! stale image boots. The build's nix inputs are three `path:` inputs the
//! builder VM mounts under `--impure`:
//!   - the user flake dir (`path:/work`),
//!   - the in-repo `nix/` flake (`path:/work/nix`), and
//!   - the workspace the guest agent is `buildRustPackage`'d from
//!     (`path:$MVM_SRC`, == the workspace root, filtered by
//!     `nix/lib/workspace-filter.nix`).
//!
//! `buildRustPackage { src = mvmSrc; }` derives its output path from the
//! *whole* filtered source NAR, so the nix revision changes on **any**
//! included-file change. The fingerprint therefore hashes the entire
//! workspace tree with the same basename excludes as
//! `workspace-filter.nix`. Hashing a *superset* of nix's inputs is always
//! sound (we bust the cache at least as often as nix would); the only
//! unsound move is excluding a basename nix includes, so [`EXCLUDED_BASENAMES`]
//! must stay a subset of the nix filter's excludes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::BuildMode;

/// Directory basenames excluded from the source fingerprint.
///
/// Bound to `nix/lib/workspace-filter.nix`: this list MUST stay a subset
/// of the basenames that filter excludes. Excluding more than nix does is
/// unsound (we would skip a file nix feeds into the build and serve a
/// stale image); excluding fewer is merely conservative (we hash some
/// files nix ignores and occasionally rebuild when nix would have cached).
/// We deliberately omit a handful of nix's excludes (e.g. `keys`) to keep
/// the binding obviously safe — the cost is a redundant rebuild, never a
/// stale image. `target`/`.build`/`node_modules`/`.git` are the heavy
/// dirs whose exclusion actually matters for walk speed.
const EXCLUDED_BASENAMES: &[&str] = &[
    "target",
    "result",
    "node_modules",
    ".direnv",
    ".cargo",
    "dist",
    ".astro",
    ".build",
    "dev-prebuilt",
    ".mvm-test",
    "graphify-out",
    ".git",
    ".claude",
    ".worktrees",
    ".playwright-mcp",
];

/// Compute the host-side fingerprint of every input the workload nix
/// build reads. `None` for `mvm_workspace` is the non-source-checkout
/// case (the user flake pins `mvm` to a published ref, recorded in its
/// own `flake.lock`, so the user flake hash alone covers it).
pub fn workload_build_fingerprint(
    user_flake: &Path,
    profile: Option<&str>,
    mode: BuildMode,
    mvm_workspace: Option<&Path>,
) -> Result<String> {
    let mut hasher = Sha256::new();

    // Salt with a scheme tag so the digest can't collide with an
    // unrelated sha256 the cache layer might key on later.
    hasher.update(b"mvm-workload-build-fingerprint-v1\0");

    fold_field(
        &mut hasher,
        "profile",
        profile.unwrap_or("default").as_bytes(),
    );
    fold_field(&mut hasher, "mode", build_mode_tag(mode).as_bytes());
    // The mvmctl version gates the embedded host bins + any build-pipeline
    // change shipped with a new binary; fold it so a CLI upgrade re-evals.
    fold_field(&mut hasher, "mvmctl", env!("CARGO_PKG_VERSION").as_bytes());

    fold_field(
        &mut hasher,
        "user-flake-tree",
        hash_source_tree(user_flake)
            .with_context(|| format!("hashing user flake at {}", user_flake.display()))?
            .as_bytes(),
    );

    // The workspace covers both `path:/work/nix` and `path:$MVM_SRC`
    // (nix/ is a subtree of the workspace root).
    let workspace_digest = match mvm_workspace {
        Some(ws) => hash_source_tree(ws)
            .with_context(|| format!("hashing mvm workspace at {}", ws.display()))?,
        None => "no-workspace".to_string(),
    };
    fold_field(
        &mut hasher,
        "mvm-workspace-tree",
        workspace_digest.as_bytes(),
    );

    Ok(format!("{:x}", hasher.finalize()))
}

/// Directory holding `fingerprint -> revision` cache records
/// (`~/.mvm/dev/build-cache/`).
fn build_cache_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("dev")
        .join("build-cache")
}

/// Look up the nix revision a previous build recorded for `fingerprint`,
/// or `None` if there is no record (or it is unreadable / malformed).
/// Never returns a value that can't be a safe build-dir component.
pub fn read_cached_revision(fingerprint: &str) -> Option<String> {
    read_cached_revision_in(&build_cache_dir(), fingerprint)
}

/// Record `fingerprint -> revision` so the next build with the same
/// inputs can skip the builder VM. Best-effort and atomic (temp +
/// rename) so a concurrent reader never sees a torn record.
pub fn write_cached_revision(fingerprint: &str, revision: &str) -> Result<()> {
    write_cached_revision_in(&build_cache_dir(), fingerprint, revision)
}

fn read_cached_revision_in(dir: &Path, fingerprint: &str) -> Option<String> {
    if !is_safe_component(fingerprint) {
        return None;
    }
    let raw = std::fs::read_to_string(dir.join(fingerprint)).ok()?;
    let rev = raw.trim();
    // The revision becomes a `~/.mvm/dev/builds/<rev>/` path component;
    // reject anything that isn't a plain store-hash token.
    is_safe_component(rev).then(|| rev.to_string())
}

fn write_cached_revision_in(dir: &Path, fingerprint: &str, revision: &str) -> Result<()> {
    anyhow::ensure!(
        is_safe_component(fingerprint) && is_safe_component(revision),
        "refusing to write build-cache record with unsafe key/value"
    );
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating build-cache dir {}", dir.display()))?;
    let final_path = dir.join(fingerprint);
    let tmp = dir.join(format!(".{}.{}.tmp", fingerprint, std::process::id()));
    std::fs::write(&tmp, format!("{revision}\n"))
        .with_context(|| format!("writing build-cache temp {}", tmp.display()))?;
    std::fs::rename(&tmp, &final_path)
        .with_context(|| format!("renaming build-cache record into {}", final_path.display()))?;
    Ok(())
}

/// A token safe to use as a single path component: non-empty, no path
/// separators, no whitespace, ASCII alphanumeric plus `-`/`_`/`.` (the
/// charset of our hex fingerprints and nix store hashes). Guards the
/// build-dir reconstruction against traversal via a tampered record.
fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && s != "."
        && s != ".."
}

/// Stable tag for a [`BuildMode`] discriminant. A dev image and a prod
/// image of the same source are different nix outputs, so they must not
/// share a fingerprint.
fn build_mode_tag(mode: BuildMode) -> &'static str {
    match mode {
        BuildMode::Dev => "dev",
        BuildMode::Prod => "prod",
    }
}

/// Fold one length-delimited, domain-tagged field into the hasher so two
/// fields can never run together ambiguously.
fn fold_field(hasher: &mut Sha256, tag: &str, value: &[u8]) {
    hasher.update(tag.as_bytes());
    hasher.update(b"\0");
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(value);
    hasher.update(b"\0");
}

/// Content-hash every regular file under `root`, deterministically,
/// applying [`EXCLUDED_BASENAMES`]. Each file folds in as
/// `<relpath>\0<len>\0<bytes>` so a rename, a resize, or a content edit
/// all move the digest. A missing `root` is an error — the caller decides
/// what a missing input means (it never silently hashes to empty).
fn hash_source_tree(root: &Path) -> Result<String> {
    let files = walk_source_files_sorted(root)
        .with_context(|| format!("walking source tree {}", root.display()))?;
    let mut hasher = Sha256::new();
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading source file {}", path.display()))?;
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Recursively collect regular-file paths under `root`, sorted, skipping
/// any directory or file whose basename is in [`EXCLUDED_BASENAMES`].
/// Sorted output makes the walk order — and thus the fingerprint —
/// independent of filesystem enumeration order.
fn walk_source_files_sorted(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_files(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let base = name.to_string_lossy();
        if EXCLUDED_BASENAMES.contains(&base.as_ref()) {
            continue;
        }
        let path = entry.path();
        let ftype = entry.file_type()?;
        if ftype.is_dir() {
            collect_files(&path, out)?;
        } else if ftype.is_file() {
            out.push(path);
        }
        // Symlinks are intentionally skipped: nix resolves flake inputs by
        // content, and a dangling/loop symlink must not abort the walk.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn fingerprint_is_deterministic_for_identical_inputs() {
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{ outputs = _: {}; }");
        let ws = tempfile::tempdir().unwrap();
        write(ws.path(), "crates/mvm-guest/src/lib.rs", "fn main() {}");

        let a = workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
            .unwrap();
        let b = workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "sha256 hex");
    }

    #[test]
    fn fingerprint_changes_when_workspace_source_changes() {
        // The footgun guard: the guest agent is buildRustPackage'd from
        // the workspace, so a crates/ edit MUST move the fingerprint or a
        // stale agent would be served.
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{ outputs = _: {}; }");
        let ws = tempfile::tempdir().unwrap();
        write(ws.path(), "crates/mvm-guest/src/lib.rs", "fn a() {}");

        let before =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        write(ws.path(), "crates/mvm-guest/src/lib.rs", "fn b() {}");
        let after =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn fingerprint_changes_when_user_flake_changes() {
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{ outputs = _: { a = 1; }; }");
        let ws = tempfile::tempdir().unwrap();
        write(ws.path(), "Cargo.lock", "lock");

        let before =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        write(flake.path(), "flake.nix", "{ outputs = _: { a = 2; }; }");
        let after =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn fingerprint_distinguishes_profile_and_mode() {
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{}");

        let base = workload_build_fingerprint(flake.path(), None, BuildMode::Prod, None).unwrap();
        let other_profile =
            workload_build_fingerprint(flake.path(), Some("worker"), BuildMode::Prod, None)
                .unwrap();
        let other_mode =
            workload_build_fingerprint(flake.path(), None, BuildMode::Dev, None).unwrap();
        assert_ne!(base, other_profile, "profile must affect the fingerprint");
        assert_ne!(base, other_mode, "dev vs prod must not share a fingerprint");
    }

    #[test]
    fn fingerprint_ignores_excluded_dirs() {
        // A change under an excluded basename (e.g. `target/`) must not
        // move the fingerprint — that's what keeps the walk fast and the
        // cache from busting on build-output churn.
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{}");
        let ws = tempfile::tempdir().unwrap();
        write(ws.path(), "crates/x/src/lib.rs", "fn x() {}");

        let before =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        write(ws.path(), "target/debug/junk", "lots of bytes");
        write(ws.path(), ".git/HEAD", "ref: refs/heads/x");
        let after =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        assert_eq!(
            before, after,
            "excluded dirs must not affect the fingerprint"
        );
    }

    #[test]
    fn excluded_basenames_are_a_subset_of_the_nix_workspace_filter() {
        // Soundness binding: excluding a basename that `workspace-filter.nix`
        // includes would skip a file nix feeds into the build and serve a
        // stale image. Read the nix filter and assert every basename we skip
        // is one the filter also skips. (We may skip fewer — that's safe.)
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root above crates/mvm-build");
        let filter = workspace_root.join("nix/lib/workspace-filter.nix");
        let body = std::fs::read_to_string(&filter)
            .unwrap_or_else(|e| panic!("reading {}: {e}", filter.display()));
        for base in EXCLUDED_BASENAMES {
            let quoted = format!("\"{base}\"");
            assert!(
                body.contains(&quoted),
                "EXCLUDED_BASENAMES contains {base:?}, which workspace-filter.nix does not \
                 exclude — that is unsound (nix would feed it into the build). Remove it here \
                 or add it to the nix filter."
            );
        }
    }

    #[test]
    fn cache_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let fp = "a".repeat(64);
        assert_eq!(
            read_cached_revision_in(dir.path(), &fp),
            None,
            "absent → None"
        );
        write_cached_revision_in(dir.path(), &fp, "l6fjg21gfazc98635yr2zjcfxm6ykilk").unwrap();
        assert_eq!(
            read_cached_revision_in(dir.path(), &fp).as_deref(),
            Some("l6fjg21gfazc98635yr2zjcfxm6ykilk")
        );
    }

    #[test]
    fn cache_record_rejects_unsafe_revision_on_read() {
        // A tampered record must never become a path component.
        let dir = tempfile::tempdir().unwrap();
        let fp = "b".repeat(64);
        std::fs::write(dir.path().join(&fp), "../../etc/passwd\n").unwrap();
        assert_eq!(read_cached_revision_in(dir.path(), &fp), None);
    }

    #[test]
    fn cache_record_write_refuses_unsafe_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write_cached_revision_in(dir.path(), "../escape", "rev").is_err());
    }
}
