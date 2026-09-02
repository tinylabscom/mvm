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
//! booted: map `fingerprint -> ActionCacheRecord` (the revision plus
//! every artifact's sha256 + size), and on the next `up` resolve the
//! fingerprint host-side, verify the record against what is actually on
//! disk, and reuse the already-materialised `~/.mvm/dev/builds/<revision>/`
//! artifacts only when it checks out.
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
//! included-file change. The fingerprint therefore has to cover everything
//! that filter admits.
//!
//! The safe direction is one-way: hashing a *superset* of nix's inputs only
//! costs a redundant rebuild, while hashing too few serves a stale image. Two
//! bindings keep us on the safe side of that line, and they point in opposite
//! directions because the nix filter admits by top-level entry and prunes by
//! basename:
//!
//!   - [`INCLUDED_TOP_LEVEL`] must be a **superset** of the filter's
//!     `includedTopLevel` — a top-level dir nix feeds into the build that we
//!     skip would go unhashed.
//!   - [`EXCLUDED_BASENAMES`] must be a **subset** of the filter's
//!     `excludedBasenames` — a basename we prune that nix keeps would likewise
//!     go unhashed.
//!
//! Both are enforced against the real `workspace-filter.nix` by tests below.
//!
//! The top-level allow-list only applies to the mvm workspace, which is the
//! tree that filter governs. A user flake is an arbitrary project directory
//! that nix ingests whole, so it keeps the conservative deny-list-only walk.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::action::ActionCacheRecord;
use sha2::{Digest, Sha256};

use super::BuildMode;

/// Which tree a walk is covering. The mvm workspace is the one
/// `nix/lib/workspace-filter.nix` governs, so only that walk applies the
/// top-level allow-list; a user flake is an arbitrary project directory nix
/// ingests whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeScope {
    /// An arbitrary user project directory. Walk everything, minus
    /// [`EXCLUDED_BASENAMES`].
    UserFlake,
    /// The mvm workspace root. Walk only [`INCLUDED_TOP_LEVEL`].
    MvmWorkspace,
}

/// Top-level workspace entries the fingerprint walks.
///
/// Bound to `includedTopLevel` in `nix/lib/workspace-filter.nix`: this list
/// MUST stay a **superset** of that one. Admitting more than nix does is
/// merely conservative (we hash files nix drops and occasionally rebuild when
/// nix would have cached); admitting fewer is unsound — we would skip a tree
/// nix feeds into the build and serve a stale image.
///
/// Everything outside this set — docs, the site, language SDK surfaces, BDD
/// features, examples, scripts — cannot reach a compiled target, so editing it
/// no longer busts the build cache.
const INCLUDED_TOP_LEVEL: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "build.rs",
    "src",
    "crates",
    "third_party",
    "xtask",
    "tests",
    "third_party",
    "schema",
    "nix",
    ".github",
];

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
#[tracing::instrument(skip_all, fields(user_flake = %user_flake.display(), mode = ?mode))]
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
        hash_source_tree(user_flake, TreeScope::UserFlake)
            .with_context(|| format!("hashing user flake at {}", user_flake.display()))?
            .as_bytes(),
    );

    // The workspace covers both `path:/work/nix` and `path:$MVM_SRC`
    // (nix/ is a subtree of the workspace root).
    let workspace_digest = match mvm_workspace {
        Some(ws) => hash_source_tree(ws, TreeScope::MvmWorkspace)
            .with_context(|| format!("hashing mvm workspace at {}", ws.display()))?,
        None => "no-workspace".to_string(),
    };
    fold_field(
        &mut hasher,
        "mvm-workspace-tree",
        workspace_digest.as_bytes(),
    );

    Ok(hex::encode(hasher.finalize()))
}

/// Directory holding `fingerprint -> ActionCacheRecord` cache records
/// (`~/.mvm/dev/build-cache/`). `pub(crate)` so sibling-module tests can
/// assert directly against the on-disk record path rather than
/// reconstructing it.
pub(crate) fn build_cache_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("dev")
        .join("build-cache")
}

/// Look up the typed cache record a previous build wrote for
/// `fingerprint`, or `None` if there is no record, it is unreadable,
/// it fails to JSON-parse (including a legacy plaintext `<revision>\n`
/// record from before this cache carried typed records), or its
/// `revision` can't be trusted as a build-dir path component. Never
/// returns a record whose `action_digest` doesn't match the key it was
/// looked up under. This lookup alone does not verify the record's
/// artifacts against disk — callers do that via
/// `mvm_core::action::verify_artifacts_on_disk`.
pub fn read_cache_record(fingerprint: &str) -> Option<ActionCacheRecord> {
    read_cache_record_in(&build_cache_dir(), fingerprint)
}

/// Record `fingerprint -> record` so the next build with the same
/// inputs can skip the builder VM. Best-effort and atomic (temp +
/// rename) so a concurrent reader never sees a torn record.
pub fn write_cache_record(fingerprint: &str, record: &ActionCacheRecord) -> Result<()> {
    write_cache_record_in(&build_cache_dir(), fingerprint, record)
}

/// Delete a stale cache record after verification against disk failed.
/// Best-effort: an unwritable cache dir just means the entry keeps
/// failing verification (and getting evicted again) on every future
/// lookup, never that a bad entry is served.
pub fn evict_cache_record(fingerprint: &str) {
    evict_cache_record_in(&build_cache_dir(), fingerprint);
}

fn read_cache_record_in(dir: &Path, fingerprint: &str) -> Option<ActionCacheRecord> {
    if !is_safe_component(fingerprint) {
        return None;
    }
    let raw = std::fs::read_to_string(dir.join(fingerprint)).ok()?;
    let record: ActionCacheRecord = serde_json::from_str(&raw).ok()?;
    if record.action_digest.as_str() != fingerprint {
        return None;
    }
    // The revision becomes a `~/.mvm/dev/builds/<rev>/` path component;
    // reject anything that isn't a plain store-hash token.
    is_safe_component(&record.revision).then_some(record)
}

fn write_cache_record_in(dir: &Path, fingerprint: &str, record: &ActionCacheRecord) -> Result<()> {
    anyhow::ensure!(
        is_safe_component(fingerprint) && is_safe_component(&record.revision),
        "refusing to write build-cache record with unsafe key/revision"
    );
    anyhow::ensure!(
        record.action_digest.as_str() == fingerprint,
        "refusing to write build-cache record whose action_digest doesn't match its key"
    );
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating build-cache dir {}", dir.display()))?;
    let final_path = dir.join(fingerprint);
    let tmp = dir.join(format!(".{}.{}.tmp", fingerprint, std::process::id()));
    let json = serde_json::to_string(record).with_context(|| "serializing build-cache record")?;
    std::fs::write(&tmp, json)
        .with_context(|| format!("writing build-cache temp {}", tmp.display()))?;
    std::fs::rename(&tmp, &final_path)
        .with_context(|| format!("renaming build-cache record into {}", final_path.display()))?;
    Ok(())
}

fn evict_cache_record_in(dir: &Path, fingerprint: &str) {
    if !is_safe_component(fingerprint) {
        return;
    }
    let _ = std::fs::remove_file(dir.join(fingerprint));
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
fn hash_source_tree(root: &Path, scope: TreeScope) -> Result<String> {
    let files = walk_source_files_sorted(root, scope)
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
    Ok(hex::encode(hasher.finalize()))
}

/// Recursively collect regular-file paths under `root`, sorted, skipping
/// any directory or file whose basename is in [`EXCLUDED_BASENAMES`].
/// Sorted output makes the walk order — and thus the fingerprint —
/// independent of filesystem enumeration order.
///
/// Under [`TreeScope::MvmWorkspace`] the walk starts from
/// [`INCLUDED_TOP_LEVEL`] rather than from `root`'s full listing, mirroring
/// the nix filter's allow-list. An entry named there but absent on disk is
/// skipped silently: the list is a superset of the filter's by construction,
/// so a missing one means nix has nothing to ingest either.
fn walk_source_files_sorted(root: &Path, scope: TreeScope) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    match scope {
        TreeScope::UserFlake => collect_files(root, &mut out)?,
        TreeScope::MvmWorkspace => {
            // Keep the "a missing root is an error, never a silent empty
            // hash" contract: without this, an unreadable workspace would
            // skip every allow-listed entry and fingerprint as empty.
            anyhow::ensure!(
                root.is_dir(),
                "mvm workspace {} is not a readable directory",
                root.display()
            );
            for entry in INCLUDED_TOP_LEVEL {
                let path = root.join(entry);
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_dir() {
                    collect_files(&path, &mut out)?;
                } else if meta.is_file() {
                    out.push(path);
                }
            }
        }
    }
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
        write(ws.path(), "crates/mvm-agentd/src/lib.rs", "fn main() {}");

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
        write(ws.path(), "crates/mvm-agentd/src/lib.rs", "fn a() {}");

        let before =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        write(ws.path(), "crates/mvm-agentd/src/lib.rs", "fn b() {}");
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

    /// Read the workspace root above `crates/mvm-build`.
    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root above crates/mvm-build")
            .to_path_buf()
    }

    /// Extract the quoted entries of a named Nix list (`<name> = [ ... ];`)
    /// out of `workspace-filter.nix`. Both bindings live in the same file, so
    /// a whole-file substring search would let an entry in one list satisfy a
    /// claim about the other.
    fn nix_filter_list(name: &str) -> Vec<String> {
        let path = workspace_root().join("nix/lib/workspace-filter.nix");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let start = body
            .find(&format!("{name} = ["))
            .unwrap_or_else(|| panic!("{name} list not found in {}", path.display()));
        let rest = &body[start..];
        let end = rest
            .find(']')
            .unwrap_or_else(|| panic!("{name} list is unterminated in {}", path.display()));
        rest[..end]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn included_top_level_is_a_superset_of_the_nix_filter_allowlist() {
        // Soundness binding, allow-list direction: a top-level entry nix feeds
        // into the build that we do NOT walk goes unhashed, so a change to it
        // would serve a stale image. We may walk more than nix admits — that
        // only costs a redundant rebuild.
        let nix_included = nix_filter_list("includedTopLevel");
        assert!(
            !nix_included.is_empty(),
            "parsed an empty includedTopLevel — the parser or the nix file drifted"
        );
        for entry in &nix_included {
            assert!(
                INCLUDED_TOP_LEVEL.contains(&entry.as_str()),
                "workspace-filter.nix admits top-level {entry:?}, which INCLUDED_TOP_LEVEL does \
                 not walk — that is unsound (nix would feed it into the build but the \
                 fingerprint would not see it change). Add it here or drop it from the filter."
            );
        }
    }

    #[test]
    fn excluded_basenames_are_a_subset_of_the_nix_workspace_filter() {
        // Soundness binding, deny-list direction: pruning a basename that
        // `workspace-filter.nix` keeps would skip a file nix feeds into the
        // build. We may prune fewer — that's safe.
        let nix_excluded = nix_filter_list("excludedBasenames");
        assert!(
            !nix_excluded.is_empty(),
            "parsed an empty excludedBasenames — the parser or the nix file drifted"
        );
        for base in EXCLUDED_BASENAMES {
            assert!(
                nix_excluded.iter().any(|e| e == base),
                "EXCLUDED_BASENAMES contains {base:?}, which workspace-filter.nix does not \
                 exclude — that is unsound (nix would feed it into the build). Remove it here \
                 or add it to the nix filter."
            );
        }
    }

    #[test]
    fn documentation_only_workspace_change_does_not_move_the_fingerprint() {
        // The point of the allow-list. Editing a spec, a doc page, an SDK
        // surface, a BDD feature, or an example cannot reach a compiled
        // target, so it must not invalidate the build cache.
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{}");
        let ws = tempfile::tempdir().unwrap();
        write(ws.path(), "crates/mvm-agentd/src/lib.rs", "fn a() {}");
        write(ws.path(), "specs/plans/1-thing.md", "before");

        let before =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        write(
            ws.path(),
            "specs/plans/1-thing.md",
            "after — a whole new plan",
        );
        write(ws.path(), "public/docs/guide.md", "new page");
        write(ws.path(), "sdks/python/README.md", "docs");
        write(ws.path(), "features/s9_kernel_pin.feature", "Scenario: x");
        write(ws.path(), "examples/python/hello/app.py", "print(1)");
        let after =
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                .unwrap();
        assert_eq!(
            before, after,
            "a documentation-only workspace change must not bust the build cache"
        );
    }

    #[test]
    fn every_walked_top_level_entry_still_moves_the_fingerprint() {
        // The converse guard: each allow-listed entry must actually be walked.
        // A typo in INCLUDED_TOP_LEVEL would silently stop hashing a real
        // input, which is the stale-image failure mode.
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{}");

        for entry in INCLUDED_TOP_LEVEL {
            let ws = tempfile::tempdir().unwrap();
            write(ws.path(), "crates/anchor/src/lib.rs", "fn anchor() {}");
            let rel = if entry.ends_with(".toml") || entry.ends_with(".rs") {
                (*entry).to_string()
            } else {
                format!("{entry}/probe.txt")
            };
            write(ws.path(), &rel, "before");
            let before =
                workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                    .unwrap();
            write(ws.path(), &rel, "after");
            let after =
                workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(ws.path()))
                    .unwrap();
            assert_ne!(
                before, after,
                "a change under {entry:?} must move the fingerprint"
            );
        }
    }

    #[test]
    fn missing_workspace_is_an_error_not_an_empty_hash() {
        // Regression guard for the allow-list walk: iterating a fixed entry
        // list over a nonexistent root must not silently produce the
        // "everything absent" digest.
        let flake = tempfile::tempdir().unwrap();
        write(flake.path(), "flake.nix", "{}");
        let missing = Path::new("/nonexistent/mvm-workspace-does-not-exist");
        assert!(
            workload_build_fingerprint(flake.path(), None, BuildMode::Prod, Some(missing)).is_err()
        );
    }

    fn sample_cache_record(fingerprint: &str, revision: &str) -> ActionCacheRecord {
        ActionCacheRecord {
            action_digest: mvm_core::action::ActionDigest::from_fingerprint_hex(fingerprint)
                .expect("test fingerprint must be valid 64-hex"),
            revision: revision.to_string(),
            artifacts: vec![mvm_core::action::ArtifactDigest {
                path: "rootfs.ext4".to_string(),
                sha256: mvm_core::packs::Sha256Hex::from_bytes(b"rootfs bytes"),
                size_bytes: 12,
            }],
        }
    }

    #[test]
    fn cache_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let fp = "a".repeat(64);
        assert_eq!(read_cache_record_in(dir.path(), &fp), None, "absent → None");
        let record = sample_cache_record(&fp, "l6fjg21gfazc98635yr2zjcfxm6ykilk");
        write_cache_record_in(dir.path(), &fp, &record).unwrap();
        assert_eq!(read_cache_record_in(dir.path(), &fp), Some(record));
    }

    #[test]
    fn cache_record_rejects_unsafe_revision_on_read() {
        // A tampered record must never become a path component, even
        // though the JSON parses fine.
        let dir = tempfile::tempdir().unwrap();
        let fp = "b".repeat(64);
        let mut record = sample_cache_record(&fp, "placeholder");
        record.revision = "../../etc/passwd".to_string();
        let json = serde_json::to_string(&record).unwrap();
        std::fs::write(dir.path().join(&fp), json).unwrap();
        assert_eq!(read_cache_record_in(dir.path(), &fp), None);
    }

    #[test]
    fn cache_record_rejects_mismatched_action_digest_on_read() {
        // A record filed under one fingerprint but carrying another
        // action_digest is a sign of a corrupted or spoofed cache dir;
        // the key must match the recorded digest.
        let dir = tempfile::tempdir().unwrap();
        let fp = "c".repeat(64);
        let other_digest = "d".repeat(64);
        let record = sample_cache_record(&other_digest, "rev-1");
        let json = serde_json::to_string(&record).unwrap();
        std::fs::write(dir.path().join(&fp), json).unwrap();
        assert_eq!(read_cache_record_in(dir.path(), &fp), None);
    }

    #[test]
    fn legacy_plaintext_record_fails_to_parse_on_read() {
        // Pre-typed-record cache entries were a bare `<revision>\n`
        // marker; that is not valid JSON, so it must read back as a
        // cold miss rather than a partially-trusted value.
        let dir = tempfile::tempdir().unwrap();
        let fp = "e".repeat(64);
        std::fs::write(dir.path().join(&fp), "l6fjg21gfazc98635yr2zjcfxm6ykilk\n").unwrap();
        assert_eq!(read_cache_record_in(dir.path(), &fp), None);
    }

    #[test]
    fn cache_record_write_refuses_unsafe_key() {
        let dir = tempfile::tempdir().unwrap();
        let fp = "f".repeat(64);
        let record = sample_cache_record(&fp, "rev");
        assert!(write_cache_record_in(dir.path(), "../escape", &record).is_err());
    }

    #[test]
    fn cache_record_write_refuses_mismatched_action_digest() {
        let dir = tempfile::tempdir().unwrap();
        let fp = "1".repeat(64);
        let other_digest = "2".repeat(64);
        let record = sample_cache_record(&other_digest, "rev");
        assert!(write_cache_record_in(dir.path(), &fp, &record).is_err());
    }

    #[test]
    fn evict_removes_an_existing_record() {
        let dir = tempfile::tempdir().unwrap();
        let fp = "3".repeat(64);
        let record = sample_cache_record(&fp, "rev-1");
        write_cache_record_in(dir.path(), &fp, &record).unwrap();
        assert!(read_cache_record_in(dir.path(), &fp).is_some());

        evict_cache_record_in(dir.path(), &fp);
        assert!(read_cache_record_in(dir.path(), &fp).is_none());
        assert!(!dir.path().join(&fp).exists());
    }

    #[test]
    fn evict_is_a_no_op_when_no_record_exists() {
        let dir = tempfile::tempdir().unwrap();
        let fp = "4".repeat(64);
        // Must not panic or error when there is nothing to evict.
        evict_cache_record_in(dir.path(), &fp);
    }
}
