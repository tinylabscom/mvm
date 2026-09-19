//! A checkout's commit and working-tree state, read through `git`.
//!
//! Every invocation is pinned to the checkout it names: the ambient
//! `GIT_DIR`/`GIT_WORK_TREE` family is cleared, because a caller running under
//! a git hook (or any tool that exports them) would otherwise have `git -C`
//! silently answer for a different repository. Optional locks are disabled so
//! a probe never contends with a concurrent `git` in the same checkout.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use mvm_core::image_set::GitCommit;
pub use mvm_core::image_set::{RepoIdentity, WorktreeState};
use mvm_core::packs::Sha256Hex;
use sha2::{Digest, Sha256};

/// Environment `git` would otherwise use to address a repository other than
/// the one passed with `-C`.
const REPOSITORY_REDIRECT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
];

/// Read the identity of the checkout rooted at `root`: its commit, and whether
/// its files match it.
///
/// A dirty tree is fingerprinted over the status listing, the diff against
/// `HEAD`, and every untracked, non-ignored file. A locally built image set
/// records identities computed this way, and is compared against a fresh
/// reading, so the fingerprint is a wire format: the image repository's
/// manifest emitter computes it byte for byte the same way.
pub fn probe_identity(root: &Path) -> Result<RepoIdentity, String> {
    let head = git_text(root, ["rev-parse", "--verify", "HEAD^{commit}"])?;
    let commit = GitCommit::new(head).map_err(|e| e.to_string())?;
    Ok(RepoIdentity {
        commit,
        worktree: worktree_state(root)?,
    })
}

/// The top-level directory of the work tree containing `dir`.
pub fn toplevel(dir: &Path) -> Result<String, String> {
    git_text(dir, ["rev-parse", "--show-toplevel"])
}

/// The status listing a fingerprint covers. Renames are off so a
/// `status.renames` setting cannot change the bytes.
const STATUS_ARGS: [&str; 6] = [
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
    "--no-renames",
    "--ignore-submodules=none",
];

/// The diff a fingerprint covers, with every option that git configuration
/// could otherwise change spelled out: prefixes, rename detection, relative
/// paths, abbreviation, hunk shape, algorithm, submodules and file order.
/// Two hosts with different `diff.*` settings must fingerprint one tree the
/// same way, or a set built on one would read as stale on the other.
const DIFF_ARGS: [&str; 18] = [
    "diff",
    "HEAD",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--no-renames",
    "--no-relative",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--unified=3",
    "--inter-hunk-context=0",
    "--diff-algorithm=myers",
    "--indent-heuristic",
    "--ignore-submodules=none",
    "-O/dev/null",
    "--",
];

fn worktree_state(root: &Path) -> Result<WorktreeState, String> {
    let status = git_bytes(root, STATUS_ARGS)?;
    if status.is_empty() {
        return Ok(WorktreeState::Clean);
    }
    let mut hasher = Sha256::new();
    hash_section(&mut hasher, b"status", &status);
    let diff = git_bytes(root, DIFF_ARGS)?;
    hash_section(&mut hasher, b"diff", &diff);
    let untracked = git_bytes(root, ["ls-files", "--others", "--exclude-standard", "-z"])?;
    for name in untracked.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        hash_untracked(&mut hasher, root, name)?;
    }
    Ok(WorktreeState::Dirty {
        fingerprint: Sha256Hex::new(hex::encode(hasher.finalize())).map_err(|e| e.to_string())?,
    })
}

/// Length-prefixed, so no section's bytes can be read as another's.
fn hash_section(hasher: &mut Sha256, label: &[u8], body: &[u8]) {
    hasher.update(label);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
}

/// An untracked file contributes its name and what it is: a symlink its
/// target, a file its bytes. Nothing is followed, so a symlink pointing out of
/// the checkout fingerprints as the link rather than as what it points at.
fn hash_untracked(hasher: &mut Sha256, root: &Path, name: &[u8]) -> Result<(), String> {
    let path = root.join(bytes_as_path(name));
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| format!("reading untracked {}: {e}", path.display()))?;
    hash_section(hasher, b"path", name);
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&path)
            .map_err(|e| format!("reading untracked link {}: {e}", path.display()))?;
        hash_section(hasher, b"link", target.as_os_str().as_encoded_bytes());
    } else if meta.is_file() {
        let body = std::fs::read(&path)
            .map_err(|e| format!("reading untracked {}: {e}", path.display()))?;
        hash_section(hasher, b"file", &body);
    }
    Ok(())
}

#[cfg(unix)]
fn bytes_as_path(name: &[u8]) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(OsStr::from_bytes(name))
}

#[cfg(not(unix))]
fn bytes_as_path(name: &[u8]) -> std::path::PathBuf {
    std::path::PathBuf::from(String::from_utf8_lossy(name).into_owned())
}

fn git_text<const N: usize>(dir: &Path, args: [&str; N]) -> Result<String, String> {
    let out = git_bytes(dir, args)?;
    String::from_utf8(out)
        .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
        .map_err(|_| format!("git {} printed non-UTF-8 output", args.join(" ")))
}

fn git_bytes<const N: usize>(dir: &Path, args: [&str; N]) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0");
    for var in REPOSITORY_REDIRECT_ENV {
        cmd.env_remove(var);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("running git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}
