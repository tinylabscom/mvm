//! A checkout's commit and working-tree state, read through `git`.
//!
//! Every invocation is pinned to the checkout it names: the ambient
//! `GIT_DIR`/`GIT_WORK_TREE` family is cleared, because a caller running under
//! a git hook (or any tool that exports them) would otherwise have `git -C`
//! silently answer for a different repository. Optional locks are disabled so
//! a probe never contends with a concurrent `git` in the same checkout.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use std::process::Command;

use mvm_core::image_set::GitCommit;
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

/// Whether a checkout's files match its commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorktreeState {
    Clean,
    /// Differs from its commit. The fingerprint covers the tracked diff against
    /// `HEAD`, the status listing, and every untracked, non-ignored file's
    /// path and contents, so two different dirty trees on one commit do not
    /// share an identity.
    Dirty {
        fingerprint: Sha256Hex,
    },
}

impl WorktreeState {
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        matches!(self, Self::Dirty { .. })
    }
}

impl fmt::Display for WorktreeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::Dirty { fingerprint } => {
                write!(f, "dirty {}", &fingerprint.as_str()[..16])
            }
        }
    }
}

/// The commit a checkout is at and whether its files match it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoIdentity {
    pub commit: GitCommit,
    pub worktree: WorktreeState,
}

impl RepoIdentity {
    /// Read the identity of the checkout rooted at `root`.
    pub fn probe(root: &Path) -> Result<Self, String> {
        let head = git_text(root, ["rev-parse", "--verify", "HEAD^{commit}"])?;
        let commit = GitCommit::new(head).map_err(|e| e.to_string())?;
        Ok(Self {
            commit,
            worktree: worktree_state(root)?,
        })
    }
}

impl fmt::Display for RepoIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.commit, self.worktree)
    }
}

/// The top-level directory of the work tree containing `dir`.
pub fn toplevel(dir: &Path) -> Result<String, String> {
    git_text(dir, ["rev-parse", "--show-toplevel"])
}

fn worktree_state(root: &Path) -> Result<WorktreeState, String> {
    let status = git_bytes(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if status.is_empty() {
        return Ok(WorktreeState::Clean);
    }
    let mut hasher = Sha256::new();
    hash_section(&mut hasher, b"status", &status);
    let diff = git_bytes(
        root,
        [
            "diff",
            "HEAD",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
        ],
    )?;
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
