//! Persistence for audit-chain verification checkpoints.
//!
//! A checkpoint is a cache, never an authority: every read and write here is
//! best-effort, and losing one costs a full re-verification rather than
//! producing a wrong answer. It lives under the mvm cache dir rather than
//! beside the audit log so that a checkpoint is never mistaken for part of the
//! chain, and so wiping the cache restores genesis-anchored verification.

use std::path::{Path, PathBuf};

use super::audit_file::ChainCheckpoint;

/// Directory holding one checkpoint per verified chain.
fn checkpoint_dir() -> PathBuf {
    Path::new(&mvm_core::config::mvm_cache_dir()).join("audit-verify")
}

/// Cache filename for `chain_path`.
///
/// Keyed on the full path, not just the file name: two chains with the same
/// basename under different roots (a test `MVM_HOME`, a second audit dir) must
/// not share a checkpoint, or one would resume onto the other's history.
fn checkpoint_name(chain_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(chain_path.as_os_str().as_encoded_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let stem = chain_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("chain");
    // The readable stem is for a human looking in the cache dir; the digest is
    // what actually distinguishes entries.
    format!("{stem}-{}.json", hex::encode(&digest[..8]))
}

/// Path of the checkpoint file for `chain_path`.
pub fn checkpoint_path(chain_path: &Path) -> PathBuf {
    checkpoint_dir().join(checkpoint_name(chain_path))
}

/// Load the stored checkpoint for `chain_path`, if any is readable.
///
/// A missing, unreadable, or unparseable checkpoint is `None` — the caller
/// falls back to a full walk, which is always correct.
pub fn load(chain_path: &Path) -> Option<ChainCheckpoint> {
    let raw = std::fs::read_to_string(checkpoint_path(chain_path)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Store `checkpoint` for `chain_path`. Best-effort; a failure to persist only
/// costs the next run a full walk.
pub fn store(chain_path: &Path, checkpoint: &ChainCheckpoint) {
    let path = checkpoint_path(chain_path);
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let Ok(encoded) = serde_json::to_string(checkpoint) else {
        return;
    };
    // Write via a temp file and rename so a concurrent reader never sees a
    // half-written checkpoint and resumes onto a truncated hash.
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, encoded).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Point `MVM_HOME` at a scratch dir so the cache never touches a real one.
    fn with_scratch_home<T>(body: impl FnOnce(&Path) -> T) -> T {
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: single-threaded test body; the guard restores the prior value.
        let prior = std::env::var_os("MVM_HOME");
        unsafe { std::env::set_var("MVM_HOME", dir.path()) };
        let out = body(dir.path());
        match prior {
            Some(v) => unsafe { std::env::set_var("MVM_HOME", v) },
            None => unsafe { std::env::remove_var("MVM_HOME") },
        }
        out
    }

    fn checkpoint(lines: usize) -> ChainCheckpoint {
        ChainCheckpoint {
            verified_lines: lines,
            chain_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        }
    }

    #[test]
    fn absent_checkpoint_reads_as_none() {
        with_scratch_home(|_| {
            assert!(load(Path::new("/a/audit/local.jsonl")).is_none());
        });
    }

    #[test]
    fn a_stored_checkpoint_round_trips() {
        with_scratch_home(|_| {
            let chain = Path::new("/a/audit/local.jsonl");
            let cp = checkpoint(42);
            store(chain, &cp);
            assert_eq!(load(chain), Some(cp));
        });
    }

    #[test]
    fn distinct_chains_do_not_share_a_checkpoint() {
        with_scratch_home(|_| {
            let a = Path::new("/a/audit/local.jsonl");
            let b = Path::new("/b/audit/local.jsonl");
            store(a, &checkpoint(1));
            store(b, &checkpoint(2));
            assert_eq!(load(a).unwrap().verified_lines, 1);
            assert_eq!(load(b).unwrap().verified_lines, 2);
        });
    }

    #[test]
    fn same_basename_under_different_roots_gets_different_files() {
        let a = checkpoint_path(Path::new("/a/audit/local.jsonl"));
        let b = checkpoint_path(Path::new("/b/audit/local.jsonl"));
        assert_ne!(a, b, "path must key the checkpoint, not just the basename");
    }

    #[test]
    fn a_corrupt_checkpoint_reads_as_none_rather_than_erroring() {
        with_scratch_home(|_| {
            let chain = Path::new("/a/audit/local.jsonl");
            store(chain, &checkpoint(3));
            std::fs::write(checkpoint_path(chain), "{ not json").expect("clobber");
            assert!(
                load(chain).is_none(),
                "a corrupt cache entry must degrade to a full walk"
            );
        });
    }

    #[test]
    fn storing_twice_overwrites_rather_than_appending() {
        with_scratch_home(|_| {
            let chain = Path::new("/a/audit/local.jsonl");
            store(chain, &checkpoint(1));
            store(chain, &checkpoint(9));
            assert_eq!(load(chain).unwrap().verified_lines, 9);
        });
    }

    #[test]
    fn the_checkpoint_lives_outside_the_audit_directory() {
        // A checkpoint beside the chain could be mistaken for part of it, and
        // `is_host_lifecycle_chain` would have to learn to skip it.
        with_scratch_home(|home| {
            let path = checkpoint_path(Path::new("/a/audit/local.jsonl"));
            assert!(path.starts_with(home), "{path:?} should be under MVM_HOME");
            assert!(!path.to_string_lossy().contains("/audit/local.jsonl"));
        });
    }
}
