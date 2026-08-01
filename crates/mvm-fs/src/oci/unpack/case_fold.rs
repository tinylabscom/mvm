//! Host case-folding detection and the deferral index that keeps a
//! Linux rootfs faithful on a case-insensitive host filesystem.
//!
//! An OCI layer routinely carries two entries whose paths differ only
//! by case — `usr/share/man/man7/PAM.7.gz` (the page) and
//! `usr/share/man/man7/pam.7.gz` (a symlink to it) ship in Debian's
//! `libpam-runtime`, so every Debian-derived image has the pair. On
//! Linux both land as distinct files. On a default macOS APFS volume
//! they name the same file, so the second write hits `EEXIST`.
//!
//! Overwriting on `EEXIST` would be corruption, not a fix: it destroys
//! the regular file and leaves a dangling self-referential symlink. So
//! the second entry is instead **deferred** — kept out of the host tree
//! and carried in [`super::UnpackReport::deferred_nodes`] as an ext4
//! [`Node`], for the image writer to merge. The host tree stays the
//! host's best effort; the ext4 image, which is what actually boots,
//! holds both paths.
//!
//! Deferral is gated on two conditions, both required:
//!
//! 1. The filesystem backing `output_root` actually folds case
//!    ([`probe_host_case_folding`]). On a case-sensitive host the
//!    index is never consulted and behavior is bit-identical to before.
//! 2. The colliding path was written **by this same unpack**. That
//!    discriminator is what keeps the `O_EXCL` guarantee intact: a
//!    pre-existing or externally-planted file at the target still
//!    refuses, because it is not in the index.
//!
//! Only ASCII case folding is modelled. A host that also folds Unicode
//! case or normalizes NFD/NFC (HFS+) can still collide in ways this
//! index does not predict; those entries refuse with
//! [`super::RefusalReason::HostPathCollision`] rather than being
//! silently lost.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Whether the filesystem backing an unpack root distinguishes two
/// paths that differ only by ASCII case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostCaseFolding {
    /// Case-distinct paths are distinct files — Linux ext4/tmpfs/overlayfs,
    /// and APFS volumes formatted case-sensitive.
    Sensitive,
    /// Case-distinct paths name the same file — the macOS APFS default,
    /// and HFS+.
    Insensitive,
}

/// Filename used to probe the host's case behavior. Written into the
/// unpack root and removed before the first tar entry is read, so it
/// never reaches the assembled tree.
const PROBE_NAME: &str = ".mvm-case-probe";

/// Detect whether `output_root`'s filesystem folds case, by creating a
/// lowercase probe file and asking for it back under an uppercase name.
///
/// Answers [`HostCaseFolding::Sensitive`] when the probe cannot be
/// created at all. That is the conservative direction: it leaves the
/// pre-existing refuse-on-`EEXIST` behavior in place rather than
/// enabling deferral on a host we failed to characterize.
pub(super) fn probe_host_case_folding(output_root: &Path) -> HostCaseFolding {
    let probe = output_root.join(PROBE_NAME);
    // `create_new` so a leftover probe from an interrupted run can't be
    // mistaken for a successful write.
    let _ = std::fs::remove_file(&probe);
    if std::fs::File::create(&probe).is_err() {
        return HostCaseFolding::Sensitive;
    }
    let folded = output_root.join(PROBE_NAME.to_ascii_uppercase());
    let answer = match std::fs::symlink_metadata(&folded) {
        Ok(_) => HostCaseFolding::Insensitive,
        Err(_) => HostCaseFolding::Sensitive,
    };
    let _ = std::fs::remove_file(&probe);
    answer
}

/// Index of the paths an unpack has materialized, keyed by their
/// ASCII-case-folded form, so a later entry can ask "does the host
/// already hold a file at a path that folds equal to mine, and did
/// *I* put it there?".
pub(super) struct CaseFoldIndex {
    folding: HostCaseFolding,
    /// Fold-key → the exact path that occupies the host name. Only
    /// populated when `folding` is [`HostCaseFolding::Insensitive`];
    /// on a case-sensitive host the map stays empty and every lookup
    /// short-circuits.
    occupied: HashMap<String, PathBuf>,
}

impl CaseFoldIndex {
    /// Build the index over the paths earlier layers already wrote.
    pub(super) fn new(folding: HostCaseFolding, prior_layer_paths: &HashSet<PathBuf>) -> Self {
        let mut index = Self {
            folding,
            occupied: HashMap::new(),
        };
        if folding == HostCaseFolding::Insensitive {
            for path in prior_layer_paths {
                index.record(path);
            }
        }
        index
    }

    /// Note that `rel` now occupies its host name.
    pub(super) fn record(&mut self, rel: &Path) {
        if self.folding == HostCaseFolding::Sensitive {
            return;
        }
        self.occupied.insert(fold_key(rel), rel.to_path_buf());
    }

    /// `true` when writing `rel` would land on a host name this unpack
    /// already filled with a *differently spelled* path — the entry is
    /// unrepresentable on this host tree and must be deferred.
    ///
    /// Byte-equal paths are not collisions: an OCI layer replacing an
    /// earlier layer's file at the identical path is ordinary
    /// last-layer-wins behavior, handled by the prior-layer removal.
    pub(super) fn collides(&self, rel: &Path) -> bool {
        if self.folding == HostCaseFolding::Sensitive {
            return false;
        }
        match self.occupied.get(&fold_key(rel)) {
            Some(occupant) => occupant != rel,
            None => false,
        }
    }
}

/// ASCII-case-folded lookup key for a relative path. Lossy UTF-8 is
/// fine here: the key only has to collide for paths the host would
/// collide, and any byte sequence that survives lossy decoding
/// identically still compares equal.
fn fold_key(rel: &Path) -> String {
    rel.to_string_lossy().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn rel(p: &str) -> PathBuf {
        PathBuf::from(p)
    }

    #[test]
    fn probe_answers_sensitive_when_the_root_is_not_writable() {
        // A path that does not exist can't take the probe file.
        let missing = Path::new("/definitely/not/a/real/unpack/root");
        assert_eq!(
            probe_host_case_folding(missing),
            HostCaseFolding::Sensitive,
            "an uncharacterizable host must keep the refuse-on-EEXIST default"
        );
    }

    #[test]
    fn probe_leaves_no_trace_in_the_unpack_root() {
        let tmp = TempDir::new().unwrap();
        let _ = probe_host_case_folding(tmp.path());
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe must not contribute an entry to the assembled tree, found {leftovers:?}"
        );
    }

    #[test]
    fn probe_matches_what_the_host_filesystem_actually_does() {
        let tmp = TempDir::new().unwrap();
        let probed = probe_host_case_folding(tmp.path());

        // Ground truth, measured the same way the unpacker would hit it.
        std::fs::write(tmp.path().join("Aa"), b"x").unwrap();
        let actual = if tmp.path().join("aA").exists() {
            HostCaseFolding::Insensitive
        } else {
            HostCaseFolding::Sensitive
        };
        assert_eq!(probed, actual);
    }

    #[test]
    fn case_sensitive_host_never_reports_a_collision() {
        let mut index = CaseFoldIndex::new(HostCaseFolding::Sensitive, &HashSet::new());
        index.record(&rel("usr/PAM.7.gz"));
        assert!(!index.collides(&rel("usr/pam.7.gz")));
    }

    #[test]
    fn case_insensitive_host_reports_a_differently_spelled_collision() {
        let mut index = CaseFoldIndex::new(HostCaseFolding::Insensitive, &HashSet::new());
        index.record(&rel("usr/share/man/man7/PAM.7.gz"));
        assert!(index.collides(&rel("usr/share/man/man7/pam.7.gz")));
    }

    #[test]
    fn identical_path_is_a_layer_replacement_not_a_collision() {
        let mut index = CaseFoldIndex::new(HostCaseFolding::Insensitive, &HashSet::new());
        index.record(&rel("etc/passwd"));
        assert!(
            !index.collides(&rel("etc/passwd")),
            "a later layer rewriting the same path must keep the replacement path"
        );
    }

    #[test]
    fn unwritten_path_is_not_a_collision() {
        let index = CaseFoldIndex::new(HostCaseFolding::Insensitive, &HashSet::new());
        assert!(
            !index.collides(&rel("etc/passwd")),
            "a path this unpack never wrote must fall through to the O_EXCL guard"
        );
    }

    #[test]
    fn prior_layer_paths_seed_the_index() {
        let prior: HashSet<PathBuf> = [rel("usr/share/man/man7/PAM.7.gz")].into_iter().collect();
        let index = CaseFoldIndex::new(HostCaseFolding::Insensitive, &prior);
        assert!(index.collides(&rel("usr/share/man/man7/pam.7.gz")));
    }

    #[test]
    fn distinct_paths_do_not_collide() {
        let mut index = CaseFoldIndex::new(HostCaseFolding::Insensitive, &HashSet::new());
        index.record(&rel("usr/bin/python3"));
        assert!(!index.collides(&rel("usr/bin/python3.12")));
        assert!(!index.collides(&rel("usr/bin/perl")));
    }
}
