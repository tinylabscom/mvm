//! Real on-disk footprint of a file or a directory tree.
//!
//! Every "how much would this reclaim" counter in mvm — `cache info`,
//! `cache prune`, `cache repair`, the orphan-VM reaper, `cleanup` — needs the
//! same number, and each one that computes it by hand gets it wrong in a
//! different way. Three mistakes matter, and all three inflate the answer:
//!
//! - **Following symlinks.** A materialized OCI rootfs is mostly symlinks. A
//!   walker that recurses through a symlinked directory re-walks whole
//!   subtrees, and one that stats through a symlinked file charges the
//!   target's blocks to the link. Deleting the tree frees neither.
//! - **Charging a hardlinked inode once per link.** The blocks come back once,
//!   so they may be counted once.
//! - **Reading the apparent length of a sparse file.** A 64 GiB store image
//!   with a few megabytes written occupies a few megabytes.
//!
//! [`tree_bytes`] is the one implementation: allocated blocks, symlinks
//! charged as themselves, and each inode charged once. It answers the same
//! question `du` does, so an operator can check it against `du -sh` and get
//! the same number.
//!
//! Best-effort by construction: an entry that cannot be read is skipped and a
//! path that does not exist measures zero. These counters drive UI, never a
//! correctness decision, so a partial read is better than an error.

use std::path::Path;

/// Bytes `path` occupies on disk, recursively.
///
/// Returns 0 for a path that cannot be stat'd. Symlinks are charged as
/// themselves and never traversed; a hardlinked inode reached twice within one
/// call is charged once.
///
/// ```
/// let dir = tempfile::tempdir().expect("tempdir");
/// std::fs::write(dir.path().join("blob"), vec![0u8; 8192]).expect("write");
/// assert!(mvm_core::disk_usage::tree_bytes(dir.path()) >= 8192);
/// assert_eq!(mvm_core::disk_usage::tree_bytes(&dir.path().join("absent")), 0);
/// ```
#[must_use]
pub fn tree_bytes(path: &Path) -> u64 {
    let mut charge = InodeCharge::default();
    // `symlink_metadata` so a symlink handed in directly is measured as the
    // link, matching how the walk below treats one it finds.
    let Ok(root) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    let mut total = charge.bytes(&root);
    if !root.is_dir() {
        return total;
    }
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // `DirEntry::metadata` does not traverse a symlink, which is what
            // keeps a link out of both the byte count and the descent.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            total = total.saturating_add(charge.bytes(&meta));
            if meta.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    total
}

/// Charges each inode at most once per measurement.
#[derive(Default)]
struct InodeCharge {
    #[cfg(unix)]
    multiply_linked: std::collections::HashSet<(u64, u64)>,
}

impl InodeCharge {
    #[cfg(unix)]
    fn bytes(&mut self, meta: &std::fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt as _;
        // Only multiply-linked inodes need the set; tracking every file in a
        // 500k-entry tree would cost more than the answer is worth.
        if meta.nlink() > 1 && !self.multiply_linked.insert((meta.dev(), meta.ino())) {
            return 0;
        }
        meta.blocks().saturating_mul(512)
    }

    /// Without `st_blocks` there is no allocation to read, so the apparent
    /// length is the best available answer.
    #[cfg(not(unix))]
    fn bytes(&mut self, meta: &std::fs::Metadata) -> u64 {
        meta.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_path_measures_zero() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(tree_bytes(&tmp.path().join("nope")), 0);
    }

    #[test]
    fn single_file_measures_at_least_its_length() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("blob");
        std::fs::write(&file, vec![0u8; 4096]).expect("write");
        assert!(tree_bytes(&file) >= 4096, "{}", tree_bytes(&file));
    }

    #[test]
    fn nested_files_are_summed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("a/b")).expect("mkdir");
        std::fs::write(tmp.path().join("a/one"), vec![0u8; 4096]).expect("write");
        std::fs::write(tmp.path().join("a/b/two"), vec![0u8; 4096]).expect("write");
        assert!(tree_bytes(tmp.path()) >= 8192);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_re_walked() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::write(real.join("blob"), vec![0u8; 64 * 1024]).expect("write");
        let baseline = tree_bytes(tmp.path());

        // The shape a materialized OCI rootfs has: a directory reachable both
        // directly and through a link beside it.
        std::os::unix::fs::symlink(&real, tmp.path().join("alias")).expect("symlink");
        let with_alias = tree_bytes(tmp.path());

        assert!(
            with_alias < baseline + 64 * 1024,
            "a symlinked directory must not be charged a second time: \
             baseline {baseline}, with alias {with_alias}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_is_charged_as_the_link_not_the_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        std::fs::write(&target, vec![0u8; 128 * 1024]).expect("write");
        let baseline = tree_bytes(tmp.path());

        std::os::unix::fs::symlink(&target, tmp.path().join("alias")).expect("symlink");
        let with_alias = tree_bytes(tmp.path());

        assert!(
            with_alias < baseline + 128 * 1024,
            "a symlink must not be charged its target's blocks: \
             baseline {baseline}, with alias {with_alias}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_hardlinked_inode_is_charged_once() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("blob");
        std::fs::write(&target, vec![0u8; 128 * 1024]).expect("write");
        let baseline = tree_bytes(tmp.path());

        std::fs::hard_link(&target, tmp.path().join("blob-link")).expect("hard link");
        let with_link = tree_bytes(tmp.path());

        assert_eq!(
            with_link, baseline,
            "the blocks come back once, so they may be counted once"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_sparse_file_is_charged_its_allocation_not_its_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let img = tmp.path().join("store.img");
        let file = std::fs::File::create(&img).expect("create");
        file.set_len(64 * 1024 * 1024 * 1024).expect("set_len");
        drop(file);

        let measured = tree_bytes(&img);
        assert!(
            measured < 64 * 1024 * 1024 * 1024,
            "a sparse image must be charged its allocation, not its cap: {measured}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_subdirectory_is_skipped_rather_than_failing() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let locked = tmp.path().join("locked");
        std::fs::create_dir_all(&locked).expect("mkdir");
        std::fs::write(locked.join("blob"), vec![0u8; 4096]).expect("write");
        std::fs::write(tmp.path().join("readable"), vec![0u8; 4096]).expect("write");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let measured = tree_bytes(tmp.path());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("restore");

        assert!(
            measured >= 4096,
            "the readable half must still be counted: {measured}"
        );
    }
}
