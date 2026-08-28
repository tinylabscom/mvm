//! Which libc a materialized guest rootfs carries.
//!
//! The host can read the unpacked tree only while it is still a directory.
//! Once it is an ext4 blob nothing on the host opens it again, so anything
//! admission needs to know about the guest's C library has to be observed
//! here and recorded in the sidecar.
//!
//! What needs it: `libmvm_host_services.so`, the C-ABI shim every language SDK
//! loads, is built against one libc. A musl process cannot `dlopen` a
//! glibc-linked object — it fails resolving glibc-only symbols such as
//! `_dl_find_object` — and shipping a second loader alongside does not help,
//! because the process doing the loading already has one.

use std::path::Path;

/// The guest's C library.
///
/// Defined in `mvm-contract` rather than here because two crates that cannot
/// see each other both need it: this one detects it from an unpacked tree, and
/// `mvm-fs` keys the SDK sidecar cache on it so a guest is offered the variant
/// it can load. Those are siblings, so the vocabulary sits underneath both
/// while the detection — which reads a filesystem — stays here.
pub use mvm_contract::guest_libc::GuestLibc;

/// Directories a dynamic loader lives in, relative to the rootfs.
const LOADER_DIRS: [&str; 2] = ["lib", "lib64"];

/// Identify the libc of an unpacked rootfs by looking for its dynamic loader.
///
/// Matching is by file name prefix rather than by a fixed set of full paths, so
/// this holds across architectures without enumerating them:
/// `ld-musl-aarch64.so.1` and `ld-linux-x86-64.so.2` are both recognised by
/// their stem.
///
/// Entries are matched by name and never followed. On Alpine the loader is a
/// symlink to `libc.musl-<arch>.so.1`, and `Path::exists` on a dangling link
/// would report the loader absent when the name is right there in the
/// directory.
///
/// Finding both families is reported as [`GuestLibc::Unknown`] rather than
/// picking one: an image carrying two loaders gives no basis for choosing which
/// one a workload's interpreter will use.
pub fn detect_guest_libc(root: &Path) -> GuestLibc {
    let mut saw_musl = false;
    let mut saw_glibc = false;

    for dir in LOADER_DIRS {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with("ld-musl-") {
                saw_musl = true;
            } else if name.starts_with("ld-linux-") {
                saw_glibc = true;
            }
        }
    }

    match (saw_glibc, saw_musl) {
        (true, false) => GuestLibc::Glibc,
        (false, true) => GuestLibc::Musl,
        _ => GuestLibc::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a rootfs tree carrying `names` in `lib/`.
    fn rootfs_with(names: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        for name in names {
            std::fs::write(dir.path().join("lib").join(name), b"").unwrap();
        }
        dir
    }

    #[test]
    fn an_alpine_style_tree_is_musl() {
        let dir = rootfs_with(&["ld-musl-aarch64.so.1", "libc.musl-aarch64.so.1"]);
        assert_eq!(detect_guest_libc(dir.path()), GuestLibc::Musl);
    }

    #[test]
    fn a_glibc_tree_is_glibc() {
        let dir = rootfs_with(&["ld-linux-aarch64.so.1", "libc.so.6"]);
        assert_eq!(detect_guest_libc(dir.path()), GuestLibc::Glibc);
    }

    /// The x86-64 glibc loader lives in `lib64`, not `lib`, so a detector that
    /// only scanned `lib` would call a perfectly ordinary image unknown.
    #[test]
    fn the_glibc_loader_is_found_in_lib64_too() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib64")).unwrap();
        std::fs::write(dir.path().join("lib64/ld-linux-x86-64.so.2"), b"").unwrap();
        assert_eq!(detect_guest_libc(dir.path()), GuestLibc::Glibc);
    }

    /// A dangling loader symlink still names the libc. Alpine ships exactly
    /// this shape, so following links here would misreport real images.
    #[test]
    fn a_dangling_loader_symlink_still_identifies_the_libc() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::os::unix::fs::symlink(
            "libc.musl-aarch64.so.1",
            dir.path().join("lib/ld-musl-aarch64.so.1"),
        )
        .unwrap();
        assert!(!dir.path().join("lib/ld-musl-aarch64.so.1").exists());
        assert_eq!(detect_guest_libc(dir.path()), GuestLibc::Musl);
    }

    #[test]
    fn a_tree_with_no_loader_is_unknown() {
        let dir = rootfs_with(&["libz.so.1"]);
        assert_eq!(detect_guest_libc(dir.path()), GuestLibc::Unknown);
    }

    /// Two loaders give no basis for picking one, so this reports unknown and
    /// lets the caller refuse rather than guessing.
    #[test]
    fn a_tree_carrying_both_loaders_is_unknown() {
        let dir = rootfs_with(&["ld-musl-aarch64.so.1", "ld-linux-aarch64.so.1"]);
        assert_eq!(detect_guest_libc(dir.path()), GuestLibc::Unknown);
    }

    #[test]
    fn a_missing_tree_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            detect_guest_libc(&dir.path().join("nope")),
            GuestLibc::Unknown
        );
    }
}
