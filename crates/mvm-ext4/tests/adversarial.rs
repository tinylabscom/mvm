//! Adversarial-input regression suite for the pure-Rust ext4 writer.
//!
//! The cargo-fuzz `fuzz_build_image` target proves "no panic on well-shaped
//! node sets," but it deliberately restricts its inputs: a safe path alphabet
//! (never `/`, NUL, or `..`), files capped at 64 KiB, depth capped at 4, and
//! symlink targets that never loop. These tests pin the writer's contract on
//! exactly the shapes the fuzz never reaches — deep nesting, over-cap sizes,
//! symlink loops, and malformed / hostile paths. The contract:
//!
//!   * a valid tree materializes and round-trips through an independent reader;
//!   * an impossible tree returns `Err`;
//!   * nothing ever panics.

use mvm_ext4::{Node, build_image};

/// A regular file cannot be a directory: a node whose parent path resolves to a
/// file (not a dir) must be rejected, not silently emitted as an orphaned,
/// unreachable inode. The fuzz harness only ever synthesizes *directory*
/// ancestors, so this branch is unreachable there.
#[test]
fn parent_that_is_a_file_is_rejected() {
    let nodes = vec![
        Node::File {
            path: "/a".into(),
            mode: 0o644,
            data: b"x".to_vec(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/a/b".into(),
            mode: 0o644,
            data: b"y".to_vec(),
            xattrs: Vec::new(),
        },
    ];
    build_image(&nodes).expect_err("a file cannot be a parent directory");
}

/// Two nodes at the same path would allocate two inodes and emit two dirents of
/// the same name into the parent — a malformed directory. The writer must
/// reject the collision. Deterministic-order sorting hides this from the fuzz
/// (which rarely generates a byte-exact path twice).
#[test]
fn duplicate_paths_are_rejected() {
    let nodes = vec![
        Node::File {
            path: "/dup".into(),
            mode: 0o644,
            data: b"first".to_vec(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/dup".into(),
            mode: 0o644,
            data: b"second".to_vec(),
            xattrs: Vec::new(),
        },
    ];
    build_image(&nodes).expect_err("duplicate path must be rejected");
}

/// Paths with empty (`//`), dot (`.`/`..`), or NUL-bearing components are
/// malformed: they either alias another node (`//a` collapsing to `/a`) or would
/// emit an un-representable directory entry. Each must be refused. The fuzz's
/// safe segment alphabet never produces any of these.
#[test]
fn malformed_path_components_are_rejected() {
    for bad in ["//a", "/a//b", "/a/./b", "/a/../b", "/a/\0b", "/.", "/.."] {
        let nodes = vec![Node::File {
            path: bad.into(),
            mode: 0o644,
            data: b"x".to_vec(),
            xattrs: Vec::new(),
        }];
        assert!(
            build_image(&nodes).is_err(),
            "malformed path {bad:?} must be rejected"
        );
    }
}

/// Deep nesting well past the fuzz's depth cap (4) must still materialize and
/// stay reachable: the leaf file at the bottom of a 64-level chain round-trips.
#[test]
fn deep_nesting_round_trips() {
    const DEPTH: usize = 64;
    let mut nodes = Vec::new();
    let mut path = String::new();
    for i in 0..DEPTH {
        path.push_str(&format!("/d{i}"));
        nodes.push(Node::Dir {
            path: path.clone(),
            mode: 0o755,
            xattrs: Vec::new(),
        });
    }
    let leaf = format!("{path}/leaf");
    let content = b"bottom".to_vec();
    nodes.push(Node::File {
        path: leaf,
        mode: 0o644,
        data: content.clone(),
        xattrs: Vec::new(),
    });

    let fs = mount(build_image(&nodes).expect("deep valid tree builds"));
    // Walk d0/d1/.../d63/leaf and read it back.
    let mut ino = 2u32; // root
    for i in 0..DEPTH {
        let (child, ft) = find(&list_dir(&fs, ino), &format!("d{i}")).expect("dir present");
        assert_eq!(ft, DirEntryType::Directory);
        ino = child;
    }
    let (leaf_ino, ft) = find(&list_dir(&fs, ino), "leaf").expect("leaf present");
    assert_eq!(ft, DirEntryType::RegFile);
    assert_eq!(
        read_file(&fs, leaf_ino),
        content,
        "deep leaf content intact"
    );
}

/// Symlink cycles (`a → b`, `b → a`) and a self-loop (`s → s`) must not hang or
/// resolve — the writer stores link text verbatim as opaque bytes. The image
/// builds, mounts, and each link inode carries its literal target length.
#[test]
fn symlink_cycles_are_stored_verbatim() {
    let nodes = vec![
        Node::Symlink {
            path: "/a".into(),
            target: "/b".into(),
        },
        Node::Symlink {
            path: "/b".into(),
            target: "/a".into(),
        },
        Node::Symlink {
            path: "/s".into(),
            target: "/s".into(),
        },
    ];
    let fs = mount(build_image(&nodes).expect("symlink cycle builds"));
    let root = list_dir(&fs, 2);
    for (name, target) in [("a", "/b"), ("b", "/a"), ("s", "/s")] {
        let (ino, ft) = find(&root, name).unwrap_or_else(|| panic!("/{name} present"));
        assert_eq!(ft, DirEntryType::Symlink);
        let (inode, _) = fs.read_inode_verified(ino).expect("read symlink inode");
        assert!(inode.is_symlink());
        assert_eq!(
            inode.size,
            target.len() as u64,
            "/{name} stores verbatim target {target:?}"
        );
    }
}

/// A directory with far more entries than fit one 4 KiB block materializes as a
/// linear multi-block directory (no htree): it builds, mounts, and the
/// independent reader lists every entry back across the block boundaries — never
/// a panic, a truncated directory, or an entry lost at a block seam.
#[test]
fn directory_over_one_block_spans_multiple_blocks() {
    const N: usize = 400;
    let mut nodes = vec![Node::Dir {
        path: "/big".into(),
        mode: 0o755,
        xattrs: Vec::new(),
    }];
    for i in 0..N {
        nodes.push(Node::File {
            path: format!("/big/f{i:04}"),
            mode: 0o644,
            data: Vec::new(),
            xattrs: Vec::new(),
        });
    }

    let fs = mount(build_image(&nodes).expect("over-full directory builds as multi-block"));
    let (big_ino, ft) = find(&list_dir(&fs, 2), "big").expect("/big present");
    assert_eq!(ft, DirEntryType::Directory);

    // The directory inode must occupy more than one block.
    let (inode, _) = fs.read_inode_verified(big_ino).expect("read /big inode");
    assert!(
        inode.size > 4096,
        "/big should span multiple blocks, got size {}",
        inode.size
    );

    // Every child reads back across all blocks — none lost at a boundary.
    let entries = list_dir(&fs, big_ino);
    for i in 0..N {
        let name = format!("f{i:04}");
        assert!(
            find(&entries, &name).is_some(),
            "child {name} missing from multi-block directory"
        );
    }
    let children = entries
        .iter()
        .filter(|(name, _, _)| name != "." && name != "..")
        .count();
    assert_eq!(
        children, N,
        "unexpected child count in multi-block directory"
    );
}

// ---- oracle mount helpers (independent ext4 reader; dev-only) ----------------

use fs_ext4::block_io::BlockDevice;
use fs_ext4::dir::{self, DirEntryType};
use fs_ext4::file_io;
use fs_ext4::fs::Filesystem;
use std::sync::Arc;

struct MemDev(Vec<u8>);
impl BlockDevice for MemDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        let start = offset as usize;
        let end = start + buf.len();
        assert!(end <= self.0.len(), "oracle read past image end");
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
}

fn mount(image: Vec<u8>) -> Filesystem {
    Filesystem::mount(Arc::new(MemDev(image))).expect("image must mount in independent reader")
}

fn list_dir(fs: &Filesystem, ino: u32) -> Vec<(String, u32, DirEntryType)> {
    let (inode, _) = fs.read_inode_verified(ino).expect("read dir inode");
    let data = file_io::read_all(fs, &inode).expect("read dir data");
    // A linear directory is a sequence of independent 4 KiB blocks; parse each
    // so a multi-block directory reads back every entry, not just block 0's.
    data.chunks(4096)
        .flat_map(|block| dir::parse_block(block, true).expect("parse dir block"))
        .map(|e| {
            (
                String::from_utf8_lossy(&e.name).into_owned(),
                e.inode,
                e.file_type,
            )
        })
        .collect()
}

fn find(entries: &[(String, u32, DirEntryType)], name: &str) -> Option<(u32, DirEntryType)> {
    entries
        .iter()
        .find(|(n, ..)| n == name)
        .map(|(_, i, t)| (*i, *t))
}

fn read_file(fs: &Filesystem, ino: u32) -> Vec<u8> {
    let (inode, _) = fs.read_inode_verified(ino).expect("read file inode");
    file_io::read_all(fs, &inode).expect("read file data")
}
