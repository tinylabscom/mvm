//! Correctness oracle: our writer's output must mount and read back identically
//! through an independent ext4 reader (`am-fs-ext4`). This is an integration
//! test (its own crate), so it may depend on the dev-only oracle; the library
//! itself never does.

use std::sync::Arc;

use fs_ext4::block_io::BlockDevice;
use fs_ext4::dir::{self, DirEntryType};
use fs_ext4::file_io;
use fs_ext4::fs::Filesystem;
use mvm_fs::ext4::mkfs::format_empty_ext4;
use mvm_fs::ext4::{Node, build_image};

/// An in-memory block device over our image bytes (safe).
struct MemDev(Vec<u8>);

impl BlockDevice for MemDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        let start = offset as usize;
        let end = start + buf.len();
        // Reads beyond the image would be our bug; surface it as a clear failure
        // rather than a panic.
        assert!(
            end <= self.0.len(),
            "oracle read past image end: {start}..{end} of {}",
            self.0.len()
        );
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
}

fn mount(image: Vec<u8>) -> Filesystem {
    Filesystem::mount(Arc::new(MemDev(image)))
        .expect("our image must mount in an independent ext4 reader")
}

/// Return (name, inode, type) for the entries of directory inode `ino`.
fn list_dir(fs: &Filesystem, ino: u32) -> Vec<(String, u32, DirEntryType)> {
    let (inode, _) = fs.read_inode_verified(ino).expect("read dir inode");
    let data = file_io::read_all(fs, &inode).expect("read dir data");
    dir::parse_block(&data, true)
        .expect("parse dir block")
        .into_iter()
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

/// Read a symlink target back exactly as the independent reader's `readlink`
/// does: a target strictly shorter than the 60-byte `i_block` is a *fast*
/// symlink stored inline; a target of 60 bytes or more is a *slow* symlink read
/// from a data block. The writer must pick the same boundary or the reader
/// resolves the wrong bytes. Asserts the fast/slow flag matches the length so a
/// misclassified symlink fails here rather than silently truncating.
fn read_symlink_target(fs: &Filesystem, ino: u32) -> Vec<u8> {
    let (inode, _) = fs.read_inode_verified(ino).expect("read symlink inode");
    assert!(inode.is_symlink(), "inode {ino} must be a symlink");
    if inode.size < 60 {
        assert!(
            !inode.has_extents(),
            "fast symlink (size {}) must store its target inline, not in extents",
            inode.size
        );
        inode.block[..inode.size as usize].to_vec()
    } else {
        assert!(
            inode.has_extents(),
            "slow symlink (size {}) must be extent-backed, not inline",
            inode.size
        );
        file_io::read_all(fs, &inode).expect("read slow symlink target")
    }
}

#[test]
fn empty_tree_mounts_with_root_dir() {
    let fs = mount(build_image(Vec::new()).unwrap());
    let (root, _) = fs.read_inode_verified(2).unwrap();
    assert_eq!(root.mode & 0o170000, 0o040000, "root must be a directory");
    let names: Vec<String> = list_dir(&fs, 2).into_iter().map(|(n, ..)| n).collect();
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
}

#[test]
fn tree_round_trips_through_real_reader() {
    let hosts = b"127.0.0.1 localhost\n".to_vec();
    let hello = b"#!/bin/sh\necho hi\n".to_vec();
    let nodes = vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/etc/hosts".into(),
            mode: 0o644,
            data: hosts.clone(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/hello".into(),
            mode: 0o755,
            data: hello.clone(),
            xattrs: Vec::new(),
        },
        Node::Symlink {
            path: "/etc/localhost".into(),
            target: "hosts".into(),
        },
    ];
    let fs = mount(build_image(nodes).unwrap());

    // Root lists /etc (dir) + /hello (file).
    let root = list_dir(&fs, 2);
    let (etc_ino, etc_ft) = find(&root, "etc").expect("/etc present");
    assert_eq!(etc_ft, DirEntryType::Directory);
    let (hello_ino, hello_ft) = find(&root, "hello").expect("/hello present");
    assert_eq!(hello_ft, DirEntryType::RegFile);

    // /hello content matches.
    assert_eq!(read_file(&fs, hello_ino), hello);

    // /etc lists hosts (file) + localhost (symlink).
    let etc = list_dir(&fs, etc_ino);
    let (hosts_ino, hosts_ft) = find(&etc, "hosts").expect("/etc/hosts present");
    assert_eq!(hosts_ft, DirEntryType::RegFile);
    assert_eq!(read_file(&fs, hosts_ino), hosts);
    let (link_ino, link_ft) = find(&etc, "localhost").expect("/etc/localhost present");
    assert_eq!(link_ft, DirEntryType::Symlink);
    let (link_inode, _) = fs.read_inode_verified(link_ino).unwrap();
    assert!(link_inode.is_symlink());
    assert_eq!(link_inode.size, "hosts".len() as u64);
}

/// Symlink targets must round-trip byte-for-byte across the fast/slow boundary.
/// The inode's `i_block` area is exactly 60 bytes, so a fast (inline) symlink
/// can hold a target of at most 59 bytes; a 60-byte target is a *slow* symlink
/// backed by a data block. A 60-byte target previously stored inline lost its
/// final byte on readback (an independent reader treats `i_size >= 60` as slow
/// and reads the — absent — data block). Boundary-checked around the transition
/// and out to a multi-block target.
#[test]
fn symlink_targets_round_trip_across_fast_slow_boundary() {
    // A real 60-byte target: `/usr/local/bin/claude` after `npm i -g` points at
    // `../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`.
    let real_60 = "../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe";
    assert_eq!(real_60.len(), 60, "fixture must be exactly 60 bytes");

    // Distinct generated targets straddling the boundary plus a multi-block
    // long target. Each byte is a printable ASCII letter, so the target is
    // valid UTF-8 and every position is individually distinguishable.
    let make_target =
        |len: usize| -> String { (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect() };
    let mut cases: Vec<(String, String)> = [58usize, 59, 60, 61, 62, 200]
        .into_iter()
        .map(|len| (format!("/links/gen{len}"), make_target(len)))
        .collect();
    cases.push(("/links/real60".to_string(), real_60.to_string()));

    let mut nodes = vec![Node::Dir {
        path: "/links".into(),
        mode: 0o755,
        xattrs: Vec::new(),
    }];
    for (path, target) in &cases {
        nodes.push(Node::Symlink {
            path: path.clone(),
            target: target.clone(),
        });
    }

    let fs = mount(build_image(nodes).unwrap());
    let (links_ino, links_ft) = find(&list_dir(&fs, 2), "links").expect("/links present");
    assert_eq!(links_ft, DirEntryType::Directory);
    let entries = list_dir(&fs, links_ino);

    for (path, target) in &cases {
        let name = path.rsplit('/').next().unwrap();
        let (ino, ft) = find(&entries, name).unwrap_or_else(|| panic!("{path} present"));
        assert_eq!(ft, DirEntryType::Symlink, "{path} must be a symlink");
        let got = read_symlink_target(&fs, ino);
        assert_eq!(
            got,
            target.as_bytes(),
            "symlink {path} (target {} bytes) must round-trip intact",
            target.len()
        );
    }
}

/// The empty-growable `mkfs` path (a writable Stage 0 store, not a sealed
/// rootfs) must also produce a filesystem the independent reader mounts: a bare
/// root directory holding only "." and "..", sized to the full device with free
/// space to grow. Exercises both a single partial group and a multi-group
/// layout (with backup superblocks).
#[test]
fn empty_mkfs_mounts_in_real_reader() {
    for size in [64 * 1024 * 1024u64, 160 * 1024 * 1024] {
        let mut cur = std::io::Cursor::new(vec![0u8; size as usize]);
        let summary = format_empty_ext4(&mut cur, size).expect("format empty ext4");
        assert!(
            summary.free_blocks > 0,
            "a fresh store must have free space"
        );

        let fs = mount(cur.into_inner());
        let (root, _) = fs.read_inode_verified(2).expect("read root inode");
        assert_eq!(
            root.mode & 0o170000,
            0o040000,
            "root must be a directory (size {size})"
        );
        let names: Vec<String> = list_dir(&fs, 2).into_iter().map(|(n, ..)| n).collect();
        assert!(
            names.contains(&".".to_string()),
            "root has '.' (size {size})"
        );
        assert!(
            names.contains(&"..".to_string()),
            "root has '..' (size {size})"
        );
        assert!(
            names.iter().all(|n| n == "." || n == ".."),
            "a fresh store's root holds only '.' and '..' (size {size})"
        );
    }
}

#[test]
fn output_is_deterministic() {
    let nodes = vec![
        Node::Dir {
            path: "/a".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/a/f".into(),
            mode: 0o644,
            data: b"xyz".to_vec(),
            xattrs: Vec::new(),
        },
    ];
    let one = build_image(nodes.clone()).unwrap();
    let two = build_image(nodes).unwrap();
    assert_eq!(one, two, "same input must produce byte-identical images");
}

/// One group holds 128 MiB of blocks at 4 KiB. A file past that forces a second
/// block group and a file that spans two groups' data regions as two extents —
/// the multi-group path the single-group tests never exercise. The independent
/// reader must still mount it and read every byte back.
#[test]
fn multi_group_image_round_trips_through_real_reader() {
    const ONE_GROUP_BYTES: usize = 32768 * mvm_fs::ext4::BLOCK_SIZE as usize; // 128 MiB

    // 130 MiB deterministic payload → ~33 280 blocks > one group's data region.
    let big: Vec<u8> = (0..130 * 1024 * 1024usize)
        .map(|i| (i % 251) as u8)
        .collect();
    let small = b"i live in a multi-group image\n".to_vec();
    let nodes = vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/etc/marker".into(),
            mode: 0o644,
            data: small.clone(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/big".into(),
            mode: 0o644,
            data: big.clone(),
            xattrs: Vec::new(),
        },
    ];

    let image = build_image(nodes).unwrap();
    assert!(
        image.len() > ONE_GROUP_BYTES,
        "image ({} bytes) should span more than one block group",
        image.len()
    );

    let fs = mount(image);
    let root = list_dir(&fs, 2);

    // The small file (in group 0) reads back exactly.
    let etc = find(&root, "etc").expect("etc").0;
    let (marker_ino, marker_ft) = find(&list_dir(&fs, etc), "marker").expect("marker");
    assert_eq!(marker_ft, DirEntryType::RegFile);
    assert_eq!(read_file(&fs, marker_ino), small);

    // The big file (spanning groups as multiple extents) reads back byte-exact.
    let (big_ino, big_ft) = find(&root, "big").expect("big");
    assert_eq!(big_ft, DirEntryType::RegFile);
    let got = read_file(&fs, big_ino);
    assert_eq!(got.len(), big.len(), "big file length round-trips");
    assert_eq!(
        got, big,
        "big file bytes round-trip across the group boundary"
    );
}

/// A single file past four group-data-regions (~128 MiB each) needs more than
/// the four extents an inode holds inline, so the writer grows a **depth-1
/// extent tree** (index entries in the inode → leaf blocks). The independent
/// reader must follow the tree and read every byte back. Heavy (allocates ~1.5
/// GiB), so `#[ignore]`d out of the default suite; the CI kernel-mount lane
/// exercises the same path continuously.
#[test]
#[ignore = "allocates ~1.5 GiB (a >512 MiB single file forces a depth-1 extent tree); run explicitly"]
fn depth1_extent_tree_file_round_trips_through_real_reader() {
    const N: usize = 520 * 1024 * 1024; // > 4 * ~128 MiB → ≥ 5 extents → depth-1
    let big: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    let nodes = vec![Node::File {
        path: "/huge".into(),
        mode: 0o644,
        data: big,
        xattrs: Vec::new(),
    }];
    let image = build_image(nodes).unwrap();

    let fs = mount(image);
    let (ino, ft) = find(&list_dir(&fs, 2), "huge").expect("/huge present");
    assert_eq!(ft, DirEntryType::RegFile);
    let got = read_file(&fs, ino);
    assert_eq!(got.len(), N, "depth-1 file length round-trips");
    // Spot-check bytes at and past each ~128 MiB group boundary — the extent
    // seams the depth-1 tree stitches together.
    for off in [
        0usize,
        1,
        N / 4,
        200 * 1024 * 1024,
        400 * 1024 * 1024,
        512 * 1024 * 1024,
        N - 1,
    ] {
        assert_eq!(
            got[off],
            (off % 251) as u8,
            "byte {off} round-trips across the depth-1 extent tree"
        );
    }
}
