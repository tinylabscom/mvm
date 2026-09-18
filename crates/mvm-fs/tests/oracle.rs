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
use mvm_fs::ext4::{Node, Owner, build_image};

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
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/etc/hosts".into(),
            mode: 0o644,
            data: hosts.clone(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/hello".into(),
            mode: 0o755,
            data: hello.clone(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        },
        Node::Symlink {
            path: "/etc/localhost".into(),
            target: "hosts".into(),
            owner: Owner::ROOT,
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
        owner: Owner::ROOT,
    }];
    for (path, target) in &cases {
        nodes.push(Node::Symlink {
            path: path.clone(),
            target: target.clone(),
            owner: Owner::ROOT,
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
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/a/f".into(),
            mode: 0o644,
            data: b"xyz".to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
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
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/etc/marker".into(),
            mode: 0o644,
            data: small.clone(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/big".into(),
            mode: 0o644,
            data: big.clone(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
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
        owner: Owner::ROOT,
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

/// A root-owned tree touching every node kind: a directory, an inline file, an
/// xattr-bearing file, and a fast symlink.
fn root_owned_fixture() -> Vec<Node> {
    vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/etc/hosts".into(),
            mode: 0o644,
            data: b"127.0.0.1 localhost\n".to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        },
        Node::File {
            path: "/ping".into(),
            mode: 0o755,
            data: b"\x7fELF".to_vec(),
            xattrs: vec![mvm_fs::ext4::Xattr {
                name: "security.capability".into(),
                value: vec![1, 0, 0, 2],
            }],
            owner: Owner::ROOT,
        },
        Node::Symlink {
            path: "/etc/localhost".into(),
            target: "hosts".into(),
            owner: Owner::ROOT,
        },
    ]
}

/// Images built without any ownership must stay byte-identical to what the
/// writer emitted before inodes could carry an owner: flake-built images and
/// host-directory shares are root-owned, and their cached verity roots must
/// not move.
#[test]
fn root_owned_image_bytes_are_pinned() {
    use sha2::Digest as _;
    let image = build_image(root_owned_fixture()).unwrap();
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&image)),
        "42b16364352722d7b9ade5566df33b278339c5b8204dc8f8497b1fb813a4dd03",
    );
}

/// The content fingerprint of a root-owned tree is pinned for the same reason:
/// a cache keyed on it must keep hitting for trees that carry no owners.
#[test]
fn root_owned_fingerprint_is_pinned() {
    assert_eq!(
        mvm_fs::rootfs::fingerprint_ext4_nodes(&root_owned_fixture()).unwrap(),
        "51bd9a5461b60b1e94762b3985784b2e61db8d721e6a2a55795694863a139179",
    );
}

/// Walk `path` (guest-absolute, `/`-separated) from the root inode and return
/// the inode number the independent reader resolves it to.
fn resolve(fs: &Filesystem, path: &str) -> u32 {
    path.trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .fold(2, |dir, segment| {
            find(&list_dir(fs, dir), segment)
                .unwrap_or_else(|| panic!("{path}: no entry {segment}"))
                .0
        })
}

/// The owner the independent reader reports for `path`.
fn owner_of(fs: &Filesystem, path: &str) -> Owner {
    let (inode, _) = fs.read_inode_verified(resolve(fs, path)).unwrap();
    Owner::new(inode.uid, inode.gid)
}

/// Every node kind carries its owner onto the inode, and an id past 16 bits
/// survives through the high-half fields rather than being truncated.
#[test]
fn owners_round_trip_through_real_reader() {
    let svc = Owner::new(999, 999);
    let wide = Owner::new(70_000, 131_072);
    let widest = Owner::new(u32::MAX, u32::MAX - 1);
    let nodes = vec![
        Node::Dir {
            path: "/data".into(),
            mode: 0o700,
            xattrs: Vec::new(),
            owner: svc,
        },
        Node::File {
            path: "/data/state".into(),
            mode: 0o600,
            data: b"ready\n".to_vec(),
            xattrs: Vec::new(),
            owner: wide,
        },
        Node::Symlink {
            path: "/data/current".into(),
            target: "state".into(),
            owner: widest,
        },
        Node::File {
            path: "/rootfile".into(),
            mode: 0o644,
            data: Vec::new(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        },
    ];
    let fs = mount(build_image(nodes).unwrap());
    assert_eq!(owner_of(&fs, "/data"), svc);
    assert_eq!(owner_of(&fs, "/data/state"), wide);
    assert_eq!(owner_of(&fs, "/data/current"), widest);
    assert_eq!(owner_of(&fs, "/rootfile"), Owner::ROOT);
    let (root, _) = fs.read_inode_verified(2).unwrap();
    assert_eq!(Owner::new(root.uid, root.gid), Owner::ROOT);
}

fn owned_header(path: &str, kind: tar::EntryType, owner: Owner, body_len: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_size(body_len);
    header.set_mode(match kind {
        tar::EntryType::Directory => 0o750,
        _ => 0o640,
    });
    header.set_entry_type(kind);
    header.set_uid(u64::from(owner.uid));
    header.set_gid(u64::from(owner.gid));
    header.set_cksum();
    header
}

/// A service layer as a container image ships one: the data directory and
/// its contents owned by the service account, under parents the stream never
/// lists.
fn service_layer(svc: Owner, wide: Owner) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append(
            &owned_header("var/lib/svc/", tar::EntryType::Directory, svc, 0),
            std::io::empty(),
        )
        .unwrap();
    builder
        .append(
            &owned_header("var/lib/svc/db", tar::EntryType::Regular, svc, 3),
            b"row".as_slice(),
        )
        .unwrap();
    builder
        .append(
            &owned_header("home/wide/.profile", tar::EntryType::Regular, wide, 0),
            std::io::empty(),
        )
        .unwrap();
    builder.into_inner().unwrap()
}

fn materialize_layer(layer: &[u8]) -> Vec<u8> {
    use mvm_fs::oci::unpack::{UnpackOptions, unpack_layer};
    use mvm_fs::ownership::OwnerTable;
    use mvm_fs::rootfs::{MaterializeOptions, build_ext4_pure};

    let root = tempfile::tempdir().unwrap();
    let report = unpack_layer(layer, root.path(), &UnpackOptions::default()).unwrap();
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    let mut owners = OwnerTable::new();
    owners.absorb(&report.ownership);
    let options = MaterializeOptions::builder().owners(owners).build();
    build_ext4_pure(root.path(), &options).unwrap().0
}

/// The unpack runs unprivileged and cannot `chown`, so the host tree is owned
/// by whoever ran it. The owners in the layer's tar headers still have to be
/// the owners inside the image.
#[test]
fn layer_owners_survive_unpack_and_materialize() {
    let svc = Owner::new(999, 999);
    let wide = Owner::new(100_000, 100_001);
    let image = materialize_layer(&service_layer(svc, wide));
    let fs = mount(image);
    assert_eq!(owner_of(&fs, "/var/lib/svc"), svc);
    assert_eq!(owner_of(&fs, "/var/lib/svc/db"), svc);
    assert_eq!(owner_of(&fs, "/home/wide/.profile"), wide);
    assert_eq!(
        owner_of(&fs, "/var/lib"),
        Owner::ROOT,
        "a parent the layer only implied is root-owned"
    );
    assert_eq!(owner_of(&fs, "/home/wide"), Owner::ROOT);
}

/// A layer that names the files the runtime injects after the layers are
/// stacked, claiming each for an account of its own.
fn hostile_layer(attacker: Owner) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for path in [
        "etc/passwd",
        "etc/group",
        "etc/mvm/verb-trust.json",
        "usr/lib/mvm/wrappers/oci-entrypoint",
        "srv/app.conf",
    ] {
        builder
            .append(
                &owned_header(path, tar::EntryType::Regular, attacker, 0),
                std::io::empty(),
            )
            .unwrap();
    }
    builder.into_inner().unwrap()
}

/// An image cannot take the files mvm injects away from root by declaring an
/// owner for them — `/etc/passwd` and `/etc/group` most of all, since a guest
/// resolving its uid through an image-owned account database is the elevation
/// path a sealed rootfs exists to close.
#[test]
fn a_layer_cannot_own_the_files_the_runtime_injects() {
    use mvm_fs::oci::unpack::{UnpackOptions, unpack_layer};
    use mvm_fs::ownership::{OwnerTable, RootOwnedPaths};
    use mvm_fs::rootfs::{MaterializeOptions, build_ext4_pure};

    let attacker = Owner::new(1000, 1000);
    let root_dir = tempfile::tempdir().unwrap();
    let report = unpack_layer(
        hostile_layer(attacker).as_slice(),
        root_dir.path(),
        &UnpackOptions::default(),
    )
    .unwrap();
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    let mut owners = OwnerTable::new();
    owners.absorb(&report.ownership);

    let injected = RootOwnedPaths::none()
        .with_path("etc/passwd")
        .with_path("etc/group")
        .with_tree("etc/mvm")
        .with_tree("usr/lib/mvm");
    let options = MaterializeOptions::builder()
        .owners(owners)
        .root_owned(injected)
        .build();
    let fs = mount(build_ext4_pure(root_dir.path(), &options).unwrap().0);

    for path in [
        "/etc/passwd",
        "/etc/group",
        "/etc/mvm/verb-trust.json",
        "/usr/lib/mvm/wrappers/oci-entrypoint",
    ] {
        assert_eq!(
            owner_of(&fs, path),
            Owner::ROOT,
            "{path} is the runtime's, whatever the layer declared"
        );
    }
    assert_eq!(
        owner_of(&fs, "/srv/app.conf"),
        attacker,
        "a path the runtime does not inject keeps the owner its layer declared"
    );
}

/// Ownership is content, not host state: the same layer materializes to the
/// same bytes every time.
#[test]
fn owned_layer_materializes_deterministically() {
    let layer = service_layer(Owner::new(999, 999), Owner::new(100_000, 100_001));
    assert_eq!(materialize_layer(&layer), materialize_layer(&layer));
}

/// A cache keyed on the fingerprint must miss when only an owner changed —
/// otherwise a root-owned image built earlier would be reused for a tree that
/// now declares a service account.
#[test]
fn changing_only_an_owner_changes_the_fingerprint() {
    use mvm_fs::rootfs::fingerprint_ext4_nodes;

    let base = fingerprint_ext4_nodes(&root_owned_fixture()).unwrap();
    let mut seen = std::collections::HashSet::from([base.clone()]);
    for index in 0..root_owned_fixture().len() {
        for owner in [
            Owner::new(999, 0),
            Owner::new(0, 999),
            Owner::new(70_000, 70_000),
        ] {
            let mut nodes = root_owned_fixture();
            nodes[index].set_owner(owner);
            let changed = fingerprint_ext4_nodes(&nodes).unwrap();
            assert_ne!(changed, base, "node {index} owner {owner:?}");
            assert!(
                seen.insert(changed),
                "node {index} owner {owner:?} collided"
            );
        }
    }
}
