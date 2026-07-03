//! Correctness oracle: our writer's output must mount and read back identically
//! through an independent ext4 reader (`am-fs-ext4`). This is an integration
//! test (its own crate), so it may depend on the dev-only oracle; the library
//! itself never does.

use std::sync::Arc;

use fs_ext4::block_io::BlockDevice;
use fs_ext4::dir::{self, DirEntryType};
use fs_ext4::file_io;
use fs_ext4::fs::Filesystem;
use mvm_ext4::{Node, build_image};

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

#[test]
fn empty_tree_mounts_with_root_dir() {
    let fs = mount(build_image(&[]).unwrap());
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
        },
        Node::File {
            path: "/etc/hosts".into(),
            mode: 0o644,
            data: hosts.clone(),
        },
        Node::File {
            path: "/hello".into(),
            mode: 0o755,
            data: hello.clone(),
        },
        Node::Symlink {
            path: "/etc/localhost".into(),
            target: "hosts".into(),
        },
    ];
    let fs = mount(build_image(&nodes).unwrap());

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

#[test]
fn output_is_deterministic() {
    let nodes = vec![
        Node::Dir {
            path: "/a".into(),
            mode: 0o755,
        },
        Node::File {
            path: "/a/f".into(),
            mode: 0o644,
            data: b"xyz".to_vec(),
        },
    ];
    let one = build_image(&nodes).unwrap();
    let two = build_image(&nodes).unwrap();
    assert_eq!(one, two, "same input must produce byte-identical images");
}
