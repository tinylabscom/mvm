//! Native inline extended-attribute support: a file's `security.capability`
//! (and other image-semantic xattrs) is written into the inode's in-inode xattr
//! area and reads back identically through the independent `am-fs-ext4` reader.

use std::sync::Arc;

use fs_ext4::block_io::BlockDevice;
use fs_ext4::dir::{self, DirEntryType};
use fs_ext4::file_io;
use fs_ext4::fs::Filesystem;
use mvm_fs::ext4::{Node, Xattr, build_image};

struct MemDev(Vec<u8>);
impl BlockDevice for MemDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        let s = offset as usize;
        buf.copy_from_slice(&self.0[s..s + buf.len()]);
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
}

fn root_entry(fs: &Filesystem, name: &str) -> (u32, DirEntryType) {
    let (inode, _) = fs.read_inode_verified(2).unwrap();
    let data = file_io::read_all(fs, &inode).unwrap();
    dir::parse_block(&data, true)
        .unwrap()
        .into_iter()
        .find(|e| e.name == name.as_bytes())
        .map(|e| (e.inode, e.file_type))
        .unwrap_or_else(|| panic!("/{name} present"))
}

/// A VFS capability blob (vfs_cap_data v2: magic+flags then two u32 pairs) —
/// 24 opaque bytes we must preserve verbatim.
fn cap_value() -> Vec<u8> {
    let mut v = vec![0u8; 24];
    v[0..4].copy_from_slice(&0x0200_0002u32.to_le_bytes()); // VFS_CAP_REVISION_2
    v[4..8].copy_from_slice(&0x0000_2000u32.to_le_bytes()); // permitted: cap_net_bind_service
    v
}

fn read_xattrs(dev: Arc<MemDev>, fs: &Filesystem, ino: u32) -> Vec<fs_ext4::xattr::XattrEntry> {
    let (inode, raw) = fs.read_inode_verified(ino).unwrap();
    fs_ext4::xattr::read_all(dev.as_ref(), &inode, &raw, 256, 4096).unwrap()
}

#[test]
fn file_capability_round_trips_through_the_reader() {
    let cap = cap_value();
    let nodes = vec![Node::File {
        path: "/ping".into(),
        mode: 0o755,
        data: b"\x7fELF".to_vec(),
        xattrs: vec![Xattr {
            name: "security.capability".into(),
            value: cap.clone(),
        }],
    }];
    let dev = Arc::new(MemDev(build_image(&nodes).expect("build with xattr")));
    let fs = Filesystem::mount(dev.clone()).expect("mount");

    let (ino, ft) = root_entry(&fs, "ping");
    assert_eq!(ft, DirEntryType::RegFile);
    let xattrs = read_xattrs(dev, &fs, ino);
    let got = xattrs
        .iter()
        .find(|x| x.name == "security.capability")
        .expect("capability xattr present after round-trip");
    assert_eq!(got.value, cap, "capability bytes must survive verbatim");
}

#[test]
fn xattrs_are_deterministic_and_order_independent() {
    let mk = |order: bool| {
        let mut xattrs = vec![
            Xattr {
                name: "user.a".into(),
                value: b"1".to_vec(),
            },
            Xattr {
                name: "security.capability".into(),
                value: cap_value(),
            },
        ];
        if order {
            xattrs.reverse();
        }
        build_image(&[Node::File {
            path: "/f".into(),
            mode: 0o644,
            data: b"x".to_vec(),
            xattrs,
        }])
        .unwrap()
    };
    assert_eq!(mk(false), mk(true), "xattr order must not affect the image");
}
