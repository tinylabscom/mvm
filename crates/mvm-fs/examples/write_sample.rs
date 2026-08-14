//! Write a fixed sample ext4 image with the pure-Rust writer, for the CI lane
//! that loop-mounts it on the real Linux kernel (the strongest correctness
//! oracle — beyond the in-process `am-fs-ext4` read oracle).
//!
//! Usage: `cargo run -p mvm-fs --example write_sample -- <out.ext4>`
//!
//! The tree here MUST match what `.github/workflows/ci.yml::ext4-real-mount`
//! asserts after mounting.

use mvm_fs::ext4::{Node, Xattr, build_image};

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: write_sample <out.ext4>");
    // A fixed VFS capability blob (revision 2, cap_net_admin|cap_net_raw
    // permitted). The CI lane reads it back with `getfattr` to prove the real
    // kernel sees the inline xattr the writer emitted, byte-for-byte.
    let cap = vec![
        0x00, 0x00, 0x00, 0x02, // magic_etc: VFS_CAP_REVISION_2 (LE)
        0x00, 0x30, 0x00, 0x00, // permitted lo
        0x00, 0x00, 0x00, 0x00, // inheritable lo
        0x00, 0x00, 0x00, 0x00, // permitted hi
        0x00, 0x00, 0x00, 0x00, // inheritable hi
    ];
    let nodes = vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/etc/hosts".into(),
            mode: 0o644,
            data: b"127.0.0.1 localhost\n".to_vec(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/hello".into(),
            mode: 0o755,
            data: b"hi from pure-rust ext4\n".to_vec(),
            xattrs: Vec::new(),
        },
        Node::Symlink {
            path: "/etc/localhost".into(),
            target: "hosts".into(),
        },
        Node::Dir {
            path: "/bin".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/bin/ping".into(),
            mode: 0o755,
            data: b"\x7fELF fake capability binary".to_vec(),
            xattrs: vec![Xattr {
                name: "security.capability".into(),
                value: cap,
            }],
        },
        // A big file so the image exceeds 128 data blocks (512 KiB) — this
        // forces a MULTI-level verity hash tree, so the byte-for-byte cmp
        // against veritysetup actually exercises the level layout/ordering.
        Node::File {
            path: "/big".into(),
            mode: 0o644,
            data: (0..700 * 1024u32).map(|i| (i % 251) as u8).collect(),
            xattrs: Vec::new(),
        },
    ];
    let image = build_image(nodes).expect("build ext4 image");
    std::fs::write(&out, &image).expect("write image file");
    eprintln!("wrote {} bytes to {out}", image.len());

    // dm-verity (v1, sha256, 4 KiB data+hash blocks, zero salt): write the
    // no-superblock hash tree beside the image and print the root hash, so the
    // CI lane can diff both against real `veritysetup` on the same image.
    // `ROOTHASH <64-hex>` on stdout; `<out>.verity` holds the tree.
    let salt = [0u8; 32];
    let vout = mvm_fs::ext4::verity::format(&image, &salt, 4096, 4096);
    std::fs::write(format!("{out}.verity"), &vout.hash_tree).expect("write hash tree");
    println!("ROOTHASH {}", mvm_fs::ext4::verity::to_hex(&vout.root_hash));
}
