//! Write a fixed sample ext4 image with the pure-Rust writer, for the CI lane
//! that loop-mounts it on the real Linux kernel (the strongest correctness
//! oracle — beyond the in-process `am-fs-ext4` read oracle).
//!
//! Usage: `cargo run -p mvm-ext4 --example write_sample -- <out.ext4>`
//!
//! The tree here MUST match what `.github/workflows/ci.yml::ext4-real-mount`
//! asserts after mounting.

use mvm_ext4::{Node, build_image};

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: write_sample <out.ext4>");
    let nodes = vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
        },
        Node::File {
            path: "/etc/hosts".into(),
            mode: 0o644,
            data: b"127.0.0.1 localhost\n".to_vec(),
        },
        Node::File {
            path: "/hello".into(),
            mode: 0o755,
            data: b"hi from pure-rust ext4\n".to_vec(),
        },
        Node::Symlink {
            path: "/etc/localhost".into(),
            target: "hosts".into(),
        },
        Node::Dir {
            path: "/bin".into(),
            mode: 0o755,
        },
        // A big file so the image exceeds 128 data blocks (512 KiB) — this
        // forces a MULTI-level verity hash tree, so the byte-for-byte cmp
        // against veritysetup actually exercises the level layout/ordering.
        Node::File {
            path: "/big".into(),
            mode: 0o644,
            data: (0..700 * 1024u32).map(|i| (i % 251) as u8).collect(),
        },
    ];
    let image = build_image(&nodes).expect("build ext4 image");
    std::fs::write(&out, &image).expect("write image file");
    eprintln!("wrote {} bytes to {out}", image.len());

    // dm-verity (v1, sha256, 4 KiB data+hash blocks, zero salt): write the
    // no-superblock hash tree beside the image and print the root hash, so the
    // CI lane can diff both against real `veritysetup` on the same image.
    // `ROOTHASH <64-hex>` on stdout; `<out>.verity` holds the tree.
    let salt = [0u8; 32];
    let vout = mvm_ext4::verity::format(&image, &salt, 4096, 4096);
    std::fs::write(format!("{out}.verity"), &vout.hash_tree).expect("write hash tree");
    println!("ROOTHASH {}", mvm_ext4::verity::to_hex(&vout.root_hash));
}
