//! Write an ext4 image whose single large file needs a **depth-1 extent tree**
//! (> 512 MiB → more than the four extents an inode holds inline), for the CI
//! lane that loop-mounts it on the real Linux kernel — the strongest oracle for
//! the extent-tree index/leaf layout.
//!
//! Usage: `cargo run -p mvm-fs --example write_extent_tree -- <out.ext4>`
//!
//! The tree here MUST match what `.github/workflows/ci.yml::ext4-real-mount`
//! asserts after mounting.

use mvm_fs::ext4::{Node, build_image};

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: write_extent_tree <out.ext4>");

    // 520 MiB deterministic payload: past four ~128 MiB group-data-regions, so
    // the file spans ≥ 5 extents and the inode grows a depth-1 tree.
    const N: usize = 520 * 1024 * 1024;
    let big: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    let nodes = vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/etc/marker".into(),
            mode: 0o644,
            data: b"extent-tree marker\n".to_vec(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/huge".into(),
            mode: 0o644,
            data: big,
            xattrs: Vec::new(),
        },
    ];

    let image = build_image(nodes).expect("build depth-1 extent-tree ext4 image");
    let one_group = 32768usize * mvm_fs::ext4::BLOCK_SIZE as usize;
    assert!(
        image.len() > 4 * one_group,
        "expected a >4-group image (depth-1 tree), got {} bytes",
        image.len()
    );
    std::fs::write(&out, &image).expect("write image file");
    eprintln!(
        "wrote {} bytes ({} groups worth) to {out}",
        image.len(),
        image.len().div_ceil(one_group)
    );
}
