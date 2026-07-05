//! Write a **multi-block-group** ext4 image (> 128 MiB, so it needs a second
//! block group) for the CI lane that loop-mounts it on the real Linux kernel —
//! the strongest oracle for the multi-group layout the single-group sample
//! can't reach.
//!
//! Usage: `cargo run -p mvm-ext4 --example write_multigroup -- <out.ext4>`
//!
//! The tree here MUST match what `.github/workflows/ci.yml::ext4-real-mount`
//! asserts after mounting.

use mvm_ext4::{Node, build_image};

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: write_multigroup <out.ext4>");

    // 130 MiB deterministic payload: past one group's 128 MiB, so the file
    // spans two groups' data regions as two extents.
    let big: Vec<u8> = (0..130 * 1024 * 1024usize)
        .map(|i| (i % 251) as u8)
        .collect();
    let nodes = vec![
        Node::Dir {
            path: "/etc".into(),
            mode: 0o755,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/etc/marker".into(),
            mode: 0o644,
            data: b"multi-group marker\n".to_vec(),
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/big".into(),
            mode: 0o644,
            data: big,
            xattrs: Vec::new(),
        },
    ];

    let image = build_image(&nodes).expect("build multi-group ext4 image");
    let one_group = 32768usize * mvm_ext4::BLOCK_SIZE as usize;
    assert!(
        image.len() > one_group,
        "expected a multi-group image, got {} bytes",
        image.len()
    );
    std::fs::write(&out, &image).expect("write image file");
    eprintln!(
        "wrote {} bytes ({} groups worth) to {out}",
        image.len(),
        image.len().div_ceil(one_group)
    );
}
