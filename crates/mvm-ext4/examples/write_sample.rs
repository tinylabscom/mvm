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
    ];
    let image = build_image(&nodes).expect("build ext4 image");
    std::fs::write(&out, &image).expect("write image file");
    eprintln!("wrote {} bytes to {out}", image.len());

    // Print our dm-verity root hash (v1, sha256, 4 KiB data+hash blocks, zero
    // salt) so the CI lane can diff it against real `veritysetup` on the same
    // image. Single stdout line: `ROOTHASH <64-hex>`.
    let salt = [0u8; 32];
    let root = mvm_ext4::verity::root_hash(&image, &salt, 4096, 4096);
    println!("ROOTHASH {}", mvm_ext4::verity::to_hex(&root));
}
