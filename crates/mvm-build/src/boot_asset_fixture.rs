//! Synthetic archive fixtures for offline admission tests, not boot witnesses.
use mvm_core::arch::GuestArch;
use mvm_core::plan::bundle::sha256_hex;
use mvm_fs::ext4::{Node, Owner};

pub fn valid_overlay_ext4_bytes() -> Vec<u8> {
    let mut nodes: Vec<Node> = mvm_fs::overlay::REQUIRED_OVERLAY_GUEST_PATHS
        .iter()
        .filter(|path| **path != "/VERSION")
        .map(|path| Node::File {
            path: (*path).to_string(),
            mode: 0o555,
            data: path.as_bytes().to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        })
        .collect();
    nodes.push(Node::File {
        path: "/VERSION".into(),
        mode: 0o444,
        data: b"0.14.0\n".to_vec(),
        xattrs: Vec::new(),
        owner: Owner::ROOT,
    });
    mvm_fs::ext4::build_image(nodes, &Default::default()).expect("build valid overlay ext4 fixture")
}

pub fn runtime_overlay_archive_bytes(
    arch: GuestArch,
    ext4_bytes: &[u8],
    verity_bytes: &[u8],
    roothash_bytes: &[u8],
    version_bytes: &[u8],
) -> Vec<u8> {
    let guest_files: Vec<(&str, Vec<u8>)> =
        crate::guest_agent_build::OCI_GUEST_RUNTIME_BINARY_NAMES
            .iter()
            .map(|name| {
                (
                    *name,
                    crate::guest_agent_build::fake_static_elf(arch, name.as_bytes()),
                )
            })
            .collect();
    let mut checksums = format!(
        "{}  overlay.ext4\n{}  overlay.verity\n{}  overlay.roothash\n{}  VERSION\n",
        sha256_hex(ext4_bytes),
        sha256_hex(verity_bytes),
        sha256_hex(roothash_bytes),
        sha256_hex(version_bytes),
    );
    for (name, bytes) in &guest_files {
        checksums.push_str(&format!("{}  {name}\n", sha256_hex(bytes)));
    }
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    append_archive_file(&mut tar, "overlay.ext4", ext4_bytes);
    append_archive_file(&mut tar, "overlay.verity", verity_bytes);
    append_archive_file(&mut tar, "overlay.roothash", roothash_bytes);
    append_archive_file(&mut tar, "VERSION", version_bytes);
    for (name, bytes) in &guest_files {
        append_archive_file(&mut tar, name, bytes);
    }
    append_archive_file(&mut tar, "checksums-sha256.txt", checksums.as_bytes());
    tar.into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

pub fn initramfs_archive_bytes(
    image_bytes: &[u8],
    hash_bytes: &[u8],
    size_bytes: &[u8],
    version_bytes: &[u8],
) -> Vec<u8> {
    let checksums = format!(
        "{}  initramfs.cpio.gz\n{}  initramfs.hash\n{}  initramfs.size\n{}  VERSION\n",
        sha256_hex(image_bytes),
        sha256_hex(hash_bytes),
        sha256_hex(size_bytes),
        sha256_hex(version_bytes),
    );
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    append_archive_file(&mut tar, "initramfs.cpio.gz", image_bytes);
    append_archive_file(&mut tar, "initramfs.hash", hash_bytes);
    append_archive_file(&mut tar, "initramfs.size", size_bytes);
    append_archive_file(&mut tar, "VERSION", version_bytes);
    append_archive_file(&mut tar, "checksums-sha256.txt", checksums.as_bytes());
    tar.into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

/// Real gzip bytes, their uncompressed digest, and compressed size.
pub fn initramfs_fixture(payload: &[u8]) -> (Vec<u8>, String, String) {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("write gzip");
    let image = encoder.finish().expect("finish gzip");
    let hash = sha256_hex(payload);
    let size = image.len().to_string();
    (image, hash, size)
}

fn append_archive_file<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(u64::try_from(bytes.len()).expect("fixture size"));
    header.set_cksum();
    tar.append_data(&mut header, path, bytes)
        .expect("append fixture");
}
