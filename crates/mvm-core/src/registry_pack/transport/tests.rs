use super::*;
use crate::packs::Sha256Hex;
use crate::plan::KeyId;
use crate::registry_pack::application::{RegistryBundleTransport, RegistryTransportCompression};
use std::io::Write as _;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip input");
    encoder.finish().expect("gzip finish")
}

fn bundle(archive: &[u8], transport: Option<RegistryBundleTransport>) -> RegistryApplicationBundle {
    RegistryApplicationBundle {
        source: "https://bundles.example/test/hello/1.0.0/app.mvmpkg".into(),
        archive_sha256: Sha256Hex::from_bytes(archive),
        archive_size: archive.len() as u64,
        key_id: KeyId("b".repeat(32)),
        transport,
    }
}

fn transport(compressed: &[u8]) -> RegistryBundleTransport {
    RegistryBundleTransport {
        compression: RegistryTransportCompression::Gzip,
        compressed_sha256: Sha256Hex::from_bytes(compressed),
        compressed_size: compressed.len() as u64,
    }
}

fn spool(bytes: &[u8]) -> tempfile::TempPath {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(bytes).expect("write temp file");
    file.into_temp_path()
}

#[test]
fn valid_gzip_transport_recovers_the_signed_tar() {
    let archive = b"signed tar bytes that must come back exactly";
    let compressed = gzip(archive);
    let path = spool(&compressed);
    let out = decompress_transport_archive(&path, &transport(&compressed), &bundle(archive, None))
        .expect("transport decompresses");
    assert_eq!(std::fs::read(&out).expect("read result"), archive);
}

#[test]
fn decompression_bomb_stops_at_the_signed_size_cap() {
    let bomb_source = vec![0_u8; 1024 * 1024];
    let compressed = gzip(&bomb_source);
    let pinned = bundle(&bomb_source[..256], None);
    let path = spool(&compressed);
    let error = decompress_transport_archive(&path, &transport(&compressed), &pinned)
        .expect_err("a bomb exceeding its signed cap must refuse");
    assert!(matches!(error, RegistryTransportError::Size), "{error}");
}

#[test]
fn truncated_gzip_refuses_with_an_error_not_a_panic() {
    let archive = b"some signed content";
    let mut compressed = gzip(archive);
    compressed.truncate(compressed.len() - 4);
    let mut declared = transport(&compressed);
    declared.compressed_sha256 = Sha256Hex::from_bytes(&compressed);
    declared.compressed_size = compressed.len() as u64;
    let path = spool(&compressed);
    assert!(decompress_transport_archive(&path, &declared, &bundle(archive, None)).is_err());
}

#[test]
fn decompressed_digest_mismatch_refuses() {
    // Same length as the signed tar so the size cap cannot fire first.
    let archive = b"the signed tar";
    let other = b"the signed TAR";
    let compressed = gzip(other);
    let path = spool(&compressed);
    let error =
        decompress_transport_archive(&path, &transport(&compressed), &bundle(archive, None))
            .expect_err("decompressed bytes must match the signed descriptor digest");
    assert!(matches!(error, RegistryTransportError::Digest), "{error}");
}

#[test]
fn compressed_size_mismatch_refuses() {
    let archive = b"signed tar";
    let compressed = gzip(archive);
    let mut declared = transport(&compressed);
    declared.compressed_size = compressed.len() as u64 - 1;
    let path = spool(&compressed);
    let error = decompress_transport_archive(&path, &declared, &bundle(archive, None))
        .expect_err("a size-pinned asset must not drift");
    assert!(
        matches!(error, RegistryTransportError::CompressedSize),
        "{error}"
    );
}

#[test]
fn compressed_digest_mismatch_refuses() {
    let archive = b"signed tar";
    let compressed = gzip(archive);
    let mut declared = transport(&compressed);
    declared.compressed_sha256 = Sha256Hex::from_bytes(b"not the asset");
    let path = spool(&compressed);
    let error = decompress_transport_archive(&path, &declared, &bundle(archive, None))
        .expect_err("a digest-pinned asset must not drift");
    assert!(
        matches!(error, RegistryTransportError::CompressedDigest),
        "{error}"
    );
}

#[test]
fn non_gzip_bytes_refuse() {
    let archive = b"signed tar";
    let not_gzip = b"this is not a gzip stream at all";
    let declared = transport(not_gzip);
    let path = spool(not_gzip);
    assert!(decompress_transport_archive(&path, &declared, &bundle(archive, None)).is_err());
}

#[test]
fn short_output_under_the_cap_verifies_when_hashes_match() {
    let archive = b"small";
    let compressed = gzip(archive);
    let path = spool(&compressed);
    let out = decompress_transport_archive(&path, &transport(&compressed), &bundle(archive, None))
        .expect("short output under the cap is fine when hashes match");
    assert_eq!(std::fs::read(&out).expect("read result"), archive);
}
