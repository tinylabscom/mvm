use mvm_cli::host_binaries::embedded::EMBEDDED;
use sha2::{Digest, Sha256};

#[test]
fn each_embedded_binary_starts_with_elf_magic() {
    for bin in EMBEDDED.iter() {
        if bin.bytes.is_empty() {
            continue;
        }
        assert!(
            bin.bytes.len() > 1024,
            "{}: non-stub payload is implausibly small",
            bin.name
        );
        assert_eq!(
            &bin.bytes[..4],
            &[0x7F, b'E', b'L', b'F'],
            "{}: non-stub payload is not an ELF binary",
            bin.name
        );
    }
}

#[test]
fn embedded_sha256_matches_payload() {
    for bin in EMBEDDED.iter() {
        let mut h = Sha256::new();
        h.update(bin.bytes);
        let actual = hex::encode(h.finalize());
        assert_eq!(actual, bin.sha256_hex, "{}: embedded hash drift", bin.name);
    }
}
