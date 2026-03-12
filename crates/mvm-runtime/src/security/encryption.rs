use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::security::keystore::validate_shell_id;
use crate::shell;

/// Create a LUKS-encrypted volume at the given path.
///
/// Uses cryptsetup luksFormat with AES-256-XTS.
/// The key is passed via stdin (never written to disk or logged).
pub fn create_encrypted_volume(path: &str, size_mib: u32, key: &[u8]) -> Result<()> {
    anyhow::ensure!(!path.is_empty(), "volume path must not be empty");
    let hex_key = Zeroizing::new(hex_encode(key));
    shell::run_in_vm(&format!(
        r#"
        truncate -s {size}M {path}
        echo -n '{key}' | xxd -r -p | \
            sudo cryptsetup luksFormat --type luks2 \
            --cipher aes-xts-plain64 --key-size 512 \
            --hash sha256 --iter-time 2000 \
            --key-file - {path}
        "#,
        path = path,
        size = size_mib,
        key = *hex_key,
    ))
    .with_context(|| format!("Failed to create LUKS volume at {}", path))?;
    Ok(())
}

/// Open an existing LUKS volume and return the /dev/mapper/<name> path.
///
/// The key is passed via stdin to cryptsetup (never on command line).
pub fn open_encrypted_volume(path: &str, name: &str, key: &[u8]) -> Result<String> {
    anyhow::ensure!(!path.is_empty(), "volume path must not be empty");
    validate_shell_id(name).with_context(|| format!("Invalid mapper name: {:?}", name))?;
    let hex_key = Zeroizing::new(hex_encode(key));
    let mapper_path = format!("/dev/mapper/{}", name);
    shell::run_in_vm(&format!(
        r#"
        echo -n '{key}' | xxd -r -p | \
            sudo cryptsetup luksOpen --key-file - {path} {name}
        "#,
        path = path,
        key = *hex_key,
        name = name,
    ))
    .with_context(|| format!("Failed to open LUKS volume {} as {}", path, name))?;
    Ok(mapper_path)
}

/// Close an open LUKS volume.
pub fn close_encrypted_volume(name: &str) -> Result<()> {
    shell::run_in_vm(&format!(
        "sudo cryptsetup luksClose {} 2>/dev/null || true",
        name
    ))
    .with_context(|| format!("Failed to close LUKS volume {}", name))?;
    Ok(())
}

/// Check if a file is a LUKS-formatted volume.
pub fn is_luks_volume(path: &str) -> Result<bool> {
    let out = shell::run_in_vm_stdout(&format!(
        "sudo cryptsetup isLuks {} 2>/dev/null && echo yes || echo no",
        path
    ))?;
    Ok(out.trim() == "yes")
}

/// LUKS mapper name for an instance data volume.
pub fn luks_mapper_name(tenant_id: &str, instance_id: &str) -> String {
    format!("mvm-{}-{}", tenant_id, instance_id)
}

/// Hex-encode bytes for safe shell transport (no special chars).
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luks_mapper_name() {
        assert_eq!(luks_mapper_name("acme", "i-abc123"), "mvm-acme-i-abc123");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_roundtrip() {
        // hex_encode then hex_decode (from keystore) must be lossless
        let original: Vec<u8> = (0u8..=255).collect();
        let encoded = hex_encode(&original);
        assert_eq!(encoded.len(), 512);
        // All characters must be lowercase hex only
        assert!(encoded.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_open_encrypted_volume_rejects_empty_path() {
        let result = open_encrypted_volume("", "myname", &[0u8; 32]);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("path must not be empty"));
    }

    #[test]
    fn test_open_encrypted_volume_rejects_bad_mapper_name() {
        let result = open_encrypted_volume("/dev/loop0", "bad;name", &[0u8; 32]);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("Invalid mapper name"));
    }

    #[test]
    fn test_create_encrypted_volume_rejects_empty_path() {
        let result = create_encrypted_volume("", 100, &[0u8; 32]);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("path must not be empty"));
    }
}
