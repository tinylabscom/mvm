//! `EncryptedStorage` — the non-Linux at-rest `StorageProvider` arm.
//!
//! Wraps the per-file AES-256-GCM volume sealer
//! ([`mvm_core::crypto::volume`]): a volume is plaintext only *while
//! attached*; detach seals every file in place, so at rest the backing dir
//! is ciphertext, and a flipped byte fails the GCM tag on the next open.
//!
//! Linux uses block-level LUKS2 instead (`cryptsetup` over a loop device).
//! That arm is a tracked follow-up — it needs a Linux host + loop devices +
//! root to build and verify, none of which exist on a macOS dev host, and
//! shipping un-compile-checked block-device code would be dishonest. This
//! module is gated exactly like the engine it wraps
//! (`#![cfg(not(target_os = "linux"))]`).
//!
//! The per-volume DEK's binding to the artifact content-hash + signed plan +
//! audit head (`WrappedKey.bound`) is verified at the admit
//! gate *before* the volume is unlocked — not here. This arm only performs
//! the at-rest seal/open with a DEK it's already been handed.
#![cfg(not(target_os = "linux"))]

use std::path::PathBuf;

use mvm_core::crypto::volume;
use mvm_core::volume::VolumeError;
use zeroize::Zeroizing;

use crate::provider::{AttachedVolume, StorageProvider, VolumeHandle, VolumeSpec};

/// At-rest-encrypted `StorageProvider` for non-Linux hosts. Holds the
/// 32-byte per-volume DEK (zeroized on drop) and seals/opens the backing
/// directory around each detach/attach.
pub struct EncryptedStorage {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl EncryptedStorage {
    pub fn new(root: impl Into<PathBuf>, key: [u8; 32]) -> Self {
        Self {
            root: root.into(),
            key: Zeroizing::new(key),
        }
    }
}

impl StorageProvider for EncryptedStorage {
    fn kind(&self) -> &'static str {
        "encrypted"
    }

    fn provision(&self, spec: &VolumeSpec) -> Result<VolumeHandle, VolumeError> {
        let backing = self.root.join(spec.name().as_str());
        std::fs::create_dir_all(&backing)?;
        Ok(VolumeHandle::new(spec.name().clone(), backing))
    }

    fn attach(&self, handle: &VolumeHandle) -> Result<AttachedVolume, VolumeError> {
        // Decrypt the backing dir in place so the guest mount sees plaintext.
        // A tampered ciphertext fails the GCM tag here and surfaces as Err.
        volume::open_dir(handle.backing_path(), &self.key[..])
            .map_err(|e| VolumeError::Other(e.to_string()))?;
        Ok(AttachedVolume::new(
            handle.name().clone(),
            handle.backing_path().to_path_buf(),
        ))
    }

    fn detach(&self, attached: AttachedVolume) -> Result<(), VolumeError> {
        // Re-seal every file so the volume is ciphertext once detached.
        volume::seal_dir(attached.host_path(), &self.key[..])
            .map_err(|e| VolumeError::Other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::volume::VolumeName;

    fn dek() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn encrypted_volume_is_ciphertext_at_rest_and_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = EncryptedStorage::new(tmp.path(), dek());
        let handle = storage
            .provision(&VolumeSpec::new(VolumeName::new("secrets").unwrap()))
            .unwrap();

        // Attach (open), write recognizable plaintext, detach (seal).
        let attached = storage.attach(&handle).unwrap();
        let file = attached.host_path().join("creds.txt");
        std::fs::write(&file, b"RECOGNIZABLE_SECRET_value").unwrap();
        storage.detach(attached).unwrap();

        // At rest the backing bytes are ciphertext — the marker is gone.
        let raw = std::fs::read(&file).unwrap();
        assert!(
            !raw.windows(11).any(|w| w == b"RECOGNIZABLE"),
            "detached volume must be ciphertext at rest"
        );

        // Re-attach: the guest sees plaintext again.
        let attached = storage.attach(&handle).unwrap();
        assert_eq!(
            std::fs::read(attached.host_path().join("creds.txt")).unwrap(),
            b"RECOGNIZABLE_SECRET_value"
        );
        storage.detach(attached).unwrap();
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = EncryptedStorage::new(tmp.path(), dek());
        let handle = storage
            .provision(&VolumeSpec::new(VolumeName::new("vault").unwrap()))
            .unwrap();

        let attached = storage.attach(&handle).unwrap();
        let file = attached.host_path().join("data.bin");
        std::fs::write(&file, b"sensitive volume bytes").unwrap();
        storage.detach(attached).unwrap(); // seals in place

        // Flip the last byte (inside the GCM tag) — the next open must reject.
        let mut raw = std::fs::read(&file).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&file, &raw).unwrap();

        assert!(
            storage.attach(&handle).is_err(),
            "tampered ciphertext must fail the AEAD tag on open"
        );
    }
}
