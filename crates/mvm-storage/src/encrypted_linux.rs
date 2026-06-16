//! `EncryptedStorage` — the Linux at-rest `StorageProvider` arm: block-level
//! LUKS2 over a loop-backed image (`cryptsetup`), the counterpart to the
//! non-Linux per-file AEAD arm in [`crate::encrypted`]. Same type name +
//! constructor on both platforms so callers never branch on `target_os`.
//!
//! A volume is a LUKS2 image file under `root`. `provision` formats it once
//! (`luksFormat` + an ext4 filesystem laid on the opened mapper); `attach`
//! `luksOpen`s it onto a loop-backed `/dev/mapper` device and mounts it,
//! handing the guest a plaintext mountpoint; `detach` unmounts + `luksClose`s.
//! At rest the image is LUKS2 ciphertext, so the plaintext never survives a
//! detach — the block-device analogue of the non-Linux arm's per-file seal.
//!
//! **Integrity scope.** Plain LUKS2 (aes-xts, no `dm-integrity`) authenticates
//! the *keyslot*, not data blocks: a wrong DEK fails `luksOpen`, but a flipped
//! data byte decrypts to garbage without a hard open-time error. That matches
//! this arm's job — confidentiality at rest. Block-level tamper *detection* is
//! dm-verity's domain (claim 3), a separate path. So the tamper test here is
//! "wrong key fails to open", the guarantee LUKS2 actually makes.
//!
//! Like `mvm_core::rotate_luks_slot`, the live path needs a real `cryptsetup`
//! binary, loop devices, and root, so the full lifecycle test is gated behind
//! `MVM_LIVE_LUKS=1`; the non-gated test covers the fail-closed path that runs
//! on any host. The DEK's binding to the artifact hash + signed plan + audit
//! head is verified at the admit gate before unlock, not here.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mvm_core::volume::{VolumeError, VolumeName};
use zeroize::Zeroizing;

use crate::provider::{AttachedVolume, StorageProvider, VolumeHandle, VolumeSpec};

/// Backing-image size used when a [`VolumeSpec`] doesn't pin one. Must clear
/// the LUKS2 header (16 MiB default metadata + alignment) with room for a
/// usable filesystem.
const DEFAULT_VOLUME_MIB: u64 = 256;

/// Raw DEK length cryptsetup reads from the key-file. The DEK is 32 bytes; we
/// pass `--keyfile-size` so an embedded `0x0a` can't be read as a key
/// terminator (the reason a key *file* is used over piping the DEK on stdin).
const DEK_BYTES: usize = 32;

/// Block-level at-rest-encrypted `StorageProvider` for Linux hosts. Holds the
/// 32-byte per-volume DEK (zeroized on drop) and drives `cryptsetup` around
/// each provision/attach/detach.
pub struct EncryptedStorage {
    root: PathBuf,
    key: Zeroizing<[u8; DEK_BYTES]>,
    default_size_mib: u64,
}

impl EncryptedStorage {
    /// Same signature as the non-Linux arm so callers don't branch. Per-volume
    /// size comes from [`VolumeSpec::with_size_mib`], falling back to
    /// `DEFAULT_VOLUME_MIB`.
    pub fn new(root: impl Into<PathBuf>, key: [u8; DEK_BYTES]) -> Self {
        Self {
            root: root.into(),
            key: Zeroizing::new(key),
            default_size_mib: DEFAULT_VOLUME_MIB,
        }
    }

    fn image_path(&self, name: &VolumeName) -> PathBuf {
        self.root.join(format!("{}.luks", name.as_str()))
    }

    fn mount_path(&self, name: &VolumeName) -> PathBuf {
        self.root.join(format!("{}.mnt", name.as_str()))
    }

    /// `/dev/mapper` node name for a volume. A volume is open at most once at a
    /// time (detach consumes the `AttachedVolume`), so the name need only be
    /// stable, not per-attach unique.
    fn mapper_name(name: &VolumeName) -> String {
        format!("mvm-{}", name.as_str())
    }

    fn mapper_dev(name: &VolumeName) -> PathBuf {
        Path::new("/dev/mapper").join(Self::mapper_name(name))
    }
}

impl StorageProvider for EncryptedStorage {
    fn kind(&self) -> &'static str {
        "encrypted"
    }

    fn provision(&self, spec: &VolumeSpec) -> Result<VolumeHandle, VolumeError> {
        std::fs::create_dir_all(&self.root)?;
        let image = self.image_path(spec.name());
        // Idempotent: an already-formatted image returns its handle untouched —
        // re-formatting would destroy the volume's data.
        if image.exists() {
            return Ok(VolumeHandle::new(spec.name().clone(), image));
        }

        // Sparse-allocate the backing image (LUKS writes blocks on demand).
        let size = spec.size_mib().unwrap_or(self.default_size_mib);
        let f = std::fs::File::create(&image)?;
        f.set_len(size * 1024 * 1024)?;
        drop(f);

        // Roll back the half-made image if any format step fails, so a retry
        // re-enters the from-scratch path rather than the idempotent shortcut.
        let result = self.format_image(spec.name(), &image);
        if result.is_err() {
            let _ = std::fs::remove_file(&image);
        }
        result.map(|()| VolumeHandle::new(spec.name().clone(), image))
    }

    fn attach(&self, handle: &VolumeHandle) -> Result<AttachedVolume, VolumeError> {
        let name = handle.name();
        let key_file = write_key_tempfile(&self.key[..])?;
        let mapper = Self::mapper_name(name);

        // luksOpen — a wrong DEK fails the keyslot here and surfaces as Err.
        let mut open = Command::new("cryptsetup");
        open.arg("luksOpen")
            .arg(handle.backing_path())
            .arg(&mapper)
            .arg("--key-file")
            .arg(key_file.path())
            .arg("--keyfile-size")
            .arg(DEK_BYTES.to_string());
        check(open, "cryptsetup luksOpen")?;

        let mnt = self.mount_path(name);
        if let Err(e) = std::fs::create_dir_all(&mnt) {
            let _ = close_mapper(&mapper);
            return Err(e.into());
        }
        let mut mount = Command::new("mount");
        mount.arg(Self::mapper_dev(name)).arg(&mnt);
        if let Err(e) = check(mount, "mount") {
            let _ = close_mapper(&mapper);
            return Err(e);
        }
        Ok(AttachedVolume::new(name.clone(), mnt))
    }

    fn detach(&self, attached: AttachedVolume) -> Result<(), VolumeError> {
        // host_path is the mountpoint; the name recovers the mapper node. Always
        // attempt the luksClose even if umount failed, so a stuck mount doesn't
        // strand the mapper open.
        let mut umount = Command::new("umount");
        umount.arg(attached.host_path());
        let umount_result = check(umount, "umount");
        let close_result = close_mapper(&Self::mapper_name(attached.name()));
        umount_result.and(close_result)
    }
}

impl EncryptedStorage {
    /// luksFormat the image, then open → `mkfs.ext4` → close so the volume
    /// carries a filesystem before its first attach. Factored out so
    /// `provision` can roll back the image on any failure.
    fn format_image(&self, name: &VolumeName, image: &Path) -> Result<(), VolumeError> {
        let key_file = write_key_tempfile(&self.key[..])?;

        let mut format = Command::new("cryptsetup");
        format
            .arg("luksFormat")
            .arg("--type")
            .arg("luks2")
            .arg("--batch-mode") // skip the interactive "YES" confirmation
            .arg(image)
            .arg("--key-file")
            .arg(key_file.path())
            .arg("--keyfile-size")
            .arg(DEK_BYTES.to_string());
        check(format, "cryptsetup luksFormat")?;

        let mapper = Self::mapper_name(name);
        let mut open = Command::new("cryptsetup");
        open.arg("luksOpen")
            .arg(image)
            .arg(&mapper)
            .arg("--key-file")
            .arg(key_file.path())
            .arg("--keyfile-size")
            .arg(DEK_BYTES.to_string());
        check(open, "cryptsetup luksOpen")?;

        // mkfs on the opened mapper; close unconditionally afterwards.
        let mut mkfs = Command::new("mkfs.ext4");
        mkfs.arg("-q").arg(Self::mapper_dev(name));
        let mkfs_result = check(mkfs, "mkfs.ext4");
        let close_result = close_mapper(&mapper);
        mkfs_result.and(close_result)
    }
}

/// Close a `/dev/mapper` LUKS node. Separate fn so attach's rollback path and
/// detach share one definition.
fn close_mapper(mapper: &str) -> Result<(), VolumeError> {
    let mut close = Command::new("cryptsetup");
    close.arg("luksClose").arg(mapper);
    check(close, "cryptsetup luksClose")
}

/// Stage the raw DEK in a 0600 named tempfile (auto-unlinked on drop, even on
/// panic). cryptsetup reads it via `--key-file`; a file read is byte-exact
/// (with `--keyfile-size`), unlike stdin where an embedded newline could
/// truncate the key.
fn write_key_tempfile(bytes: &[u8]) -> Result<tempfile::NamedTempFile, VolumeError> {
    let mut tf = tempfile::Builder::new()
        .prefix("mvm-luks-key-")
        .tempfile()
        .map_err(|e| VolumeError::Other(format!("create key tempfile: {e}")))?;
    std::fs::set_permissions(tf.path(), std::fs::Permissions::from_mode(0o600))?;
    tf.write_all(bytes)?;
    tf.flush().ok();
    Ok(tf)
}

/// Run a built command, mapping a missing binary or non-zero exit to a
/// fail-closed [`VolumeError`]. stdin is `/dev/null` so cryptsetup never blocks
/// on an interactive prompt (we always pass `--key-file`).
fn check(mut cmd: Command, what: &str) -> Result<(), VolumeError> {
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?; // a missing binary → io::Error → VolumeError::Io (fail-closed)
    if !out.status.success() {
        return Err(VolumeError::Other(format!(
            "{what} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a handle pointing at `path` without provisioning (so a non-LUKS
    /// file can be fed to `attach`). `VolumeHandle::new` is `pub(crate)`.
    fn handle_at(name: &str, path: PathBuf) -> VolumeHandle {
        VolumeHandle::new(VolumeName::new(name).unwrap(), path)
    }

    #[test]
    fn attach_fails_closed_on_non_luks_backing() {
        // Runs on any host: cryptsetup luksOpen on a non-LUKS file fails ("not a
        // valid LUKS device"); a missing cryptsetup binary fails with io::Error.
        // Either way attach must surface Err, never a silent success that would
        // hand a guest an unencrypted/garbage mount.
        let tmp = tempfile::tempdir().unwrap();
        let garbage = tmp.path().join("garbage.luks");
        std::fs::write(&garbage, b"this is not a LUKS2 header").unwrap();
        let storage = EncryptedStorage::new(tmp.path(), [0x11; DEK_BYTES]);
        assert!(
            storage.attach(&handle_at("vol", garbage)).is_err(),
            "attach on a non-LUKS backing must fail closed"
        );
    }

    /// Skip-or-run guard for the live `cryptsetup` path. Returns false (skip)
    /// unless `MVM_LIVE_LUKS=1`; mirrors `mvm_core::rotate_luks_slot`'s gate.
    fn live_luks() -> bool {
        if std::env::var("MVM_LIVE_LUKS").as_deref() == Ok("1") {
            return true;
        }
        eprintln!("skip: set MVM_LIVE_LUKS=1 (needs root + cryptsetup + loop) to run");
        false
    }

    #[test]
    fn luks_volume_roundtrips_and_is_ciphertext_at_rest() {
        if !live_luks() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let storage = EncryptedStorage::new(tmp.path(), [0xAB; DEK_BYTES]);
        // 64 MiB clears the LUKS2 header with room for an ext4 fs.
        let spec = VolumeSpec::new(VolumeName::new("secrets").unwrap()).with_size_mib(64);

        let handle = storage.provision(&spec).unwrap();
        let attached = storage.attach(&handle).unwrap();
        let file = attached.host_path().join("creds.txt");
        std::fs::write(&file, b"RECOGNIZABLE_SECRET_value").unwrap();
        storage.detach(attached).unwrap();

        // At rest the LUKS2 image must not contain the plaintext marker.
        let raw = std::fs::read(handle.backing_path()).unwrap();
        assert!(
            !raw.windows(12).any(|w| w == b"RECOGNIZABLE"),
            "detached LUKS image must be ciphertext at rest"
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
    fn luks_open_with_wrong_key_fails() {
        if !live_luks() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let spec = VolumeSpec::new(VolumeName::new("vault").unwrap()).with_size_mib(64);

        // Format under key A.
        let storage_a = EncryptedStorage::new(tmp.path(), [0x01; DEK_BYTES]);
        let handle = storage_a.provision(&spec).unwrap();

        // A provider with a different DEK must fail the keyslot on open — the
        // confidentiality guarantee LUKS2 actually makes (cf. the module-level
        // integrity-scope note: data-block tamper detection is dm-verity's job).
        let storage_b = EncryptedStorage::new(tmp.path(), [0x02; DEK_BYTES]);
        assert!(
            storage_b.attach(&handle).is_err(),
            "luksOpen with the wrong DEK must fail"
        );

        // The correct key still opens — proves the format wasn't corrupted.
        let attached = storage_a.attach(&handle).unwrap();
        storage_a.detach(attached).unwrap();
    }
}
