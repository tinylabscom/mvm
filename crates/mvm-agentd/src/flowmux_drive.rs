//! The per-boot identity drive a guest reads its FlowMux keys from.
//!
//! The host attaches a small read-only ext4 image carrying the guest's signing
//! key and the host-signer trust anchor (built by
//! `mvm_vmm::host::flowmux_identity`). Every guest init — the Nix-built
//! workload `/init`, the OCI init, Stage 0, and the persistent builder VM —
//! copies those files into `/run/mvm` before starting the egress client,
//! which cannot bind its loopback listener without them.
//!
//! This module is deliberately **not** behind the `addons` feature: the guest
//! inits that mount the drive must reach it without pulling in
//! [`crate::flowmux_keys`]' tokio-backed loader, which would put tokio in the
//! sealed agent's closure.
//!
//! The drive is found by ext4 volume label, not device path. Device
//! enumeration order differs per backend and per attachment set, and mounting
//! the wrong disk as the identity source fails later, during the handshake,
//! where nothing points back at the mount.

#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};

/// ext4 volume label of the identity drive. One declaration, referenced by the
/// host writer too, so a rename cannot leave writer and reader describing
/// different drives.
pub const IDENTITY_DRIVE_LABEL: &str = "mvm-identity";

/// Basename of the guest's 32-byte signing key on the drive.
pub const GUEST_SIGNING_KEY_FILE: &str = "flowmux-guest-signing-key";

/// Basename of the host-signer trust anchor on the drive.
pub const HOST_SIGNER_PUB_FILE: &str = "host-signer.pub";

/// Basename of the guest-visible declared ingress targets on the drive.
pub const INGRESS_TARGETS_FILE: &str = "flowmux-ingress.json";

/// One guest-loopback target keyed by the signed ingress mapping ID.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestIngressTarget {
    /// Stable non-zero ID from the signed ingress mapping.
    pub mapping_id: u16,
    /// Transport the guest loopback service expects.
    pub protocol: mvm_contract::plan::IngressProtocol,
    /// Exact guest-loopback IP address (`127.0.0.1` or `::1`).
    pub guest_addr: String,
    /// Guest-loopback service port.
    pub guest_port: u16,
}

/// Where the guest copies the drive's contents to.
pub const RUN_MVM_DIR: &str = "/run/mvm";

/// Mode the signing key is written with inside the guest.
pub const GUEST_SIGNING_KEY_MODE: u32 = 0o400;

/// Mode the public anchor is written with inside the guest.
pub const HOST_SIGNER_PUB_MODE: u32 = 0o444;

/// Mode the non-secret ingress target map is written with inside the guest.
pub const INGRESS_TARGETS_MODE: u32 = 0o444;

/// Where the kernel lists this guest's block devices.
const SYS_CLASS_BLOCK: &str = "/sys/class/block";

/// Enumerate the guest's virtio-blk devices, in name order.
///
/// A fixed candidate list is not safe here. The host assigns workload block
/// slots dynamically after the fixed rootfs/verity/overlay four
/// (`mvm_vmm::host::spec_map::workload_blocks`), so a run with user volumes
/// pushes the identity drive to an arbitrary slot — past the end of any list
/// short enough to be worth writing down. Enumerating makes the scan
/// independent of both position and count, which is the same reasoning that
/// puts a label on the drive in the first place.
///
/// Name order only decides probe order, not correctness: the label picks the
/// device, so an unlucky order costs a few extra 1 KiB reads.
/// Whether a `/sys/class/block` entry names a whole virtio-blk device.
///
/// Partitions (`vda1`) are excluded: mvm attaches whole unpartitioned devices,
/// and a partition of a labelled disk would otherwise be probed as though it
/// were the disk.
#[must_use]
pub fn is_virtio_block_name(name: &str) -> bool {
    name.len() > 2 && name.starts_with("vd") && name[2..].chars().all(|c| c.is_ascii_lowercase())
}

#[must_use]
pub fn virtio_block_devices() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(SYS_CLASS_BLOCK) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| is_virtio_block_name(name))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| PathBuf::from("/dev").join(name))
        .collect()
}

/// Offset of the ext4 superblock within a device.
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
/// `s_magic` offset within the superblock.
const EXT4_MAGIC_OFFSET_IN_SUPERBLOCK: usize = 0x38;
/// ext4's little-endian magic.
const EXT4_MAGIC_LE: [u8; 2] = [0x53, 0xEF];
/// `s_volume_name` offset within the superblock.
const EXT4_VOLUME_NAME_OFFSET_IN_SUPERBLOCK: usize = 0x78;
/// `s_volume_name` length.
const EXT4_VOLUME_NAME_LEN: usize = 16;

/// Decode the ext4 volume label (`s_volume_name`) from the first superblock in
/// `buf`, matching the layout the in-tree ext4 writer stamps.
///
/// `None` when `buf` is too short, the magic does not match (not ext4, or a
/// zeroed/absent device), or the label is empty or not valid UTF-8.
#[must_use]
pub fn ext4_volume_label_from_superblock(buf: &[u8]) -> Option<String> {
    let magic_off = EXT4_SUPERBLOCK_OFFSET + EXT4_MAGIC_OFFSET_IN_SUPERBLOCK;
    let label_off = EXT4_SUPERBLOCK_OFFSET + EXT4_VOLUME_NAME_OFFSET_IN_SUPERBLOCK;
    if buf.len() < label_off + EXT4_VOLUME_NAME_LEN {
        return None;
    }
    if buf[magic_off..magic_off + EXT4_MAGIC_LE.len()] != EXT4_MAGIC_LE {
        return None;
    }
    let raw = &buf[label_off..label_off + EXT4_VOLUME_NAME_LEN];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&raw[..end]).ok().map(str::to_string)
}

/// How many bytes of a device are needed to decode its label.
#[must_use]
pub const fn label_probe_len() -> usize {
    EXT4_SUPERBLOCK_OFFSET + EXT4_VOLUME_NAME_OFFSET_IN_SUPERBLOCK + EXT4_VOLUME_NAME_LEN
}

/// Read just enough of `path` to decode an ext4 volume label. `None` on any I/O
/// error — missing device, device shorter than a superblock, or not ext4.
#[must_use]
pub fn read_ext4_volume_label(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut buf = vec![0u8; label_probe_len()];
    std::fs::File::open(path).ok()?.read_exact(&mut buf).ok()?;
    ext4_volume_label_from_superblock(&buf)
}

/// Probe `candidates` in order for the first whose ext4 superblock carries
/// `label`. Content-addressed rather than position-addressed: correct
/// regardless of which slot the host attached the labelled disk in.
#[must_use]
pub fn find_labeled_ext4_disk(candidates: &[&str], label: &str) -> Option<PathBuf> {
    find_labeled_ext4_disk_among(candidates.iter().map(Path::new), label)
}

/// [`find_labeled_ext4_disk`] over any iterator of paths — what
/// [`virtio_block_devices`] feeds.
pub fn find_labeled_ext4_disk_among<P: AsRef<Path>>(
    candidates: impl IntoIterator<Item = P>,
    label: &str,
) -> Option<PathBuf> {
    candidates
        .into_iter()
        .find(|path| read_ext4_volume_label(path.as_ref()).as_deref() == Some(label))
        .map(|path| path.as_ref().to_path_buf())
}

/// Why a guest could not provision its FlowMux identity.
#[derive(Debug)]
pub enum IdentityDriveError {
    /// No attached disk carries [`IDENTITY_DRIVE_LABEL`].
    NotAttached,
    /// The drive is there but could not be read.
    Unreadable(String),
}

impl IdentityDriveError {
    /// Return the failures worth printing during unconditional guest setup.
    ///
    /// A boot with no egress policy intentionally has no identity drive, while
    /// a drive that was attached but cannot be read is a real provisioning
    /// failure and must stay visible.
    #[must_use]
    pub fn boot_warning(&self) -> Option<&Self> {
        match self {
            Self::NotAttached => None,
            Self::Unreadable(_) => Some(self),
        }
    }
}

impl std::fmt::Display for IdentityDriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAttached => write!(
                f,
                "no attached disk carries the ext4 label {IDENTITY_DRIVE_LABEL}; \
                 the host did not attach a FlowMux identity drive for this boot"
            ),
            Self::Unreadable(why) => write!(f, "reading the FlowMux identity drive: {why}"),
        }
    }
}

impl std::error::Error for IdentityDriveError {}

#[cfg(target_os = "linux")]
pub use linux::{provision_identity_from_drive, provision_identity_from_drive_for_uid};

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        GUEST_SIGNING_KEY_FILE, GUEST_SIGNING_KEY_MODE, HOST_SIGNER_PUB_FILE, HOST_SIGNER_PUB_MODE,
        IDENTITY_DRIVE_LABEL, INGRESS_TARGETS_FILE, INGRESS_TARGETS_MODE, IdentityDriveError,
        RUN_MVM_DIR, find_labeled_ext4_disk_among, virtio_block_devices,
    };
    use std::path::Path;

    /// Where the drive is mounted while its two files are copied out. Removed
    /// again before the workload runs, so the drive is not part of the guest's
    /// visible filesystem for any longer than the copy takes.
    const MOUNTPOINT: &str = "/run/mvm-identity";

    /// Mount the identity drive, copy its two files into `/run/mvm`, unmount.
    ///
    /// Copying rather than leaving it mounted keeps the guest's steady state
    /// the same whether the material arrived on a drive or, historically, some
    /// other way — every reader looks only at `/run/mvm`.
    pub fn provision_identity_from_drive() -> Result<(), IdentityDriveError> {
        provision_identity_from_drive_with_owner(None)
    }

    /// Provision the identity for a dedicated non-root service uid.
    ///
    /// The short-lived caller must still have mount and ownership privileges.
    /// Only the secret signing key changes owner; the trust anchor and ingress
    /// map remain world-readable public inputs.
    pub fn provision_identity_from_drive_for_uid(uid: u32) -> Result<(), IdentityDriveError> {
        provision_identity_from_drive_with_owner(Some(uid))
    }

    fn provision_identity_from_drive_with_owner(
        signing_key_uid: Option<u32>,
    ) -> Result<(), IdentityDriveError> {
        let device = find_labeled_ext4_disk_among(virtio_block_devices(), IDENTITY_DRIVE_LABEL)
            .ok_or(IdentityDriveError::NotAttached)?;

        std::fs::create_dir_all(MOUNTPOINT).map_err(io_err("create the identity mountpoint"))?;
        mount_ro(&device, MOUNTPOINT)?;

        let copied = copy_identity_files(signing_key_uid);
        // Unmount whatever happened to the copy: leaving the drive mounted
        // would leave the signing key readable in the guest's namespace for
        // the whole run, which is exactly what /run/mvm's modes exist to avoid.
        umount(MOUNTPOINT);
        let _ = std::fs::remove_dir(MOUNTPOINT);
        copied
    }

    fn copy_identity_files(signing_key_uid: Option<u32>) -> Result<(), IdentityDriveError> {
        std::fs::create_dir_all(RUN_MVM_DIR).map_err(io_err("create /run/mvm"))?;
        copy_one(
            GUEST_SIGNING_KEY_FILE,
            GUEST_SIGNING_KEY_MODE,
            "the guest signing key",
            signing_key_uid,
        )?;
        copy_one(
            HOST_SIGNER_PUB_FILE,
            HOST_SIGNER_PUB_MODE,
            "the host-signer anchor",
            None,
        )?;
        copy_one(
            INGRESS_TARGETS_FILE,
            INGRESS_TARGETS_MODE,
            "the declared ingress targets",
            None,
        )
    }

    fn copy_one(
        name: &str,
        mode: u32,
        what: &str,
        owner_uid: Option<u32>,
    ) -> Result<(), IdentityDriveError> {
        use std::os::unix::fs::PermissionsExt;
        let from = Path::new(MOUNTPOINT).join(name);
        let to = Path::new(RUN_MVM_DIR).join(name);
        let bytes = std::fs::read(&from).map_err(io_err(&format!("read {what} from the drive")))?;
        std::fs::write(&to, &bytes).map_err(io_err(&format!("write {what} to /run/mvm")))?;
        if let Some(uid) = owner_uid {
            std::os::unix::fs::chown(&to, Some(uid), Some(uid))
                .map_err(io_err(&format!("assign {what} to service uid {uid}")))?;
        }
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode))
            .map_err(io_err(&format!("set the mode on {what}")))
    }

    /// Mount `device` at `target` read-only.
    ///
    /// Raw `libc::mount` rather than `nix::mount`, matching
    /// [`crate::guest_mount`]: this crate ships in the sealed guest agent and
    /// deliberately does not enable `nix`'s `mount` feature.
    fn mount_ro(device: &Path, target: &str) -> Result<(), IdentityDriveError> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let nul =
            |what: &str| IdentityDriveError::Unreadable(format!("{what} contains an interior NUL"));
        let src = CString::new(device.as_os_str().as_bytes()).map_err(|_| nul("device path"))?;
        let tgt = CString::new(target).map_err(|_| nul("mountpoint"))?;
        let fstype = CString::new("ext4").map_err(|_| nul("fstype"))?;
        let flags = libc::MS_RDONLY | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV;
        // SAFETY: all three pointers are valid NUL-terminated C strings owned by
        // this stack frame and outliving the call; the data pointer is null.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fstype.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(IdentityDriveError::Unreadable(format!(
                "mount {} read-only: {}",
                device.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Best-effort unmount. A failure here leaves the drive mounted, which the
    /// caller cannot fix and which does not stop the boot.
    fn umount(target: &str) {
        use std::ffi::CString;
        let Ok(tgt) = CString::new(target) else {
            return;
        };
        // SAFETY: `tgt` is a valid NUL-terminated C string owned by this frame.
        unsafe {
            libc::umount(tgt.as_ptr());
        }
    }

    fn io_err(what: &str) -> impl Fn(std::io::Error) -> IdentityDriveError + '_ {
        move |e| IdentityDriveError::Unreadable(format!("{what}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A superblock-shaped buffer carrying `label`.
    fn superblock_with_label(label: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; label_probe_len()];
        let magic = EXT4_SUPERBLOCK_OFFSET + EXT4_MAGIC_OFFSET_IN_SUPERBLOCK;
        buf[magic..magic + 2].copy_from_slice(&EXT4_MAGIC_LE);
        let at = EXT4_SUPERBLOCK_OFFSET + EXT4_VOLUME_NAME_OFFSET_IN_SUPERBLOCK;
        buf[at..at + label.len()].copy_from_slice(label);
        buf
    }

    #[test]
    fn the_identity_label_round_trips_through_a_superblock() {
        let buf = superblock_with_label(IDENTITY_DRIVE_LABEL.as_bytes());
        assert_eq!(
            ext4_volume_label_from_superblock(&buf).as_deref(),
            Some(IDENTITY_DRIVE_LABEL)
        );
    }

    #[test]
    fn a_device_without_the_ext4_magic_has_no_label() {
        let mut buf = superblock_with_label(IDENTITY_DRIVE_LABEL.as_bytes());
        let magic = EXT4_SUPERBLOCK_OFFSET + EXT4_MAGIC_OFFSET_IN_SUPERBLOCK;
        buf[magic] = 0;
        assert!(ext4_volume_label_from_superblock(&buf).is_none());
    }

    #[test]
    fn an_empty_label_is_not_a_match() {
        let buf = superblock_with_label(b"");
        assert!(ext4_volume_label_from_superblock(&buf).is_none());
    }

    #[test]
    fn a_short_read_is_not_a_match() {
        let buf = superblock_with_label(IDENTITY_DRIVE_LABEL.as_bytes());
        assert!(ext4_volume_label_from_superblock(&buf[..64]).is_none());
    }

    #[test]
    fn the_wrong_label_does_not_match_the_identity_drive() {
        let buf = superblock_with_label(b"mvm-work");
        assert_eq!(
            ext4_volume_label_from_superblock(&buf).as_deref(),
            Some("mvm-work")
        );
        assert_ne!(
            ext4_volume_label_from_superblock(&buf).as_deref(),
            Some(IDENTITY_DRIVE_LABEL),
            "the work disk must not be mistaken for the identity drive"
        );
    }

    #[test]
    fn find_labeled_ext4_disk_finds_it_wherever_it_was_attached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let decoy = dir.path().join("vda");
        let real = dir.path().join("vdc");
        std::fs::write(&decoy, superblock_with_label(b"mvm-work")).unwrap();
        std::fs::write(
            &real,
            superblock_with_label(IDENTITY_DRIVE_LABEL.as_bytes()),
        )
        .unwrap();
        let missing = dir.path().join("missing");
        let candidates = [
            decoy.to_str().unwrap(),
            missing.to_str().unwrap(),
            real.to_str().unwrap(),
        ];
        assert_eq!(
            find_labeled_ext4_disk(&candidates, IDENTITY_DRIVE_LABEL),
            Some(real)
        );
    }

    #[test]
    fn ext4_volume_label_from_superblock_rejects_too_short_buffers() {
        assert_eq!(ext4_volume_label_from_superblock(&[]), None);
        assert_eq!(ext4_volume_label_from_superblock(&[0u8; 1024]), None);
    }

    #[test]
    fn ext4_volume_label_from_superblock_rejects_wrong_magic() {
        let mut buf = vec![0u8; 1024 + 0x78 + 16];
        buf[1024 + 0x38] = 0xAA;
        buf[1024 + 0x38 + 1] = 0xBB;
        buf[1024 + 0x78..1024 + 0x78 + 8].copy_from_slice(b"mvm-work");
        assert_eq!(ext4_volume_label_from_superblock(&buf), None);
    }

    #[test]
    fn ext4_volume_label_from_superblock_rejects_empty_label() {
        let mut buf = vec![0u8; 1024 + 0x78 + 16];
        buf[1024 + 0x38] = 0x53;
        buf[1024 + 0x38 + 1] = 0xEF;
        // Label bytes left all-zero.
        assert_eq!(ext4_volume_label_from_superblock(&buf), None);
    }

    #[test]
    fn ext4_volume_label_from_superblock_decodes_a_nul_padded_label() {
        let mut buf = vec![0u8; 1024 + 0x78 + 16];
        buf[1024 + 0x38] = 0x53;
        buf[1024 + 0x38 + 1] = 0xEF;
        buf[1024 + 0x78..1024 + 0x78 + 8].copy_from_slice(b"mvm-work");
        assert_eq!(
            ext4_volume_label_from_superblock(&buf),
            Some("mvm-work".to_string())
        );
    }

    #[test]
    fn ext4_volume_label_from_superblock_decodes_a_full_16_byte_label() {
        // No trailing NUL at all — the full field is label content.
        let mut buf = vec![0u8; 1024 + 0x78 + 16];
        buf[1024 + 0x38] = 0x53;
        buf[1024 + 0x38 + 1] = 0xEF;
        buf[1024 + 0x78..1024 + 0x78 + 16].copy_from_slice(b"0123456789abcdef");
        assert_eq!(
            ext4_volume_label_from_superblock(&buf),
            Some("0123456789abcdef".to_string())
        );
    }

    #[test]
    fn find_labeled_ext4_disk_picks_the_matching_candidate_regardless_of_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut labeled = vec![0u8; 1024 + 0x78 + 16];
        labeled[1024 + 0x38] = 0x53;
        labeled[1024 + 0x38 + 1] = 0xEF;
        labeled[1024 + 0x78..1024 + 0x78 + 8].copy_from_slice(b"mvm-work");
        let other = vec![0u8; 1024 + 0x78 + 16]; // no magic at all — e.g. an empty/unformatted disk

        // The labeled device is the SECOND candidate — the scan must not
        // assume it's always first (content-addressed, not position-addressed).
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&first, &other).expect("write first");
        std::fs::write(&second, &labeled).expect("write second");

        let first_str = first.to_str().expect("utf8 path");
        let second_str = second.to_str().expect("utf8 path");
        let found = find_labeled_ext4_disk(&[first_str, second_str], "mvm-work");
        assert_eq!(found, Some(second));
    }

    #[test]
    fn find_labeled_ext4_disk_returns_none_when_nothing_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unformatted = dir.path().join("unformatted");
        std::fs::write(&unformatted, vec![0u8; 1024 + 0x78 + 16]).expect("write");
        let missing = dir.path().join("does-not-exist");

        let unformatted_str = unformatted.to_str().expect("utf8 path");
        let missing_str = missing.to_str().expect("utf8 path");
        assert_eq!(
            find_labeled_ext4_disk(&[missing_str, unformatted_str], "mvm-work"),
            None
        );
    }

    #[test]
    fn whole_virtio_disks_are_probed_and_partitions_are_not() {
        for whole in ["vda", "vdb", "vdz", "vdaa"] {
            assert!(is_virtio_block_name(whole), "{whole} is a whole disk");
        }
        for other in ["vda1", "vdb12", "sda", "nvme0n1", "vd", "loop0", ""] {
            assert!(!is_virtio_block_name(other), "{other} must not be probed");
        }
    }

    #[test]
    fn the_scan_is_not_bounded_by_a_fixed_slot_list() {
        // The host assigns workload block slots dynamically after the fixed
        // four, so a run with user volumes can push the identity drive well
        // past any hand-written candidate list. Names far down the alphabet
        // must still be probed.
        assert!(is_virtio_block_name("vdm"));
        assert!(is_virtio_block_name("vdz"));
    }

    #[test]
    fn find_labeled_ext4_disk_among_accepts_enumerated_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("vdq");
        std::fs::write(
            &real,
            superblock_with_label(IDENTITY_DRIVE_LABEL.as_bytes()),
        )
        .unwrap();
        let decoy = dir.path().join("vdb");
        std::fs::write(&decoy, superblock_with_label(b"mvm-work")).unwrap();
        assert_eq!(
            find_labeled_ext4_disk_among([decoy, real.clone()], IDENTITY_DRIVE_LABEL),
            Some(real)
        );
    }

    #[test]
    fn a_missing_drive_reports_that_the_host_did_not_attach_one() {
        let rendered = IdentityDriveError::NotAttached.to_string();
        assert!(rendered.contains(IDENTITY_DRIVE_LABEL), "{rendered}");
        assert!(rendered.contains("did not attach"), "{rendered}");
    }

    #[test]
    fn an_unattached_identity_drive_is_an_expected_secretless_boot() {
        assert!(IdentityDriveError::NotAttached.boot_warning().is_none());
    }

    #[test]
    fn an_attached_but_unreadable_identity_drive_stays_loud() {
        let error = IdentityDriveError::Unreadable("mount refused".to_owned());
        let warning = error
            .boot_warning()
            .expect("an unreadable attached drive must remain visible");
        assert_eq!(
            warning.to_string(),
            "reading the FlowMux identity drive: mount refused"
        );
    }
}
