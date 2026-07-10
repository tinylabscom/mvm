//! In-process assembler for the `mvm-verity-init` verity initramfs
//! (`rootfs.initrd`).
//!
//! The verity boot pivot runs `mvm-verity-init` as PID 1 of a tiny initramfs:
//! it mounts pseudo-filesystems, builds the dm-verity device-mapper target(s)
//! via raw ioctls, mounts the verified rootfs at `/sysroot`, then
//! `switch_root`s to the real init. That init must ship as a `cpio.gz` the
//! kernel unpacks into the initial ramfs before it runs `/init`.
//!
//! This module produces that archive on the host — no VM, no `mkinitramfs`, no
//! subprocess — so it is pure and unit-testable. It reuses the newc cpio writer
//! from [`crate::rootfs_inject`] (extended there to emit device nodes) rather
//! than forking a second encoder.
//!
//! The archive carries exactly what `mvm-verity-init` needs to reach its first
//! mount:
//!
//! - `/init` — the `mvm-verity-init` binary, mode 0755.
//! - Device nodes for the console and the four virtio-blk disks the init opens
//!   by path before it mounts devtmpfs over `/dev`. devtmpfs re-materializes
//!   these once mounted; the baked nodes cover the pre-mount window and the
//!   console the kernel attaches stdio to.
//! - The pseudo-fs and pivot mount-point directories.
//!
//! Output is deterministic (fixed mtime/uid/gid = 0, fixed gzip header) so the
//! same init binary always yields byte-identical bytes.

use std::io::Write;

use anyhow::{Context, Result};
use flate2::Compression;

use crate::rootfs_inject::{CpioEntry, build_newc_cpio};

/// Character-device major for `/dev/console` (Linux `MEM` major, minor 1).
const CONSOLE_MAJOR: u32 = 5;
const CONSOLE_MINOR: u32 = 1;

/// Block-device major the virtio-blk disks (`/dev/vda`..`/dev/vdd`) present in
/// the microVM guest. The four disks are the rootfs data + hash devices and the
/// optional runtime-overlay data + hash devices `mvm-verity-init` reads by path
/// (`mvm.data`/`mvm.hash`/`mvm.runtime_data`/`mvm.runtime_hash`, defaulting to
/// vda/vdb/vdc/vdd). devtmpfs owns the authoritative nodes at boot; these baked
/// nodes are the pre-devtmpfs fallback.
const VIRTIO_BLK_MAJOR: u32 = 254;

/// The four virtio-blk device nodes, in disk order (vda..vdd → minor 0..3).
const VIRTIO_BLK_NODES: [(&str, u32); 4] = [
    ("dev/vda", 0),
    ("dev/vdb", 1),
    ("dev/vdc", 2),
    ("dev/vdd", 3),
];

/// The pseudo-fs and pivot mount-point directories `mvm-verity-init` expects to
/// find already present in the initramfs. Parents precede children (newc
/// requires it, and the kernel needs the parent to exist to create the child).
/// `sysroot/mvm/runtime` is baked for completeness even though the `/sysroot`
/// ext4 mount covers it at boot — the real mount target lives in the verified
/// rootfs, per the `mvm-verity-init` overlay contract.
const MOUNT_DIRS: [&str; 6] = [
    "proc",
    "sys",
    "dev",
    "sysroot",
    "sysroot/mvm",
    "sysroot/mvm/runtime",
];

/// Assemble the gzip'd newc cpio verity initramfs carrying `verity_init_bin` as
/// `/init`, the required device nodes, and the mount-point directories.
///
/// Deterministic: two calls with the same `verity_init_bin` return
/// byte-identical output.
pub fn assemble_verity_initramfs(verity_init_bin: &[u8]) -> Result<Vec<u8>> {
    let mut entries = vec![CpioEntry::file("init", 0o755, verity_init_bin.to_vec())];

    // Directories first (parents before children so `dev` exists before the
    // device nodes below, and `sysroot`/`sysroot/mvm` before their children).
    for dir in MOUNT_DIRS {
        entries.push(CpioEntry::dir(dir));
    }

    // Console: the kernel attaches stdio here and the init writes early
    // progress here before devtmpfs is mounted.
    entries.push(CpioEntry::char_dev(
        "dev/console",
        0o600,
        CONSOLE_MAJOR,
        CONSOLE_MINOR,
    ));

    // The four virtio-blk disks the init opens by path.
    for (path, minor) in VIRTIO_BLK_NODES {
        entries.push(CpioEntry::block_dev(path, 0o660, VIRTIO_BLK_MAJOR, minor));
    }

    let cpio = build_newc_cpio(&entries);
    gzip_deterministic(&cpio).context("gzip verity initramfs cpio")
}

/// gzip `data` with a zeroed header (mtime 0, no filename) so the output is a
/// pure function of the input.
fn gzip_deterministic(data: &[u8]) -> Result<Vec<u8>> {
    // GzEncoder's default header already zeroes mtime; the explicit builder
    // pins it so a flate2 default change can't reintroduce a timestamp.
    let mut enc = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    enc.write_all(data).context("gzip write")?;
    enc.finish().context("gzip finish")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A parsed newc record: everything the structural assertions need.
    struct Record {
        name: String,
        mode: u32,
        rdevmajor: u32,
        rdevminor: u32,
        data: Vec<u8>,
    }

    impl Record {
        fn type_bits(&self) -> u32 {
            self.mode & 0o170000
        }
        fn perm_bits(&self) -> u32 {
            self.mode & 0o7777
        }
        fn is_dir(&self) -> bool {
            self.type_bits() == 0o040000
        }
        fn is_char(&self) -> bool {
            self.type_bits() == 0o020000
        }
        fn is_block(&self) -> bool {
            self.type_bits() == 0o060000
        }
        fn is_reg(&self) -> bool {
            self.type_bits() == 0o100000
        }
    }

    /// Parse a newc archive into its records (excluding the trailer), reading
    /// back the fields the assembler is responsible for.
    fn parse_newc(buf: &[u8]) -> Vec<Record> {
        let hex = |s: &[u8]| u32::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap();
        let mut out = Vec::new();
        let mut off = 0;
        loop {
            assert_eq!(&buf[off..off + 6], b"070701", "newc magic at {off}");
            let field = |i: usize| hex(&buf[off + 6 + i * 8..off + 6 + i * 8 + 8]);
            let mode = field(1);
            let filesize = field(6) as usize;
            let rdevmajor = field(9);
            let rdevminor = field(10);
            let namesize = field(11) as usize;
            let name_start = off + 110;
            let name =
                String::from_utf8(buf[name_start..name_start + namesize - 1].to_vec()).unwrap();
            let mut data_start = name_start + namesize;
            while !data_start.is_multiple_of(4) {
                data_start += 1;
            }
            if name == "TRAILER!!!" {
                break;
            }
            let data = buf[data_start..data_start + filesize].to_vec();
            out.push(Record {
                name,
                mode,
                rdevmajor,
                rdevminor,
                data,
            });
            let mut next = data_start + filesize;
            while !next.is_multiple_of(4) {
                next += 1;
            }
            off = next;
        }
        out
    }

    fn gunzip(buf: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut dec = flate2::read::GzDecoder::new(buf);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).expect("gunzip");
        out
    }

    fn records_for(init: &[u8]) -> Vec<Record> {
        let gz = assemble_verity_initramfs(init).expect("assemble");
        parse_newc(&gunzip(&gz))
    }

    fn find<'a>(recs: &'a [Record], name: &str) -> &'a Record {
        recs.iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("record {name} missing"))
    }

    #[test]
    fn init_is_the_passed_binary_mode_0755() {
        let init = b"\x7fELF-fake-verity-init";
        let recs = records_for(init);
        let rec = find(&recs, "init");
        assert!(rec.is_reg(), "/init must be a regular file");
        assert_eq!(rec.perm_bits(), 0o755, "/init must be mode 0755");
        assert_eq!(
            rec.data, init,
            "/init contents must equal the passed binary"
        );
    }

    #[test]
    fn console_node_is_char_5_1() {
        let recs = records_for(b"x");
        let rec = find(&recs, "dev/console");
        assert!(rec.is_char(), "/dev/console must be a char device");
        assert_eq!((rec.rdevmajor, rec.rdevminor), (5, 1));
        assert_eq!(rec.perm_bits(), 0o600);
    }

    #[test]
    fn virtio_blk_nodes_are_block_254_0_through_3() {
        let recs = records_for(b"x");
        for (name, minor) in [
            ("dev/vda", 0),
            ("dev/vdb", 1),
            ("dev/vdc", 2),
            ("dev/vdd", 3),
        ] {
            let rec = find(&recs, name);
            assert!(rec.is_block(), "{name} must be a block device");
            assert_eq!(
                (rec.rdevmajor, rec.rdevminor),
                (254, minor),
                "{name} major/minor"
            );
            assert_eq!(rec.perm_bits(), 0o660, "{name} perms");
        }
    }

    #[test]
    fn mount_point_dirs_present_as_directories() {
        let recs = records_for(b"x");
        for dir in [
            "proc",
            "sys",
            "dev",
            "sysroot",
            "sysroot/mvm",
            "sysroot/mvm/runtime",
        ] {
            let rec = find(&recs, dir);
            assert!(rec.is_dir(), "{dir} must be a directory");
        }
    }

    #[test]
    fn parent_dirs_precede_their_children() {
        // The kernel's cpio unpacker needs `dev` before `dev/console` and
        // `sysroot/mvm` before `sysroot/mvm/runtime`.
        let recs = records_for(b"x");
        let pos = |name: &str| recs.iter().position(|r| r.name == name).unwrap();
        assert!(pos("dev") < pos("dev/console"));
        assert!(pos("dev") < pos("dev/vda"));
        assert!(pos("sysroot") < pos("sysroot/mvm"));
        assert!(pos("sysroot/mvm") < pos("sysroot/mvm/runtime"));
    }

    #[test]
    fn trailer_record_present() {
        // parse_newc stops at TRAILER!!! — assert it exists by scanning the
        // raw (decompressed) bytes for the record name.
        let gz = assemble_verity_initramfs(b"x").expect("assemble");
        let raw = gunzip(&gz);
        assert!(
            raw.windows(b"TRAILER!!!".len()).any(|w| w == b"TRAILER!!!"),
            "cpio must end with the TRAILER!!! record"
        );
    }

    #[test]
    fn output_is_deterministic() {
        let init = b"\x7fELF-deterministic";
        let a = assemble_verity_initramfs(init).expect("assemble a");
        let b = assemble_verity_initramfs(init).expect("assemble b");
        assert_eq!(
            a, b,
            "two assembles of the same binary must be byte-identical"
        );
    }
}
