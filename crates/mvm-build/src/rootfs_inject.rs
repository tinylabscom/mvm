//! Self-hosting builder-rootfs bootstrap: inject freshly built mvm host binaries
//! (`/sbin/mvm-host-vm-init`, …) into a builder rootfs using ONLY the hvf
//! VMM — no legacy (vz/libkrun) builder.
//!
//! The mechanism is an initramfs boot: this module builds a newc cpio carrying a
//! tiny patcher init (`mvm-rootfs-patcher`) plus a payload of binaries + a
//! manifest naming their install paths. The hvf VMM boots `kernel +
//! initramfs + the target rootfs as a writable disk`; the patcher mounts the
//! rootfs read-write, copies each payload binary to its install path, and powers
//! off. The result is a rootfs with the current init baked in, produced without a
//! full image rebuild — the primitive that breaks the builder bootstrap
//! chicken-and-egg (a stale init would otherwise need a builder to re-bake).
//!
//! The cpio writer is pure + host-side (no ext4, no VM), so it is unit-testable.

/// One file, directory, or device node in the initramfs.
pub struct CpioEntry {
    /// Archive path, no leading slash (e.g. `init`, `payload/manifest`).
    pub path: String,
    /// Full mode incl. type bits (e.g. `0o100755` for an executable file,
    /// `0o040755` for a directory, `0o020600` for a char device).
    pub mode: u32,
    /// File contents (empty for a directory or device node).
    pub data: Vec<u8>,
    /// `(major, minor)` for a device node; `None` for files and directories.
    /// Written into the newc `rdevmajor`/`rdevminor` header fields so the
    /// kernel materializes the node with the right backing device.
    pub rdev: Option<(u32, u32)>,
}

// newc type bits (subset of S_IFMT). Kept local so the cpio writer has no
// libc dependency and stays host-buildable on every target.
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFMT: u32 = 0o170000;

impl CpioEntry {
    pub fn file(path: &str, mode: u32, data: Vec<u8>) -> Self {
        Self {
            path: path.to_string(),
            mode: S_IFREG | (mode & 0o7777),
            data,
            rdev: None,
        }
    }
    pub fn dir(path: &str) -> Self {
        Self {
            path: path.to_string(),
            mode: S_IFDIR | 0o755,
            data: Vec::new(),
            rdev: None,
        }
    }
    /// A character-special device node (e.g. `/dev/console` = `c 5 1`).
    pub fn char_dev(path: &str, mode: u32, major: u32, minor: u32) -> Self {
        Self {
            path: path.to_string(),
            mode: S_IFCHR | (mode & 0o7777),
            data: Vec::new(),
            rdev: Some((major, minor)),
        }
    }
    /// A block-special device node (e.g. `/dev/vda` = `b 254 0`).
    pub fn block_dev(path: &str, mode: u32, major: u32, minor: u32) -> Self {
        Self {
            path: path.to_string(),
            mode: S_IFBLK | (mode & 0o7777),
            data: Vec::new(),
            rdev: Some((major, minor)),
        }
    }
}

/// Pad `buf` with zeros to the next 4-byte boundary (newc aligns headers + data).
fn pad4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Build a `newc`-format cpio archive from `entries`, in order. Parent
/// directories must precede their children. Appends the mandatory `TRAILER!!!`.
pub fn build_newc_cpio(entries: &[CpioEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    // A unique inode per entry keeps them distinct (the kernel uses it for
    // hardlink detection; unique inodes mean no accidental links).
    for (i, e) in entries.iter().enumerate() {
        write_entry(
            &mut out,
            i as u32 + 1,
            e.mode,
            e.path.as_bytes(),
            &e.data,
            e.rdev.unwrap_or((0, 0)),
        );
    }
    // Trailer: an entry named TRAILER!!! with nlink 1 and no data.
    write_entry(&mut out, 0, 0, b"TRAILER!!!", &[], (0, 0));
    out
}

/// Write one newc record: a 110-byte ASCII header, the NUL-terminated name
/// (padded to 4), then the data (padded to 4). `rdev` is `(major, minor)` for
/// device nodes and `(0, 0)` otherwise.
fn write_entry(out: &mut Vec<u8>, ino: u32, mode: u32, name: &[u8], data: &[u8], rdev: (u32, u32)) {
    let namesize = name.len() as u32 + 1; // includes the trailing NUL
    // Directories get nlink 2 (`.` + `..`); everything else (files AND device
    // nodes) gets 1. The check must mask the full type field — S_IFBLK
    // (0o060000) shares the 0o040000 bit with S_IFDIR, so a bare bit test
    // would misclassify block devices as directories.
    let nlink: u32 = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
    let f = |v: u32| format!("{v:08x}");
    out.extend_from_slice(b"070701"); // newc magic
    out.extend_from_slice(f(ino).as_bytes());
    out.extend_from_slice(f(mode).as_bytes());
    out.extend_from_slice(f(0).as_bytes()); // uid
    out.extend_from_slice(f(0).as_bytes()); // gid
    out.extend_from_slice(f(nlink).as_bytes());
    out.extend_from_slice(f(0).as_bytes()); // mtime
    out.extend_from_slice(f(data.len() as u32).as_bytes()); // filesize
    out.extend_from_slice(f(0).as_bytes()); // devmajor
    out.extend_from_slice(f(0).as_bytes()); // devminor
    out.extend_from_slice(f(rdev.0).as_bytes()); // rdevmajor
    out.extend_from_slice(f(rdev.1).as_bytes()); // rdevminor
    out.extend_from_slice(f(namesize).as_bytes());
    out.extend_from_slice(f(0).as_bytes()); // check (0 for newc)
    out.extend_from_slice(name);
    out.push(0); // NUL terminator
    pad4(out); // align data to 4
    out.extend_from_slice(data);
    pad4(out); // align next header to 4
}

/// One binary to inject into the target rootfs.
pub struct InjectBinary<'a> {
    /// Payload file name inside the initramfs (e.g. `mvm-host-vm-init`).
    pub name: &'a str,
    /// Absolute install path inside the rootfs (e.g. `/sbin/mvm-host-vm-init`).
    pub install_path: &'a str,
    /// Executable bytes.
    pub bytes: Vec<u8>,
}

/// Assemble the injection initramfs: the patcher as `/init`, plus a `/payload`
/// tree carrying a `manifest` (one `"<name> <install_path> <octal-mode>"` line
/// per binary) and the binaries themselves. `mvm-rootfs-patcher` reads the
/// manifest and copies each binary into the rootfs mounted at `/mnt`.
pub fn build_inject_initramfs(patcher: &[u8], binaries: &[InjectBinary<'_>]) -> Vec<u8> {
    let mut manifest = String::new();
    for b in binaries {
        manifest.push_str(&format!("{} {} 0755\n", b.name, b.install_path));
    }

    let mut entries = vec![
        CpioEntry::file("init", 0o755, patcher.to_vec()),
        // Mount points the patcher needs (empty dirs in the ramfs).
        CpioEntry::dir("dev"),
        CpioEntry::dir("proc"),
        CpioEntry::dir("mnt"),
        CpioEntry::dir("payload"),
        CpioEntry::file("payload/manifest", 0o644, manifest.into_bytes()),
    ];
    for b in binaries {
        entries.push(CpioEntry::file(
            &format!("payload/{}", b.name),
            0o755,
            b.bytes.clone(),
        ));
    }
    build_newc_cpio(&entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse just enough of a newc archive to walk its entries: returns
    /// `(name, mode, filesize)` per record, stopping at the trailer.
    fn parse_newc(buf: &[u8]) -> Vec<(String, u32, usize)> {
        let hex = |s: &[u8]| u32::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap();
        let mut out = Vec::new();
        let mut off = 0;
        loop {
            assert_eq!(&buf[off..off + 6], b"070701", "newc magic at {off}");
            let field = |i: usize| hex(&buf[off + 6 + i * 8..off + 6 + i * 8 + 8]);
            let mode = field(1);
            let filesize = field(6) as usize;
            let namesize = field(11) as usize;
            let name_start = off + 110;
            let name =
                String::from_utf8(buf[name_start..name_start + namesize - 1].to_vec()).unwrap();
            // data starts after (header+name) padded to 4.
            let mut data_start = name_start + namesize;
            while !data_start.is_multiple_of(4) {
                data_start += 1;
            }
            if name == "TRAILER!!!" {
                break;
            }
            out.push((name, mode, filesize));
            let mut next = data_start + filesize;
            while !next.is_multiple_of(4) {
                next += 1;
            }
            off = next;
        }
        out
    }

    #[test]
    fn newc_cpio_round_trips_files_and_dirs_with_modes() {
        let entries = vec![
            CpioEntry::file("init", 0o755, b"ELF-PATCHER".to_vec()),
            CpioEntry::dir("payload"),
            CpioEntry::file("payload/manifest", 0o644, b"x y 0755\n".to_vec()),
        ];
        let cpio = build_newc_cpio(&entries);
        assert_eq!(&cpio[..6], b"070701");
        assert_eq!(cpio.len() % 4, 0, "archive is 4-aligned");

        let parsed = parse_newc(&cpio);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], ("init".to_string(), 0o100755, 11));
        assert_eq!(parsed[1].0, "payload");
        assert_eq!(parsed[1].1 & 0o040000, 0o040000); // dir type bit
        assert_eq!(parsed[2], ("payload/manifest".to_string(), 0o100644, 9));
    }

    #[test]
    fn inject_initramfs_carries_the_patcher_manifest_and_binaries() {
        let patcher = b"PATCHER-ELF".to_vec();
        let bins = [
            InjectBinary {
                name: "mvm-host-vm-init",
                install_path: "/sbin/mvm-host-vm-init",
                bytes: b"INIT-ELF".to_vec(),
            },
            InjectBinary {
                name: "mvm-builderd",
                install_path: "/sbin/mvm-builderd",
                bytes: b"BUILDERD-ELF".to_vec(),
            },
        ];
        let cpio = build_inject_initramfs(&patcher, &bins);
        let names: Vec<String> = parse_newc(&cpio).into_iter().map(|(n, _, _)| n).collect();
        assert!(names.contains(&"init".to_string()));
        assert!(names.contains(&"payload/manifest".to_string()));
        assert!(names.contains(&"payload/mvm-host-vm-init".to_string()));
        assert!(names.contains(&"payload/mvm-builderd".to_string()));

        // The manifest maps each payload name to its rootfs install path.
        let entries = parse_newc(&cpio);
        // Find the manifest's byte range to read it back.
        let manifest = extract(&cpio, "payload/manifest");
        assert!(manifest.contains("mvm-host-vm-init /sbin/mvm-host-vm-init 0755"));
        assert!(manifest.contains("mvm-builderd /sbin/mvm-builderd 0755"));
        // /init precedes /payload/* so the patcher is entry 0.
        assert_eq!(entries[0].0, "init");
    }

    /// Read a file entry's data back out of a newc archive (test helper).
    fn extract(buf: &[u8], want: &str) -> String {
        let hex = |s: &[u8]| u32::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap();
        let mut off = 0;
        loop {
            let field = |i: usize| hex(&buf[off + 6 + i * 8..off + 6 + i * 8 + 8]);
            let filesize = field(6) as usize;
            let namesize = field(11) as usize;
            let name_start = off + 110;
            let name =
                String::from_utf8(buf[name_start..name_start + namesize - 1].to_vec()).unwrap();
            let mut data_start = name_start + namesize;
            while !data_start.is_multiple_of(4) {
                data_start += 1;
            }
            if name == "TRAILER!!!" {
                panic!("{want} not found");
            }
            if name == want {
                return String::from_utf8(buf[data_start..data_start + filesize].to_vec()).unwrap();
            }
            let mut next = data_start + filesize;
            while !next.is_multiple_of(4) {
                next += 1;
            }
            off = next;
        }
    }
}
