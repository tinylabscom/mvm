//! Self-hosting builder-rootfs bootstrap: inject freshly built mvm host binaries
//! (`/sbin/mvm-host-vm-init`, …) into a builder rootfs using ONLY the hvf
//! VMM, with no libkrun builder.
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

/// A value the newc header cannot carry: every numeric field is eight hex
/// digits, so anything past `u32::MAX` would be written truncated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CpioError {
    /// A header field (`filesize`, `namesize`, `ino`) or the archive as a whole
    /// does not fit in 32 bits. Only the field and its size are named; the
    /// entry path is caller-controlled and not echoed.
    #[error("cpio {field} of {len} bytes does not fit the 32-bit newc field")]
    FieldTooLarge { field: &'static str, len: u64 },
}

/// A length or count as a newc header value, or the field that overflows it.
fn newc_field(field: &'static str, len: usize) -> Result<u32, CpioError> {
    u32::try_from(len).map_err(|_| CpioError::FieldTooLarge {
        field,
        len: len as u64,
    })
}

/// The `(ino, filesize, namesize)` header values for one entry. Pure, so the
/// overflow edges are testable without allocating the oversized entry.
fn entry_fields(
    index: usize,
    name_len: usize,
    data_len: usize,
) -> Result<(u32, u32, u32), CpioError> {
    let ino = newc_field("inode number", index.saturating_add(1))?;
    let namesize = newc_field("namesize", name_len.saturating_add(1))?; // trailing NUL
    let filesize = newc_field("filesize", data_len)?;
    Ok((ino, filesize, namesize))
}

/// Build a `newc`-format cpio archive from `entries`, in order. Parent
/// directories must precede their children. Appends the mandatory `TRAILER!!!`.
///
/// # Errors
///
/// [`CpioError::FieldTooLarge`] when an entry's size, name length or position,
/// or the archive's total length, exceeds what a newc header can express.
pub fn build_newc_cpio(entries: &[CpioEntry]) -> Result<Vec<u8>, CpioError> {
    let mut out = Vec::new();
    // A unique inode per entry keeps them distinct (the kernel uses it for
    // hardlink detection; unique inodes mean no accidental links).
    for (i, e) in entries.iter().enumerate() {
        let (ino, filesize, namesize) = entry_fields(i, e.path.len(), e.data.len())?;
        write_entry(
            &mut out,
            (ino, filesize, namesize),
            e.mode,
            e.path.as_bytes(),
            &e.data,
            e.rdev.unwrap_or((0, 0)),
        );
        newc_field("archive", out.len())?;
    }
    // Trailer: an entry named TRAILER!!! with nlink 1 and no data.
    let trailer = entry_fields(entries.len(), b"TRAILER!!!".len(), 0)?;
    write_entry(
        &mut out,
        (0, trailer.1, trailer.2),
        0,
        b"TRAILER!!!",
        &[],
        (0, 0),
    );
    newc_field("archive", out.len())?;
    Ok(out)
}

/// Write one newc record: a 110-byte ASCII header, the NUL-terminated name
/// (padded to 4), then the data (padded to 4). `rdev` is `(major, minor)` for
/// device nodes and `(0, 0)` otherwise. `fields` is `(ino, filesize, namesize)`,
/// already checked to fit.
fn write_entry(
    out: &mut Vec<u8>,
    fields: (u32, u32, u32),
    mode: u32,
    name: &[u8],
    data: &[u8],
    rdev: (u32, u32),
) {
    let (ino, filesize, namesize) = fields;
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
    out.extend_from_slice(f(filesize).as_bytes());
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
        let cpio = build_newc_cpio(&entries).unwrap();
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
    fn a_length_past_32_bits_is_refused_without_allocating_it() {
        let over = u32::MAX as usize + 1;
        assert_eq!(
            entry_fields(0, 4, over),
            Err(CpioError::FieldTooLarge {
                field: "filesize",
                len: over as u64
            })
        );
        // namesize counts the trailing NUL, so a name of u32::MAX bytes is already one too long.
        assert!(matches!(
            entry_fields(0, u32::MAX as usize, 0),
            Err(CpioError::FieldTooLarge {
                field: "namesize",
                ..
            })
        ));
        assert!(matches!(
            entry_fields(u32::MAX as usize, 1, 0),
            Err(CpioError::FieldTooLarge {
                field: "inode number",
                ..
            })
        ));
        assert_eq!(entry_fields(0, 4, u32::MAX as usize), Ok((1, u32::MAX, 5)));
    }

    #[test]
    fn the_error_names_the_field_and_size_not_the_path() {
        let err = entry_fields(0, 3, u32::MAX as usize + 7)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("filesize") && err.contains("4294967302"),
            "{err}"
        );
    }
}
