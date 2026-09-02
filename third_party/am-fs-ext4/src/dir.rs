//! Linear directory entry parsing.
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/directory.html
//!
//! A directory is a regular file whose contents are a sequence of variable-length
//! records (`ext4_dir_entry_2`). Each record:
//!   0x00 u32 inode      (0 = unused entry)
//!   0x04 u16 rec_len    (distance to next record; multiple of 4)
//!   0x06 u8  name_len   (low 8 bits when FILETYPE; rev<0.5 had a u16 split)
//!   0x07 u8  file_type  (when FILETYPE feature; otherwise high byte of name_len)
//!   0x08 .. name (name_len bytes, NOT null-terminated, padded to 4-byte align)
//!
//! When METADATA_CSUM is enabled, the last 12 bytes of each block are a fake
//! "tail" entry: inode=0, rec_len=12, name_len=0, file_type=0xDE, csum (u32).

use crate::checksum::Checksummer;
use crate::error::{Error, Result};

/// File-type byte in a directory entry (when FILETYPE feature is set).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirEntryType {
    Unknown = 0,
    RegFile = 1,
    Directory = 2,
    CharDev = 3,
    BlockDev = 4,
    Fifo = 5,
    Socket = 6,
    Symlink = 7,
}

impl DirEntryType {
    pub fn from_u8(b: u8) -> Self {
        match b {
            1 => Self::RegFile,
            2 => Self::Directory,
            3 => Self::CharDev,
            4 => Self::BlockDev,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::Symlink,
            _ => Self::Unknown,
        }
    }
}

/// Parsed directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u32,
    pub name: Vec<u8>,
    pub file_type: DirEntryType,
}

/// Iterator over directory entries in a single data block.
///
/// Skips entries with `inode == 0` (unused / tombstone) and the metadata-csum
/// tail entry (file_type == 0xDE, name_len == 0).
pub struct DirBlockIter<'a> {
    buf: &'a [u8],
    offset: usize,
    /// When true, the FILETYPE feature is on so byte 0x07 is file_type;
    /// otherwise it's the high byte of name_len.
    has_file_type: bool,
}

impl<'a> DirBlockIter<'a> {
    pub fn new(buf: &'a [u8], has_file_type: bool) -> Self {
        Self {
            buf,
            offset: 0,
            has_file_type,
        }
    }
}

impl<'a> Iterator for DirBlockIter<'a> {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset + 8 > self.buf.len() {
                return None;
            }

            let inode_bytes = &self.buf[self.offset..self.offset + 4];
            let inode = u32::from_le_bytes(inode_bytes.try_into().unwrap());
            let rec_len = u16::from_le_bytes(
                self.buf[self.offset + 4..self.offset + 6]
                    .try_into()
                    .unwrap(),
            );

            // Sanity-check rec_len before trusting it for the next iteration.
            if rec_len < 8
                || (rec_len as usize) > self.buf.len() - self.offset
                || (rec_len % 4) != 0
            {
                return Some(Err(Error::CorruptDirEntry("bad rec_len")));
            }

            let name_len_lo = self.buf[self.offset + 6];
            let type_or_namehi = self.buf[self.offset + 7];

            // Detect csum tail: inode==0, rec_len==12, name_len==0, type==0xDE.
            let is_csum_tail =
                inode == 0 && rec_len == 12 && name_len_lo == 0 && type_or_namehi == 0xDE;

            let entry_end = self.offset + rec_len as usize;

            // Skip unused / tail entries.
            if inode == 0 || is_csum_tail {
                self.offset = entry_end;
                if is_csum_tail {
                    return None; // tail marks end of useful entries in this block
                }
                continue;
            }

            let name_len = if self.has_file_type {
                name_len_lo as usize
            } else {
                ((type_or_namehi as usize) << 8) | name_len_lo as usize
            };

            if 8 + name_len > rec_len as usize {
                return Some(Err(Error::CorruptDirEntry("name overflows rec_len")));
            }

            let name_start = self.offset + 8;
            let name = self.buf[name_start..name_start + name_len].to_vec();
            let file_type = if self.has_file_type {
                DirEntryType::from_u8(type_or_namehi)
            } else {
                DirEntryType::Unknown
            };

            self.offset = entry_end;
            return Some(Ok(DirEntry {
                inode,
                name,
                file_type,
            }));
        }
    }
}

/// Parse all entries from one directory data block.
pub fn parse_block(buf: &[u8], has_file_type: bool) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for entry in DirBlockIter::new(buf, has_file_type) {
        out.push(entry?);
    }
    Ok(out)
}

/// True if this block ends in a metadata-csum tail entry
/// (`inode=0, rec_len=12, name_len=0, file_type=0xDE`).
pub fn has_csum_tail(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let off = buf.len() - 12;
    let inode = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
    let rec_len = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap());
    inode == 0 && rec_len == 12 && buf[off + 6] == 0 && buf[off + 7] == 0xDE
}

/// Verify a directory block's CRC32C tail (if present) and parse its entries.
///
/// When `csum.enabled` AND the block ends in a recognisable
/// `ext4_dir_entry_tail`, the tail's stored CRC32C is checked against
/// `crc32c(seed, ino || generation || block_with_tail_csum_zeroed)`.
/// Mismatch yields `Error::BadChecksum { what: "directory block" }`.
///
/// Blocks without the tail are parsed unchanged — older directories on
/// metadata-csum-enabled filesystems remain readable until they're rewritten.
pub fn parse_block_verified(
    buf: &[u8],
    has_file_type: bool,
    ino: u32,
    generation: u32,
    csum: &Checksummer,
) -> Result<Vec<DirEntry>> {
    if csum.enabled && has_csum_tail(buf) && !csum.verify_dir_entry_tail(ino, generation, buf) {
        return Err(Error::BadChecksum {
            what: "directory block",
        });
    }
    parse_block(buf, has_file_type)
}

// ---------------------------------------------------------------------------
// Mutation helpers — E8 (Phase 4 write path, plan layer, linear dirs only)
// ---------------------------------------------------------------------------

/// Record length an entry with `name_len` bytes occupies on disk: 8-byte
/// header + name, padded to a 4-byte boundary.
#[inline]
pub const fn entry_rec_len(name_len: usize) -> usize {
    8 + ((name_len + 3) & !3)
}

/// Write one entry header + name at `off` inside `buf`. Caller is responsible
/// for `rec_len` being correct and fitting.
fn write_entry(
    buf: &mut [u8],
    off: usize,
    inode: u32,
    rec_len: u16,
    name: &[u8],
    file_type: DirEntryType,
    has_file_type: bool,
) {
    buf[off..off + 4].copy_from_slice(&inode.to_le_bytes());
    buf[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
    let name_len = name.len();
    if has_file_type {
        buf[off + 6] = name_len as u8;
        buf[off + 7] = file_type as u8;
    } else {
        buf[off + 6] = (name_len & 0xFF) as u8;
        buf[off + 7] = ((name_len >> 8) & 0xFF) as u8;
    }
    buf[off + 8..off + 8 + name_len].copy_from_slice(name);
    // Zero the padding bytes between name and rec_len end — helps deterministic
    // checksums downstream.
    let pad_start = off + 8 + name_len;
    let pad_end = off + rec_len as usize;
    if pad_end > pad_start {
        for b in &mut buf[pad_start..pad_end] {
            *b = 0;
        }
    }
}

/// Insert a new directory entry into a single linear block.
///
/// Walks entries looking for one whose padded size is smaller than its
/// `rec_len` (i.e. has a free tail); splits it so the new entry fits in the
/// gap. Also finds a stale tombstone (`inode == 0`) whose `rec_len` is big
/// enough and reuses it.
///
/// `reserved_tail` is the number of trailing bytes the caller reserves
/// (e.g. 12 for the metadata-csum tail entry). Those bytes are untouched.
///
/// Returns `Ok(())` on success, `Err(Error::OutOfBounds)` if no slot fits.
pub fn add_entry_to_block(
    buf: &mut [u8],
    inode: u32,
    name: &[u8],
    file_type: DirEntryType,
    has_file_type: bool,
    reserved_tail: usize,
) -> Result<()> {
    if inode == 0 {
        return Err(Error::CorruptDirEntry(
            "refuse to insert entry with inode 0",
        ));
    }
    if name.is_empty() || name.len() > 255 {
        return Err(Error::CorruptDirEntry("name length out of range"));
    }
    let usable = buf
        .len()
        .checked_sub(reserved_tail)
        .ok_or(Error::OutOfBounds)?;
    let needed = entry_rec_len(name.len());
    if needed > usable {
        return Err(Error::OutOfBounds);
    }

    let mut off = 0usize;
    while off + 8 <= usable {
        let cur_inode = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap()) as usize;
        if rec_len < 8 || !rec_len.is_multiple_of(4) || off + rec_len > usable {
            return Err(Error::CorruptDirEntry("bad rec_len during add"));
        }

        if cur_inode == 0 {
            // Reuse a tombstone slot in-place (keep its rec_len).
            if rec_len >= needed {
                write_entry(
                    buf,
                    off,
                    inode,
                    rec_len as u16,
                    name,
                    file_type,
                    has_file_type,
                );
                return Ok(());
            }
        } else {
            let cur_name_lo = buf[off + 6];
            let cur_type_or_hi = buf[off + 7];
            let cur_name_len = if has_file_type {
                cur_name_lo as usize
            } else {
                ((cur_type_or_hi as usize) << 8) | cur_name_lo as usize
            };
            let cur_actual = entry_rec_len(cur_name_len);
            if rec_len >= cur_actual + needed {
                // Split: shrink current to its actual size, put new entry in the tail.
                buf[off + 4..off + 6].copy_from_slice(&(cur_actual as u16).to_le_bytes());
                let new_off = off + cur_actual;
                let new_rec_len = rec_len - cur_actual;
                write_entry(
                    buf,
                    new_off,
                    inode,
                    new_rec_len as u16,
                    name,
                    file_type,
                    has_file_type,
                );
                return Ok(());
            }
        }

        off += rec_len;
    }

    Err(Error::OutOfBounds)
}

/// Remove the first entry matching `name` from a linear directory block.
///
/// Coalesces the removed entry's `rec_len` into the previous entry's `rec_len`
/// so the block stays densely packed and iterable. If the match is the very
/// first entry in the block, its inode is zeroed (tombstone) — the kernel
/// keeps `rec_len` intact so readers still skip it via `inode == 0`.
///
/// Returns `Ok(true)` if an entry was removed, `Ok(false)` if not found.
pub fn remove_entry_from_block(
    buf: &mut [u8],
    name: &[u8],
    has_file_type: bool,
    reserved_tail: usize,
) -> Result<bool> {
    let usable = buf
        .len()
        .checked_sub(reserved_tail)
        .ok_or(Error::OutOfBounds)?;
    let mut off = 0usize;
    let mut prev_off: Option<usize> = None;

    while off + 8 <= usable {
        let cur_inode = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap()) as usize;
        if rec_len < 8 || !rec_len.is_multiple_of(4) || off + rec_len > usable {
            return Err(Error::CorruptDirEntry("bad rec_len during remove"));
        }

        if cur_inode != 0 {
            let cur_name_lo = buf[off + 6];
            let cur_type_or_hi = buf[off + 7];
            let cur_name_len = if has_file_type {
                cur_name_lo as usize
            } else {
                ((cur_type_or_hi as usize) << 8) | cur_name_lo as usize
            };
            if 8 + cur_name_len <= rec_len && &buf[off + 8..off + 8 + cur_name_len] == name {
                if let Some(prev) = prev_off {
                    // Coalesce: previous entry absorbs this one's space.
                    let prev_rec_len =
                        u16::from_le_bytes(buf[prev + 4..prev + 6].try_into().unwrap()) as usize;
                    let merged = prev_rec_len + rec_len;
                    if merged > u16::MAX as usize {
                        return Err(Error::CorruptDirEntry("merged rec_len overflows u16"));
                    }
                    buf[prev + 4..prev + 6].copy_from_slice(&(merged as u16).to_le_bytes());
                    // Zero the now-absorbed header so a stale read cannot mis-parse.
                    for b in &mut buf[off..off + 8] {
                        *b = 0;
                    }
                } else {
                    // First entry in block: tombstone it (inode = 0), keep rec_len.
                    buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
                }
                return Ok(true);
            }
        }

        prev_off = Some(off);
        off += rec_len;
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled directory block: ".", "..", "hello".
    fn synth_block() -> Vec<u8> {
        let block_size = 4096;
        let mut buf = vec![0u8; block_size];

        // "." entry: inode=2, rec_len=12, name_len=1, file_type=2 (DIR), name=".\0\0\0"
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2;
        buf[8] = b'.';

        // ".." entry: inode=2, rec_len=12, name_len=2, file_type=2, name="..\0\0"
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        buf[16..18].copy_from_slice(&12u16.to_le_bytes());
        buf[18] = 2;
        buf[19] = 2;
        buf[20] = b'.';
        buf[21] = b'.';

        // "hello" entry: inode=12, rec_len=block_size-24=4072 (rest of block),
        // name_len=5, file_type=1 (REG), name="hello\0\0\0"
        buf[24..28].copy_from_slice(&12u32.to_le_bytes());
        buf[28..30].copy_from_slice(&((block_size - 24) as u16).to_le_bytes());
        buf[30] = 5;
        buf[31] = 1;
        buf[32..37].copy_from_slice(b"hello");

        buf
    }

    #[test]
    fn parses_dot_dotdot_hello() {
        let buf = synth_block();
        let entries = parse_block(&buf, true).expect("parse");

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[0].inode, 2);
        assert_eq!(entries[0].file_type, DirEntryType::Directory);

        assert_eq!(entries[1].name, b"..");
        assert_eq!(entries[1].file_type, DirEntryType::Directory);

        assert_eq!(entries[2].name, b"hello");
        assert_eq!(entries[2].inode, 12);
        assert_eq!(entries[2].file_type, DirEntryType::RegFile);
    }

    #[test]
    fn rejects_bad_rec_len() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        // rec_len = 3 (less than 8 minimum)
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2;
        buf[8] = b'.';

        let result = parse_block(&buf, true);
        assert!(matches!(result, Err(Error::CorruptDirEntry(_))));
    }

    // ---- E8 mutation tests ---------------------------------------------

    #[test]
    fn rec_len_matches_kernel_layout() {
        assert_eq!(entry_rec_len(1), 12); // "."
        assert_eq!(entry_rec_len(2), 12); // ".."
        assert_eq!(entry_rec_len(5), 16); // "hello"
        assert_eq!(entry_rec_len(8), 16); // exact 4-byte alignment
        assert_eq!(entry_rec_len(9), 20);
    }

    #[test]
    fn add_entry_splits_terminal_record() {
        let mut buf = synth_block();
        add_entry_to_block(&mut buf, 99, b"world", DirEntryType::RegFile, true, 0)
            .expect("add_entry");

        let entries = parse_block(&buf, true).expect("parse");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[3].name, b"world");
        assert_eq!(entries[3].inode, 99);
        assert_eq!(entries[3].file_type, DirEntryType::RegFile);

        // The existing "hello" entry should now have its rec_len shrunk to
        // the minimum for a 5-char name; the new "world" entry inherits the rest.
        let hello_rec_len = u16::from_le_bytes(buf[28..30].try_into().unwrap());
        assert_eq!(hello_rec_len, 16, "hello rec_len shrinks to actual size");
    }

    #[test]
    fn add_entry_enospc_when_no_room() {
        // Block of 32 bytes; dot+dotdot+hello already fills it.
        let block_size = 32;
        let mut buf = vec![0u8; block_size];
        // "." rec_len=12
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2;
        buf[8] = b'.';
        // ".." rec_len=12
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        buf[16..18].copy_from_slice(&12u16.to_le_bytes());
        buf[18] = 2;
        buf[19] = 2;
        buf[20] = b'.';
        buf[21] = b'.';
        // "a" rec_len=8 (just header+1 padded to 12 — but set rec_len to exactly the remaining 8)
        buf[24..28].copy_from_slice(&12u32.to_le_bytes());
        buf[28..30].copy_from_slice(&8u16.to_le_bytes());
        buf[30] = 1;
        buf[31] = 1;

        let err = add_entry_to_block(&mut buf, 42, b"xx", DirEntryType::RegFile, true, 0);
        assert!(matches!(err, Err(Error::OutOfBounds)));
    }

    #[test]
    fn add_entry_respects_reserved_tail() {
        // 64-byte block with 12-byte csum tail; usable region = 52 bytes.
        // dot (12) + dotdot (12) leaves 28 usable. A name of len 21 needs 32
        // bytes and must be rejected; len 13 needs 24 bytes and must fit.
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2;
        buf[8] = b'.';
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        // ".." claims the rest of the usable area (40 bytes: 52 - 12) so its
        // rec_len extends right up to the reserved csum tail.
        buf[16..18].copy_from_slice(&40u16.to_le_bytes());
        buf[18] = 2;
        buf[19] = 2;
        buf[20] = b'.';
        buf[21] = b'.';

        // Mark the last 12 bytes as a csum tail (untouched by any call below).
        buf[52..56].copy_from_slice(&0u32.to_le_bytes());
        buf[56..58].copy_from_slice(&12u16.to_le_bytes());
        buf[58] = 0;
        buf[59] = 0xDE;

        // 21-char name needs 32 bytes → must fail.
        let too_big = b"aaaaaaaaaaaaaaaaaaaaa"; // 21 'a'
        assert!(matches!(
            add_entry_to_block(&mut buf, 10, too_big, DirEntryType::RegFile, true, 12),
            Err(Error::OutOfBounds)
        ));
        // 13-char name needs 24 bytes → fits in the 28-byte dotdot tail.
        let ok = b"aaaaaaaaaaaaa"; // 13 'a'
        add_entry_to_block(&mut buf, 10, ok, DirEntryType::RegFile, true, 12)
            .expect("add should succeed within reserved tail");

        // Csum tail bytes must be untouched.
        assert_eq!(buf[58], 0);
        assert_eq!(buf[59], 0xDE);
    }

    #[test]
    fn remove_entry_coalesces_into_previous() {
        let mut buf = synth_block();
        let ok = remove_entry_from_block(&mut buf, b"hello", true, 0).expect("remove");
        assert!(ok);

        let entries = parse_block(&buf, true).expect("parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[1].name, b"..");

        // ".." rec_len now absorbs hello's rec_len (was 4072, grows to 4084).
        let dotdot_rec_len = u16::from_le_bytes(buf[16..18].try_into().unwrap());
        assert_eq!(dotdot_rec_len, 4084);
    }

    #[test]
    fn remove_entry_tombstones_first_slot() {
        let mut buf = synth_block();
        // Overwrite "." with a regular-file entry so removal hits the first-slot path.
        buf[0..4].copy_from_slice(&17u32.to_le_bytes());
        buf[6] = 4; // name_len 4
        buf[7] = 1; // REG
        buf[8..12].copy_from_slice(b"root");

        let ok = remove_entry_from_block(&mut buf, b"root", true, 0).expect("remove");
        assert!(ok);
        // Inode zeroed, rec_len preserved.
        let first_inode = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(first_inode, 0);
        let first_rec = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        assert_eq!(first_rec, 12);

        // Parser should skip the tombstone and return just the other two.
        let entries = parse_block(&buf, true).expect("parse");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn remove_entry_reports_missing() {
        let mut buf = synth_block();
        let ok = remove_entry_from_block(&mut buf, b"nope", true, 0).expect("remove");
        assert!(!ok);

        let entries = parse_block(&buf, true).expect("parse");
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn add_then_remove_round_trips() {
        let mut buf = synth_block();
        add_entry_to_block(&mut buf, 77, b"fresh", DirEntryType::RegFile, true, 0).unwrap();
        assert_eq!(parse_block(&buf, true).unwrap().len(), 4);

        assert!(remove_entry_from_block(&mut buf, b"fresh", true, 0).unwrap());
        let entries = parse_block(&buf, true).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(!entries.iter().any(|e| e.name == b"fresh"));
    }

    #[test]
    fn add_entry_reuses_tombstone_in_middle() {
        // Layout: ".", tombstone (rec_len 16), "tail" (rec_len block-28).
        let block_size = 4096;
        let mut buf = vec![0u8; block_size];
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2;
        buf[8] = b'.';
        // Tombstone (inode=0), rec_len=16 — big enough for a 1-byte name entry.
        buf[12..14].copy_from_slice(&0u16.to_le_bytes());
        buf[14..16].copy_from_slice(&0u16.to_le_bytes());
        buf[16..18].copy_from_slice(&16u16.to_le_bytes());
        // Remaining tail entry.
        let tail_off = 28;
        let tail_rec_len = (block_size - tail_off) as u16;
        buf[tail_off..tail_off + 4].copy_from_slice(&5u32.to_le_bytes());
        buf[tail_off + 4..tail_off + 6].copy_from_slice(&tail_rec_len.to_le_bytes());
        buf[tail_off + 6] = 4;
        buf[tail_off + 7] = 1;
        buf[tail_off + 8..tail_off + 12].copy_from_slice(b"tail");

        add_entry_to_block(&mut buf, 99, b"x", DirEntryType::RegFile, true, 0).unwrap();
        // New entry should have landed in the tombstone slot (offset 12).
        let new_inode = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        assert_eq!(new_inode, 99);
        let new_rec_len = u16::from_le_bytes(buf[16..18].try_into().unwrap());
        assert_eq!(new_rec_len, 16, "tombstone slot rec_len preserved");
        assert_eq!(&buf[20..21], b"x");

        let entries = parse_block(&buf, true).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].name, b"x");
        assert_eq!(entries[2].name, b"tail");
    }
}
