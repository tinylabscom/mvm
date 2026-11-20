//! The on-disk form of one cell.
//!
//! A cell file is two slots of the same length, written once at full size when
//! the cell is reserved. Each slot is
//! `magic | version | length | value, zero-padded to the cell size | SHA-256`,
//! with the integers little-endian and the digest over everything before it.
//! The slot with the higher version that verifies is the current value. A
//! commit overwrites the other slot in place and syncs it, so the file never
//! grows after reservation and a torn commit leaves the current slot intact.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest as _, Sha256};

use super::CellValue;

const MAGIC: [u8; 8] = *b"mvmcell1";
const HEADER: u64 = 8 + 8 + 8;
const CHECKSUM: u64 = 32;

fn slot_len(size: u64) -> u64 {
    HEADER + size + CHECKSUM
}

/// The length of a reserved cell file.
pub(super) fn file_len(size: u64) -> u64 {
    2 * slot_len(size)
}

fn encode(size: u64, version: u64, value: &[u8]) -> Vec<u8> {
    let mut slot = Vec::with_capacity(slot_len(size) as usize);
    slot.extend_from_slice(&MAGIC);
    slot.extend_from_slice(&version.to_le_bytes());
    slot.extend_from_slice(&(value.len() as u64).to_le_bytes());
    slot.extend_from_slice(value);
    slot.resize((HEADER + size) as usize, 0);
    let digest = Sha256::digest(&slot);
    slot.extend_from_slice(&digest);
    slot
}

fn word(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

fn decode(slot: &[u8], size: u64) -> Option<CellValue> {
    let (body, digest) = slot.split_at(slot.len() - CHECKSUM as usize);
    if Sha256::digest(body).as_slice() != digest || body[..8] != MAGIC {
        return None;
    }
    let len = word(body, 16);
    if len > size {
        return None;
    }
    let start = HEADER as usize;
    Some(CellValue {
        version: word(body, 8),
        value: body[start..start + len as usize].to_vec(),
    })
}

/// A freshly reserved cell: both slots verify and hold an empty value at
/// version 0.
pub(super) fn reserved(size: u64) -> Vec<u8> {
    encode(size, 0, &[]).repeat(2)
}

/// One cell file, opened under the cell's lock.
pub(super) struct CellFile {
    file: File,
    size: u64,
    slot: u64,
    current: CellValue,
}

impl CellFile {
    /// Open and verify the cell at `path`, reserved at `size` bytes. A file
    /// of any other length, or one in which neither slot verifies, is refused.
    pub(super) fn open(path: &Path, size: u64) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let expected = file_len(size);
        let mut bytes = Vec::new();
        (&mut file)
            .take(expected + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            bytes.len() as u64 == expected,
            "{} is {} bytes, not the {expected} reserved for it",
            path.display(),
            bytes.len()
        );
        let half = slot_len(size) as usize;
        let (slot, current) = match (decode(&bytes[..half], size), decode(&bytes[half..], size)) {
            (Some(a), Some(b)) if b.version > a.version => (1, b),
            (Some(a), _) => (0, a),
            (None, Some(b)) => (1, b),
            (None, None) => bail!("neither slot of {} verifies", path.display()),
        };
        Ok(Self {
            file,
            size,
            slot,
            current,
        })
    }

    pub(super) fn current(&self) -> &CellValue {
        &self.current
    }

    pub(super) fn into_current(self) -> CellValue {
        self.current
    }

    /// Write `value` at `version` over the slot that does not hold the
    /// current value, and sync it. The caller has checked the version and the
    /// size.
    pub(super) fn commit(mut self, version: u64, value: &[u8]) -> Result<()> {
        let other = 1 - self.slot;
        self.file
            .seek(SeekFrom::Start(other * slot_len(self.size)))
            .context("seeking to the cell's free slot")?;
        self.file
            .write_all(&encode(self.size, version, value))
            .context("writing the cell's free slot")?;
        self.file.sync_data().context("syncing the cell")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_round_trips_and_any_flipped_byte_fails_it() {
        let slot = encode(8, 3, b"abc");
        assert_eq!(
            decode(&slot, 8),
            Some(CellValue {
                version: 3,
                value: b"abc".to_vec()
            })
        );
        for at in 0..slot.len() {
            let mut torn = slot.clone();
            torn[at] ^= 1;
            assert_eq!(decode(&torn, 8), None, "byte {at}");
        }
    }
}
