//! Decode Git index records, including split-index EWAH maps, without tools.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

use super::{IndexEntry, message};

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| "index length overflow".to_owned())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "truncated index".to_owned())?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, String> {
        let value = self.take(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let value = self.take(4)?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let value = self.take(8)?;
        let mut bytes = [0; 8];
        bytes.copy_from_slice(value);
        Ok(u64::from_be_bytes(bytes))
    }
    fn name(&mut self) -> Result<Vec<u8>, String> {
        let end = self
            .bytes
            .get(self.offset..)
            .and_then(|v| v.iter().position(|b| *b == 0))
            .ok_or_else(|| "unterminated index path".to_owned())?;
        let value = self.take(end)?.to_vec();
        self.take(1)?;
        Ok(value)
    }
}

pub(super) fn read(path: &Path) -> Result<Vec<IndexEntry>, String> {
    read_inner(path, None, &mut BTreeSet::new())
}

fn read_inner(
    path: &Path,
    expected: Option<&[u8]>,
    active: &mut BTreeSet<PathBuf>,
) -> Result<Vec<IndexEntry>, String> {
    if active.len() >= 64 || !active.insert(path.to_path_buf()) {
        return Err("recursive split index or maximum depth exceeded".to_owned());
    }
    let result = decode(path, expected, active);
    active.remove(path);
    result
}

fn decode(
    path: &Path,
    expected: Option<&[u8]>,
    active: &mut BTreeSet<PathBuf>,
) -> Result<Vec<IndexEntry>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if expected.is_none() && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(format!("reading index {}: {e}", path.display())),
    };
    if bytes.len() < 32 {
        return Err("truncated index".to_owned());
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 20);
    let actual = Sha1::digest(body);
    if (checksum != [0; 20] && checksum != actual.as_slice())
        || expected.is_some_and(|v| v != checksum || v != actual.as_slice())
    {
        return Err("index checksum mismatch".to_owned());
    }
    let mut cursor = Cursor {
        bytes: body,
        offset: 0,
    };
    if cursor.take(4)? != b"DIRC" {
        return Err("invalid index signature".to_owned());
    }
    let version = cursor.u32()?;
    if !(2..=4).contains(&version) {
        return Err(format!("unsupported index version {version}"));
    }
    let count = usize::try_from(cursor.u32()?).map_err(message)?;
    if count > body.len() / 62 {
        return Err("index entry count exceeds its length".to_owned());
    }
    let mut entries = Vec::with_capacity(count);
    let mut previous = Vec::new();
    for _ in 0..count {
        let start = cursor.offset;
        cursor.take(24)?;
        let mode = cursor.u32()?;
        cursor.take(12)?;
        let oid = cursor.take(20)?.to_vec();
        let flags = cursor.u16()?;
        let extended = if flags & 0x4000 != 0 {
            if version < 3 {
                return Err("extended index flags require version 3".to_owned());
            }
            cursor.u16()?
        } else {
            0
        };
        let name = if version == 4 {
            let mut byte = cursor.take(1)?[0];
            let mut remove = usize::from(byte & 127);
            while byte & 128 != 0 {
                byte = cursor.take(1)?[0];
                remove = remove
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(128))
                    .and_then(|n| n.checked_add(usize::from(byte & 127)))
                    .ok_or_else(|| "index prefix overflow".to_owned())?;
            }
            if remove > previous.len() {
                return Err("invalid compressed index path".to_owned());
            }
            [previous[..previous.len() - remove].to_vec(), cursor.name()?].concat()
        } else {
            let name = cursor.name()?;
            let padding = (8 - (cursor.offset - start) % 8) % 8;
            if cursor.take(padding)?.iter().any(|b| *b != 0) {
                return Err("invalid index padding".to_owned());
            }
            name
        };
        let stored_len = usize::from(flags & 0x0fff);
        if name.len().min(4095) != stored_len {
            return Err("index path length mismatch".to_owned());
        }
        previous = name.clone();
        entries.push(IndexEntry {
            path: name,
            mode,
            stage: u32::from((flags >> 12) & 3),
            flags: u32::from(flags & 0x8000 != 0)
                | (u32::from(extended & 0x2000 != 0) << 1)
                | (u32::from(extended & 0x4000 != 0) << 2),
            oid,
        });
    }
    let mut link = None;
    let mut sparse_directory_extension = false;
    while cursor.offset < body.len() {
        let signature = cursor.take(4)?;
        let length = usize::try_from(cursor.u32()?).map_err(message)?;
        let data = cursor.take(length)?;
        if signature == b"link" {
            if link.replace(data).is_some() {
                return Err("duplicate split-index extension".to_owned());
            }
        } else if signature == b"sdir" {
            if sparse_directory_extension || !data.is_empty() {
                return Err("invalid sparse-index extension".to_owned());
            }
            sparse_directory_extension = true;
        } else if !signature[0].is_ascii_uppercase() {
            return Err(format!(
                "unsupported mandatory index extension {:?}",
                signature
            ));
        }
    }
    if let Some(link) = link {
        let mut cursor = Cursor {
            bytes: link,
            offset: 0,
        };
        let shared_id = cursor.take(20)?;
        let shared_path = path
            .parent()
            .ok_or_else(|| "index has no directory".to_owned())?
            .join(format!("sharedindex.{}", hex::encode(shared_id)));
        let mut shared = read_inner(&shared_path, Some(shared_id), active)?;
        if cursor.offset < link.len() {
            let deleted = bitmap(&mut cursor, shared.len())?;
            let replaced = bitmap(&mut cursor, shared.len())?;
            if cursor.offset != link.len()
                || !deleted.is_disjoint(&replaced)
                || replaced.len() > entries.len()
            {
                return Err("invalid split-index maps".to_owned());
            }
            for (source, target) in replaced.iter().enumerate() {
                if !entries[source].path.is_empty() || shared[*target].path.is_empty() {
                    return Err("invalid split-index replacement path".to_owned());
                }
                let mut replacement = entries[source].clone();
                replacement.path = shared[*target].path.clone();
                shared[*target] = replacement;
            }
            shared = shared
                .into_iter()
                .enumerate()
                .filter_map(|(i, e)| (!deleted.contains(&i)).then_some(e))
                .collect();
            shared.extend(entries.into_iter().skip(replaced.len()));
            entries = shared;
        }
    }
    entries.sort_by(|a, b| (&a.path, a.stage).cmp(&(&b.path, b.stage)));
    if entries
        .windows(2)
        .any(|e| e[0].path == e[1].path && e[0].stage == e[1].stage)
    {
        return Err("duplicate index path/stage".to_owned());
    }
    Ok(entries)
}

fn bitmap(cursor: &mut Cursor<'_>, limit: usize) -> Result<BTreeSet<usize>, String> {
    let bits = usize::try_from(cursor.u32()?).map_err(message)?;
    let count = usize::try_from(cursor.u32()?).map_err(message)?;
    if count > (cursor.bytes.len() - cursor.offset).saturating_sub(4) / 8 {
        return Err("truncated EWAH bitmap".to_owned());
    }
    let words = (0..count)
        .map(|_| cursor.u64())
        .collect::<Result<Vec<_>, _>>()?;
    let rlw = usize::try_from(cursor.u32()?).map_err(message)?;
    if count != 0 && rlw >= count {
        return Err("invalid EWAH cursor".to_owned());
    }
    let mut out = BTreeSet::new();
    let mut offset = 0usize;
    let mut pos = 0usize;
    while offset < words.len() {
        let word = words[offset];
        offset += 1;
        let repeated = usize::try_from((word >> 1) & 0xffff_ffff).map_err(message)?;
        let literals = usize::try_from(word >> 33).map_err(message)?;
        if literals > words.len() - offset {
            return Err("invalid EWAH literal count".to_owned());
        }
        let end = repeated
            .checked_mul(64)
            .and_then(|n| pos.checked_add(n))
            .ok_or_else(|| "EWAH length overflow".to_owned())?;
        if word & 1 != 0 {
            if end.min(bits) > limit {
                return Err("EWAH bitmap exceeds shared index".to_owned());
            }
            out.extend(pos..end.min(bits));
        }
        pos = end;
        for mut literal in words[offset..offset + literals].iter().copied() {
            while literal != 0 {
                let bit = pos
                    .checked_add(usize::try_from(literal.trailing_zeros()).map_err(message)?)
                    .ok_or_else(|| "EWAH bit overflow".to_owned())?;
                if bit >= bits || bit >= limit {
                    return Err("EWAH bitmap exceeds shared index".to_owned());
                }
                out.insert(bit);
                literal &= literal - 1;
            }
            pos = pos
                .checked_add(64)
                .ok_or_else(|| "EWAH length overflow".to_owned())?;
        }
        offset += literals;
    }
    Ok(out)
}
