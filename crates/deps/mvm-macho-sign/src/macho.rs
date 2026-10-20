// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Adapted from apple-codesign 0.29.0 macho.rs, macho_signing.rs and
// macho_universal.rs, Copyright Gregory Szorc. See ../PROVENANCE.md.

use crate::{Error, Result, be32, range, signature, size32};

#[derive(Clone, Debug)]
struct Command {
    offset: usize,
    kind: u32,
}
#[derive(Clone, Debug)]
struct Segment {
    command: usize,
    name: String,
    offset: usize,
    size: usize,
}

/// Checked thin Mach-O view. `offset` is relative to the enclosing fat file.
#[derive(Clone, Debug)]
pub struct Slice<'a> {
    pub data: &'a [u8],
    pub offset: usize,
    little: bool,
    wide: bool,
    commands: Vec<Command>,
    segments: Vec<Segment>,
    first_section: usize,
    info: Option<&'a [u8]>,
    target: Option<(u32, u32, u32)>,
}
impl<'a> Slice<'a> {
    fn u32(&self, at: usize) -> Result<u32> {
        read32(self.data, at, self.little)
    }
    fn u64(&self, at: usize) -> Result<u64> {
        read64(self.data, at, self.little)
    }
    pub fn cpu_type(&self) -> Result<u32> {
        self.u32(4)
    }
    pub fn code_directory(&self) -> Result<Option<signature::CodeDirectory>> {
        self.signature_blobs()?
            .get(&0)
            .map(|blob| signature::CodeDirectory::parse(blob))
            .transpose()
    }
    pub fn signature_blobs(&self) -> Result<std::collections::BTreeMap<u32, &'a [u8]>> {
        if let Some(command) = self.commands.iter().find(|c| c.kind == 0x1d) {
            signature::signature_blobs(range(
                self.data,
                self.u32(command.offset + 8)? as usize,
                self.u32(command.offset + 12)? as usize,
            )?)
        } else {
            Ok(Default::default())
        }
    }
    pub(crate) fn needs_sha1(&self) -> bool {
        match self.target {
            None => true,
            Some((1, min, _)) => min < 0x000a_0b04,
            Some((2 | 3, min, _)) => min < 0x000b_0000,
            Some((0 | 4, _, _)) => true,
            Some(_) => false,
        }
    }
    pub(crate) fn sdk(&self) -> Option<u32> {
        self.target.map(|(_, _, sdk)| sdk)
    }
    pub(crate) fn is_executable(&self) -> Result<bool> {
        Ok(self.u32(12)? == 2)
    }
    pub(crate) fn info(&self) -> Option<&[u8]> {
        self.info
    }
    pub(crate) fn text_boundary(&self) -> Result<(u64, u64)> {
        let text = self
            .segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .ok_or("no __TEXT")?;
        Ok((text.offset as u64, (text.offset + text.size) as u64))
    }
    /// Never move referenced data to make load-command space.
    pub(crate) fn code_limit(&self) -> Result<usize> {
        let link = self
            .segments
            .iter()
            .find(|s| s.name == "__LINKEDIT")
            .ok_or("no __LINKEDIT")?;
        let end = link
            .offset
            .checked_add(link.size)
            .ok_or("segment overflow")?;
        let commands_end = self.header_size() + self.u32(20)? as usize;
        if self
            .segments
            .iter()
            .any(|s| s.command != link.command && s.size != 0 && s.offset + s.size > link.offset)
            || end != self.data.len()
            || link.offset < commands_end
        {
            return Err("__LINKEDIT must be the final file data".into());
        }
        if let Some(command) = self.commands.iter().find(|c| c.kind == 0x1d) {
            let offset = self.u32(command.offset + 8)? as usize;
            let size = self.u32(command.offset + 12)? as usize;
            if offset < link.offset || offset.checked_add(size) != Some(end) {
                return Err("signature is not at the end of __LINKEDIT".into());
            }
            Ok(offset)
        } else {
            let room_end = commands_end
                .checked_add(16)
                .ok_or("load command overflow")?;
            if room_end > self.first_section
                || room_end > link.offset
                || range(self.data, commands_end, 16)?.iter().any(|b| *b != 0)
            {
                return Err(Error::NoSignatureCommandRoom);
            }
            Ok(end)
        }
    }
    fn header_size(&self) -> usize {
        if self.wide { 32 } else { 28 }
    }
    pub(crate) fn rewrite(&self, signature: &[u8]) -> Result<Vec<u8>> {
        let limit = self.code_limit()?;
        let aligned = limit.checked_add(15).ok_or("signature offset overflow")? & !15;
        let mut output = range(self.data, 0, limit)?.to_vec();
        output.resize(aligned, 0);
        output.extend_from_slice(signature);
        size32(output.len())?;
        let link = self
            .segments
            .iter()
            .find(|s| s.name == "__LINKEDIT")
            .ok_or("no __LINKEDIT")?;
        let size = output
            .len()
            .checked_sub(link.offset)
            .ok_or("invalid linkedit offset")?;
        let vm_size = size.checked_add(16383).ok_or("segment size overflow")? & !16383;
        if self.wide {
            write64(&mut output, link.command + 32, vm_size as u64, self.little);
            write64(&mut output, link.command + 48, size as u64, self.little);
        } else {
            write32(
                &mut output,
                link.command + 28,
                size32(vm_size)?,
                self.little,
            );
            write32(&mut output, link.command + 36, size32(size)?, self.little);
        }
        let command = if let Some(command) = self.commands.iter().find(|c| c.kind == 0x1d) {
            command.offset
        } else {
            let end = self.header_size() + self.u32(20)? as usize;
            write32(
                &mut output,
                16,
                self.u32(16)?
                    .checked_add(1)
                    .ok_or("command count overflow")?,
                self.little,
            );
            write32(
                &mut output,
                20,
                self.u32(20)?
                    .checked_add(16)
                    .ok_or("command size overflow")?,
                self.little,
            );
            write32(&mut output, end, 0x1d, self.little);
            write32(&mut output, end + 4, 16, self.little);
            end
        };
        write32(&mut output, command + 8, size32(aligned)?, self.little);
        write32(
            &mut output,
            command + 12,
            size32(signature.len())?,
            self.little,
        );
        Ok(output)
    }
}
fn read32(data: &[u8], at: usize, little: bool) -> Result<u32> {
    let bytes = range(data, at, 4)?.try_into().map_err(|_| "invalid u32")?;
    Ok(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}
fn read64(data: &[u8], at: usize, little: bool) -> Result<u64> {
    let bytes = range(data, at, 8)?.try_into().map_err(|_| "invalid u64")?;
    Ok(if little {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}
fn write32(data: &mut [u8], at: usize, value: u32, little: bool) {
    let bytes = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    data[at..at + 4].copy_from_slice(&bytes);
}
fn write64(data: &mut [u8], at: usize, value: u64, little: bool) {
    let bytes = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    data[at..at + 8].copy_from_slice(&bytes);
}
fn name(data: &[u8]) -> Result<String> {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8(data[..end].to_vec()).map_err(|e| e.to_string().into())
}
fn thin(data: &[u8], offset: usize) -> Result<Slice<'_>> {
    let (little, wide) = match be32(data, 0)? {
        0xcefa_edfe => (true, false),
        0xcffa_edfe => (true, true),
        0xfeed_face => (false, false),
        0xfeed_facf => (false, true),
        _ => return Err("not a thin Mach-O".into()),
    };
    let mut slice = Slice {
        data,
        offset,
        little,
        wide,
        commands: Vec::new(),
        segments: Vec::new(),
        first_section: data.len(),
        info: None,
        target: None,
    };
    range(data, 0, slice.header_size())?;
    let end = slice
        .header_size()
        .checked_add(slice.u32(20)? as usize)
        .ok_or("command overflow")?;
    range(data, 0, end)?;
    let mut at = slice.header_size();
    let mut build_target = None;
    let mut old_target = None;
    for _ in 0..slice.u32(16)? {
        if at.checked_add(8).filter(|x| *x <= end).is_none() {
            return Err("truncated load command".into());
        }
        let kind = slice.u32(at)?;
        let size = slice.u32(at + 4)? as usize;
        if size < 8 || size % 4 != 0 || at.checked_add(size).filter(|x| *x <= end).is_none() {
            return Err("invalid load command size".into());
        }
        if kind == 1 || kind == 0x19 {
            if (kind == 0x19) != wide || size < if wide { 72 } else { 56 } {
                return Err("invalid segment command".into());
            }
            let (fileoff, filesize, section_count, section_start, section_size) = if wide {
                (
                    slice.u64(at + 40)?,
                    slice.u64(at + 48)?,
                    slice.u32(at + 64)?,
                    at + 72,
                    80,
                )
            } else {
                (
                    slice.u32(at + 32)? as u64,
                    slice.u32(at + 36)? as u64,
                    slice.u32(at + 48)?,
                    at + 56,
                    68,
                )
            };
            let fileoff = usize::try_from(fileoff).map_err(|_| "segment offset overflow")?;
            let filesize = usize::try_from(filesize).map_err(|_| "segment size overflow")?;
            range(data, fileoff, filesize)?;
            let segment_name = name(range(data, at + 8, 16)?)?;
            let section_bytes = (section_count as usize)
                .checked_mul(section_size)
                .ok_or("sections overflow")?;
            if section_start
                .checked_add(section_bytes)
                .filter(|x| *x <= at + size)
                .is_none()
            {
                return Err("sections exceed load command".into());
            }
            for index in 0..section_count as usize {
                let section = section_start + index * section_size;
                let section_offset = slice.u32(section + if wide { 48 } else { 40 })? as usize;
                let section_len = if wide {
                    slice.u64(section + 40)?
                } else {
                    slice.u32(section + 36)? as u64
                };
                let flags = slice.u32(section + if wide { 64 } else { 56 })? & 0xff;
                if !matches!(flags, 1 | 0xc | 0x12) {
                    let section_len =
                        usize::try_from(section_len).map_err(|_| "section overflow")?;
                    let section_end = section_offset
                        .checked_add(section_len)
                        .ok_or("section overflow")?;
                    if section_offset < fileoff || section_end > fileoff + filesize {
                        return Err("file-backed section exceeds segment".into());
                    }
                    if section_offset != 0 {
                        slice.first_section = slice.first_section.min(section_offset);
                    }
                    let payload = range(data, section_offset, section_len)?;
                    if segment_name == "__TEXT"
                        && name(range(data, section, 16)?)? == "__info_plist"
                        && slice.info.replace(payload).is_some()
                    {
                        return Err("duplicate embedded Info.plist".into());
                    }
                }
            }
            if slice.segments.iter().any(|s| s.name == segment_name) {
                return Err("duplicate segment name".into());
            }
            slice.segments.push(Segment {
                command: at,
                name: segment_name,
                offset: fileoff,
                size: filesize,
            });
        }
        match kind {
            0x1d => {
                if size != 16 || slice.commands.iter().any(|c| c.kind == 0x1d) {
                    return Err("invalid or duplicate signature command".into());
                }
            }
            0x32 => {
                if size < 24 || build_target.is_some() {
                    return Err("invalid build version".into());
                }
                let tools = slice.u32(at + 20)? as usize;
                if tools.checked_mul(8).and_then(|n| n.checked_add(24)) != Some(size) {
                    return Err("build tools exceed command".into());
                }
                build_target = Some((slice.u32(at + 8)?, slice.u32(at + 12)?, slice.u32(at + 16)?));
            }
            0x24 | 0x25 | 0x2f | 0x30 => {
                if size != 16 || old_target.is_some() {
                    return Err("invalid minimum version command".into());
                }
                let platform = match kind {
                    0x24 => 1,
                    0x25 => 2,
                    0x2f => 3,
                    _ => 4,
                };
                old_target = Some((platform, slice.u32(at + 8)?, slice.u32(at + 12)?));
            }
            _ => {}
        }
        slice.commands.push(Command { offset: at, kind });
        at += size;
    }
    if at != end {
        return Err("load command count disagrees with size".into());
    }
    slice.target = build_target.or(old_target);
    Ok(slice)
}
/// Parse all architectures, rejecting overlapping or inconsistent fat descriptors.
pub fn slices(data: &[u8]) -> Result<Vec<Slice<'_>>> {
    let (little, wide) = match be32(data, 0)? {
        0xcafe_babe => (false, false),
        0xbeba_feca => (true, false),
        0xcafe_babf => (false, true),
        0xbfba_feca => (true, true),
        _ => return Ok(vec![thin(data, 0)?]),
    };
    let count = read32(data, 4, little)? as usize;
    let record_size = if wide { 32 } else { 20 };
    let header_end = 8usize
        .checked_add(
            count
                .checked_mul(record_size)
                .ok_or("fat header overflow")?,
        )
        .ok_or("fat header overflow")?;
    range(data, 0, header_end)?;
    if count == 0 {
        return Err("Mach-O has no executable slices".into());
    }
    let mut result: Vec<Slice<'_>> = Vec::new();
    for index in 0..count {
        let at = 8 + index * record_size;
        let (offset, size) = if wide {
            (
                read64(data, at + 8, little)?,
                read64(data, at + 16, little)?,
            )
        } else {
            (
                read32(data, at + 8, little)? as u64,
                read32(data, at + 12, little)? as u64,
            )
        };
        let offset = usize::try_from(offset).map_err(|_| "fat offset overflow")?;
        let size = usize::try_from(size).map_err(|_| "fat size overflow")?;
        let end = offset.checked_add(size).ok_or("fat slice overflow")?;
        let align = read32(data, at + if wide { 24 } else { 16 }, little)?;
        let alignment = 1usize.checked_shl(align).ok_or("invalid fat alignment")?;
        if offset % alignment != 0 || (wide && read32(data, at + 28, little)? != 0) {
            return Err("invalid fat descriptor alignment or reserved field".into());
        }
        if offset < header_end
            || result
                .iter()
                .any(|s| offset < s.offset + s.data.len() && end > s.offset)
        {
            return Err("overlapping fat slices".into());
        }
        let slice = thin(range(data, offset, size)?, offset)?;
        if slice.cpu_type()? != read32(data, at, little)?
            || slice.u32(8)? != read32(data, at + 4, little)?
        {
            return Err("fat CPU descriptor disagrees with slice".into());
        }
        result.push(slice);
    }
    Ok(result)
}
/// Assemble thin slices at upstream's 16 KiB universal alignment.
pub fn universal_binary(binaries: &[Vec<u8>]) -> Result<Vec<u8>> {
    if binaries.is_empty() {
        return Err("empty universal binary".into());
    }
    let header_len = 8usize
        .checked_add(
            binaries
                .len()
                .checked_mul(20)
                .ok_or("fat header overflow")?,
        )
        .ok_or("fat header overflow")?;
    let mut output = vec![0; header_len];
    crate::put32(&mut output, 0, 0xcafe_babe);
    crate::put32(&mut output, 4, size32(binaries.len())?);
    for (index, binary) in binaries.iter().enumerate() {
        let slice = thin(binary, 0)?;
        let offset = output.len().checked_add(16383).ok_or("fat size overflow")? & !16383;
        output.resize(offset, 0);
        let at = 8 + index * 20;
        crate::put32(&mut output, at, slice.cpu_type()?);
        crate::put32(&mut output, at + 4, slice.u32(8)?);
        crate::put32(&mut output, at + 8, size32(offset)?);
        crate::put32(&mut output, at + 12, size32(binary.len())?);
        crate::put32(&mut output, at + 16, 14);
        output.extend_from_slice(binary);
        size32(output.len())?;
    }
    Ok(output)
}
