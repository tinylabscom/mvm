use super::{BLOCK_SIZE_USIZE, EmitImageError, Ext4Error, Image, Planned};

pub(super) fn emit_verified_host_file_blocks<E, F>(
    emit: &mut F,
    img: &Image,
    planned: &Planned,
    source: &std::path::Path,
    len: usize,
    expected_sha256: &[u8; 32],
) -> Result<(), EmitImageError<E>>
where
    F: FnMut(u64, &[u8]) -> Result<(), E>,
{
    use sha2::Digest as _;
    use std::io::Read as _;

    let file = std::fs::File::open(source)
        .map_err(|_| EmitImageError::Build(Ext4Error::HostFileChanged(source.to_path_buf())))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; BLOCK_SIZE_USIZE];
    let mut written = 0usize;
    for extent in &planned.extents {
        if written >= len {
            break;
        }
        let span = extent.len as usize * BLOCK_SIZE_USIZE;
        let mut offset_in_extent = 0usize;
        while offset_in_extent < span && written + offset_in_extent < len {
            let want = buf
                .len()
                .min(span - offset_in_extent)
                .min(len - written - offset_in_extent);
            reader.read_exact(&mut buf[..want]).map_err(|_| {
                EmitImageError::Build(Ext4Error::HostFileChanged(source.to_path_buf()))
            })?;
            hasher.update(&buf[..want]);
            emit(
                img.block_off(extent.phys) as u64 + offset_in_extent as u64,
                &buf[..want],
            )
            .map_err(EmitImageError::Emit)?;
            offset_in_extent += want;
        }
        written += span;
    }
    let mut extra = [0u8; 1];
    let has_extra = loop {
        match reader.read(&mut extra) {
            Ok(0) => break false,
            Ok(_) => break true,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(EmitImageError::Build(Ext4Error::HostFileChanged(
                    source.to_path_buf(),
                )));
            }
        }
    };
    let actual: [u8; 32] = hasher.finalize().into();
    if has_extra || actual != *expected_sha256 {
        return Err(EmitImageError::Build(Ext4Error::HostFileChanged(
            source.to_path_buf(),
        )));
    }
    Ok(())
}

/// Stream one host file's bytes into the extents planned for it.
///
/// The layout is already committed by the time this runs. A short read leaves
/// the rest of this file's allocated extents as holes; a long read stops at the
/// planned length. Either result stays within this file's allocation.
pub(super) fn emit_host_file_blocks<E, F>(
    emit: &mut F,
    img: &Image,
    planned: &Planned,
    source: &std::path::Path,
    len: usize,
) -> Result<(), E>
where
    F: FnMut(u64, &[u8]) -> Result<(), E>,
{
    let Ok(file) = std::fs::File::open(source) else {
        return Ok(());
    };
    let mut reader = std::io::BufReader::new(file);

    let mut buf = vec![0u8; BLOCK_SIZE_USIZE];
    let mut written = 0usize;
    for extent in &planned.extents {
        if written >= len {
            break;
        }
        let span = extent.len as usize * BLOCK_SIZE_USIZE;
        let mut offset_in_extent = 0usize;
        while offset_in_extent < span && written + offset_in_extent < len {
            let want = buf
                .len()
                .min(span - offset_in_extent)
                .min(len - written - offset_in_extent);
            let got = read_up_to(&mut reader, &mut buf[..want]);
            if got == 0 {
                return Ok(());
            }
            emit(
                img.block_off(extent.phys) as u64 + offset_in_extent as u64,
                &buf[..got],
            )?;
            offset_in_extent += got;
        }
        written += span;
    }
    Ok(())
}

fn read_up_to<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> usize {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    filled
}
