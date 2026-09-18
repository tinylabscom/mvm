//! virtio-blk `DISCARD`: validating the guest's range list and handing the
//! freed space back to the host filesystem.
//!
//! A sparse disk image otherwise only ever grows. The guest filesystem frees
//! blocks, but without discard nothing tells the host, so the image file stays
//! at its high-water mark forever. With discard offered, `fstrim` (or a
//! `discard` mount) sends the free extents here and the host punches holes over
//! them.
//!
//! Everything in a discard payload is guest-controlled. A request is validated
//! whole before any byte is released: one bad range refuses the request rather
//! than applying the ranges that happened to precede it.

use std::fs::File;
use std::io;

use super::virtio::SECTOR;

/// virtio-blk feature bit 13 (low feature word): the device honours
/// `VIRTIO_BLK_T_DISCARD`. Offered only for a writable backing.
pub(super) const VIRTIO_BLK_F_DISCARD: u32 = 1 << 13;
/// Request type for a discard.
pub(super) const VIRTIO_BLK_T_DISCARD: u32 = 11;

/// Most ranges a single request may carry. The Linux driver's own ceiling, so a
/// conformant guest never has to split below what it would send anyway, and a
/// payload is never larger than 4 KiB.
pub(super) const MAX_DISCARD_SEG: u32 = 256;
/// Largest single range, in sectors (4 GiB). Punching a hole is extent metadata
/// work on the host, and this bounds how long one range holds the vCPU thread
/// that services the queue.
pub(super) const MAX_DISCARD_SECTORS: u32 = 1 << 23;
/// Ranges are aligned to 4 KiB, the guest filesystem's block size and the host
/// filesystem's, so a range the guest frees is one the host can release whole.
pub(super) const DISCARD_SECTOR_ALIGNMENT: u32 = 8;

/// `struct virtio_blk_discard_write_zeroes`: sector le64, num_sectors le32,
/// flags le32.
const SEGMENT_LEN: usize = 16;

/// A validated range to release, in bytes from the start of the disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DiscardRange {
    pub(super) offset: u64,
    pub(super) len: u64,
}

/// Why a discard request was refused. The two map to different status bytes:
/// the spec requires `VIRTIO_BLK_S_UNSUPP` for a flag the device does not
/// implement, and everything else is an I/O error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiscardRefusal {
    /// A segment set a flag. The only defined one, unmap, belongs to
    /// write-zeroes, and the rest are reserved.
    UnsupportedFlags,
    /// The payload is empty, not a whole number of segments, carries more than
    /// [`MAX_DISCARD_SEG`], or names a range that is oversized or does not lie
    /// entirely inside the disk.
    Malformed,
}

/// The largest payload a well-formed request can carry.
pub(super) const MAX_DISCARD_PAYLOAD: usize = MAX_DISCARD_SEG as usize * SEGMENT_LEN;

/// Validate a discard payload against a disk of `capacity_sectors`, returning
/// the byte ranges to release. Refuses rather than clamps: a range that runs
/// past the end of the disk is a guest bug or an attack, and trimming it to fit
/// would release bytes the guest never named.
pub(super) fn parse_discard_ranges(
    payload: &[u8],
    capacity_sectors: u64,
) -> Result<Vec<DiscardRange>, DiscardRefusal> {
    if payload.is_empty()
        || !payload.len().is_multiple_of(SEGMENT_LEN)
        || payload.len() > MAX_DISCARD_PAYLOAD
    {
        return Err(DiscardRefusal::Malformed);
    }
    payload
        .as_chunks::<SEGMENT_LEN>()
        .0
        .iter()
        .map(|segment| parse_segment(segment, capacity_sectors))
        .collect()
}

fn parse_segment(
    segment: &[u8; SEGMENT_LEN],
    capacity_sectors: u64,
) -> Result<DiscardRange, DiscardRefusal> {
    let field = |at: usize, width: usize| {
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(&segment[at..at + width]);
        u64::from_le_bytes(bytes)
    };
    let (sector, num_sectors, flags) = (field(0, 8), field(8, 4), field(12, 4));
    if flags != 0 {
        return Err(DiscardRefusal::UnsupportedFlags);
    }
    // A zero-sector range is refused rather than ignored. No driver emits one,
    // and accepting it would mean accepting a start sector that was never
    // checked against the disk — the range is vacuous, so nothing constrains it.
    if num_sectors == 0 || num_sectors > u64::from(MAX_DISCARD_SECTORS) {
        return Err(DiscardRefusal::Malformed);
    }
    let end = sector
        .checked_add(num_sectors)
        .filter(|&end| end <= capacity_sectors)
        .ok_or(DiscardRefusal::Malformed)?;
    Ok(DiscardRange {
        offset: sector * SECTOR,
        len: (end - sector) * SECTOR,
    })
}

/// Release `range` of `file` back to the host filesystem without changing the
/// file's length.
///
/// A host filesystem with no hole support reports success: discard is advice,
/// and a guest told its trim failed can do nothing but log it. Any other
/// failure is returned.
pub(super) fn punch_hole(file: &File, range: DiscardRange) -> io::Result<()> {
    match release(file, range) {
        Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(()),
        other => other,
    }
}

/// macOS: `F_PUNCHHOLE` requires a range aligned to the filesystem's block
/// size, so release only the whole blocks inside `range`. The partial blocks at
/// either edge keep their bytes, which discard permits.
#[cfg(target_os = "macos")]
fn release(file: &File, range: DiscardRange) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let block = fs_block_size(file)?;
    let start = range.offset.div_ceil(block) * block;
    let end = (range.offset + range.len) / block * block;
    if end <= start {
        return Ok(());
    }
    let arg = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: to_off_t(start)?,
        fp_length: to_off_t(end - start)?,
    };
    // SAFETY: `F_PUNCHHOLE` reads one `fpunchhole_t`, and `arg` outlives the
    // call. The descriptor is owned by `file`, which is borrowed for its duration.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &arg) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn fs_block_size(file: &File) -> io::Result<u64> {
    use std::os::fd::AsRawFd;

    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `fstatfs` fills the `statfs` it is handed, which is sized for it.
    let rc = unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstatfs` returned success, so it initialized the struct.
    let block = u64::from(unsafe { stat.assume_init() }.f_bsize);
    Ok(block.max(1))
}

/// Linux: `fallocate` zeroes partial blocks itself, so the range goes through
/// unaligned.
#[cfg(target_os = "linux")]
fn release(file: &File, range: DiscardRange) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: `fallocate` takes plain integers; the descriptor is owned by
    // `file`, which is borrowed for the call.
    let rc = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            to_off_t(range.offset)?,
            to_off_t(range.len)?,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn release(_file: &File, _range: DiscardRange) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn to_off_t(value: u64) -> io::Result<libc::off_t> {
    libc::off_t::try_from(value).map_err(|_| io::ErrorKind::InvalidInput.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(sector: u64, num_sectors: u32, flags: u32) -> Vec<u8> {
        let mut bytes = sector.to_le_bytes().to_vec();
        bytes.extend_from_slice(&num_sectors.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes
    }

    #[test]
    fn a_range_inside_the_disk_becomes_a_byte_range() {
        let ranges = parse_discard_ranges(&segment(8, 16, 0), 64).unwrap();
        assert_eq!(
            ranges,
            vec![DiscardRange {
                offset: 8 * SECTOR,
                len: 16 * SECTOR
            }]
        );
    }

    #[test]
    fn every_segment_in_a_request_is_returned_in_order() {
        let mut payload = segment(0, 8, 0);
        payload.extend(segment(32, 8, 0));
        let ranges = parse_discard_ranges(&payload, 64).unwrap();
        assert_eq!(
            ranges.iter().map(|r| r.offset).collect::<Vec<_>>(),
            vec![0, 32 * SECTOR]
        );
    }

    #[test]
    fn a_range_ending_exactly_at_capacity_is_accepted() {
        assert!(parse_discard_ranges(&segment(56, 8, 0), 64).is_ok());
    }

    #[test]
    fn a_range_running_one_sector_past_capacity_is_refused_not_clamped() {
        assert_eq!(
            parse_discard_ranges(&segment(57, 8, 0), 64),
            Err(DiscardRefusal::Malformed)
        );
    }

    #[test]
    fn a_range_starting_past_capacity_is_refused() {
        assert_eq!(
            parse_discard_ranges(&segment(64, 1, 0), 64),
            Err(DiscardRefusal::Malformed)
        );
    }

    #[test]
    fn a_zero_sector_range_is_refused_rather_than_silently_accepted() {
        // Vacuous, so nothing bounds its start sector: accepting it would admit
        // a start past the end of the disk.
        assert_eq!(
            parse_discard_ranges(&segment(0, 0, 0), 64),
            Err(DiscardRefusal::Malformed)
        );
        assert_eq!(
            parse_discard_ranges(&segment(64, 0, 0), 64),
            Err(DiscardRefusal::Malformed)
        );
    }

    #[test]
    fn a_sector_that_overflows_when_extended_is_refused() {
        assert_eq!(
            parse_discard_ranges(&segment(u64::MAX, 1, 0), u64::MAX),
            Err(DiscardRefusal::Malformed)
        );
    }

    #[test]
    fn a_range_over_the_advertised_maximum_is_refused() {
        assert_eq!(
            parse_discard_ranges(&segment(0, MAX_DISCARD_SECTORS + 1, 0), u64::MAX / SECTOR),
            Err(DiscardRefusal::Malformed)
        );
        assert!(
            parse_discard_ranges(&segment(0, MAX_DISCARD_SECTORS, 0), u64::MAX / SECTOR).is_ok()
        );
    }

    #[test]
    fn any_flag_is_unsupported_rather_than_an_io_error() {
        for flags in [1, 2, 1 << 31] {
            assert_eq!(
                parse_discard_ranges(&segment(0, 8, flags), 64),
                Err(DiscardRefusal::UnsupportedFlags),
                "flags {flags:#x}"
            );
        }
    }

    #[test]
    fn one_bad_segment_refuses_the_whole_request() {
        let mut payload = segment(0, 8, 0);
        payload.extend(segment(60, 8, 0));
        assert_eq!(
            parse_discard_ranges(&payload, 64),
            Err(DiscardRefusal::Malformed)
        );
    }

    #[test]
    fn a_payload_that_is_not_whole_segments_is_refused() {
        for len in [0, 1, 15, 17, 31] {
            assert_eq!(
                parse_discard_ranges(&vec![0; len], 64),
                Err(DiscardRefusal::Malformed),
                "payload of {len} bytes"
            );
        }
    }

    #[test]
    fn more_segments_than_advertised_is_refused() {
        let at_limit = segment(0, 1, 0).repeat(MAX_DISCARD_SEG as usize);
        assert!(parse_discard_ranges(&at_limit, 64).is_ok());
        let over = segment(0, 1, 0).repeat(MAX_DISCARD_SEG as usize + 1);
        assert_eq!(
            parse_discard_ranges(&over, 64),
            Err(DiscardRefusal::Malformed)
        );
    }

    /// Allocated blocks of `file` in 512-byte units, as `stat` reports them.
    fn allocated_sectors(file: &File) -> u64 {
        use std::os::unix::fs::MetadataExt;
        file.metadata().unwrap().blocks()
    }

    #[test]
    fn punching_a_hole_releases_host_blocks_and_keeps_the_length() {
        use std::os::unix::fs::FileExt;

        const LEN: u64 = 8 * 1024 * 1024;
        let f = tempfile::NamedTempFile::new().unwrap();
        let file = f.as_file();
        file.write_all_at(&vec![0xA5; LEN as usize], 0).unwrap();
        file.sync_all().unwrap();
        let before = allocated_sectors(file);

        punch_hole(
            file,
            DiscardRange {
                offset: 0,
                len: LEN,
            },
        )
        .unwrap();
        file.sync_all().unwrap();

        assert_eq!(file.metadata().unwrap().len(), LEN);
        let after = allocated_sectors(file);
        if after == before {
            // A temp directory on a filesystem without holes: nothing to measure.
            return;
        }
        assert!(
            after < before / 2,
            "expected most blocks released: {before} -> {after}"
        );
        let mut head = [0xFFu8; 4096];
        file.read_exact_at(&mut head, 0).unwrap();
        assert!(
            head.iter().all(|&b| b == 0),
            "a punched range reads as zeros"
        );
    }

    #[test]
    fn a_hole_punch_leaves_bytes_outside_the_range_untouched() {
        use std::os::unix::fs::FileExt;

        const BLOCK: u64 = 64 * 1024;
        let f = tempfile::NamedTempFile::new().unwrap();
        let file = f.as_file();
        file.write_all_at(&vec![0x5A; 3 * BLOCK as usize], 0)
            .unwrap();

        punch_hole(
            file,
            DiscardRange {
                offset: BLOCK,
                len: BLOCK,
            },
        )
        .unwrap();

        let mut first = vec![0u8; BLOCK as usize];
        let mut last = vec![0u8; BLOCK as usize];
        file.read_exact_at(&mut first, 0).unwrap();
        file.read_exact_at(&mut last, 2 * BLOCK).unwrap();
        assert!(first.iter().chain(&last).all(|&b| b == 0x5A));
    }
}
