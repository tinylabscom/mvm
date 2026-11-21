//! The racily-clean file memo: a cheap metadata stamp of a file and the rule
//! for when that stamp may stand in for hashing the file's bytes.

use std::path::Path;

/// A cheap rejection filter, not proof that a file's bytes are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FileStamp {
    pub(crate) len: u64,
    /// Nanoseconds since the Unix epoch; epoch-ns fits an `i64` until 2262.
    pub(crate) mtime_ns: i64,
    pub(crate) ctime_ns: i64,
    pub(crate) inode: Option<u64>,
}

pub(crate) fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    let ns_since_epoch = |time: std::io::Result<std::time::SystemTime>| {
        time.ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
    };
    let mtime_ns = ns_since_epoch(metadata.modified())?;
    #[cfg(unix)]
    let (ctime_ns, inode) =
        unix_stamp_ext(&metadata).map(|(ctime_ns, inode)| (ctime_ns, Some(inode)))?;
    #[cfg(not(unix))]
    let (ctime_ns, inode) = (mtime_ns, None);
    Some(FileStamp {
        len: metadata.len(),
        mtime_ns,
        ctime_ns,
        inode,
    })
}

#[cfg(unix)]
fn unix_stamp_ext(metadata: &std::fs::Metadata) -> Option<(i64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let ctime_ns = metadata
        .ctime()
        .checked_mul(1_000_000_000)?
        .checked_add(metadata.ctime_nsec())?;
    Some((ctime_ns, metadata.ino()))
}

/// Whether a file's timestamps are old enough, relative to when its memo was
/// written, to prove no rewrite has happened since. A rewrite made after the
/// memo carries a later mtime and ctime, so it cannot match the stamp, unless
/// it lands in the same timestamp tick as the write the memo describes; a
/// stamp within [`RACY_MARGIN_NS`] of the memo (or after it) cannot rule that
/// out. This is the "racily clean" rule: such a file is hashed instead.
///
/// A memo written after `observed_ns` came from a clock that has since moved
/// backwards, so its age proves nothing and the file is hashed too.
///
/// File timestamps and the clock read here must come from the same clock. A
/// filesystem served by a host whose clock runs more than the margin behind
/// this one can stamp a rewrite as older than the memo.
pub(crate) fn stamp_is_settled(stamp: &FileStamp, recorded_ns: i64, observed_ns: i64) -> bool {
    let newest = stamp.mtime_ns.max(stamp.ctime_ns);
    recorded_ns <= observed_ns && recorded_ns.saturating_sub(newest) >= RACY_MARGIN_NS
}

/// Wider than the coarsest timestamp granularity a supported filesystem
/// offers (two seconds on FAT), so a settled stamp cannot share a tick with
/// the write that preceded the memo.
pub(crate) const RACY_MARGIN_NS: i64 = 2_000_000_000;

pub(crate) fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
        .unwrap_or(0)
}
