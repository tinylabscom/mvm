//! Authentication for the artifact digest sidecar.
//!
//! `image_verify::sha256_file_cached` skips re-hashing a large, unchanged
//! artifact by remembering its digest in a `<file>.sha256cache` sidecar. A
//! sidecar is a plain file beside the artifact, so anyone who can write the
//! artifact can write its sidecar too: keying it on size and mtime defends
//! against an accident, not against a person who restores the mtime.
//!
//! This module makes the sidecar a claim only this host can make. Each digest is
//! sealed with an HMAC-SHA256 under a per-install key kept in the private keys
//! directory, and the HMAC covers the file's device, inode, size, mtime and
//! ctime as well as the digest. A user-space writer cannot choose a file's
//! ctime or inode, so editing the file in place, replacing it, or copying a
//! valid sidecar line from another file all change an input to the HMAC and
//! the line stops verifying. Without the key an attacker cannot make a new one.
//!
//! Any failure here (no key, wrong permissions, unreadable file) means "do not
//! use the cache": the caller hashes the file, which is always correct.
//!
//! The seal is a claim only this host's key can make; it does not stop a process
//! of the same user that can read the key file, which can mint a seal for any
//! bytes. A malicious host is out of scope, so that is the line this cache
//! holds, not a stronger one.
//!
//! A digest is sealed only for a file that has [`settled`](FileIdentity::settled):
//! a write in the same timestamp tick as the sealing `stat` leaves size, mtime
//! and ctime unchanged, so a file that was just written cannot be told apart
//! from the same file rewritten.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fs::Metadata;
use std::io;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

#[cfg(unix)]
const KEY_FILE: &str = "digest-cache.key";
const KEY_LEN: usize = 32;
const DOMAIN: &[u8] = b"mvm digest cache v1\0";

/// The per-install secret that seals sidecar digests.
#[derive(Clone)]
pub struct CacheKey([u8; KEY_LEN]);

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CacheKey(..)")
    }
}

/// What the HMAC binds a digest to: the file as the kernel names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_nanos: i128,
    ctime_nanos: i128,
}

impl FileIdentity {
    /// The identity of the file `meta` describes, or `None` where the platform
    /// has no inode and ctime to bind to (the cache is then not used).
    #[cfg(unix)]
    #[must_use]
    pub fn of(meta: &Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let nanos = |secs: i64, nsec: i64| i128::from(secs) * 1_000_000_000 + i128::from(nsec);
        Some(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_nanos: nanos(meta.mtime(), meta.mtime_nsec()),
            ctime_nanos: nanos(meta.ctime(), meta.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    #[must_use]
    pub fn of(_meta: &Metadata) -> Option<Self> {
        None
    }

    /// Whether the newest of mtime and ctime is at least `window` older than
    /// `now`, so a later write cannot share the recorded timestamps. A
    /// timestamp in the future, a clock before the epoch, and a ctime with no
    /// sub-second part (a filesystem too coarse for any window to outlast its
    /// tick) are all unsettled.
    #[must_use]
    pub fn settled(&self, now: std::time::SystemTime, window: std::time::Duration) -> bool {
        self.settle_delay(now, window) == Some(std::time::Duration::ZERO)
    }

    /// Time remaining before this identity can settle; `None` means waiting
    /// cannot help (coarse timestamps, a future timestamp, or a pre-epoch clock).
    #[must_use]
    pub fn settle_delay(
        &self,
        now: std::time::SystemTime,
        window: std::time::Duration,
    ) -> Option<std::time::Duration> {
        const SECOND: i128 = 1_000_000_000;
        let now = now.duration_since(std::time::UNIX_EPOCH).ok()?;
        let newest = self.mtime_nanos.max(self.ctime_nanos);
        let age = i128::try_from(now.as_nanos()).unwrap_or(i128::MAX) - newest;
        if self.ctime_nanos.rem_euclid(SECOND) == 0 || age < 0 {
            return None;
        }
        if age >= i128::try_from(window.as_nanos()).unwrap_or(i128::MAX) {
            return Some(std::time::Duration::ZERO);
        }
        let age = std::time::Duration::new(
            u64::try_from(age / SECOND).ok()?,
            u32::try_from(age % SECOND).ok()?,
        );
        Some(window.saturating_sub(age))
    }
}

impl CacheKey {
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    fn mac(&self, identity: &FileIdentity, digest_hex: &str) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(DOMAIN);
        mac.update(&identity.dev.to_le_bytes());
        mac.update(&identity.ino.to_le_bytes());
        mac.update(&identity.size.to_le_bytes());
        mac.update(&identity.mtime_nanos.to_le_bytes());
        mac.update(&identity.ctime_nanos.to_le_bytes());
        mac.update(digest_hex.as_bytes());
        mac
    }

    /// The seal for `digest_hex` on the file `identity` names, as lowercase hex.
    #[must_use]
    pub fn seal(&self, identity: &FileIdentity, digest_hex: &str) -> String {
        hex::encode(self.mac(identity, digest_hex).finalize().into_bytes())
    }

    /// Whether `seal_hex` is this key's seal for `digest_hex` on `identity`.
    /// The comparison is constant time.
    #[must_use]
    pub fn verify(&self, identity: &FileIdentity, digest_hex: &str, seal_hex: &str) -> bool {
        let Ok(seal) = hex::decode(seal_hex) else {
            return false;
        };
        self.mac(identity, digest_hex).verify_slice(&seal).is_ok()
    }
}

/// The process-wide key from the host's keys directory, created on first use.
/// `None` when it cannot be read or created, which disables the cache.
#[must_use]
pub fn process_key() -> Option<&'static CacheKey> {
    static KEY: std::sync::OnceLock<Option<CacheKey>> = std::sync::OnceLock::new();
    KEY.get_or_init(|| load_or_create_in(&crate::config::mvm_keys_dir()).ok())
        .as_ref()
}

/// Load `<dir>/digest-cache.key`, creating it private if it does not exist.
///
/// The file must be a regular file owned by this user and not accessible to
/// anyone else, 32 bytes long; anything else is an error rather than a key.
/// Creation publishes a fully written file with a no-clobber link, so two
/// processes racing to create it agree on one key.
#[cfg(unix)]
pub fn load_or_create_in(dir: &Path) -> io::Result<CacheKey> {
    use rand::Rng as _;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    crate::config::create_private_dir(dir)?;
    let path = dir.join(KEY_FILE);
    if let Some(key) = read_key(&path)? {
        return Ok(key);
    }
    let mut bytes = [0_u8; KEY_LEN];
    rand::rng().fill_bytes(&mut bytes);
    // A name no other creator, in this process or another, can share: threads
    // of one process have the same pid.
    let tmp = dir.join(format!("{KEY_FILE}.tmp.{}", hex::encode(&bytes[..8])));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let linked = std::fs::hard_link(&tmp, &path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    read_key(&path)?.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "digest cache key"))
}

#[cfg(not(unix))]
pub fn load_or_create_in(dir: &Path) -> io::Result<CacheKey> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "{}: the digest cache needs Unix file identity",
            dir.display()
        ),
    ))
}

#[cfg(unix)]
fn read_key(path: &Path) -> io::Result<Option<CacheKey>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let refuse = |why: &str| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: {why}", path.display()),
        ))
    };
    if !meta.file_type().is_file() {
        return refuse("not a regular file");
    }
    crate::private_fs::require_current_owner(&meta)?;
    if crate::private_fs::mode_bits(path, &meta)? & 0o077 != 0 {
        return refuse("readable by other users");
    }
    let bytes = std::fs::read(path)?;
    let key: [u8; KEY_LEN] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "digest cache key length"))?;
    Ok(Some(CacheKey(key)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn identity(ino: u64, ctime: i128) -> FileIdentity {
        FileIdentity {
            dev: 1,
            ino,
            size: 4096,
            mtime_nanos: 10,
            ctime_nanos: ctime,
        }
    }

    const WINDOW: std::time::Duration = std::time::Duration::from_millis(250);

    fn at(nanos: i128) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_nanos(u64::try_from(nanos).unwrap())
    }

    fn stamped(mtime: i128, ctime: i128) -> FileIdentity {
        FileIdentity {
            mtime_nanos: mtime,
            ..identity(1, ctime)
        }
    }

    #[test]
    fn a_file_is_settled_exactly_at_the_window_and_not_a_nanosecond_before() {
        let ctime = 5_000_000_123;
        let id = stamped(ctime, ctime);
        let window = WINDOW.as_nanos() as i128;
        assert!(!id.settled(at(ctime + window - 1), WINDOW));
        assert!(id.settled(at(ctime + window), WINDOW));
    }

    #[test]
    fn the_newer_of_mtime_and_ctime_decides() {
        let id = stamped(9_000_000_007, 5_000_000_123);
        let window = WINDOW.as_nanos() as i128;
        assert!(!id.settled(at(9_000_000_007 + window - 1), WINDOW));
        assert!(id.settled(at(9_000_000_007 + window), WINDOW));
    }

    #[test]
    fn a_timestamp_in_the_future_is_never_settled() {
        let id = stamped(5_000_000_123, 9_000_000_007);
        assert!(!id.settled(at(5_000_000_124), WINDOW));
        assert!(!id.settled(at(9_000_000_006), WINDOW));
    }

    #[test]
    fn a_whole_second_ctime_is_never_settled() {
        let id = stamped(1_000_000_001, 2_000_000_000);
        assert!(!id.settled(at(1_000_000_000_000), WINDOW));
    }

    #[test]
    fn a_clock_before_the_epoch_settles_nothing() {
        let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert!(!stamped(5_000_000_123, 5_000_000_123).settled(before, WINDOW));
    }

    #[test]
    fn settle_delay_only_waits_for_identities_that_can_settle() {
        use std::time::Duration;
        let stamp = 5_000_000_123;
        let id = stamped(stamp, stamp);
        let read_started = at(stamp + 100_000_000);
        assert_eq!(
            id.settle_delay(read_started, WINDOW),
            Some(Duration::from_millis(150))
        );
        assert!(!id.settled(read_started, WINDOW));
        assert!(id.settled(read_started + Duration::from_millis(300), WINDOW));
        assert_eq!(
            id.settle_delay(at(stamp + 250_000_000), WINDOW),
            Some(Duration::ZERO)
        );
        assert_eq!(id.settle_delay(at(stamp - 1), WINDOW), None);
        assert_eq!(
            stamped(stamp, 5_000_000_000).settle_delay(at(stamp), WINDOW),
            None
        );
        assert_eq!(
            id.settle_delay(std::time::UNIX_EPOCH - Duration::from_secs(1), WINDOW),
            None
        );
    }

    #[test]
    fn a_seal_verifies_only_for_the_same_key_file_and_digest() {
        let key = CacheKey::from_bytes([7; KEY_LEN]);
        let digest = "ab".repeat(32);
        let seal = key.seal(&identity(5, 100), &digest);
        assert!(key.verify(&identity(5, 100), &digest, &seal));
        assert!(
            !key.verify(&identity(6, 100), &digest, &seal),
            "another inode"
        );
        assert!(
            !key.verify(&identity(5, 101), &digest, &seal),
            "a changed ctime"
        );
        assert!(
            !key.verify(&identity(5, 100), &"cd".repeat(32), &seal),
            "another digest"
        );
        let other = CacheKey::from_bytes([8; KEY_LEN]);
        assert!(
            !other.verify(&identity(5, 100), &digest, &seal),
            "another key"
        );
        assert!(!key.verify(&identity(5, 100), &digest, "nothex"));
        assert!(!key.verify(&identity(5, 100), &digest, ""));
    }

    #[test]
    fn the_key_is_created_private_and_reloaded_identically() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let first = load_or_create_in(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let second = load_or_create_in(&dir).unwrap();
        assert_eq!(first.0, second.0);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file is left behind: {leftovers:?}"
        );
    }

    #[test]
    fn a_key_other_users_can_read_or_of_the_wrong_length_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        load_or_create_in(&dir).unwrap();
        let path = dir.join(KEY_FILE);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_in(&dir).is_err(), "group/other readable");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"short").unwrap();
        assert!(load_or_create_in(&dir).is_err(), "wrong length");
    }

    #[test]
    fn a_symlink_at_the_key_path_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        crate::config::create_private_dir(&dir).unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::write(&elsewhere, [0_u8; KEY_LEN]).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join(KEY_FILE)).unwrap();
        assert!(load_or_create_in(&dir).is_err());
    }

    #[test]
    fn racing_creators_agree_on_one_key() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let keys: Vec<[u8; KEY_LEN]> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| load_or_create_in(&dir).unwrap().0))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
