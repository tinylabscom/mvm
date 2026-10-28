//! A nonce ledger that survives the process.
//!
//! [`super::validity::NonceStore`] remembers the nonces of one admission. An
//! externally signed plan is replayable for its whole validity window unless
//! the host remembers the nonces it has spent across launches, so this keeps
//! them in a file under the private mvm home.
//!
//! Every spend takes an exclusive lock on a sibling lock file, re-reads the
//! ledger, drops entries whose plan has expired, refuses a nonce already
//! recorded for the same signer, and publishes the new set with a
//! write-then-rename. Two `mvmctl` processes therefore see each other's
//! nonces, and a crash leaves either the old ledger or the new one.
//!
//! An entry is dropped only once `check_window` would refuse its plan anyway,
//! so pruning never re-admits a replay.

use super::validity::Freshness;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

const LEDGER_FILE: &str = "nonces.tsv";
const LEDGER_TMP: &str = "nonces.tsv.tmp";
const LOCK_FILE: &str = "nonces.lock";

/// Why a nonce could not be spent.
#[derive(Debug)]
pub enum NonceLedgerError {
    /// This signer has already used the nonce.
    Replay { signer: String },
    /// The ledger could not be read, locked or written. Admission must refuse:
    /// a plan whose nonce cannot be recorded cannot be told apart from a replay.
    Unavailable(String),
}

impl std::fmt::Display for NonceLedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replay { signer } => write!(f, "nonce already used by signer {signer}"),
            Self::Unavailable(why) => write!(f, "plan replay ledger unavailable: {why}"),
        }
    }
}

impl std::error::Error for NonceLedgerError {}

fn unavailable(what: &str, e: impl std::fmt::Display) -> NonceLedgerError {
    NonceLedgerError::Unavailable(format!("{what}: {e}"))
}

/// A file-backed, cross-process nonce ledger rooted at one private directory.
#[derive(Debug, Clone)]
pub struct FileNonceLedger {
    dir: PathBuf,
}

impl FileNonceLedger {
    /// Open (creating it private if missing) the ledger directory `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        crate::config::create_private_dir(&dir)?;
        Ok(Self { dir })
    }

    /// The directory holding the ledger.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Record `item`'s nonce for `signer`, or refuse if it is already there.
    ///
    /// `now` decides which recorded entries have expired and are dropped.
    pub fn check_and_insert<F: Freshness>(
        &self,
        signer: &str,
        item: &F,
        now: DateTime<Utc>,
    ) -> Result<(), NonceLedgerError> {
        if signer.is_empty() || signer.contains(['\t', '\n', '\r']) {
            return Err(NonceLedgerError::Unavailable(format!(
                "signer id {signer:?} cannot be recorded"
            )));
        }
        let _lock = self.lock()?;
        let mut live = self.read_live(now)?;
        let key = (signer.to_string(), item.nonce().to_string());
        if live.iter().any(|(s, n, _)| (s, n) == (&key.0, &key.1)) {
            return Err(NonceLedgerError::Replay {
                signer: signer.to_string(),
            });
        }
        live.push((key.0, key.1, item.valid_until()));
        self.publish(&live)
    }

    fn lock(&self) -> Result<std::fs::File, NonceLedgerError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dir.join(LOCK_FILE))
            .map_err(|e| unavailable("opening the ledger lock", e))?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|e| unavailable("locking the ledger", e))?;
        Ok(file)
    }

    fn read_live(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, String, DateTime<Utc>)>, NonceLedgerError> {
        let text = match std::fs::read_to_string(self.dir.join(LEDGER_FILE)) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(unavailable("reading the ledger", e)),
        };
        let mut seen = HashSet::new();
        let mut live = Vec::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let mut fields = line.split('\t');
            let (Some(signer), Some(nonce), Some(until), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(NonceLedgerError::Unavailable(format!(
                    "malformed ledger line {line:?}"
                )));
            };
            let until = DateTime::parse_from_rfc3339(until)
                .map_err(|e| unavailable("parsing a ledger expiry", e))?
                .with_timezone(&Utc);
            if until > now && seen.insert((signer.to_string(), nonce.to_string())) {
                live.push((signer.to_string(), nonce.to_string(), until));
            }
        }
        Ok(live)
    }

    fn publish(&self, live: &[(String, String, DateTime<Utc>)]) -> Result<(), NonceLedgerError> {
        let mut text = String::new();
        for (signer, nonce, until) in live {
            text.push_str(&format!("{signer}\t{nonce}\t{}\n", until.to_rfc3339()));
        }
        let tmp = self.dir.join(LEDGER_TMP);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| unavailable("writing the ledger", e))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| unavailable("writing the ledger", e))?;
        std::fs::rename(&tmp, self.dir.join(LEDGER_FILE))
            .map_err(|e| unavailable("publishing the ledger", e))?;
        // Make the rename itself durable; a failure here still leaves a valid ledger.
        if let Ok(dir) = std::fs::File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::Nonce;
    use super::super::validity::{FreshnessClaims, checked};
    use super::*;
    use chrono::Duration;
    use std::os::unix::fs::PermissionsExt as _;

    fn claims(seed: u8, now: DateTime<Utc>, ttl: Duration) -> FreshnessClaims {
        FreshnessClaims::new(
            now - Duration::seconds(1),
            now + ttl,
            Nonce::from_bytes([seed; 16]),
        )
    }

    fn ledger(root: &Path) -> FileNonceLedger {
        FileNonceLedger::open(root.join("plan-nonces")).unwrap()
    }

    #[test]
    fn a_nonce_spent_once_is_refused_by_a_second_ledger_on_the_same_directory() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let plan = checked(&claims(1, now, Duration::minutes(5))).unwrap();
        // Two separate openings stand in for two `mvmctl` processes.
        ledger(root.path())
            .check_and_insert("signer-a", &plan, now)
            .unwrap();
        let err = ledger(root.path())
            .check_and_insert("signer-a", &plan, now)
            .unwrap_err();
        assert!(matches!(err, NonceLedgerError::Replay { ref signer } if signer == "signer-a"));
    }

    #[test]
    fn the_same_nonce_from_another_signer_is_independent() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let plan = checked(&claims(2, now, Duration::minutes(5))).unwrap();
        let ledger = ledger(root.path());
        ledger.check_and_insert("signer-a", &plan, now).unwrap();
        ledger.check_and_insert("signer-b", &plan, now).unwrap();
    }

    #[test]
    fn an_expired_entry_is_pruned_from_the_file() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let short = checked(&claims(3, now, Duration::seconds(10))).unwrap();
        let other = checked(&claims(4, now, Duration::minutes(5))).unwrap();
        let ledger = ledger(root.path());
        ledger.check_and_insert("signer-a", &short, now).unwrap();
        let later = now + Duration::seconds(30);
        ledger.check_and_insert("signer-a", &other, later).unwrap();
        let text = std::fs::read_to_string(ledger.dir().join(LEDGER_FILE)).unwrap();
        assert_eq!(
            text.lines().count(),
            1,
            "only the live entry remains: {text}"
        );
        assert!(text.contains(&Nonce::from_bytes([4; 16]).to_string()));
    }

    #[test]
    fn the_ledger_files_are_private() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let plan = checked(&claims(5, now, Duration::minutes(5))).unwrap();
        let ledger = ledger(root.path());
        ledger.check_and_insert("signer-a", &plan, now).unwrap();
        for name in [LEDGER_FILE, LOCK_FILE] {
            let mode = std::fs::metadata(ledger.dir().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        let dir_mode = std::fs::metadata(ledger.dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn a_corrupt_ledger_refuses_instead_of_forgetting_nonces() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let plan = checked(&claims(6, now, Duration::minutes(5))).unwrap();
        let ledger = ledger(root.path());
        std::fs::write(ledger.dir().join(LEDGER_FILE), "not a ledger line\n").unwrap();
        let err = ledger.check_and_insert("signer-a", &plan, now).unwrap_err();
        assert!(matches!(err, NonceLedgerError::Unavailable(_)), "{err}");
    }

    #[test]
    fn a_signer_id_that_would_break_the_format_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let plan = checked(&claims(7, now, Duration::minutes(5))).unwrap();
        let ledger = ledger(root.path());
        for bad in ["", "a\tb", "a\nb"] {
            assert!(ledger.check_and_insert(bad, &plan, now).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn racing_spends_of_one_nonce_admit_exactly_one() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("plan-nonces");
        let now = Utc::now();
        let winners = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let ledger = FileNonceLedger::open(&dir).unwrap();
                    let plan = checked(&claims(9, now, Duration::minutes(5))).unwrap();
                    if ledger.check_and_insert("signer-a", &plan, now).is_ok() {
                        winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
