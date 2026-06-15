//! Session entity — opaque ID + persistent metadata for the
//! `mvmctl session` verbs.
//!
//! A session is a microVM kept alive across multiple
//! `mvmctl invoke` calls. Today the warm-process pool already
//! intercepts most `RunEntrypoint` requests, but each
//! `mvmctl invoke` call still boots+tears down the substrate VM —
//! the session abstraction is what lets a long-running client
//! (mvmforge SDK's `Session`) hold a VM open and run multiple
//! function calls against it.
//!
//! ## Backing store
//!
//! Each session is one JSON file at
//! `$XDG_RUNTIME_DIR/mvmctl/sessions/<id>.json`. The runtime dir is
//! 0700 and per-user; the session file inherits 0600. Concurrent
//! writers are serialized via `crate::atomic_io::write_atomic` (same
//! discipline as the instance-state files).
//!
//! ## Field stability
//!
//! Adding a field is non-breaking (existing readers ignore unknown
//! fields). Renaming or removing a field is a breaking change —
//! mvmforge's `Session.info()` surfaces this struct verbatim, so
//! field names are part of the cross-repo contract.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Default idle timeout for newly-created sessions (5 minutes).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Env var to opt into the strict-creator-PID gate. When set to
/// "1", `mvmctl session attach` / `exec` / `run-code` / `console`
/// refuse calls whose PID isn't an ancestor or sibling of the
/// session's `creator_pid`. Off by default — file perms (0600) are
/// the real access boundary; this is a foot-gun guard for users
/// who want a second check.
pub const STRICT_CREATOR_PID_ENV: &str = "MVMCTL_STRICT_CREATOR_PID";

/// True iff the strict-creator gate is enabled.
pub fn strict_creator_pid_enabled() -> bool {
    std::env::var(STRICT_CREATOR_PID_ENV).is_ok_and(|v| v == "1")
}

/// Hard ceiling on idle timeout — 24 hours.
///
/// A session held open longer than this is almost certainly a forgotten
/// `--keep-alive` rather than an intentional long-running workload.
/// Refusing values past the ceiling is a foot-gun guard, not a hard
/// security boundary — operators with a legitimate need can call
/// `mvmctl session set-timeout` periodically to extend, or use
/// `mvmctl session reap` selectively.
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 86_400;

/// Opaque session identifier — base32-encoded random bytes.
///
/// Construction goes through [`SessionId::new`] which uses 16 random
/// bytes (~128 bits) base32-encoded without padding (26 characters).
/// Validation accepts any 16–64 character base32 alphabet string;
/// the conservative range allows future widening without a wire-shape
/// break.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh session id.
    pub fn new() -> Self {
        // Use UUIDv4 (16 random bytes / ~122 bits of entropy after the
        // version+variant fixed bits) as the entropy source, then base32-
        // encode for an opaque human-typeable token. UUID's randomness
        // comes from the platform RNG via `rand` (already a workspace
        // dep — we avoid adding fastrand). 16 bytes → 26 base32 chars.
        let bytes = uuid::Uuid::new_v4().into_bytes();
        Self(base32_encode(&bytes))
    }

    /// Parse a string into a session id, validating the alphabet and
    /// length range.
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() < 16 || s.len() > 64 {
            bail!(
                "session id must be 16-64 base32 characters, got {} characters",
                s.len()
            );
        }
        for c in s.bytes() {
            if !is_base32_alphabet(c) {
                bail!(
                    "session id contains non-base32 character {:?} (allowed: a-z, 2-7)",
                    c as char
                );
            }
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle state of a session as recorded in the on-disk file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Substrate VM is up and accepting calls.
    Running,
    /// `mvmctl session kill` requested teardown; inflight calls
    /// resolve as `kind="session-killed"`.
    Killed,
    /// Idle timeout expired; substrate reaped the VM.
    Reaped,
    /// Substrate VM exited unexpectedly (crash / OOM).
    Crashed,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Killed => write!(f, "killed"),
            Self::Reaped => write!(f, "reaped"),
            Self::Crashed => write!(f, "crashed"),
        }
    }
}

/// On-disk session metadata. Persisted at
/// `$XDG_RUNTIME_DIR/mvmctl/sessions/<id>.json`.
///
/// Every field except `id`, `vm_name`, `started_at` is mutated over
/// the session's lifetime. Writers serialize through atomic-rename
/// (`crate::atomic_io::write_atomic`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    /// Opaque identifier — surfaced to mvmforge SDK callers.
    pub id: SessionId,
    /// Underlying microVM name registered with the dev network.
    pub vm_name: String,
    /// Workload identifier (template name or slot hash) the session
    /// is running.
    pub workload_id: String,
    /// `dev` if the wrapper was started with `mode=dev` (allows ad-hoc
    /// `mvmctl session exec` / `run-code`); `prod` otherwise.
    pub mode: SessionMode,
    /// Substrate-side idle reaper timeout. `mvmctl session set-timeout`
    /// updates this; the warm-process pool consults it when deciding
    /// whether to retire an idle worker.
    pub idle_timeout_secs: u64,
    /// RFC 3339 wall-clock when the session was created. Stable for
    /// the lifetime of the session.
    pub started_at: String,
    /// RFC 3339 wall-clock of the most recent `RunEntrypoint` call.
    /// `None` until the first invoke arrives.
    pub last_invoke_at: Option<String>,
    /// Number of `RunEntrypoint` calls dispatched into this session
    /// since creation.
    #[serde(default)]
    pub invoke_count: u64,
    /// Current lifecycle state.
    pub state: SessionState,
    /// PID of the process that created this session, captured at
    /// `register` time. Used by the optional strict-creator-PID gate
    /// to refuse `attach` / `exec` / `run-code` / `console` from a
    /// different process tree (`MVMCTL_STRICT_CREATOR_PID=1`).
    ///
    /// **Limitations** — this is a foot-gun guard, not a security
    /// boundary. PIDs are reused: once the creating process exits,
    /// the next process to receive its PID looks like a legitimate
    /// owner. Process-group lookups would tighten the check but
    /// break the common SDK pattern of attaching from a sibling
    /// shell. The 0700 file perms on the session table are still
    /// the actual access boundary; this field exists so an operator
    /// who *wants* an extra "did the same shell that started this
    /// session also do the attach?" check can opt in.
    ///
    /// `#[serde(default)]` keeps records written before this field
    /// existed parseable; a `creator_pid: 0` indicates "unknown,
    /// gate is implicitly disabled for this record."
    #[serde(default)]
    pub creator_pid: u32,
    /// When true, the session is torn down automatically after an
    /// attach completes (vz-style `--ephemeral`). Defaults false so
    /// records written before this field still parse.
    #[serde(default)]
    pub ephemeral: bool,
}

/// Whether the session's wrapper is allowed to run ad-hoc code (dev)
/// or strictly the baked entrypoint (prod). Mirrors the wrapper-side
/// `mode` field at `/etc/mvm/wrapper.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Prod,
    Dev,
}

impl std::fmt::Display for SessionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prod => write!(f, "prod"),
            Self::Dev => write!(f, "dev"),
        }
    }
}

impl SessionRecord {
    /// Construct a fresh `SessionRecord` for a newly-booted VM.
    /// Captures the calling process's PID into `creator_pid` so the
    /// optional strict-creator gate (`MVMCTL_STRICT_CREATOR_PID=1`)
    /// has a baseline to compare against.
    pub fn new_running(
        vm_name: impl Into<String>,
        workload_id: impl Into<String>,
        mode: SessionMode,
    ) -> Self {
        Self {
            id: SessionId::new(),
            vm_name: vm_name.into(),
            workload_id: workload_id.into(),
            mode,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            started_at: now_rfc3339(),
            last_invoke_at: None,
            invoke_count: 0,
            state: SessionState::Running,
            creator_pid: std::process::id(),
            ephemeral: false,
        }
    }
}

fn now_rfc3339() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// On-disk session store.
//
// Each session is a single JSON file; the directory is the runtime dir
// (`config::ensure_runtime_dir()`) plus a `sessions/` subdir. Concurrent
// writers serialize through `atomic_io::atomic_write` (write to temp,
// fsync, rename). Readers see either the old or the new content — never
// a partial write.
// ---------------------------------------------------------------------------

/// Path of the session-table directory:
/// `<mvm_runtime_dir>/sessions/`.
pub fn sessions_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(crate::config::mvm_runtime_dir()).join("sessions")
}

/// Ensure the sessions dir exists with mode 0700 and return its path.
#[cfg(unix)]
pub fn ensure_sessions_dir() -> Result<std::path::PathBuf> {
    use anyhow::Context;
    use std::os::unix::fs::PermissionsExt;
    crate::config::ensure_runtime_dir().map_err(|e| anyhow::anyhow!("ensure runtime dir: {e}"))?;
    let dir = sessions_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create sessions dir: {}", dir.display()))?;
    let mut perms = std::fs::metadata(&dir)?.permissions();
    if perms.mode() & 0o777 != 0o700 {
        perms.set_mode(0o700);
        std::fs::set_permissions(&dir, perms)?;
    }
    Ok(dir)
}

/// Write a session record to its JSON file (atomic).
#[cfg(unix)]
pub fn write_session(record: &SessionRecord) -> Result<()> {
    use anyhow::Context;
    use std::os::unix::fs::PermissionsExt;
    let dir = ensure_sessions_dir()?;
    let path = dir.join(format!("{}.json", record.id));
    let text = serde_json::to_string_pretty(record).context("serialize session record")?;
    crate::util::atomic_io::atomic_write(&path, text.as_bytes())?;
    // Lock down to 0600 — defense in depth on top of the dir's 0700.
    let mut perms = std::fs::metadata(&path)?.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(())
}

/// Read a session record by id. Returns `Ok(None)` if no record exists.
pub fn read_session(id: &SessionId) -> Result<Option<SessionRecord>> {
    use anyhow::Context;
    let path = sessions_dir().join(format!("{id}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read session file: {}", path.display()))?;
    let record: SessionRecord = serde_json::from_str(&text)
        .with_context(|| format!("parse session record: {}", path.display()))?;
    Ok(Some(record))
}

/// Delete a session record. Returns `Ok(false)` if no record existed.
pub fn remove_session(id: &SessionId) -> Result<bool> {
    use anyhow::Context;
    let path = sessions_dir().join(format!("{id}.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("remove session file: {}", path.display())),
    }
}

/// List all session records currently in the table. Skips files that
/// can't be parsed (logs a warning) — a corrupt entry shouldn't take
/// the rest of the table down. Returns records sorted by `started_at`
/// (earliest first).
pub fn list_sessions() -> Result<Vec<SessionRecord>> {
    let dir = sessions_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "skipping unreadable session file");
                continue;
            }
        };
        match serde_json::from_str::<SessionRecord>(&text) {
            Ok(rec) => out.push(rec),
            Err(e) => {
                tracing::warn!(path = %path.display(), err = %e, "skipping unparseable session file");
            }
        }
    }
    out.sort_by(|a, b| a.started_at.cmp(&b.started_at));
    Ok(out)
}

/// Read-modify-write a session record atomically. The closure receives
/// `&mut SessionRecord` and may mutate it; on `Ok`, the modified record
/// is written back.
#[cfg(unix)]
pub fn update_session<F>(id: &SessionId, mutate: F) -> Result<SessionRecord>
where
    F: FnOnce(&mut SessionRecord) -> Result<()>,
{
    let mut record = read_session(id)?.ok_or_else(|| anyhow::anyhow!("no session with id {id}"))?;
    mutate(&mut record)?;
    write_session(&record)?;
    Ok(record)
}

/// Return the IDs of `Running` sessions whose idle timeout has elapsed
/// as of `now`. Pure: does not perform any teardown — the caller in
/// `mvm-cli` translates each id into `tear_down_session_vm` + a
/// `state = Reaped` update.
///
/// Idle is measured against `last_invoke_at` if the session has
/// handled at least one call, else against `started_at`. Records whose
/// timestamps fail to parse are skipped (warn-and-continue rather than
/// erroring out — a corrupt record shouldn't block reaping the rest).
pub fn list_expired_session_ids(now: chrono::DateTime<chrono::Utc>) -> Result<Vec<SessionId>> {
    let mut expired = Vec::new();
    for record in list_sessions()? {
        if record.state != SessionState::Running {
            continue;
        }
        let last_str = record
            .last_invoke_at
            .as_deref()
            .unwrap_or(&record.started_at);
        let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(last_str) else {
            tracing::warn!(
                session = %record.id,
                ts = %last_str,
                "skip expiry check: unparseable timestamp"
            );
            continue;
        };
        let elapsed = now
            .signed_duration_since(last_dt.with_timezone(&chrono::Utc))
            .num_seconds();
        if elapsed > 0 && (elapsed as u64) > record.idle_timeout_secs {
            expired.push(record.id);
        }
    }
    Ok(expired)
}

/// The most-recently-active Running session, ranked by
/// `last_invoke_at` (falling back to `started_at`). Pure over the
/// input so it can be tested without touching disk.
pub fn most_recent_running(records: Vec<SessionRecord>) -> Option<SessionRecord> {
    records
        .into_iter()
        .filter(|r| r.state == SessionState::Running)
        .max_by(|a, b| {
            let ka = a.last_invoke_at.as_deref().unwrap_or(&a.started_at);
            let kb = b.last_invoke_at.as_deref().unwrap_or(&b.started_at);
            ka.cmp(kb)
        })
}

/// Disk-backed convenience: scan the session table and return the
/// most-recently-active Running session.
pub fn most_recent_running_on_disk() -> Result<Option<SessionRecord>> {
    Ok(most_recent_running(list_sessions()?))
}

// ---------------------------------------------------------------------------
// Base32 helpers — RFC 4648, no padding, lowercase.
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

fn is_base32_alphabet(c: u8) -> bool {
    matches!(c, b'a'..=b'z' | b'2'..=b'7')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_new_is_26_chars_base32() {
        let id = SessionId::new();
        assert_eq!(id.as_str().len(), 26);
        for c in id.as_str().bytes() {
            assert!(is_base32_alphabet(c), "non-base32 char: {}", c as char);
        }
    }

    #[test]
    fn session_id_new_is_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_parse_accepts_generated() {
        let id = SessionId::new();
        let parsed = SessionId::parse(id.as_str()).expect("roundtrip");
        assert_eq!(parsed, id);
    }

    #[test]
    fn session_id_parse_rejects_too_short() {
        let err = SessionId::parse("abc").unwrap_err();
        assert!(
            err.to_string().contains("16-64 base32"),
            "expected length-range message, got: {err}"
        );
    }

    #[test]
    fn session_id_parse_rejects_invalid_chars() {
        let err = SessionId::parse("ABCDEFGHIJKLMNOP").unwrap_err();
        assert!(
            err.to_string().contains("non-base32"),
            "expected non-base32 message for uppercase, got: {err}"
        );
        let err = SessionId::parse("aaaaaaaaaaaaaaa!").unwrap_err();
        assert!(
            err.to_string().contains("non-base32"),
            "expected non-base32 message for `!`, got: {err}"
        );
    }

    #[test]
    fn session_id_serde_roundtrip() {
        let id = SessionId::new();
        let json = serde_json::to_string(&id).unwrap();
        // transparent serde: serialized as a bare string.
        assert!(json.starts_with('"') && json.ends_with('"'));
        let decoded: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn session_record_roundtrip() {
        let rec = SessionRecord::new_running("happy-cat-1234", "openclaw", SessionMode::Prod);
        let json = serde_json::to_string(&rec).unwrap();
        let decoded: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, rec.id);
        assert_eq!(decoded.vm_name, "happy-cat-1234");
        assert_eq!(decoded.workload_id, "openclaw");
        assert_eq!(decoded.mode, SessionMode::Prod);
        assert_eq!(decoded.state, SessionState::Running);
        assert_eq!(decoded.invoke_count, 0);
        assert_eq!(decoded.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT_SECS);
    }

    #[test]
    fn session_record_rejects_unknown_field() {
        let json = r#"{
            "id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "vm_name": "x",
            "workload_id": "y",
            "mode": "prod",
            "idle_timeout_secs": 300,
            "started_at": "2026-05-06T00:00:00Z",
            "invoke_count": 0,
            "state": "running",
            "extra_field": "boom"
        }"#;
        let err = serde_json::from_str::<SessionRecord>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }

    #[test]
    fn session_state_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&SessionState::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Killed).unwrap(),
            "\"killed\""
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Reaped).unwrap(),
            "\"reaped\""
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Crashed).unwrap(),
            "\"crashed\""
        );
    }

    #[test]
    fn base32_encode_round_examples() {
        // Empty input → empty output.
        assert_eq!(base32_encode(&[]), "");
        // Single byte 0x00 → "aa" (top 5 bits = 00000 = 'a', remaining 3
        // bits zero-padded → "aa").
        assert_eq!(base32_encode(&[0x00]), "aa");
        // 16 bytes always produce 26 chars (per session-id contract).
        let sixteen = [0u8; 16];
        assert_eq!(base32_encode(&sixteen).len(), 26);
    }

    // --- on-disk store --------------------------------------------------

    /// Set up a temp runtime dir for the duration of one test. Returns a
    /// guard that resets `MVM_RUNTIME_DIR` on drop and holds an exclusive
    /// lock for the duration so parallel tests don't race the env var.
    struct RuntimeDirGuard {
        _temp: tempfile::TempDir,
        _env: crate::util::test_env::TestEnv,
    }

    fn isolated_runtime_dir() -> RuntimeDirGuard {
        let temp = tempfile::tempdir().expect("tempdir");
        // `TestEnv` serializes env-mutating tests behind a process-wide lock
        // and restores `MVM_RUNTIME_DIR` to its prior value on drop.
        let mut env = crate::util::test_env::TestEnv::new();
        env.set("MVM_RUNTIME_DIR", temp.path());
        RuntimeDirGuard {
            _temp: temp,
            _env: env,
        }
    }

    #[cfg(unix)]
    #[test]
    fn store_write_then_read_roundtrip() {
        let _guard = isolated_runtime_dir();
        let rec = SessionRecord::new_running("vm-1", "openclaw", SessionMode::Prod);
        let id = rec.id.clone();
        write_session(&rec).expect("write");
        let read = read_session(&id).expect("read").expect("present");
        assert_eq!(read.id, id);
        assert_eq!(read.vm_name, "vm-1");
    }

    #[cfg(unix)]
    #[test]
    fn store_read_missing_returns_none() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new();
        assert!(read_session(&id).expect("read missing").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn store_remove_returns_existence() {
        let _guard = isolated_runtime_dir();
        let rec = SessionRecord::new_running("vm-1", "x", SessionMode::Prod);
        let id = rec.id.clone();
        write_session(&rec).unwrap();
        assert!(remove_session(&id).unwrap(), "should report 'existed'");
        assert!(
            !remove_session(&id).unwrap(),
            "second remove should report 'did not exist'"
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_list_sorts_by_started_at() {
        let _guard = isolated_runtime_dir();
        // Build records with known started_at strings so ordering is deterministic.
        let mut a = SessionRecord::new_running("vm-a", "x", SessionMode::Prod);
        a.started_at = "2026-01-01T00:00:00Z".into();
        let mut b = SessionRecord::new_running("vm-b", "x", SessionMode::Prod);
        b.started_at = "2026-02-01T00:00:00Z".into();
        let mut c = SessionRecord::new_running("vm-c", "x", SessionMode::Prod);
        c.started_at = "2026-03-01T00:00:00Z".into();
        // Write in non-sorted order.
        write_session(&c).unwrap();
        write_session(&a).unwrap();
        write_session(&b).unwrap();
        let listed = list_sessions().unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].vm_name, "vm-a");
        assert_eq!(listed[1].vm_name, "vm-b");
        assert_eq!(listed[2].vm_name, "vm-c");
    }

    #[cfg(unix)]
    #[test]
    fn store_update_mutates_and_persists() {
        let _guard = isolated_runtime_dir();
        let rec = SessionRecord::new_running("vm-1", "x", SessionMode::Prod);
        let id = rec.id.clone();
        write_session(&rec).unwrap();
        let updated = update_session(&id, |r| {
            r.idle_timeout_secs = 999;
            r.invoke_count = 42;
            Ok(())
        })
        .unwrap();
        assert_eq!(updated.idle_timeout_secs, 999);
        assert_eq!(updated.invoke_count, 42);
        let reread = read_session(&id).unwrap().unwrap();
        assert_eq!(reread.idle_timeout_secs, 999);
        assert_eq!(reread.invoke_count, 42);
    }

    #[cfg(unix)]
    #[test]
    fn store_update_missing_errors() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new();
        let err = update_session(&id, |_| Ok(())).unwrap_err();
        assert!(
            err.to_string().contains("no session with id"),
            "expected missing-id error, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sessions_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = isolated_runtime_dir();
        let dir = ensure_sessions_dir().unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn list_expired_session_ids_picks_only_idle_running_records() {
        let _guard = isolated_runtime_dir();
        let now = chrono::Utc::now();
        let stale = now - chrono::Duration::seconds(900);
        let recent = now - chrono::Duration::seconds(60);

        // Idle, running, past timeout → reapable.
        let mut a = SessionRecord::new_running("vm-a", "x", SessionMode::Prod);
        a.idle_timeout_secs = 300;
        a.started_at = stale.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        a.last_invoke_at = Some(stale.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

        // Idle but recent — within timeout, not reapable.
        let mut b = SessionRecord::new_running("vm-b", "x", SessionMode::Prod);
        b.idle_timeout_secs = 300;
        b.last_invoke_at = Some(recent.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

        // Idle and stale, but already Killed — skip.
        let mut c = SessionRecord::new_running("vm-c", "x", SessionMode::Prod);
        c.state = SessionState::Killed;
        c.idle_timeout_secs = 300;
        c.last_invoke_at = Some(stale.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

        // Stale but never invoked — falls back to started_at.
        let mut d = SessionRecord::new_running("vm-d", "x", SessionMode::Prod);
        d.idle_timeout_secs = 300;
        d.started_at = stale.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        d.last_invoke_at = None;

        for r in [&a, &b, &c, &d] {
            write_session(r).unwrap();
        }

        let expired = list_expired_session_ids(now).unwrap();
        let expired_vms: std::collections::HashSet<String> = expired
            .iter()
            .map(|id| read_session(id).unwrap().unwrap().vm_name)
            .collect();
        assert!(expired_vms.contains("vm-a"));
        assert!(expired_vms.contains("vm-d"));
        assert!(!expired_vms.contains("vm-b"));
        assert!(!expired_vms.contains("vm-c"));
        assert_eq!(expired_vms.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn list_expired_skips_unparseable_timestamps() {
        let _guard = isolated_runtime_dir();
        let now = chrono::Utc::now();
        let mut a = SessionRecord::new_running("vm-a", "x", SessionMode::Prod);
        a.idle_timeout_secs = 0;
        a.started_at = "not-an-rfc3339-date".into();
        write_session(&a).unwrap();
        // Should not panic, and shouldn't include the unparseable record.
        let expired = list_expired_session_ids(now).unwrap();
        assert!(expired.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn session_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = isolated_runtime_dir();
        let rec = SessionRecord::new_running("vm-1", "x", SessionMode::Prod);
        let id = rec.id.clone();
        write_session(&rec).unwrap();
        let path = sessions_dir().join(format!("{id}.json"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn most_recent_running_prefers_latest_activity() {
        let mut a = SessionRecord::new_running("vm-a", "tmpl", SessionMode::Prod);
        a.started_at = "2026-01-01T00:00:00Z".to_string();
        a.last_invoke_at = Some("2026-01-01T05:00:00Z".to_string());
        let mut b = SessionRecord::new_running("vm-b", "tmpl", SessionMode::Prod);
        b.started_at = "2026-01-02T00:00:00Z".to_string();
        b.last_invoke_at = None; // falls back to started_at
        let mut killed = SessionRecord::new_running("vm-c", "tmpl", SessionMode::Prod);
        killed.started_at = "2026-09-09T00:00:00Z".to_string();
        killed.state = SessionState::Killed; // excluded

        let pick = most_recent_running(vec![a, b, killed]);
        // b's started_at (Jan 2) beats a's last_invoke (Jan 1 05:00).
        assert_eq!(pick.unwrap().vm_name, "vm-b");
    }

    #[test]
    fn most_recent_running_none_when_empty() {
        assert!(most_recent_running(Vec::new()).is_none());
    }

    #[test]
    fn most_recent_running_compares_two_invoked() {
        // Both records have last_invoke_at set; the later one wins.
        let mut earlier = SessionRecord::new_running("vm-early", "tmpl", SessionMode::Prod);
        earlier.last_invoke_at = Some("2026-03-01T10:00:00Z".to_string());
        let mut later = SessionRecord::new_running("vm-late", "tmpl", SessionMode::Prod);
        later.last_invoke_at = Some("2026-03-01T11:00:00Z".to_string());

        let pick = most_recent_running(vec![earlier, later]);
        assert_eq!(
            pick.unwrap().vm_name,
            "vm-late",
            "later last_invoke_at should win"
        );
    }

    #[test]
    fn session_record_ephemeral_defaults_false_and_roundtrips() {
        let mut r = SessionRecord::new_running("vm", "tmpl", SessionMode::Prod);
        assert!(!r.ephemeral);
        r.ephemeral = true;
        let json = serde_json::to_string(&r).unwrap();
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert!(back.ephemeral);
    }

    #[test]
    fn session_record_legacy_without_ephemeral_parses() {
        // A record serialized before `ephemeral` existed must still parse
        // (serde default), despite deny_unknown_fields.
        let r = SessionRecord::new_running("vm", "tmpl", SessionMode::Prod);
        let mut val = serde_json::to_value(&r).unwrap();
        val.as_object_mut().unwrap().remove("ephemeral");
        let back: SessionRecord = serde_json::from_value(val).unwrap();
        assert!(!back.ephemeral);
    }
}
