use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// `LocalAuditKind`, `LocalAuditEvent`, and the per-tenant
/// `AuditAction`/`AuditEntry` DTOs live in
/// `mvm_contract::policy::audit`, re-exported here so every existing
/// `crate::policy::audit::{LocalAuditKind, LocalAuditEvent,
/// AuditAction, AuditEntry}` path keeps resolving unchanged. This
/// module carries the `std::fs`-backed writer, the composition
/// helpers, and the clock-stamped constructor those DTOs need.
pub use mvm_contract::policy::audit::{AuditAction, AuditEntry, LocalAuditEvent, LocalAuditKind};

/// Host-reported AI usage audit payload.
pub mod ai_usage;

// ============================================================================
// Local mvmctl audit log (single-host operations)
// ============================================================================

/// Default path for the local audit log:
/// `<mvm_state_dir>/log/audit.jsonl`.
pub fn default_audit_log() -> String {
    format!("{}/log/audit.jsonl", crate::config::mvm_state_dir())
}

/// Rotate when the audit log exceeds this size.
const ROTATE_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// Create a [`LocalAuditEvent`] stamped with the current UTC time.
///
/// A free function rather than an inherent method on
/// `LocalAuditEvent`: that type now lives in `mvm-contract`, and the
/// orphan rule forbids `mvm-core` from adding inherent `impl`s to a
/// foreign type. `Utc::now()` also needs chrono's `clock` feature
/// (std), unavailable in the no_std `mvm-contract` crate.
pub fn now_event(
    kind: LocalAuditKind,
    vm_name: Option<String>,
    detail: Option<String>,
) -> LocalAuditEvent {
    let timestamp = chrono::Utc::now().to_rfc3339();
    LocalAuditEvent {
        timestamp,
        kind,
        vm_name,
        detail,
    }
}

/// Append-only local audit log writer.
pub struct LocalAuditLog {
    path: PathBuf,
}

impl LocalAuditLog {
    /// Open (or create) a local audit log at `path`.
    ///
    /// Creates parent directories if they don't exist.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create audit log dir: {}", parent.display()))?;
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Append one JSONL line.  Rotates to `audit.jsonl.1` when the file
    /// exceeds `ROTATE_THRESHOLD_BYTES`.
    pub fn append(&self, event: &LocalAuditEvent) -> Result<()> {
        self.maybe_rotate()?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("Failed to open audit log: {}", self.path.display()))?;

        let line = serde_json::to_string(event).context("Failed to serialize audit event")?;
        writeln!(file, "{line}").context("Failed to write audit event")?;
        Ok(())
    }

    fn maybe_rotate(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let meta = std::fs::metadata(&self.path)
            .with_context(|| format!("Failed to stat {}", self.path.display()))?;
        if meta.len() >= ROTATE_THRESHOLD_BYTES {
            let rotated = self.path.with_extension("jsonl.1");
            std::fs::rename(&self.path, &rotated)
                .with_context(|| format!("Failed to rotate audit log to {}", rotated.display()))?;
        }
        Ok(())
    }
}

/// Convenience macro for the most common audit emit shapes.
///
/// The four arms mirror the chained-builder forms but collapse the
/// `event(LocalAuditKind::Variant)…emit()` boilerplate to a single
/// line:
///
/// ```ignore
/// // bare — no vm_name, no detail
/// audit_emit!(CachePrune);
///
/// // detail via format-string
/// audit_emit!(StorageGc, "count={count}");
/// audit_emit!(SlotPrune, "source={src} count={n}", src = "x", n = 4);
///
/// // vm_name + no detail
/// audit_emit!(SlotRemove, vm: slot_hash);
///
/// // vm_name + format-string detail (positional or named args)
/// audit_emit!(
///     SlotRemove,
///     vm: slot_hash,
///     "manifest_path={} manifest_file_deleted={deleted}",
///     path.display(),
///     deleted = file_was_deleted,
/// );
/// ```
///
/// More elaborate compositions (multiple modifiers, conditional
/// fields) should drop down to [`event`] + [`LocalAuditBuilder`]
/// directly. The macro deliberately doesn't add knobs beyond the
/// four shapes — every existing call site falls into one of them.
#[macro_export]
macro_rules! audit_emit {
    // Bare:  audit_emit!(CachePrune)
    ($variant:ident $(,)?) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        ).emit()
    };

    // vm_name + format-string detail (positional or named format args):
    //   audit_emit!(SlotRemove, vm: hash, "path={}", p);
    //   audit_emit!(SlotRemove, vm: hash, "k={v}", v = "x");
    ($variant:ident, vm: $vm:expr, $($args:tt)+) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        )
            .vm_name($vm)
            .detail(format!($($args)+))
            .emit()
    };

    // vm_name only:  audit_emit!(SlotRemove, vm: hash)
    ($variant:ident, vm: $vm:expr $(,)?) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        )
            .vm_name($vm)
            .emit()
    };

    // Format-string detail (positional or named format args):
    //   audit_emit!(StorageGc, "count={count}");
    //   audit_emit!(SlotPrune, "src={src} count={n}", src = "x", n = 4);
    ($variant:ident, $($args:tt)+) => {
        $crate::policy::audit::event(
            $crate::policy::audit::LocalAuditKind::$variant
        )
            .detail(format!($($args)+))
            .emit()
    };
}

/// Start composing a local audit event.
///
/// Preferred over the positional [`emit`] / [`emit_to`] helpers — chains
/// read top-to-bottom and adding a new optional field (e.g. `outcome`)
/// won't churn every call site. The event lands in
/// [`default_audit_log`] when terminated with [`LocalAuditBuilder::emit`];
/// tests redirect via [`LocalAuditBuilder::to_path`] before terminating.
///
/// ```ignore
/// audit::event(LocalAuditKind::CachePrune)
///     .detail(format!("count={count}"))
///     .emit();
/// ```
pub fn event(kind: LocalAuditKind) -> LocalAuditBuilder {
    LocalAuditBuilder {
        kind,
        vm_name: None,
        detail: None,
        path_override: None,
    }
}

/// Fluent builder for [`LocalAuditEvent`]. Construct with [`event`].
#[must_use = "the audit event isn't written until `.emit()` is called"]
pub struct LocalAuditBuilder {
    kind: LocalAuditKind,
    vm_name: Option<String>,
    detail: Option<String>,
    path_override: Option<PathBuf>,
}

impl LocalAuditBuilder {
    /// Attach a VM identifier to the event. Optional.
    pub fn vm_name(mut self, name: impl Into<String>) -> Self {
        self.vm_name = Some(name.into());
        self
    }

    /// Attach a free-form `detail` string. Conventionally a
    /// space-separated `key=value` list (`source=… count=…`).
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Redirect the emission to an explicit path instead of
    /// [`default_audit_log`]. Used by tests so emission can be
    /// observed without mutating `MVM_HOME` (which serializes
    /// badly across the test runner).
    pub fn to_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path_override = Some(path.into());
        self
    }

    /// Land the event. Best-effort: open/write failures are logged
    /// via `tracing::warn!` and never propagated — audit failures
    /// must not block the operation being logged.
    pub fn emit(self) {
        let path = self
            .path_override
            .unwrap_or_else(|| PathBuf::from(default_audit_log()));
        let event = now_event(self.kind, self.vm_name, self.detail);
        match LocalAuditLog::open(&path).and_then(|log| log.append(&event)) {
            Ok(()) => {}
            Err(e) => tracing::warn!("audit log write failed: {e}"),
        }
    }
}

/// Emit a local audit event to the default log path (best-effort).
///
/// Thin shim over [`event`] / [`LocalAuditBuilder::emit`] kept for
/// existing positional call sites. New code should prefer the builder
/// — the chained form scales to additional optional fields without
/// touching every caller.
pub fn emit(kind: LocalAuditKind, vm_name: Option<&str>, detail: Option<&str>) {
    let mut b = event(kind);
    if let Some(n) = vm_name {
        b = b.vm_name(n);
    }
    if let Some(d) = detail {
        b = b.detail(d);
    }
    b.emit();
}

/// Emit a local audit event to an explicit path (best-effort).
///
/// Thin shim over [`event`] / [`LocalAuditBuilder::to_path`] kept for
/// existing positional call sites. Tests should prefer
/// `event(kind).to_path(p).emit()` for parity with production-path
/// composition.
pub fn emit_to(path: &Path, kind: LocalAuditKind, vm_name: Option<&str>, detail: Option<&str>) {
    let mut b = event(kind).to_path(path.to_path_buf());
    if let Some(n) = vm_name {
        b = b.vm_name(n);
    }
    if let Some(d) = detail {
        b = b.detail(d);
    }
    b.emit();
}

/// Return the most recent Stage 0 lifecycle event (`Stage0Boot`,
/// `Stage0CachePromoted`, or `Stage0Failed`) in the default local
/// audit log, or `None` if Stage 0 has never run.
/// `mvmctl doctor` uses this to answer "when did Stage 0 last run and
/// how did it land?" without grep-ing the log.
pub fn read_last_stage0_event() -> Option<LocalAuditEvent> {
    read_last_stage0_event_in(Path::new(&default_audit_log()))
}

/// [`read_last_stage0_event`] against an explicit log path (tests
/// inject a temp JSONL so they don't depend on `$HOME`). Reads only
/// the live `audit.jsonl` (not the rotated `.1`) and caps the scan to
/// the tail so `doctor` stays fast on a large log. Malformed lines are
/// skipped rather than fatal — the log is observability, not a parser
/// contract.
pub fn read_last_stage0_event_in(path: &Path) -> Option<LocalAuditEvent> {
    /// Bound the scan so a near-rotation-size log (10 MiB) doesn't make
    /// `doctor` parse every line; the last Stage 0 event is always near
    /// the tail in practice.
    const MAX_TAIL_LINES: usize = 4096;
    let contents = std::fs::read_to_string(path).ok()?;
    let mut lines: Vec<&str> = contents.lines().collect();
    if lines.len() > MAX_TAIL_LINES {
        lines = lines.split_off(lines.len() - MAX_TAIL_LINES);
    }
    lines
        .iter()
        .rev()
        .filter_map(|line| serde_json::from_str::<LocalAuditEvent>(line).ok())
        .find(|ev| {
            matches!(
                ev.kind,
                LocalAuditKind::Stage0Boot
                    | LocalAuditKind::Stage0CachePromoted
                    | LocalAuditKind::Stage0Failed
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // `LocalAuditKind`/`LocalAuditEvent`/`AuditAction`/`AuditEntry`
    // serde-shape tests moved with the types to
    // `mvm_contract::policy::audit`. What stays here exercises the
    // `std::fs`-backed writer, the `event()`/`LocalAuditBuilder`
    // composition, the `audit_emit!` macro, and the Stage 0 tail
    // readers — none of which mvm-contract can host.

    #[test]
    fn read_last_stage0_event_picks_the_last_stage0_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // Interleave non-Stage0 events so the reader must filter.
        emit_to(&path, LocalAuditKind::VmStart, Some("vm-a"), None);
        emit_to(
            &path,
            LocalAuditKind::Stage0Boot,
            None,
            Some("seed=root-dir fingerprint_prefix=aaaaaaaa flavor=current"),
        );
        emit_to(&path, LocalAuditKind::VmStop, Some("vm-a"), None);
        emit_to(
            &path,
            LocalAuditKind::Stage0CachePromoted,
            None,
            Some("cache=/x fingerprint_prefix=bbbbbbbb duration_ms=42"),
        );
        emit_to(&path, LocalAuditKind::CachePrune, None, Some("removed=0"));

        let ev = read_last_stage0_event_in(&path).expect("a stage0 event");
        // The promoted event is the most recent Stage 0 entry.
        assert!(matches!(ev.kind, LocalAuditKind::Stage0CachePromoted));
        assert_eq!(
            ev.detail.as_deref(),
            Some("cache=/x fingerprint_prefix=bbbbbbbb duration_ms=42")
        );
    }

    #[test]
    fn read_last_stage0_event_is_none_without_stage0_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        emit_to(&path, LocalAuditKind::VmStart, Some("vm-a"), None);
        emit_to(&path, LocalAuditKind::CachePrune, None, Some("removed=0"));
        assert!(read_last_stage0_event_in(&path).is_none());
    }

    #[test]
    fn read_last_stage0_event_missing_log_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.jsonl");
        assert!(read_last_stage0_event_in(&path).is_none());
    }

    #[test]
    fn emit_to_writes_a_single_jsonl_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        emit_to(
            &path,
            LocalAuditKind::SnapshotIntegrityFailed,
            Some("vm-x"),
            Some("variant=tag_mismatch"),
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1, "exactly one line per emit");
        assert!(contents.contains("snapshot_integrity_failed"));
        assert!(contents.contains("vm-x"));
        assert!(contents.contains("tag_mismatch"));
    }

    #[test]
    fn builder_with_no_optionals_matches_legacy_emit() {
        // Builder default state is the same wire shape `emit` produces
        // with `(kind, None, None)` — minus the timestamp string,
        // which is `now()` on each call. The kind + null optionals
        // are what matter for the contract.
        let tmp = tempfile::tempdir().unwrap();
        let p_builder = tmp.path().join("builder.jsonl");
        let p_legacy = tmp.path().join("legacy.jsonl");

        event(LocalAuditKind::CachePrune).to_path(&p_builder).emit();
        emit_to(&p_legacy, LocalAuditKind::CachePrune, None, None);

        let builder_line = std::fs::read_to_string(&p_builder).unwrap();
        let legacy_line = std::fs::read_to_string(&p_legacy).unwrap();
        // Drop the timestamp segment from each so we compare shape, not
        // wall-clock drift between the two `chrono::Utc::now()` calls.
        let strip_ts = |s: &str| -> String {
            // Format: {"timestamp":"…","kind":"…",…}
            let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
            let mut obj = v.as_object().unwrap().clone();
            obj.remove("timestamp");
            serde_json::to_string(&obj).unwrap()
        };
        assert_eq!(strip_ts(&builder_line), strip_ts(&legacy_line));
    }

    #[test]
    fn builder_with_vm_name_and_detail_carries_both_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        event(LocalAuditKind::VmStop)
            .vm_name("vm-42")
            .detail("source=test")
            .to_path(&path)
            .emit();
        let body = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(v["kind"], "vm_stop");
        assert_eq!(v["vm_name"], "vm-42");
        assert_eq!(v["detail"], "source=test");
    }

    #[test]
    fn audit_emit_macro_all_four_arms_compile() {
        // The macro routes through `default_audit_log()`, which depends
        // on process env vars — driving it from a unit test would need
        // a process-global mutex around `set_var`/`remove_var`. Skip
        // the file-contents check here: end-to-end validation lives in
        // `tests/audit_emissions_live.rs`, where each migrated call
        // site is exercised via a subprocess with hermetic HOME.
        //
        // What this test buys: a compile-time shape check that all
        // four arms expand cleanly against `LocalAuditKind` variants
        // and the surrounding builder API. Renaming a variant or
        // changing `LocalAuditBuilder`'s signature surfaces here as a
        // compile error before the migration sites notice.
        if false {
            crate::audit_emit!(CachePrune);
            crate::audit_emit!(StorageGc, "count={n}", n = 3);
            let hash = String::from("deadbeef");
            crate::audit_emit!(SlotRemove, vm: hash.clone());
            crate::audit_emit!(SlotRemove, vm: hash, "path={p}", p = "/x");
        }
    }

    #[test]
    fn builder_terminator_required_must_use_emit() {
        // Compile-time check that `#[must_use]` on the builder
        // surfaces a warning if a caller forgets `.emit()`. We can't
        // assert the warning in unit tests; this test just shows that
        // the type is usable in the documented chained form so a
        // refactor that breaks the API surfaces as a compile error.
        let _b = event(LocalAuditKind::CachePrune).detail("noop");
        // intentionally not calling `.emit()` — confirms the dead
        // builder is the lint surface, not a runtime panic.
    }

    #[test]
    fn test_local_audit_log_append() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        let log = LocalAuditLog::open(&path).unwrap();
        let event = now_event(LocalAuditKind::VmStop, Some("vm1".to_string()), None);
        log.append(&event).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("vm_stop"));
        assert!(contents.contains("vm1"));
        // One line per event.
        assert_eq!(contents.lines().count(), 1);

        // Append a second event.
        let event2 = now_event(
            LocalAuditKind::UpdateInstall,
            None,
            Some("v1.2.3".to_string()),
        );
        log.append(&event2).unwrap();
        let contents2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents2.lines().count(), 2);
    }

    #[test]
    fn test_local_audit_log_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        // Write a file that exceeds the rotation threshold.
        let big_content = "x".repeat(ROTATE_THRESHOLD_BYTES as usize + 1);
        std::fs::write(&path, big_content).unwrap();

        let log = LocalAuditLog::open(&path).unwrap();
        let event = now_event(LocalAuditKind::Uninstall, None, None);
        log.append(&event).unwrap();

        // The rotated file should exist.
        let rotated = path.with_extension("jsonl.1");
        assert!(rotated.exists(), "rotation file should be created");

        // The new log file should contain only the new event.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("uninstall"));
    }
}
