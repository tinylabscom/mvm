//! Session lifecycle for the MCP `run` tool.
//!
//! Plan 32 / Proposal A.2. v1 ships the bookkeeping layer:
//!
//! - [`SessionMap`] tracks `(session_id → SessionState)` with idle and
//!   max-lifetime expiry — *protocol-only safe*, no I/O.
//! - [`SessionConfig`] reads `MVM_MCP_SESSION_IDLE` / `MVM_MCP_SESSION_MAX`
//!   from the environment with documented defaults.
//! - The [`Reaper`] trait is the bridge between the pure map and the
//!   side-effecting world (kill the VM, audit-log the close); the
//!   stdio server and mvmd's hosted variant each plug in their own.
//!
//! Warm-VM materialisation (booting a long-running VM that persists
//! across `tools/call` invocations) is deferred to A.2 v2 because the
//! existing `crate::exec` boot/dispatch/teardown path is tightly
//! coupled and a clean split is risky without live-KVM integration
//! tests. The wire schema (`session`, `close`) is already in place —
//! v1 honours the schema for bookkeeping/correlation; v2 will materialise
//! the VM behind the bookkeeping. ADR-003 §"Decisions" 6 documents the
//! split.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Default session idle timeout (seconds). Overridable via
/// `MVM_MCP_SESSION_IDLE` env var.
pub const DEFAULT_IDLE_SECS: u64 = 300;

/// Default session max lifetime (seconds). Overridable via
/// `MVM_MCP_SESSION_MAX` env var.
pub const DEFAULT_MAX_SECS: u64 = 3600;

/// Configuration knobs for the session map.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    pub idle: Duration,
    pub max: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(DEFAULT_IDLE_SECS),
            max: Duration::from_secs(DEFAULT_MAX_SECS),
        }
    }
}

impl SessionConfig {
    /// Read idle/max from environment, falling back to defaults.
    pub fn from_env() -> Self {
        let idle = std::env::var("MVM_MCP_SESSION_IDLE")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(DEFAULT_IDLE_SECS));
        let max = std::env::var("MVM_MCP_SESSION_MAX")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(DEFAULT_MAX_SECS));
        Self { idle, max }
    }
}

/// One row in the session map.
///
/// `vm_name` is `Option` so v1 (bookkeeping-only) can record a
/// session without owning a VM. v2 sets it when a warm VM is
/// materialised. Either way the lifetime tracking is identical.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub env: String,
    pub vm_name: Option<String>,
    pub started_at: Instant,
    pub last_used: Instant,
}

/// Outcome of [`SessionMap::touch_or_insert`]: did we hit an existing
/// session, or did we just create it?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLookup {
    /// Session existed; `last_used` was updated.
    Existing,
    /// Session did not exist; a fresh entry was created.
    Created,
}

/// Reason a session was reaped — passed to [`Reaper::on_reap`] so the
/// caller can audit-log the right kind (idle-expiry vs. max-lifetime
/// vs. explicit close vs. server-shutdown drain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapReason {
    /// `last_used + idle < now`.
    Idle,
    /// `started_at + max < now`.
    MaxLifetime,
    /// Client sent `close: true` on the most recent call.
    Closed,
    /// Server shutting down; reap everything still in the map.
    Shutdown,
}

/// The bridge between the pure [`SessionMap`] and the side-effecting
/// world. Implementors do whatever needs to happen when a session
/// ends: kill the VM, audit-log, free per-session resources.
pub trait Reaper: Send + Sync {
    fn on_reap(&self, session_id: &str, state: &SessionState, reason: ReapReason);
}

/// Pure session map. All time math goes through `Instant::now()`
/// at call time so tests can drive expiry by injecting their own
/// "now" via [`SessionMap::touch_or_insert_at`] /
/// [`SessionMap::reap_expired_at`].
#[derive(Debug, Default)]
pub struct SessionMap {
    sessions: BTreeMap<String, SessionState>,
    config: SessionConfig,
}

impl SessionMap {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: BTreeMap::new(),
            config,
        }
    }

    pub fn config(&self) -> SessionConfig {
        self.config
    }

    /// Number of live sessions currently tracked.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Look up an existing session or create a new one. Updates
    /// `last_used` to `now` either way. Returns whether the session
    /// was already present.
    ///
    /// `vm_name_hint` is what to record on first insert. v1 callers
    /// pass `None` because warm VMs aren't materialised yet; v2
    /// passes the booted VM name so the reaper has something to kill.
    pub fn touch_or_insert(
        &mut self,
        session_id: &str,
        env: &str,
        vm_name_hint: Option<String>,
    ) -> SessionLookup {
        self.touch_or_insert_at(session_id, env, vm_name_hint, Instant::now())
    }

    /// Test-friendly variant that takes an explicit "now".
    pub fn touch_or_insert_at(
        &mut self,
        session_id: &str,
        env: &str,
        vm_name_hint: Option<String>,
        now: Instant,
    ) -> SessionLookup {
        if let Some(state) = self.sessions.get_mut(session_id) {
            state.last_used = now;
            // env mismatch on a reused session is a client bug; the
            // map records the original env. Caller may want to surface
            // a warning, but the map itself is permissive.
            return SessionLookup::Existing;
        }
        self.sessions.insert(
            session_id.to_string(),
            SessionState {
                env: env.to_string(),
                vm_name: vm_name_hint,
                started_at: now,
                last_used: now,
            },
        );
        SessionLookup::Created
    }

    /// Get a snapshot of a session's state (for audit logging,
    /// inspection). Returns `None` if no such session.
    pub fn get(&self, session_id: &str) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Record the warm-VM name on an existing session. Used by A.2 v2
    /// after `boot_session_vm` succeeds, so the reaper has something
    /// to tear down. No-op if the session is unknown (the VM was
    /// reaped between insert and this call — caller should tear down
    /// the orphaned VM themselves).
    pub fn set_vm_name(&mut self, session_id: &str, vm_name: String) -> bool {
        match self.sessions.get_mut(session_id) {
            Some(state) => {
                state.vm_name = Some(vm_name);
                true
            }
            None => false,
        }
    }

    /// Remove a session by id, calling the reaper with the given
    /// reason. Used for explicit `close: true` and shutdown drain.
    pub fn remove(&mut self, session_id: &str, reason: ReapReason, reaper: &dyn Reaper) -> bool {
        if let Some(state) = self.sessions.remove(session_id) {
            reaper.on_reap(session_id, &state, reason);
            true
        } else {
            false
        }
    }

    /// Sweep expired sessions, calling the reaper for each. Returns
    /// the number of sessions reaped.
    pub fn reap_expired(&mut self, reaper: &dyn Reaper) -> usize {
        self.reap_expired_at(reaper, Instant::now())
    }

    /// Test-friendly variant that takes an explicit "now".
    pub fn reap_expired_at(&mut self, reaper: &dyn Reaper, now: Instant) -> usize {
        let mut to_reap: Vec<(String, ReapReason)> = Vec::new();
        for (id, state) in &self.sessions {
            // Max lifetime trumps idle: a session that hits both is
            // reported as MaxLifetime so audit logs distinguish "user
            // walked away" from "policy says enough."
            if now.duration_since(state.started_at) >= self.config.max {
                to_reap.push((id.clone(), ReapReason::MaxLifetime));
            } else if now.duration_since(state.last_used) >= self.config.idle {
                to_reap.push((id.clone(), ReapReason::Idle));
            }
        }
        let n = to_reap.len();
        for (id, reason) in to_reap {
            if let Some(state) = self.sessions.remove(&id) {
                reaper.on_reap(&id, &state, reason);
            }
        }
        n
    }

    /// Drain the map (server shutdown). All remaining sessions are
    /// reaped with [`ReapReason::Shutdown`].
    pub fn drain(&mut self, reaper: &dyn Reaper) -> usize {
        let drained: Vec<(String, SessionState)> =
            std::mem::take(&mut self.sessions).into_iter().collect();
        let n = drained.len();
        for (id, state) in drained {
            reaper.on_reap(&id, &state, ReapReason::Shutdown);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every reap so tests can assert on them.
    #[derive(Default)]
    struct RecordingReaper {
        calls: Mutex<Vec<(String, ReapReason)>>,
    }
    impl Reaper for RecordingReaper {
        fn on_reap(&self, session_id: &str, _state: &SessionState, reason: ReapReason) {
            self.calls
                .lock()
                .unwrap()
                .push((session_id.to_string(), reason));
        }
    }

    fn cfg(idle_secs: u64, max_secs: u64) -> SessionConfig {
        SessionConfig {
            idle: Duration::from_secs(idle_secs),
            max: Duration::from_secs(max_secs),
        }
    }

    #[test]
    fn touch_or_insert_creates_then_returns_existing() {
        let mut map = SessionMap::new(cfg(300, 3600));
        let t0 = Instant::now();
        assert_eq!(
            map.touch_or_insert_at("s1", "shell", None, t0),
            SessionLookup::Created
        );
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.touch_or_insert_at("s1", "shell", None, t0 + Duration::from_secs(5)),
            SessionLookup::Existing
        );
        assert_eq!(map.len(), 1, "second touch must not create a new entry");
    }

    #[test]
    fn touch_updates_last_used() {
        let mut map = SessionMap::new(cfg(300, 3600));
        let t0 = Instant::now();
        map.touch_or_insert_at("s1", "shell", None, t0);
        let t1 = t0 + Duration::from_secs(60);
        map.touch_or_insert_at("s1", "shell", None, t1);
        let state = map.get("s1").unwrap();
        assert_eq!(state.last_used, t1);
        assert_eq!(state.started_at, t0, "started_at must be sticky");
    }

    #[test]
    fn idle_reaps_after_idle_window() {
        let mut map = SessionMap::new(cfg(60, 3600));
        let reaper = RecordingReaper::default();
        let t0 = Instant::now();
        map.touch_or_insert_at("s1", "shell", None, t0);

        // 30 s later — under idle window.
        assert_eq!(
            map.reap_expired_at(&reaper, t0 + Duration::from_secs(30)),
            0
        );
        assert_eq!(map.len(), 1);

        // 60 s later — at idle window boundary, should reap.
        assert_eq!(
            map.reap_expired_at(&reaper, t0 + Duration::from_secs(60)),
            1
        );
        assert_eq!(map.len(), 0);
        let calls = reaper.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "s1");
        assert_eq!(calls[0].1, ReapReason::Idle);
    }

    #[test]
    fn max_lifetime_reaps_even_if_recently_touched() {
        let mut map = SessionMap::new(cfg(300, 60));
        let reaper = RecordingReaper::default();
        let t0 = Instant::now();
        map.touch_or_insert_at("s1", "shell", None, t0);

        // 50 s later — under max but recently touched.
        map.touch_or_insert_at("s1", "shell", None, t0 + Duration::from_secs(50));

        // 60 s later — at max window. last_used was 50 s ago, idle is 300 s
        // so idle would not fire; max should fire.
        assert_eq!(
            map.reap_expired_at(&reaper, t0 + Duration::from_secs(60)),
            1
        );
        let calls = reaper.calls.lock().unwrap();
        assert_eq!(calls[0].1, ReapReason::MaxLifetime);
    }

    #[test]
    fn explicit_close_reports_reason_closed() {
        let mut map = SessionMap::new(cfg(300, 3600));
        let reaper = RecordingReaper::default();
        map.touch_or_insert("s1", "shell", None);
        assert!(map.remove("s1", ReapReason::Closed, &reaper));
        let calls = reaper.calls.lock().unwrap();
        assert_eq!(calls[0].1, ReapReason::Closed);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn remove_unknown_session_returns_false() {
        let mut map = SessionMap::new(cfg(300, 3600));
        let reaper = RecordingReaper::default();
        assert!(!map.remove("nonexistent", ReapReason::Closed, &reaper));
        assert!(reaper.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn drain_reports_reason_shutdown() {
        let mut map = SessionMap::new(cfg(300, 3600));
        let reaper = RecordingReaper::default();
        map.touch_or_insert("s1", "shell", None);
        map.touch_or_insert("s2", "python", None);
        assert_eq!(map.drain(&reaper), 2);
        let calls = reaper.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|(_, r)| *r == ReapReason::Shutdown));
        assert!(map.is_empty());
    }

    #[test]
    fn config_from_env_uses_defaults_when_unset() {
        // Don't mutate env in this test (other tests rely on defaults
        // being readable without setup); just check the type-level
        // defaults.
        let c = SessionConfig::default();
        assert_eq!(c.idle, Duration::from_secs(DEFAULT_IDLE_SECS));
        assert_eq!(c.max, Duration::from_secs(DEFAULT_MAX_SECS));
    }

    #[test]
    fn vm_name_hint_persists() {
        let mut map = SessionMap::new(cfg(300, 3600));
        map.touch_or_insert("s1", "shell", Some("mcp-session-s1".to_string()));
        let state = map.get("s1").unwrap();
        assert_eq!(state.vm_name.as_deref(), Some("mcp-session-s1"));
    }

    #[test]
    fn set_vm_name_records_after_boot() {
        // A.2 v2: dispatcher inserts on first call (vm_name=None),
        // then sets the name once boot_session_vm returns.
        let mut map = SessionMap::new(cfg(300, 3600));
        map.touch_or_insert("s1", "shell", None);
        assert!(map.get("s1").unwrap().vm_name.is_none());
        assert!(map.set_vm_name("s1", "mcp-session-s1-deadbeef".to_string()));
        assert_eq!(
            map.get("s1").unwrap().vm_name.as_deref(),
            Some("mcp-session-s1-deadbeef")
        );
    }

    #[test]
    fn set_vm_name_returns_false_for_unknown_session() {
        let mut map = SessionMap::new(cfg(300, 3600));
        assert!(!map.set_vm_name("ghost", "mcp-ghost".to_string()));
    }

    #[test]
    fn reap_after_drain_is_no_op() {
        let mut map = SessionMap::new(cfg(60, 3600));
        let reaper = RecordingReaper::default();
        map.touch_or_insert("s1", "shell", None);
        map.drain(&reaper);
        assert_eq!(map.reap_expired(&reaper), 0);
    }
}
