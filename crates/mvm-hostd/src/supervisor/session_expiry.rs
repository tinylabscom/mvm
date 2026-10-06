//! Session idle-timeout enforcement.
//!
//! A warm session promises to go away once it has sat idle past its timeout.
//! For a long time that promise was kept only when someone ran a `machine
//! session` verb, which swept expired records on its way in: a session nobody
//! touched again stayed up for as long as the host did. The idle timeout is
//! now enforced by the process that owns the guest for its whole life, the
//! per-VM supervisor, which is still running when every client has gone.
//!
//! Two pieces live here:
//!
//! - [`claim_expired_session`], the one decision every reaper makes: re-read a
//!   record, and if it is still a running session past its timeout, mark it
//!   `Reaped` and record the reap. The CLI's sweep and the supervisor's
//!   watcher both go through it, so a session is reaped and audited the same
//!   way whoever notices first.
//! - [`SessionExpiryWatcher`], the supervisor side: find the session record
//!   for this VM, watch it, and when it expires claim it, seal the session's
//!   audit chain the way a `machine stop` does, then stop the guest.
//!
//! The supervisor does not know at boot whether it is running a session: the
//! record is written only once the guest agent has answered. The watcher
//! therefore looks for a record for a bounded window after boot and stands
//! down if none appears, so a machine that is not a session does not poll the
//! session store for the rest of its life.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use mvm_core::audit::{LocalAuditKind, emit as audit_emit};
use mvm_core::plan::ExecutionPlan;
use mvm_core::session::{self, SessionId, SessionRecord, SessionState};

use super::wall_clock::{
    SupervisorExitKiller, SupervisorTimerInputs, WorkloadKiller, decode_admitted_plan,
    supervisor_emitter,
};
use crate::audit::emitter::AuditEmitter;
use crate::audit::session::SealReason;

/// How often the supervisor re-reads its session record.
const POLL: Duration = Duration::from_secs(2);

/// How long after boot the supervisor looks for a session record for its VM.
///
/// A session's record is written once its guest agent answers, which the
/// session start waits at most 30 seconds for. Ten times that leaves room for
/// a slow host without leaving every non-session machine polling for good.
const DISCOVERY_WINDOW: Duration = Duration::from_secs(300);

/// Mark `id` reaped if it is still a running session past its idle timeout at
/// `now`, and record the reap in the local audit log.
///
/// Returns the record as it stood before the claim, or `None` when there was
/// nothing to claim: no such record, a record that is no longer running, or
/// one that is not yet idle long enough. Tearing the VM down and sealing its
/// audit chain are the caller's, because the two reapers do them differently.
///
/// # Errors
/// The record could not be read or rewritten, or changed state between the
/// read and the rewrite.
pub fn claim_expired_session(id: &SessionId, now: DateTime<Utc>) -> Result<Option<SessionRecord>> {
    let Some(record) = session::read_session(id)? else {
        return Ok(None);
    };
    if record.state != SessionState::Running || !record.idle_expired_at(now) {
        return Ok(None);
    }
    session::update_session(id, |current| {
        if current.state != SessionState::Running {
            bail!("session {id} became {} while being reaped", current.state);
        }
        current.state = SessionState::Reaped;
        Ok(())
    })?;
    audit_emit(
        LocalAuditKind::SessionReap,
        Some(&record.vm_name),
        Some(&format!(
            "session={id},idle_timeout_secs={}",
            record.idle_timeout_secs
        )),
    );
    Ok(Some(record))
}

/// Seal a session that ended because its machine was stopped, then publish the
/// closing root over it, so the root covers the seal.
///
/// # Errors
/// The chain could not be read, or the seal or root could not be written.
pub fn seal_stopped_session(emitter: &AuditEmitter, plan: &ExecutionPlan) -> Result<()> {
    emitter.seal_session(plan, SealReason::Stopped)?;
    emitter.publish_root(&plan.tenant.0)?;
    Ok(())
}

/// What the watcher seals a reaped session's chain under.
struct Sealer {
    plan: ExecutionPlan,
    emitter: Arc<AuditEmitter>,
}

/// What one pass of the watcher decided.
#[derive(Debug, PartialEq, Eq)]
enum Pass {
    /// Keep watching.
    Continue,
    /// Nothing left to watch: no session appeared in time, or the session
    /// ended some other way.
    StandDown,
    /// The session expired and has been claimed; the guest must stop.
    Expired,
}

/// Watches the session record for one VM and stops the VM when the session
/// has been idle past its timeout.
pub struct SessionExpiryWatcher {
    vm_name: String,
    booted_at: DateTime<Utc>,
    sealer: Option<Sealer>,
    killer: Box<dyn WorkloadKiller>,
    tracked: Option<SessionId>,
}

impl SessionExpiryWatcher {
    /// A watcher for `vm_name`, which booted at `booted_at` and is stopped by
    /// `killer`. It seals nothing until given [`Self::sealing_under`].
    #[must_use]
    pub fn new(
        vm_name: impl Into<String>,
        booted_at: DateTime<Utc>,
        killer: Box<dyn WorkloadKiller>,
    ) -> Self {
        Self {
            vm_name: vm_name.into(),
            booted_at,
            sealer: None,
            killer,
            tracked: None,
        }
    }

    /// Seal a reaped session's audit chain under `plan`, in `emitter`.
    #[must_use]
    pub fn sealing_under(mut self, plan: ExecutionPlan, emitter: Arc<AuditEmitter>) -> Self {
        self.sealer = Some(Sealer { plan, emitter });
        self
    }

    /// Run one pass at `now` and stop the guest if the session expired.
    /// Returns whether there is anything left to watch.
    pub fn step(&mut self, now: DateTime<Utc>) -> bool {
        match self.pass(now) {
            Pass::Continue => true,
            Pass::StandDown => false,
            Pass::Expired => {
                self.killer.kill();
                false
            }
        }
    }

    /// Poll until the session expires or there is nothing left to watch.
    pub fn run(mut self, poll: Duration) {
        loop {
            std::thread::sleep(poll);
            if !self.step(Utc::now()) {
                return;
            }
        }
    }

    fn pass(&mut self, now: DateTime<Utc>) -> Pass {
        let id = match &self.tracked {
            Some(id) => id.clone(),
            None => match self.discover() {
                Some(id) => {
                    self.tracked = Some(id.clone());
                    id
                }
                None if self.discovery_closed(now) => return Pass::StandDown,
                None => return Pass::Continue,
            },
        };
        match session::read_session(&id) {
            Ok(Some(record)) if record.state == SessionState::Running => {}
            Ok(_) => return Pass::StandDown,
            Err(e) => {
                tracing::warn!(session = %id, err = %e, "session expiry: unreadable record");
                return Pass::Continue;
            }
        }
        match claim_expired_session(&id, now) {
            Ok(Some(record)) => {
                tracing::warn!(
                    session = %id,
                    vm = %record.vm_name,
                    idle_timeout_secs = record.idle_timeout_secs,
                    "session idle past its timeout; stopping its machine"
                );
                self.seal();
                Pass::Expired
            }
            Ok(None) => Pass::Continue,
            Err(e) => {
                tracing::warn!(session = %id, err = %e, "session expiry: could not claim");
                Pass::Continue
            }
        }
    }

    /// The running session recorded for this VM since it booted, if any.
    ///
    /// A record that predates the boot belongs to an earlier machine of the
    /// same name and must not get this one stopped.
    fn discover(&self) -> Option<SessionId> {
        let records = match session::list_sessions() {
            Ok(records) => records,
            Err(e) => {
                tracing::warn!(err = %e, "session expiry: could not list sessions");
                return None;
            }
        };
        let booted = self.booted_at.timestamp();
        records
            .into_iter()
            .filter(|r| r.state == SessionState::Running && r.vm_name == self.vm_name)
            .find(|r| {
                DateTime::parse_from_rfc3339(&r.started_at)
                    .is_ok_and(|started| started.timestamp() >= booted)
            })
            .map(|r| r.id)
    }

    fn discovery_closed(&self, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(self.booted_at)
            .to_std()
            .is_ok_and(|elapsed| elapsed >= DISCOVERY_WINDOW)
    }

    /// Best-effort: the guest is stopped either way, and a missing seal is
    /// reported by `trust audit verify` as `UNSEALED` rather than hidden.
    fn seal(&self) {
        let Some(sealer) = &self.sealer else {
            return;
        };
        if let Err(e) = seal_stopped_session(&sealer.emitter, &sealer.plan) {
            tracing::warn!(
                vm = %self.vm_name,
                error = %format!("{e:#}"),
                "could not seal the expired session"
            );
        }
    }
}

/// Start the session expiry watcher for a supervisor that is about to enter
/// its VMM run loop. Returns whether one was started.
///
/// Only an admitted boot is watched: the plan-less boots (Stage 0, the
/// builder VM) are never sessions. A watcher that cannot open the audit chain
/// still enforces the timeout, and leaves the session unsealed.
pub fn arm_for_supervisor(inputs: &SupervisorTimerInputs<'_>) -> bool {
    let Some(plan_json) = inputs.plan_json else {
        return false;
    };
    let Some(vm_name) = inputs
        .vm_state_dir
        .file_name()
        .and_then(|name| name.to_str())
    else {
        tracing::warn!(
            state_dir = %inputs.vm_state_dir.display(),
            "session expiry: the VM state dir names no VM; not watching"
        );
        return false;
    };
    let killer = Box::new(SupervisorExitKiller::new(inputs.vm_state_dir.to_path_buf()));
    let mut watcher = SessionExpiryWatcher::new(vm_name, Utc::now(), killer);
    match decode_admitted_plan(plan_json).and_then(|plan| Ok((plan, supervisor_emitter(inputs)?))) {
        Ok((plan, emitter)) => watcher = watcher.sealing_under(plan, emitter),
        Err(e) => tracing::warn!(
            error = %format!("{e:#}"),
            "session expiry: an expired session will be stopped but not sealed"
        ),
    }
    match std::thread::Builder::new()
        .name("mvm-session-expiry".to_string())
        .spawn(move || watcher.run(POLL))
    {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(error = %e, "session expiry: could not start the watcher");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ed25519_dalek::SigningKey;
    use mvm_core::session::SessionMode;
    use mvm_core::util::test_env::TestEnv;

    #[derive(Clone, Default)]
    struct CountingKiller(Arc<AtomicUsize>);

    impl WorkloadKiller for CountingKiller {
        fn kill(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl CountingKiller {
        fn kills(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct Home {
        _env: TestEnv,
        dir: tempfile::TempDir,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut env = TestEnv::new();
            env.isolate_mvm_home(dir.path());
            Self { _env: env, dir }
        }

        fn local_audit(&self) -> String {
            std::fs::read_to_string(mvm_core::audit::default_audit_log()).unwrap_or_default()
        }

        fn audit_dir(&self) -> std::path::PathBuf {
            let dir = self.dir.path().join("chain");
            std::fs::create_dir_all(&dir).expect("audit dir");
            dir
        }
    }

    fn rfc3339(at: DateTime<Utc>) -> String {
        at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// A running session for `vm`, started at `started`, idle since then.
    fn session_for(vm: &str, started: DateTime<Utc>, idle_timeout_secs: u64) -> SessionRecord {
        let mut record = SessionRecord::new_running(vm, "wl", SessionMode::Prod);
        record.started_at = rfc3339(started);
        record.idle_timeout_secs = idle_timeout_secs;
        session::write_session(&record).expect("write session");
        record
    }

    fn state_of(id: &SessionId) -> SessionState {
        session::read_session(id)
            .expect("read")
            .expect("present")
            .state
    }

    fn watcher(vm: &str, booted: DateTime<Utc>, killer: &CountingKiller) -> SessionExpiryWatcher {
        SessionExpiryWatcher::new(vm, booted, Box::new(killer.clone()))
    }

    #[test]
    fn an_expired_session_is_stopped_reaped_audited_and_sealed_without_a_command() {
        let home = Home::new();
        let booted = Utc::now() - chrono::Duration::seconds(120);
        let record = session_for("vm-idle", booted, 60);

        let audit_dir = home.audit_dir();
        let emitter = Arc::new(
            AuditEmitter::with_dir(SigningKey::from_bytes(&[3u8; 32]), &audit_dir).unwrap(),
        );
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "mock").unwrap();

        let killer = CountingKiller::default();
        let mut watcher =
            watcher("vm-idle", booted, &killer).sealing_under(plan.clone(), emitter.clone());

        // Still inside the timeout: nothing happens.
        assert!(watcher.step(booted + chrono::Duration::seconds(30)));
        assert_eq!(killer.kills(), 0);
        assert_eq!(state_of(&record.id), SessionState::Running);

        // Past it: the watcher alone stops, reaps, audits and seals.
        assert!(!watcher.step(booted + chrono::Duration::seconds(61)));
        assert_eq!(killer.kills(), 1, "the guest is stopped exactly once");
        assert_eq!(state_of(&record.id), SessionState::Reaped);
        let local = home.local_audit();
        assert!(
            local.contains(&format!("session={},idle_timeout_secs=60", record.id)),
            "the reap is recorded: {local}"
        );
        let chain = std::fs::read_to_string(crate::audit::emitter::audit_path_for_tenant(
            &audit_dir,
            &plan.tenant.0,
        ))
        .expect("chain");
        assert!(
            chain.contains("session.sealed"),
            "the session is sealed: {chain}"
        );
        assert!(
            chain.contains("\"stopped\""),
            "sealed as a stop, like `machine stop`: {chain}"
        );
    }

    #[test]
    fn a_session_still_inside_its_timeout_is_left_alone() {
        let _home = Home::new();
        let booted = Utc::now();
        let record = session_for("vm-busy", booted, 300);
        session::update_session(&record.id, |r| {
            r.last_invoke_at = Some(rfc3339(booted + chrono::Duration::seconds(400)));
            Ok(())
        })
        .expect("record a call");

        let killer = CountingKiller::default();
        let mut watcher = watcher("vm-busy", booted, &killer);
        // Long after start, but a call came in recently.
        assert!(watcher.step(booted + chrono::Duration::seconds(600)));
        assert_eq!(killer.kills(), 0);
        assert_eq!(state_of(&record.id), SessionState::Running);
    }

    #[test]
    fn another_machines_session_and_an_earlier_incarnation_are_not_ours() {
        let _home = Home::new();
        let booted = Utc::now() - chrono::Duration::seconds(120);
        let other = session_for("vm-other", booted, 1);
        // Same name, but recorded before this machine booted.
        let stale = session_for("vm-mine", booted - chrono::Duration::seconds(60), 1);

        let killer = CountingKiller::default();
        let mut watcher = watcher("vm-mine", booted, &killer);
        assert!(watcher.step(booted + chrono::Duration::seconds(30)));
        assert_eq!(killer.kills(), 0);
        assert_eq!(state_of(&other.id), SessionState::Running);
        assert_eq!(state_of(&stale.id), SessionState::Running);
    }

    #[test]
    fn a_machine_that_never_becomes_a_session_stops_looking() {
        let _home = Home::new();
        let booted = Utc::now();
        let killer = CountingKiller::default();
        let mut watcher = watcher("vm-plain", booted, &killer);
        assert!(watcher.step(booted + chrono::Duration::seconds(10)));
        assert!(!watcher.step(booted + chrono::Duration::from_std(DISCOVERY_WINDOW).unwrap()));
        assert_eq!(killer.kills(), 0);
    }

    #[test]
    fn a_session_ended_some_other_way_stands_the_watcher_down() {
        let _home = Home::new();
        let booted = Utc::now();
        let record = session_for("vm-killed", booted, 60);
        let killer = CountingKiller::default();
        let mut watcher = watcher("vm-killed", booted, &killer);
        assert!(watcher.step(booted + chrono::Duration::seconds(1)));

        session::update_session(&record.id, |r| {
            r.state = SessionState::Killed;
            Ok(())
        })
        .expect("kill");
        assert!(!watcher.step(booted + chrono::Duration::seconds(600)));
        assert_eq!(
            killer.kills(),
            0,
            "a killed session's machine is not ours to stop"
        );
        assert_eq!(state_of(&record.id), SessionState::Killed);
    }

    #[test]
    fn a_claim_refuses_what_is_not_an_expired_running_session() {
        let _home = Home::new();
        let now = Utc::now();
        assert!(
            claim_expired_session(&SessionId::new(), now)
                .expect("absent is not an error")
                .is_none()
        );
        let fresh = session_for("vm-fresh", now, 60);
        assert!(claim_expired_session(&fresh.id, now).unwrap().is_none());

        let expired = session_for("vm-expired", now - chrono::Duration::seconds(120), 60);
        let claimed = claim_expired_session(&expired.id, now)
            .unwrap()
            .expect("claimed");
        assert_eq!(claimed.vm_name, "vm-expired");
        assert!(
            claim_expired_session(&expired.id, now).unwrap().is_none(),
            "a reaped session is not claimed twice"
        );
    }

    #[test]
    fn only_an_admitted_boot_is_watched() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!arm_for_supervisor(&SupervisorTimerInputs {
            plan_json: None,
            audit_dir: None,
            signing_key_path: None,
            vm_state_dir: dir.path(),
        }));
    }
}
