//! Session idle-timeout enforcement on the backends with no per-VM supervisor.
//!
//! On libkrun and HVF the process that owns a guest for its whole life is its
//! per-VM supervisor, and that is where a session's idle timeout is enforced
//! (`supervisor::session_expiry`). Firecracker and QEMU have no such process:
//! the VMM is a third-party binary, Firecracker runs as root under `sudo`, and
//! the `mvmctl` that started the session exits as soon as it is recorded. An
//! expired session there was reaped only when someone next ran a `machine
//! session` verb.
//!
//! The owner here is the tenant's resident host agent, not a new process.
//! Two other candidates were rejected:
//!
//! - The network endpoint keeper lives exactly as long as its VM, but a
//!   workload with no secrets, no admitted egress, no ingress and no tool
//!   rules gets no endpoint at all, and that describes the default session.
//! - A per-VM wrapper around Firecracker would be one more process per VM,
//!   which is what the resident daemons exist to avoid.
//!
//! The host agent is keyless by design, so it cannot seal a session's audit
//! chain, and stopping a Firecracker guest needs the `sudo` signal route the
//! backend's stop path already takes. It therefore decides only *when*: once a
//! session it watches is idle past its timeout it runs `mvmctl machine session
//! reap`, the same sweep a client runs, which claims the session, stops its VM
//! through the backend's stop path and seals the chain. That mirrors how its
//! health watcher hands a restart to `mvmctl machine restart`.
//!
//! A session start on one of these backends makes sure the tenant's agent is
//! running, and the agent counts the sessions it watches as live work, so it
//! does not idle out while one of them is still running.

use std::time::Duration;

use chrono::{DateTime, Utc};
use mvm_core::session::{SessionRecord, SessionState};
use mvm_core::vm_backend::BackendKind;
use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};

/// How long the agent waits before running the sweep again for a session that
/// is still running after it asked for one. A sweep that cannot stop the VM
/// (no non-interactive `sudo`, say) would otherwise be retried on every poll.
const RESWEEP_AFTER: Duration = Duration::from_secs(30);

/// Whether a session on a `kind` VM has its idle timeout enforced by the host
/// agent rather than by a per-VM supervisor.
///
/// An allow-list: a backend not named here either has a supervisor that
/// enforces it or carries no sessions the host agent should touch.
#[must_use]
pub fn host_agent_enforces_session_expiry(kind: BackendKind) -> bool {
    matches!(kind, BackendKind::Firecracker | BackendKind::Qemu)
}

/// Which session records this agent is responsible for.
pub trait SessionOwnership {
    /// Whether `record`'s idle timeout is this agent's to enforce.
    fn watches(&self, record: &SessionRecord) -> bool;
}

/// The real ownership rule: a session whose VM was started on a backend the
/// host agent covers, admitted under this agent's tenant.
pub struct TenantSessions {
    tenant: String,
}

impl TenantSessions {
    #[must_use]
    pub fn new(tenant: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
        }
    }
}

impl SessionOwnership for TenantSessions {
    fn watches(&self, record: &SessionRecord) -> bool {
        let covered = mvm_runtime::AnyBackend::started_vm_kind(&record.vm_name)
            .is_some_and(host_agent_enforces_session_expiry);
        covered
            && crate::audit::plan_persist::read_plan(&record.vm_name)
                .is_ok_and(|plan| plan.tenant.0 == self.tenant)
    }
}

/// How the agent asks for expired sessions to be reaped.
pub trait SessionReaper {
    /// Reap every session past its idle timeout. Must not block on the reap.
    fn reap(&self);
}

/// Runs `mvmctl machine session reap` detached. Never waits on it: a sweep
/// stuck behind a slow VM stop must not stall the agent.
pub struct CliSessionReaper;

impl SessionReaper for CliSessionReaper {
    fn reap(&self) {
        let mut command = match crate::health_probe::mvmctl_command_for(
            &HostProcess::current(),
            CliSpawn::SessionReap,
        ) {
            Ok(command) => command,
            Err(refused) => {
                tracing::warn!(%refused, "not reaping idle sessions");
                return;
            }
        };
        let spawned = command
            .args(["machine", "session", "reap"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match spawned {
            // Reaped on a thread so a finished sweep does not linger as a
            // zombie for the rest of the agent's life.
            Ok(mut child) => {
                std::thread::spawn(move || child.wait());
            }
            Err(err) => tracing::warn!(%err, "failed to spawn mvmctl machine session reap"),
        }
    }
}

/// Watches the sessions an agent is responsible for and asks for a sweep when
/// one of them has sat idle past its timeout.
pub struct SessionSweepWatcher<O, R> {
    ownership: O,
    reaper: R,
    last_sweep: Option<DateTime<Utc>>,
}

impl<O: SessionOwnership, R: SessionReaper> SessionSweepWatcher<O, R> {
    #[must_use]
    pub fn new(ownership: O, reaper: R) -> Self {
        Self {
            ownership,
            reaper,
            last_sweep: None,
        }
    }

    /// Look at `records` as of `now`, ask for a sweep if one of this agent's
    /// sessions has expired, and return how many running sessions it watches,
    /// which keeps the agent from idling out under them.
    pub fn step(&mut self, records: &[SessionRecord], now: DateTime<Utc>) -> usize {
        let watched: Vec<&SessionRecord> = records
            .iter()
            .filter(|r| r.state == SessionState::Running && self.ownership.watches(r))
            .collect();
        if watched.iter().any(|r| r.idle_expired_at(now)) && self.sweep_due(now) {
            tracing::info!("a watched session is idle past its timeout; reaping");
            self.reaper.reap();
            self.last_sweep = Some(now);
        }
        watched.len()
    }

    fn sweep_due(&self, now: DateTime<Utc>) -> bool {
        self.last_sweep.is_none_or(|last| {
            now.signed_duration_since(last)
                .to_std()
                .is_ok_and(|since| since >= RESWEEP_AFTER)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::rc::Rc;

    use mvm_core::session::SessionMode;

    /// Watches the VMs it was told to.
    struct Named(HashSet<&'static str>);

    impl SessionOwnership for Named {
        fn watches(&self, record: &SessionRecord) -> bool {
            self.0.contains(record.vm_name.as_str())
        }
    }

    #[derive(Clone, Default)]
    struct CountingReaper(Rc<Cell<usize>>);

    impl SessionReaper for CountingReaper {
        fn reap(&self) {
            self.0.set(self.0.get() + 1);
        }
    }

    fn running(vm: &str, started: DateTime<Utc>, idle_timeout_secs: u64) -> SessionRecord {
        let mut record = SessionRecord::new_running(vm, "wl", SessionMode::Prod);
        record.started_at = started.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        record.idle_timeout_secs = idle_timeout_secs;
        record
    }

    fn watcher(
        vms: &[&'static str],
    ) -> (SessionSweepWatcher<Named, CountingReaper>, Rc<Cell<usize>>) {
        let reaper = CountingReaper::default();
        let count = reaper.0.clone();
        let named = Named(vms.iter().copied().collect());
        (SessionSweepWatcher::new(named, reaper), count)
    }

    #[test]
    fn only_firecracker_and_qemu_sessions_are_left_to_the_host_agent() {
        assert!(host_agent_enforces_session_expiry(BackendKind::Firecracker));
        assert!(host_agent_enforces_session_expiry(BackendKind::Qemu));
        for supervised in [
            BackendKind::Libkrun,
            BackendKind::Hvf,
            BackendKind::AppleContainer,
            BackendKind::Mock,
            BackendKind::Wasm,
            BackendKind::WebLinux,
        ] {
            assert!(
                !host_agent_enforces_session_expiry(supervised),
                "{supervised:?} is not the host agent's"
            );
        }
    }

    #[test]
    fn an_expired_watched_session_is_reaped_without_a_command() {
        let started = Utc::now();
        let records = [running("fc-idle", started, 60)];
        let (mut watcher, reaps) = watcher(&["fc-idle"]);

        assert_eq!(
            watcher.step(&records, started + chrono::Duration::seconds(30)),
            1
        );
        assert_eq!(reaps.get(), 0, "still inside its timeout");

        assert_eq!(
            watcher.step(&records, started + chrono::Duration::seconds(61)),
            1
        );
        assert_eq!(reaps.get(), 1, "past it, the agent asks for the sweep");
    }

    #[test]
    fn a_sweep_that_left_the_session_running_is_retried_but_not_on_every_poll() {
        let started = Utc::now();
        let records = [running("fc-stuck", started, 60)];
        let (mut watcher, reaps) = watcher(&["fc-stuck"]);
        let expired = started + chrono::Duration::seconds(61);

        watcher.step(&records, expired);
        watcher.step(&records, expired + chrono::Duration::seconds(2));
        assert_eq!(reaps.get(), 1, "one sweep in flight is enough");

        watcher.step(
            &records,
            expired + chrono::Duration::from_std(RESWEEP_AFTER).unwrap(),
        );
        assert_eq!(reaps.get(), 2, "a session still running is swept again");
    }

    #[test]
    fn sessions_the_agent_does_not_own_or_that_ended_are_not_its_work() {
        let started = Utc::now() - chrono::Duration::seconds(600);
        let mut ended = running("fc-ended", started, 60);
        ended.state = SessionState::Reaped;
        let records = [running("hvf-supervised", started, 60), ended];
        let (mut watcher, reaps) = watcher(&["fc-ended"]);

        assert_eq!(
            watcher.step(&records, Utc::now()),
            0,
            "nothing keeps the agent awake"
        );
        assert_eq!(reaps.get(), 0);
    }

    #[test]
    fn a_running_session_keeps_the_agent_awake_until_it_ends() {
        let started = Utc::now();
        let mut records = [running("fc-busy", started, 3600)];
        let (mut watcher, _reaps) = watcher(&["fc-busy"]);
        assert_eq!(watcher.step(&records, started), 1);

        records[0].state = SessionState::Killed;
        assert_eq!(watcher.step(&records, started), 0);
    }
}
