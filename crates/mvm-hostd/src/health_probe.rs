//! Host->guest healthcheck probe primitive.
//!
//! Runs a workload's declared healthcheck command in the guest via the
//! agent's exec protocol and folds the result into a `ProbeResult`. The
//! guest exec leg is factored behind the [`GuestExec`] trait so
//! [`probe_with`] is unit-testable without a live VM; [`probe_once`] wires
//! it to the real vsock transport.
//!
//! Restart-on-crash rides the probe path: a crashed service is not stopped,
//! so its daemon registration lingers and stays in the live set, where its
//! probe hits an unreachable agent (`Unreachable` → `Fail`), flips
//! `Unhealthy` after `retries`, and earns a bounded restart. A clean
//! disappearance from the live set is treated as possibly-intentional (a
//! `machine stop` early-deregisters and then erases the registry entry), so
//! it triggers no restart. Health-state transitions and restart decisions are
//! recorded two ways: structured `tracing` events (`vm`/`event`/`state`
//! fields) for host logs, and — via the [`HealthAudit`] seam — chain-signed
//! entries on each VM's per-VM workload chain, so the health history is
//! tamper-evident on the same chain `mvmctl trust audit` verifies. The seam
//! keeps the probe loop unit-testable without a live signer helper.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use mvm_agentd::vsock::{ExecEvent, GUEST_AGENT_PORT, send_exec_streaming};
use mvm_contract::ir::HealthCheck;
use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::health::{HealthAction, HealthPolicy, HealthState, HealthTracker, ProbeResult, fold};
use mvm_runtime::machine::persist::load_machine_spec;
use mvm_runtime::vm::name_registry::record_readiness;

/// Base of the exponential restart-backoff schedule, in seconds.
const BACKOFF_BASE_SECS: u64 = 1;
/// Ceiling the restart-backoff schedule saturates at, in seconds.
const BACKOFF_CAP_SECS: u64 = 300;
/// Restart attempts a workload gets before the daemon gives up on it.
const MAX_RESTART_ATTEMPTS: u32 = 5;

/// Outcome of running a command in the guest, independent of how it was
/// decided pass/fail.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecOutcome {
    /// The command ran to completion with this exit code.
    Exited(i32),
    /// The agent killed the command after the timeout elapsed.
    TimedOut,
    /// The guest agent could not be reached (connect/protocol failure), or
    /// the exec otherwise failed to produce a terminal result.
    Unreachable,
}

/// Seam over "run this command in the named VM's guest and report how it
/// ended." Exists so tests can substitute a fake without a live VM.
pub trait GuestExec {
    fn exec(&self, vm_name: &str, cmd: &str, timeout_secs: u64) -> ExecOutcome;
}

/// Real [`GuestExec`] impl: connects to the guest agent over vsock and runs
/// the command via `send_exec_streaming`.
pub struct AgentExec;

impl GuestExec for AgentExec {
    fn exec(&self, vm_name: &str, cmd: &str, timeout_secs: u64) -> ExecOutcome {
        let transport = match mvm_runtime::vsock_transport::for_vm(vm_name) {
            Ok(t) => t,
            Err(_) => return ExecOutcome::Unreachable,
        };
        let mut stream = match transport.connect(GUEST_AGENT_PORT) {
            Ok(s) => s,
            Err(_) => return ExecOutcome::Unreachable,
        };
        match send_exec_streaming(&mut stream, cmd, None, Some(timeout_secs), |_ev| {}) {
            Ok(ExecEvent::Exit { code }) => ExecOutcome::Exited(code),
            Ok(ExecEvent::TimedOut) => ExecOutcome::TimedOut,
            // send_exec_streaming only ever returns a terminal event
            // (Exit or TimedOut); any other shape or transport error means
            // the probe couldn't get a verdict out of the guest.
            Ok(_) | Err(_) => ExecOutcome::Unreachable,
        }
    }
}

/// Unwrap the phase-A stored shape (`["/bin/sh", "-lc", "<cmd>"]`) back to
/// the raw shell command string. The agent's `Exec` already runs its
/// command through `/bin/sh -c`, so handing it the raw command avoids a
/// redundant nested shell; any other shape is quoted argv-wise so it
/// survives verbatim through that same `/bin/sh -c`.
fn command_string(hc: &HealthCheck) -> String {
    if let [shell, flag, cmd] = hc.command.as_slice()
        && shell == "/bin/sh"
        && flag == "-lc"
    {
        return cmd.clone();
    }
    hc.command
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Single-quote wrap, escaping embedded single quotes the portable POSIX
/// way (`'` -> `'\''`). Mirrors the mvm-cli exec-target quoting convention.
fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Testable core: run `hc.command` in `vm_name` via `exec` and decide
/// pass/fail. Exit code 0 is the only passing outcome — non-zero exit,
/// timeout, and an unreachable guest all fail the probe.
pub fn probe_with<E: GuestExec + ?Sized>(exec: &E, vm_name: &str, hc: &HealthCheck) -> ProbeResult {
    let cmd = command_string(hc);
    match exec.exec(vm_name, &cmd, hc.timeout_secs.into()) {
        ExecOutcome::Exited(0) => ProbeResult::Pass,
        ExecOutcome::Exited(_) | ExecOutcome::TimedOut | ExecOutcome::Unreachable => {
            ProbeResult::Fail
        }
    }
}

/// Run `hc`'s command in `vm_name`'s guest over the real vsock transport
/// and decide pass/fail.
pub fn probe_once(vm_name: &str, hc: &HealthCheck) -> ProbeResult {
    probe_with(&AgentExec, vm_name, hc)
}

/// Seam over "restart this VM," so restart *decisions* stay unit-testable
/// without ever spawning a real subprocess.
pub trait Restarter {
    fn restart(&self, vm_name: &str);
}

/// Seam over "record a chain-signed health-audit entry for this VM," so the
/// prober's transition/restart bookkeeping stays unit-testable without a live
/// signer helper. The real impl (the daemon's `HealthAuditSink`) appends to the
/// VM's per-VM workload chain; `fields` carries the event name + state.
pub trait HealthAudit {
    fn record(&self, vm_name: &str, fields: serde_json::Value);
}

/// A [`HealthAudit`] that drops every entry. Used where health probing runs
/// without a chain (tests that only assert state transitions).
pub struct NoAudit;

impl HealthAudit for NoAudit {
    fn record(&self, _vm_name: &str, _fields: serde_json::Value) {}
}

/// Real [`Restarter`] impl: fire-and-forgets `mvmctl machine restart
/// <vm_name>` as a detached child process. Never waits on the child — a
/// restart that hangs must not block the health watcher's own loop.
pub struct MachineRestarter;

impl Restarter for MachineRestarter {
    fn restart(&self, vm_name: &str) {
        let mvmctl = mvmctl_path();
        let spawned = Command::new(&mvmctl)
            .args(["machine", "restart", vm_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Err(err) = spawned {
            tracing::warn!(
                vm = %vm_name,
                mvmctl = %mvmctl.display(),
                %err,
                "failed to spawn mvmctl machine restart"
            );
        }
    }
}

/// Resolve the `mvmctl` binary to run for a restart: prefer the sibling of
/// this daemon binary's own executable path (both binaries ship side by side
/// in the same target/install directory), falling back to a bare `mvmctl`
/// resolved via `PATH` when that sibling doesn't exist or the current
/// executable's path can't be determined.
fn mvmctl_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("mvmctl")))
        .filter(|candidate| candidate.exists())
        .unwrap_or_else(|| PathBuf::from("mvmctl"))
}

/// Current wall clock in unix seconds, saturating to 0 before the epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a restart-aware [`HealthPolicy`] from a workload's declared
/// healthcheck: the guest-facing probe cadence comes from `hc`, the
/// host-side restart budget from the daemon's constants.
pub fn policy_from(hc: &HealthCheck) -> HealthPolicy {
    HealthPolicy {
        interval_secs: hc.interval_secs,
        timeout_secs: hc.timeout_secs,
        retries: hc.retries,
        start_period_secs: hc.start_period_secs,
        backoff_base_secs: BACKOFF_BASE_SECS,
        backoff_cap_secs: BACKOFF_CAP_SECS,
        max_restart_attempts: MAX_RESTART_ATTEMPTS,
    }
}

/// Project a folded [`HealthState`] onto the registry's coarse readiness enum.
/// The per-service field lists stay empty: a single-workload machine has no
/// finer-grained breakdown to report.
pub fn map_state(state: HealthState) -> InstanceReadiness {
    match state {
        HealthState::Starting => InstanceReadiness::ServicesStarting { pending: vec![] },
        HealthState::Healthy => InstanceReadiness::ServicesReady,
        HealthState::Unhealthy => InstanceReadiness::Degraded { unhealthy: vec![] },
    }
}

/// Emit a structured `tracing` event for a health-state transition — the host-
/// log companion to the chain-signed entry the [`HealthAudit`] seam records.
fn log_health_transition(vm: &str, new_state: HealthState) {
    match new_state {
        HealthState::Healthy => {
            tracing::info!(vm = %vm, event = "health.transition", state = ?new_state, "healthcheck transitioned to healthy");
        }
        HealthState::Unhealthy => {
            tracing::warn!(vm = %vm, event = "health.transition", state = ?new_state, "healthcheck transitioned to unhealthy");
        }
        HealthState::Starting => {
            tracing::info!(vm = %vm, event = "health.transition", state = ?new_state, "healthcheck transitioned to starting");
        }
    }
}

/// Lower-case wire name for a health state, used in audit-entry fields.
fn state_str(state: HealthState) -> &'static str {
    match state {
        HealthState::Starting => "starting",
        HealthState::Healthy => "healthy",
        HealthState::Unhealthy => "unhealthy",
    }
}

/// Build the `fields` payload for a health audit entry: the event name plus the
/// current state. The category (`host`) is stamped by the sink; this is the
/// per-entry detail an audit reader greps.
fn health_fields(event: &str, state: HealthState) -> serde_json::Value {
    serde_json::json!({ "event": event, "state": state_str(state) })
}

/// Per-VM health probing over the daemon's live registration set.
///
/// Holds one [`HealthTracker`] plus its last-probe unix second per healthchecked
/// VM, so [`tick`](HealthProber::tick) can skip VMs that aren't yet due and retire
/// a tracker once its machine stops being a managed healthchecked machine (spec
/// gone or healthcheck removed) — a machine merely absent from the live set keeps
/// its tracker.
#[derive(Default)]
pub struct HealthProber {
    trackers: HashMap<String, (HealthTracker, u64)>,
}

impl HealthProber {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run one probe pass over `live_vm_ids` and return the restart-worthy
    /// actions (`Restart` / `GiveUp`) keyed by VM; `None` actions are dropped.
    ///
    /// For each live VM it loads the persisted spec, skips (and forgets) any VM
    /// without a healthcheck, ensures a tracker exists, and — only when the VM
    /// is due — runs the probe, folds the result, records the mapped readiness,
    /// and collects the resulting action. Executing a restart is deliberately
    /// left to the caller ([`act`](Self::act)).
    ///
    /// Restart-on-crash is delivered here, not by disappearance-detection: a
    /// crashed service is not stopped, so its registration lingers in
    /// `live_vm_ids` and its next probe finds the agent unreachable
    /// (`Unreachable` → `Fail`), flips `Unhealthy`, and restarts. A VM that
    /// cleanly leaves the live set is treated as possibly-intentional and is not
    /// probed while absent, so it earns no new restart — but its tracker (and
    /// restart budget) is preserved until its spec loses the healthcheck, so the
    /// cap holds across a restart's own stop→start deregistration window.
    pub fn tick(
        &mut self,
        live_vm_ids: &[String],
        now_unix: u64,
        exec: &dyn GuestExec,
        audit: &dyn HealthAudit,
    ) -> Vec<(String, HealthAction)> {
        // Retire a tracker only when the machine is genuinely no longer a
        // managed healthchecked machine — its spec is gone or no longer declares
        // a healthcheck. A machine that is merely absent from the live set keeps
        // its tracker (and its restart budget/backoff): a restart stops then
        // starts the guest, so the machine deregisters for the duration of that
        // window, and dropping the tracker there would reset `restart_attempts`
        // and let a persistently-broken service crash-loop past its cap.
        self.trackers.retain(|vm, _| match load_machine_spec(vm) {
            Ok(spec) => {
                let managed = spec.health_check.is_some();
                if !managed {
                    tracing::info!(
                        vm = %vm,
                        event = "health.healthcheck_removed",
                        "machine no longer declares a healthcheck; retiring tracker"
                    );
                }
                managed
            }
            Err(_) => {
                tracing::info!(
                    vm = %vm,
                    event = "health.spec_gone",
                    "machine spec gone; retiring tracker"
                );
                false
            }
        });

        let mut actions = Vec::new();
        for vm in live_vm_ids {
            let spec = match load_machine_spec(vm) {
                Ok(spec) => spec,
                Err(_) => {
                    // Unknown or unreadable spec: nothing to probe here.
                    self.trackers.remove(vm);
                    continue;
                }
            };
            let Some(hc) = spec.health_check.clone() else {
                // No declared healthcheck: drop any tracker and move on.
                self.trackers.remove(vm);
                continue;
            };
            let policy = policy_from(&hc);

            let entry = self
                .trackers
                .entry(vm.clone())
                .or_insert_with(|| (HealthTracker::new(now_unix), 0));
            // last_probe == 0 marks a never-probed VM (first sight); otherwise
            // wait out the configured interval before probing again.
            let due = entry.1 == 0 || now_unix >= entry.1 + u64::from(policy.interval_secs);
            if !due {
                continue;
            }

            let previous_state = entry.0.state;
            let result = probe_with(exec, vm, &hc);
            let action = fold(&mut entry.0, result, &policy, now_unix);
            entry.1 = now_unix;
            let new_state = entry.0.state;
            if new_state != previous_state {
                log_health_transition(vm, new_state);
                audit.record(vm, health_fields("health.transition", new_state));
            }
            record_readiness(vm, map_state(new_state));

            match action {
                HealthAction::None => {}
                HealthAction::Restart => {
                    tracing::warn!(
                        vm = %vm,
                        event = "health.restart",
                        state = ?new_state,
                        "healthcheck unhealthy; restart requested"
                    );
                    audit.record(vm, health_fields("health.restart", new_state));
                    actions.push((vm.clone(), action));
                }
                HealthAction::GiveUp => {
                    tracing::warn!(
                        vm = %vm,
                        event = "health.give_up",
                        state = ?new_state,
                        "healthcheck unhealthy; restart budget exhausted"
                    );
                    audit.record(vm, health_fields("health.give_up", new_state));
                    actions.push((vm.clone(), action));
                }
            }
        }
        actions
    }

    /// Fire every scheduled restart whose backoff gate has elapsed for a machine
    /// currently in `live_vm_ids`, then consume the gate so each scheduled
    /// restart fires exactly once.
    ///
    /// Runs on every watcher tick over *all* trackers, independent of the
    /// actions the current pass produced. `fold` schedules a restart into the
    /// future (`next_restart_after_unix = now + backoff`, backoff ≥ 1s) the
    /// moment it decides to restart, so firing must be decoupled from
    /// scheduling: calling `act` on the same instant `fold` set the gate always
    /// defers (`now < gate`), and a later tick — past the gate — fires it. A
    /// give-up clears the gate, so a parked machine is never restarted from
    /// here.
    ///
    /// Firing is gated on liveness: a machine absent from `live_vm_ids` is never
    /// restarted, even with an elapsed gate. A deliberate `machine stop`
    /// deregisters a machine that may be Unhealthy with a pending gate, and
    /// resurrecting it would be wrong; the gate is simply left pending (nothing
    /// fires while absent) and only fires if the machine returns to the live set.
    /// During a genuine restart the machine is still live when the gate fires —
    /// its own stop hasn't deregistered it yet — so real restarts are unaffected.
    pub fn act(&mut self, live_vm_ids: &[String], now_unix: u64, restarter: &dyn Restarter) {
        for (vm, (tracker, _)) in self.trackers.iter_mut() {
            if !live_vm_ids.iter().any(|id| id == vm) {
                continue;
            }
            let due = tracker
                .next_restart_after_unix
                .is_some_and(|gate| now_unix >= gate);
            if due {
                restarter.restart(vm);
                tracker.next_restart_after_unix = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake(ExecOutcome);
    impl GuestExec for Fake {
        fn exec(&self, _: &str, _: &str, _: u64) -> ExecOutcome {
            self.0.clone()
        }
    }
    fn hc() -> HealthCheck {
        HealthCheck {
            command: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
            interval_secs: 30,
            timeout_secs: 5,
            retries: 3,
            start_period_secs: 0,
        }
    }
    #[test]
    fn exit_zero_is_pass() {
        assert_eq!(
            probe_with(&Fake(ExecOutcome::Exited(0)), "vm", &hc()),
            ProbeResult::Pass
        );
    }
    #[test]
    fn nonzero_timeout_unreachable_are_fail() {
        assert_eq!(
            probe_with(&Fake(ExecOutcome::Exited(1)), "vm", &hc()),
            ProbeResult::Fail
        );
        assert_eq!(
            probe_with(&Fake(ExecOutcome::TimedOut), "vm", &hc()),
            ProbeResult::Fail
        );
        assert_eq!(
            probe_with(&Fake(ExecOutcome::Unreachable), "vm", &hc()),
            ProbeResult::Fail
        );
    }

    #[test]
    fn command_string_unwraps_phase_a_shape() {
        assert_eq!(command_string(&hc()), "true");
    }

    #[test]
    fn command_string_quotes_unknown_shape() {
        let mut h = hc();
        h.command = vec!["curl".into(), "-f".into(), "http://x/health".into()];
        assert_eq!(command_string(&h), "'curl' '-f' 'http://x/health'");
    }

    // ---- HealthProber::tick (disk-backed via MVM_HOME) ----

    use mvm_core::domain::instance::InstanceReadiness;
    use mvm_core::health::HealthState;
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::machine::persist::{
        MACHINE_SPEC_SCHEMA_VERSION, MachineSpec, save_machine_spec,
    };
    use mvm_runtime::vm::name_registry::{VmNameRegistry, registry_path};

    // Point the whole mvm root (machine specs + name registry) at `dir`,
    // holding the process-wide env lock so these disk-backed tests don't race
    // other tests that mutate the same var under a threaded runner.
    fn data_env(dir: &std::path::Path) -> TestEnv {
        let mut env = TestEnv::new();
        env.set("MVM_HOME", dir);
        env
    }

    fn spec_with_hc(name: &str, health_check: Option<HealthCheck>) -> MachineSpec {
        MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: Some("alpine:latest".to_string()),
            manifest: None,
            deployment: None,
            runtime_pack: false,
            resolved_digest: None,
            net: false,
            allow_host: vec![],
            ai: None,
            ports: vec![],
            cpus: 1,
            memory: "256M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: vec![],
            init: vec![],
            agent_verb: vec![],
            created_at: None,
            last_started_at: None,
            health_check,
            grants: None,
        }
    }

    #[test]
    fn tick_failing_check_goes_unhealthy_and_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("web", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let exec = Fake(ExecOutcome::Exited(1));
        let vms = vec!["web".to_string()];

        // retries=3, interval=30: probe at t, t+30, t+60 to walk past each due
        // window. The third failed probe flips Unhealthy and asks for a restart.
        let mut actions = Vec::new();
        for i in 0..3u64 {
            actions.extend(prober.tick(&vms, 1000 + i * 30, &exec, &NoAudit));
        }

        assert!(
            actions
                .iter()
                .any(|(vm, a)| vm == "web" && *a == HealthAction::Restart),
            "expected a Restart action, got {actions:?}"
        );
        assert_eq!(
            prober.trackers.get("web").unwrap().0.state,
            HealthState::Unhealthy
        );
    }

    /// Captures every health-audit entry the prober records, so tests can
    /// assert the chain-signed observability fires on the right events.
    struct CapturingAudit(std::cell::RefCell<Vec<(String, serde_json::Value)>>);
    impl CapturingAudit {
        fn new() -> Self {
            Self(std::cell::RefCell::new(Vec::new()))
        }
    }
    impl HealthAudit for CapturingAudit {
        fn record(&self, vm_name: &str, fields: serde_json::Value) {
            self.0.borrow_mut().push((vm_name.to_string(), fields));
        }
    }

    #[test]
    fn tick_records_chain_audit_on_transition() {
        // The first passing probe moves Starting → Healthy — a transition — and
        // must emit a chain-signed health.transition entry alongside the log.
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());
        save_machine_spec(&spec_with_hc("api", Some(hc())), true).unwrap();

        let audit = CapturingAudit::new();
        let mut prober = HealthProber::new();
        prober.tick(
            &["api".to_string()],
            1000,
            &Fake(ExecOutcome::Exited(0)),
            &audit,
        );

        let events = audit.0.borrow();
        assert!(
            events.iter().any(|(vm, f)| vm == "api"
                && f["event"] == "health.transition"
                && f["state"] == "healthy"),
            "expected a health.transition/healthy audit entry, got {events:?}"
        );
    }

    #[test]
    fn tick_records_chain_audit_on_restart_request() {
        // A wedged (unreachable) service flips Unhealthy after the retry budget
        // and requests a restart; that decision must be recorded on the chain.
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());
        save_machine_spec(&spec_with_hc("svc", Some(hc())), true).unwrap();

        let audit = CapturingAudit::new();
        let mut prober = HealthProber::new();
        let unreachable = Fake(ExecOutcome::Unreachable);
        let vms = vec!["svc".to_string()];

        let mut requested = false;
        for i in 0..10u64 {
            let actions = prober.tick(&vms, 1000 + i * 30, &unreachable, &audit);
            if actions
                .iter()
                .any(|(_, a)| matches!(a, HealthAction::Restart))
            {
                requested = true;
                break;
            }
        }
        assert!(
            requested,
            "expected a restart request within the retry budget"
        );

        let events = audit.0.borrow();
        assert!(
            events
                .iter()
                .any(|(vm, f)| vm == "svc" && f["event"] == "health.restart"),
            "expected a health.restart audit entry, got {events:?}"
        );
    }

    #[test]
    fn tick_skips_machine_without_healthcheck() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("bare", None), true).unwrap();

        let mut prober = HealthProber::new();
        let actions = prober.tick(
            &["bare".to_string()],
            1000,
            &Fake(ExecOutcome::Exited(0)),
            &NoAudit,
        );

        assert!(actions.is_empty());
        assert!(!prober.trackers.contains_key("bare"));
    }

    #[test]
    fn tick_passing_check_records_services_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("api", Some(hc())), true).unwrap();

        // record_readiness only updates an existing entry, so register first.
        let rpath = registry_path();
        let mut reg = VmNameRegistry::default();
        reg.register("api", "/tmp/api", "default", None, 0).unwrap();
        reg.save(&rpath).unwrap();

        let mut prober = HealthProber::new();
        let actions = prober.tick(
            &["api".to_string()],
            1000,
            &Fake(ExecOutcome::Exited(0)),
            &NoAudit,
        );

        assert!(actions.is_empty(), "a pass should not request a restart");
        let loaded = VmNameRegistry::load(&rpath).unwrap();
        assert_eq!(
            loaded.lookup("api").unwrap().readiness,
            Some(InstanceReadiness::ServicesReady)
        );
    }

    #[test]
    fn tracker_survives_absence_drops_when_healthcheck_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("gone", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        prober.tick(
            &["gone".to_string()],
            1000,
            &Fake(ExecOutcome::Exited(1)),
            &NoAudit,
        );
        assert!(prober.trackers.contains_key("gone"));

        // A momentary absence from the live set (e.g. a restart's stop→start
        // window) must NOT drop the tracker: its restart budget has to survive
        // the gap, or a broken service crash-loops past its cap. The absent VM
        // is not probed, so it also earns no new restart.
        let actions = prober.tick(&[], 1100, &Fake(ExecOutcome::Exited(1)), &NoAudit);
        assert!(
            prober.trackers.contains_key("gone"),
            "a briefly-absent healthchecked machine keeps its tracker"
        );
        assert!(
            actions.is_empty(),
            "a disappearance must never request a restart, got {actions:?}"
        );

        // Once the machine's spec no longer declares a healthcheck it is
        // genuinely no longer managed, so its tracker is retired.
        save_machine_spec(&spec_with_hc("gone", None), true).unwrap();
        prober.tick(&[], 1200, &Fake(ExecOutcome::Exited(1)), &NoAudit);
        assert!(
            !prober.trackers.contains_key("gone"),
            "dropping the healthcheck retires the tracker"
        );
    }

    #[test]
    fn unreachable_agent_flips_unhealthy_and_restarts() {
        // The restart-on-crash contract: a crashed service is not stopped, so
        // its registration lingers in the live set and its probe finds the
        // agent unreachable. That drives the same failing-probe path a bad
        // healthcheck does, so after `retries` the tracker flips Unhealthy and
        // asks for a restart.
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("svc", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let unreachable = Fake(ExecOutcome::Unreachable);
        let vms = vec!["svc".to_string()];

        let mut actions = Vec::new();
        for i in 0..3u64 {
            actions.extend(prober.tick(&vms, 1000 + i * 30, &unreachable, &NoAudit));
        }

        assert!(
            actions
                .iter()
                .any(|(vm, a)| vm == "svc" && *a == HealthAction::Restart),
            "an unreachable agent must drive a Restart via the probe path, got {actions:?}"
        );
        assert_eq!(
            prober.trackers.get("svc").unwrap().0.state,
            HealthState::Unhealthy
        );
    }

    // ---- restart execution (fake Restarter) ----

    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeRestarter {
        calls: Mutex<Vec<String>>,
    }
    impl Restarter for FakeRestarter {
        fn restart(&self, vm_name: &str) {
            self.calls.lock().unwrap().push(vm_name.to_string());
        }
    }

    #[test]
    fn restart_fires_exactly_once_after_backoff_gate_via_watcher_loop() {
        // Integration test of the watcher's fold→act loop. The critical
        // regression: `fold` sets the backoff gate to a *future* second the
        // instant it returns `Restart`, so `act` on that same instant must
        // defer, and a later tick must fire the pending restart exactly once —
        // firing must not depend on this-pass's actions vec.
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("web", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let exec = Fake(ExecOutcome::Exited(1));
        let restarter = FakeRestarter::default();
        let vms = vec!["web".to_string()];

        // Three due probes (interval=30) drive consecutive_failures past
        // retries=3, flipping Unhealthy at t=1060 and scheduling a restart into
        // the future. Running the full tick→act cycle each pass mirrors the
        // watcher loop; the restart must NOT fire on the instant it was set.
        for now in [1000u64, 1030, 1060] {
            prober.tick(&vms, now, &exec, &NoAudit);
            prober.act(&vms, now, &restarter);
        }
        assert!(
            restarter.calls.lock().unwrap().is_empty(),
            "restart must not fire on the same instant the backoff gate was set"
        );

        let gate = prober
            .trackers
            .get("web")
            .unwrap()
            .0
            .next_restart_after_unix
            .expect("Restart must schedule a backoff gate");
        assert!(
            gate > 1060,
            "backoff gate must be strictly in the future of the tick that set it"
        );

        // A later tick, still before the next probe-due window (t=1090), fires
        // the pending restart exactly once and consumes the gate. This is the
        // path the old `act` never reached — the bug left it dead.
        prober.tick(&vms, gate, &exec, &NoAudit);
        prober.act(&vms, gate, &restarter);
        assert_eq!(*restarter.calls.lock().unwrap(), vec!["web".to_string()]);
        assert!(
            prober
                .trackers
                .get("web")
                .unwrap()
                .0
                .next_restart_after_unix
                .is_none(),
            "a fired gate is consumed so the restart fires exactly once"
        );

        // Further ticks at/after the gate do not re-fire the consumed restart.
        prober.tick(&vms, gate + 1, &exec, &NoAudit);
        prober.act(&vms, gate + 1, &restarter);
        assert_eq!(
            restarter.calls.lock().unwrap().len(),
            1,
            "a consumed gate never re-fires"
        );
    }

    #[test]
    fn restart_not_fired_for_machine_absent_from_live_set_with_pending_gate() {
        // A deliberately-stopped machine that was Unhealthy with a pending
        // restart gate must not be resurrected: `machine stop` deregisters it
        // (leaves the live set) but keeps its spec+healthcheck, so its tracker
        // survives with a gate that has since elapsed. `act` must gate firing on
        // liveness and never restart a machine absent from the live set.
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("web", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let exec = Fake(ExecOutcome::Exited(1));
        let restarter = FakeRestarter::default();
        let vms = vec!["web".to_string()];

        // Drive to Unhealthy with a pending, not-yet-fired gate (act on the
        // setting instant defers, so nothing fires during the drive).
        for now in [1000u64, 1030, 1060] {
            prober.tick(&vms, now, &exec, &NoAudit);
            prober.act(&vms, now, &restarter);
        }
        let gate = prober
            .trackers
            .get("web")
            .unwrap()
            .0
            .next_restart_after_unix
            .expect("Unhealthy machine must hold a pending restart gate");
        assert!(restarter.calls.lock().unwrap().is_empty());

        // Machine is stopped (absent from the live set) and the clock is well
        // past the gate: no restart may fire, and the gate stays pending.
        prober.act(&[], gate + 100, &restarter);
        assert!(
            restarter.calls.lock().unwrap().is_empty(),
            "a stopped machine (absent from live set) must never be restarted"
        );
        assert_eq!(
            prober
                .trackers
                .get("web")
                .unwrap()
                .0
                .next_restart_after_unix,
            Some(gate),
            "an unfired gate for an absent machine is left pending"
        );

        // Once the machine is live again the same elapsed gate fires exactly once.
        prober.act(&vms, gate + 100, &restarter);
        assert_eq!(*restarter.calls.lock().unwrap(), vec!["web".to_string()]);
    }

    #[test]
    fn restart_budget_survives_deregister_and_cap_holds_via_watcher_loop() {
        // Integration test of the restart window: `machine restart` = stop+start,
        // which deregisters the VM, so the watcher sees it briefly absent from
        // the live set. Its restart budget must survive that gap, or a broken
        // service crash-loops forever past MAX_RESTART_ATTEMPTS.
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("web", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let exec = Fake(ExecOutcome::Exited(1));
        let restarter = FakeRestarter::default();
        let vms = vec!["web".to_string()];

        // Drive to the first restart (Unhealthy, restart_attempts=1 at t=1060).
        for now in [1000u64, 1030, 1060] {
            prober.tick(&vms, now, &exec, &NoAudit);
            prober.act(&vms, now, &restarter);
        }
        assert_eq!(prober.trackers.get("web").unwrap().0.restart_attempts, 1);
        // The gate fires on a later, non-probe tick.
        prober.tick(&vms, 1062, &exec, &NoAudit);
        prober.act(&vms, 1062, &restarter);
        assert_eq!(
            restarter.calls.lock().unwrap().len(),
            1,
            "exactly one restart fired so far"
        );

        // Restart window: the machine deregisters (absent from live set) for a
        // couple of ticks. The tracker — and its restart_attempts — must survive.
        for now in [1064u64, 1066] {
            prober.tick(&[], now, &exec, &NoAudit);
            prober.act(&[], now, &restarter);
        }
        assert!(
            prober.trackers.contains_key("web"),
            "tracker must survive a restart's deregistration window"
        );
        assert_eq!(
            prober.trackers.get("web").unwrap().0.restart_attempts,
            1,
            "restart budget must not reset across the restart window"
        );

        // Machine comes back still-failing. Drive the watcher at its real 2s
        // cadence until the cap gives up.
        let mut now = 1068u64;
        let mut gave_up = false;
        while now < 1600 && !gave_up {
            let actions = prober.tick(&vms, now, &exec, &NoAudit);
            prober.act(&vms, now, &restarter);
            if actions
                .iter()
                .any(|(vm, a)| vm == "web" && *a == HealthAction::GiveUp)
            {
                gave_up = true;
            }
            now += 2;
        }

        assert!(
            gave_up,
            "must give up once the restart budget is exhausted across the window"
        );
        assert_eq!(
            prober.trackers.get("web").unwrap().0.state,
            HealthState::Unhealthy
        );
        // Exactly MAX_RESTART_ATTEMPTS restarts total, then parked — the cap held
        // even though the VM deregistered mid-way.
        assert_eq!(
            *restarter.calls.lock().unwrap(),
            vec!["web".to_string(); MAX_RESTART_ATTEMPTS as usize],
            "cap enforced across the restart window (no crash-loop)"
        );

        // Ticking on past give-up spawns no further restarts.
        for _ in 0..5u64 {
            prober.tick(&vms, now, &exec, &NoAudit);
            prober.act(&vms, now, &restarter);
            now += 30;
        }
        assert_eq!(
            restarter.calls.lock().unwrap().len(),
            MAX_RESTART_ATTEMPTS as usize,
            "a parked machine is never restarted again"
        );
    }

    #[test]
    fn give_up_never_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("web", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let exec = Fake(ExecOutcome::Exited(1));
        let vms = vec!["web".to_string()];

        // Drive past `max_restart_attempts` (5) restarts by repeatedly
        // failing once already Unhealthy: each due probe past the initial
        // Unhealthy flip earns another restart attempt.
        let mut now = 1000u64;
        for _ in 0..3u64 {
            prober.tick(&vms, now, &exec, &NoAudit);
            now += 30;
        }
        // Tracker is now Unhealthy with restart_attempts == 1. Keep failing
        // until restart_attempts saturates at max_restart_attempts (5) and
        // the next fail after that yields GiveUp.
        let mut last_actions = Vec::new();
        for _ in 0..6u64 {
            last_actions = prober.tick(&vms, now, &exec, &NoAudit);
            now += 30;
        }

        assert!(
            last_actions
                .iter()
                .any(|(vm, a)| vm == "web" && *a == HealthAction::GiveUp),
            "expected GiveUp once max_restart_attempts is exhausted, got {last_actions:?}"
        );

        let restarter = FakeRestarter::default();
        // GiveUp clears the backoff gate, so even at a far-future now_unix `act`
        // finds no pending restart to fire.
        prober.act(&vms, now + 10_000, &restarter);
        assert!(
            restarter.calls.lock().unwrap().is_empty(),
            "GiveUp must never spawn a restart"
        );
    }

    #[test]
    fn map_state_projects_all_variants() {
        assert!(matches!(
            map_state(HealthState::Starting),
            InstanceReadiness::ServicesStarting { .. }
        ));
        assert_eq!(
            map_state(HealthState::Healthy),
            InstanceReadiness::ServicesReady
        );
        assert!(matches!(
            map_state(HealthState::Unhealthy),
            InstanceReadiness::Degraded { .. }
        ));
    }
}
