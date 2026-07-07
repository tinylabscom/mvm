//! Host->guest healthcheck probe primitive.
//!
//! Runs a workload's declared healthcheck command in the guest via the
//! agent's exec protocol and folds the result into a `ProbeResult`. The
//! guest exec leg is factored behind the [`GuestExec`] trait so
//! [`probe_with`] is unit-testable without a live VM; [`probe_once`] wires
//! it to the real vsock transport.
//!
//! [`HealthProber::tick`] also detects crash-exits: a declared service (one
//! carrying a `health_check`) whose VM process disappears without a
//! deliberate `machine stop` gets the same bounded restart treatment as a
//! failing probe. Health-state transitions and restart decisions are
//! recorded as structured `tracing` events (`vm`/`event`/`state` fields);
//! wiring them into the chain-signed audit log is a follow-up — the
//! existing `AuditEmitter` binds every entry to a signed `ExecutionPlan`,
//! which this bare-VM-name probe loop doesn't hold.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use mvm::machine::persist::load_machine_spec;
use mvm::vm::name_registry::{VmNameRegistry, record_readiness, registry_path};
use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::health::{
    HealthAction, HealthPolicy, HealthState, HealthTracker, ProbeResult, backoff_secs, fold,
};
use mvm_guest::vsock::{ExecEvent, GUEST_AGENT_PORT, send_exec_streaming};
use mvm_sdk::ir::HealthCheck;

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
        let transport = match mvm::vsock_transport::for_vm(vm_name) {
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

/// Look up a VM's current host-observed readiness in the name registry.
/// Best-effort: a load failure or an unregistered name both read as
/// "no readiness signal" rather than erroring, mirroring
/// [`record_readiness`]'s own fail-open posture.
fn registry_readiness(vm_name: &str) -> Option<InstanceReadiness> {
    VmNameRegistry::load(&registry_path())
        .ok()
        .and_then(|reg| reg.lookup(vm_name).and_then(|reg| reg.readiness.clone()))
}

/// Fold a crash-exit observation into the tracker and return the bounded
/// restart decision. Unlike [`fold`], a single observation is unambiguous
/// evidence of failure — there is no probe to retry, so it skips straight to
/// the "already unhealthy" restart-budget arithmetic `fold` uses once a
/// tracker has flipped `Unhealthy`, reusing the same backoff schedule and
/// `max_restart_attempts` cap.
fn crash_exit_action(
    tracker: &mut HealthTracker,
    policy: &HealthPolicy,
    now_unix: u64,
) -> HealthAction {
    tracker.state = HealthState::Unhealthy;
    tracker.consecutive_failures = 0;
    if tracker.restart_attempts >= policy.max_restart_attempts {
        return HealthAction::GiveUp;
    }
    tracker.restart_attempts = tracker.restart_attempts.saturating_add(1);
    tracker.next_restart_after_unix =
        Some(now_unix + backoff_secs(tracker.restart_attempts, policy));
    HealthAction::Restart
}

/// Emit a structured event for a health-state transition. Best-effort
/// observability: the daemon has no reachable chain-signed audit surface for
/// a bare VM name (the existing `AuditEmitter` binds every entry to a signed
/// `ExecutionPlan`, which this probe loop never holds), so this logs a
/// structured `tracing` event instead — see the module doc comment.
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

/// Per-VM health probing over the daemon's live registration set.
///
/// Holds one [`HealthTracker`] plus its last-probe unix second per healthchecked
/// VM, so [`tick`](HealthProber::tick) can skip VMs that aren't yet due and drop
/// trackers for VMs that have gone away or lost their healthcheck. `previously_live`
/// remembers which healthchecked VMs carried a tracker after the prior call —
/// including one mid-backoff after a still-unresolved crash-restart, not just
/// currently-live ones — so a VM's disappearance can be told apart from "never
/// seen" and a still-vanished VM keeps being re-considered until it either
/// reappears or its restart budget gives up. See [`tick`](HealthProber::tick).
#[derive(Default)]
pub struct HealthProber {
    trackers: HashMap<String, (HealthTracker, u64)>,
    previously_live: HashSet<String>,
}

impl HealthProber {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run one probe pass over `live_vm_ids` and return the restart-worthy
    /// actions (`Restart` / `GiveUp`) keyed by VM; `None` actions are dropped.
    ///
    /// Two passes happen here:
    ///
    /// 1. Crash-exit detection: any healthchecked VM that was live last call
    ///    but has vanished from `live_vm_ids` this call is either a deliberate
    ///    `machine stop` (registry readiness `Stopping` — silently forgotten)
    ///    or a crash (bounded restart through [`crash_exit_action`]).
    /// 2. The ordinary probe pass: for each live VM it loads the persisted
    ///    spec, skips (and forgets) any VM without a healthcheck, ensures a
    ///    tracker exists, and — only when the VM is due — runs the probe,
    ///    folds the result, records the mapped readiness, and collects the
    ///    resulting action.
    ///
    /// Executing a restart is deliberately left to the caller ([`act`](Self::act)).
    pub fn tick(
        &mut self,
        live_vm_ids: &[String],
        now_unix: u64,
        exec: &dyn GuestExec,
    ) -> Vec<(String, HealthAction)> {
        let mut actions = Vec::new();

        let vanished: Vec<String> = self
            .previously_live
            .iter()
            .filter(|vm| !live_vm_ids.iter().any(|live| live == *vm))
            .cloned()
            .collect();
        for vm in &vanished {
            self.handle_crash_exit(vm, now_unix, &mut actions);
        }

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
                    actions.push((vm.clone(), action));
                }
                HealthAction::GiveUp => {
                    tracing::warn!(
                        vm = %vm,
                        event = "health.give_up",
                        state = ?new_state,
                        "healthcheck unhealthy; restart budget exhausted"
                    );
                    actions.push((vm.clone(), action));
                }
            }
        }
        // Anything still tracked after this pass — currently live, or mid
        // crash-restart backoff — is worth re-checking on the next call.
        // Trackers removed above (no spec, no healthcheck, deliberate stop,
        // or a just-exhausted restart budget) drop out here too.
        self.previously_live = self.trackers.keys().cloned().collect();
        actions
    }

    /// Decide what to do about a healthchecked VM that was live last tick and
    /// is gone this tick: forget it silently if it's no longer a declared
    /// service (spec removed / healthcheck dropped) or was deliberately
    /// stopped (registry readiness `Stopping`); otherwise it crashed, so
    /// fold a bounded restart decision and push it onto `actions`. The
    /// tracker survives a `Restart` decision (so [`act`](Self::act) can gate
    /// the actual restart on the backoff schedule) but is dropped on
    /// `GiveUp` or when the disappearance turned out not to be a crash.
    fn handle_crash_exit(
        &mut self,
        vm: &str,
        now_unix: u64,
        actions: &mut Vec<(String, HealthAction)>,
    ) {
        let Ok(spec) = load_machine_spec(vm) else {
            // Spec is gone entirely (e.g. `machine rm`): nothing left to restart.
            self.trackers.remove(vm);
            return;
        };
        let Some(hc) = spec.health_check else {
            // No declared healthcheck: phase-A teardown-on-exit semantics apply
            // (the caller already tears the machine down; nothing to restart).
            self.trackers.remove(vm);
            return;
        };
        if registry_readiness(vm) == Some(InstanceReadiness::Stopping) {
            // `mvmctl machine stop` recorded this as intentional.
            tracing::info!(vm = %vm, event = "health.stopped", "machine stop recorded; not a crash");
            self.trackers.remove(vm);
            return;
        }

        let policy = policy_from(&hc);
        let Some((tracker, _)) = self.trackers.get_mut(vm) else {
            // previously_live only ever tracks VMs that had a tracker.
            return;
        };
        // Pace re-evaluation off the same backoff gate `act` uses to fire the
        // actual restart, so a still-vanished VM doesn't rack up restart
        // attempts every single tick.
        let due = tracker
            .next_restart_after_unix
            .is_none_or(|gate| now_unix >= gate);
        if !due {
            return;
        }

        let action = crash_exit_action(tracker, &policy, now_unix);
        match action {
            HealthAction::None => {}
            HealthAction::Restart => {
                tracing::warn!(
                    vm = %vm,
                    event = "health.crash_restart",
                    state = ?tracker.state,
                    "healthchecked service crash-exited; restart requested"
                );
                actions.push((vm.to_string(), action));
            }
            HealthAction::GiveUp => {
                tracing::warn!(
                    vm = %vm,
                    event = "health.crash_give_up",
                    state = ?tracker.state,
                    "healthchecked service crash-exited; restart budget exhausted"
                );
                actions.push((vm.to_string(), action));
                self.trackers.remove(vm);
            }
        }
    }

    /// Execute the restart-worthy actions `tick` returned, gated by each
    /// tracker's backoff schedule.
    ///
    /// `Restart` only fires `restarter.restart(vm)` once `now_unix` has
    /// reached the tracker's `next_restart_after_unix`. `fold` sets that gate
    /// to a future second the moment it returns `Restart`, so a call to `act`
    /// at the same `now_unix` the action was produced always defers; the
    /// restart fires once a later call observes the gate has elapsed.
    /// `GiveUp` never restarts (`tick` already logged the give-up); `None`
    /// never appears in `actions` in the first place.
    pub fn act(
        &self,
        actions: &[(String, HealthAction)],
        now_unix: u64,
        restarter: &dyn Restarter,
    ) {
        for (vm, action) in actions {
            if *action != HealthAction::Restart {
                continue;
            }
            let due = self
                .trackers
                .get(vm)
                .and_then(|(tracker, _)| tracker.next_restart_after_unix)
                .is_some_and(|gate| now_unix >= gate);
            if due {
                restarter.restart(vm);
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

    // ---- HealthProber::tick (disk-backed via MVM_DATA_DIR/MVM_SHARE_DIR) ----

    use mvm::machine::persist::{MACHINE_SPEC_SCHEMA_VERSION, MachineSpec, save_machine_spec};
    use mvm::vm::name_registry::{VmNameRegistry, registry_path};
    use mvm_core::domain::instance::InstanceReadiness;
    use mvm_core::health::HealthState;
    use mvm_core::util::test_env::TestEnv;

    // Point both the machine-spec dir and the name-registry dir at `dir`, holding
    // the process-wide env lock so these disk-backed tests don't race other tests
    // that mutate the same vars under a threaded runner.
    fn data_env(dir: &std::path::Path) -> TestEnv {
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", dir);
        env.set("MVM_SHARE_DIR", dir);
        env
    }

    fn spec_with_hc(name: &str, health_check: Option<HealthCheck>) -> MachineSpec {
        MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: Some("alpine:latest".to_string()),
            manifest: None,
            resolved_digest: None,
            net: false,
            allow_host: vec![],
            cpus: 1,
            memory: "256M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: vec![],
            init: vec![],
            ssh_agent: false,
            agent_verb: vec![],
            created_at: None,
            last_started_at: None,
            health_check,
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
            actions.extend(prober.tick(&vms, 1000 + i * 30, &exec));
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

    #[test]
    fn tick_skips_machine_without_healthcheck() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("bare", None), true).unwrap();

        let mut prober = HealthProber::new();
        let actions = prober.tick(&["bare".to_string()], 1000, &Fake(ExecOutcome::Exited(0)));

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
        let actions = prober.tick(&["api".to_string()], 1000, &Fake(ExecOutcome::Exited(0)));

        assert!(actions.is_empty(), "a pass should not request a restart");
        let loaded = VmNameRegistry::load(&rpath).unwrap();
        assert_eq!(
            loaded.lookup("api").unwrap().readiness,
            Some(InstanceReadiness::ServicesReady)
        );
    }

    #[test]
    fn tick_drops_tracker_when_deliberately_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("gone", Some(hc())), true).unwrap();
        let rpath = registry_path();
        let mut reg = VmNameRegistry::default();
        reg.register("gone", "/tmp/gone", "default", None, 0)
            .unwrap();
        reg.save(&rpath).unwrap();

        let mut prober = HealthProber::new();
        prober.tick(&["gone".to_string()], 1000, &Fake(ExecOutcome::Exited(1)));
        assert!(prober.trackers.contains_key("gone"));

        // `machine stop` fires between this tick and the next, recording
        // `Stopping` before the process actually exits — mirrors the real
        // ordering in `down.rs` (the last write wins once the vm leaves the
        // live set, since the probe loop won't touch its readiness again).
        reg = VmNameRegistry::load(&rpath).unwrap();
        reg.set_readiness(
            "gone",
            InstanceReadiness::Stopping,
            mvm_core::time::utc_now(),
        )
        .unwrap();
        reg.save(&rpath).unwrap();

        // Next pass without "gone" in the live set: a deliberate stop, not a
        // crash, so the tracker is dropped and no restart is requested.
        let actions = prober.tick(&[], 1100, &Fake(ExecOutcome::Exited(1)));
        assert!(!prober.trackers.contains_key("gone"));
        assert!(
            actions.is_empty(),
            "a deliberate stop must never request a restart, got {actions:?}"
        );
    }

    // ---- crash-exit detection (no probe involved — the VM just vanished) ----

    #[test]
    fn crash_exit_without_stop_marker_requests_bounded_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("svc", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let passing = Fake(ExecOutcome::Exited(0));

        // Seed a tracker via a normal live pass (no registry entry at all —
        // most persistent machines have one, but a crash-exit must not
        // depend on it existing to notice the disappearance).
        prober.tick(&["svc".to_string()], 1000, &passing);
        assert!(prober.trackers.contains_key("svc"));

        // Next tick: "svc" vanished from the live set without ever recording
        // `Stopping` — a crash. The very first observation restarts
        // immediately (no need to re-confirm across multiple probes).
        let actions = prober.tick(&[], 1030, &passing);
        assert!(
            actions
                .iter()
                .any(|(vm, a)| vm == "svc" && *a == HealthAction::Restart),
            "expected an immediate Restart action on first crash observation, got {actions:?}"
        );
        assert_eq!(
            prober.trackers.get("svc").unwrap().0.state,
            HealthState::Unhealthy
        );

        // Keep advancing well past the backoff cap so every subsequent tick
        // is due; the restart budget must still cap out at GiveUp rather
        // than restarting forever. Once GiveUp fires the tracker is dropped,
        // so later iterations produce no further action — collect across the
        // whole run rather than asserting on the very last tick's result.
        let mut now = 1030u64;
        let mut all_actions = actions;
        for _ in 0..6u64 {
            now += 301;
            all_actions.extend(prober.tick(&[], now, &passing));
        }
        assert!(
            all_actions
                .iter()
                .any(|(vm, a)| vm == "svc" && *a == HealthAction::GiveUp),
            "expected GiveUp once the crash-restart budget is exhausted, got {all_actions:?}"
        );
        assert!(
            !prober.trackers.contains_key("svc"),
            "GiveUp must forget the tracker so it stops re-firing every tick"
        );
    }

    #[test]
    fn crash_exit_act_restarts_only_after_backoff_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("svc", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let passing = Fake(ExecOutcome::Exited(0));
        prober.tick(&["svc".to_string()], 1000, &passing);

        let actions = prober.tick(&[], 1030, &passing);
        assert!(
            actions
                .iter()
                .any(|(vm, a)| vm == "svc" && *a == HealthAction::Restart)
        );

        let gate = prober
            .trackers
            .get("svc")
            .unwrap()
            .0
            .next_restart_after_unix
            .expect("Restart must set a backoff gate");

        let restarter = FakeRestarter::default();
        prober.act(&actions, 1030, &restarter);
        assert!(
            restarter.calls.lock().unwrap().is_empty(),
            "restart must not fire before the backoff gate elapses"
        );

        prober.act(&actions, gate, &restarter);
        assert_eq!(*restarter.calls.lock().unwrap(), vec!["svc".to_string()]);
    }

    #[test]
    fn crash_exit_skipped_when_no_healthcheck_declared() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("bare", None), true).unwrap();

        let mut prober = HealthProber::new();
        prober.tick(&["bare".to_string()], 1000, &Fake(ExecOutcome::Exited(0)));
        assert!(!prober.trackers.contains_key("bare"));

        // A no-healthcheck machine never earns a tracker in the first place
        // (phase-A teardown-on-exit semantics apply), so its disappearance
        // yields no restart-worthy action.
        let actions = prober.tick(&[], 1030, &Fake(ExecOutcome::Exited(0)));
        assert!(
            actions.is_empty(),
            "a no-healthcheck machine must never be restarted, got {actions:?}"
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
    fn restart_gated_by_backoff_not_before_not_missing_after() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = data_env(tmp.path());

        save_machine_spec(&spec_with_hc("web", Some(hc())), true).unwrap();

        let mut prober = HealthProber::new();
        let exec = Fake(ExecOutcome::Exited(1));
        let vms = vec!["web".to_string()];

        // Same walk as `tick_failing_check_goes_unhealthy_and_restarts`: three
        // due probes (interval=30) drive consecutive_failures past retries=3,
        // flipping Unhealthy and returning the first Restart action.
        let mut actions = Vec::new();
        let mut last_tick_now = 0u64;
        for i in 0..3u64 {
            let now = 1000 + i * 30;
            last_tick_now = now;
            actions = prober.tick(&vms, now, &exec);
        }
        assert!(
            actions
                .iter()
                .any(|(vm, a)| vm == "web" && *a == HealthAction::Restart),
            "expected a Restart action, got {actions:?}"
        );

        let gate = prober
            .trackers
            .get("web")
            .unwrap()
            .0
            .next_restart_after_unix
            .expect("Restart action must set a backoff gate");
        assert!(
            gate > last_tick_now,
            "backoff gate must be strictly in the future of the tick that set it"
        );

        // Before the gate: no restart fires.
        let restarter = FakeRestarter::default();
        prober.act(&actions, last_tick_now, &restarter);
        assert!(
            restarter.calls.lock().unwrap().is_empty(),
            "restart must not fire before the backoff gate elapses"
        );

        // At/after the gate: the restart fires exactly once.
        prober.act(&actions, gate, &restarter);
        assert_eq!(*restarter.calls.lock().unwrap(), vec!["web".to_string()]);
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
            prober.tick(&vms, now, &exec);
            now += 30;
        }
        // Tracker is now Unhealthy with restart_attempts == 1. Keep failing
        // until restart_attempts saturates at max_restart_attempts (5) and
        // the next fail after that yields GiveUp.
        let mut last_actions = Vec::new();
        for _ in 0..6u64 {
            last_actions = prober.tick(&vms, now, &exec);
            now += 30;
        }

        assert!(
            last_actions
                .iter()
                .any(|(vm, a)| vm == "web" && *a == HealthAction::GiveUp),
            "expected GiveUp once max_restart_attempts is exhausted, got {last_actions:?}"
        );

        let restarter = FakeRestarter::default();
        // Even at a far-future now_unix, GiveUp must never trigger a restart.
        prober.act(&last_actions, now + 10_000, &restarter);
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
