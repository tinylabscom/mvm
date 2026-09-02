//! Boot-sequence background init: entrypoint validation, warm-process pool
//! startup, and the integrations/probes drop-in scans. Each of these runs on
//! its own background thread spawned from `main` so a slow or malformed
//! drop-in can't delay the accept loop.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mvm_agentd::entrypoint::EntrypointPolicy;
use mvm_agentd::integrations;
use mvm_agentd::lifecycle_hooks::ReadinessConfig;
use mvm_agentd::probes;
use mvm_agentd::runtime_config::{self, ConcurrencyConfig};
use mvm_agentd::vsock::ComponentState;
use mvm_agentd::worker_pool::WorkerPool;

use crate::globals::{VALIDATED_ENTRYPOINT, WARM_POOL};
use crate::health::integration_health_loop;
use crate::probe::probe_health_loop;
use crate::state::{AgentBootState, IntegrationHealth, IntegrationState, ProbeHealth, ProbeState};

// Baked-in lifecycle hook path. The Nix factory at
// `nix/lib/factories/mkFunctionService.nix` always emits this
// script (no-op `:` body when the user declared no commands for
// the phase). The agent only needs to know the canonical path;
// missing-script fall-through is handled inside `lifecycle_hooks`
// defensively.
pub(crate) const AFTER_START_HOOK: &str = "/etc/mvm/hooks/after_start.sh";

/// Maximum time to wait for the after_start probe to exit 0 before
/// the agent gives up (30s). On timeout, the pool stays NotReady and
/// dispatch refuses fast.
pub(crate) const READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Sleep between readiness probe attempts. 200 ms balances fast
/// ready-detection against shell-fork overhead.
pub(crate) const READINESS_INTERVAL: Duration = Duration::from_millis(200);

/// Validate `/etc/mvm/entrypoint` at agent boot. The result is stashed in
/// `VALIDATED_ENTRYPOINT`. On failure, log a single line — the agent stays
/// up; only `RunEntrypoint` requests fail with `EntrypointInvalid`.
///
/// Also updates `AgentBootState.entrypoint` so `ReadinessStatus`
/// reports `Ready` (or `Failed { message }`) and stamps
/// `entrypoint_ready_ms` for cold-path timing.
pub(crate) fn init_entrypoint_validation(boot_state: &Arc<AgentBootState>) {
    let result = match EntrypointPolicy::production().validate() {
        Ok(v) => {
            boot_state.set_entrypoint(ComponentState::Ready);
            Ok(v)
        }
        Err(e) if e.is_entrypoint_not_offered() => {
            // Sealed images currently bake the entrypoint as a script inside
            // `/etc/mvm/entrypoint` rather than a wrapper path. Try the
            // fallback policy that validates the marker file itself, so
            // `RunEntrypoint` works for these images until mkGuest produces
            // the `/usr/lib/mvm/wrappers/` layout.
            match EntrypointPolicy::sealed_script_marker().validate() {
                Ok(v) => {
                    boot_state.set_entrypoint(ComponentState::Ready);
                    Ok(v)
                }
                Err(e2) => {
                    // Boot-script image: the marker is not a usable wrapper
                    // or sealed script. RunEntrypoint is not offered — a
                    // clean state, not a failure.
                    boot_state.set_entrypoint(ComponentState::Disabled);
                    Err(format!(
                        "this image does not offer a per-call entrypoint (RunEntrypoint): {e2}"
                    ))
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            eprintln!(
                "mvm-guest-agent: entrypoint validation failed at boot: {msg}; \
                 RunEntrypoint requests will return EntrypointInvalid"
            );
            boot_state.set_entrypoint(ComponentState::Failed {
                message: msg.clone(),
            });
            Err(msg)
        }
    };
    let _ = VALIDATED_ENTRYPOINT.set(result);
}

/// Read `/etc/mvm/runtime.json` and, if it carries `concurrency.kind
/// = "warm_process"`, stand up the worker pool.
///
/// Failure modes are deliberately fail-loud — mvmforge owns
/// `runtime.json`, so a malformed file or rejected `in_process` mode
/// is a build bug, not a runtime fallback. The agent exits non-zero
/// rather than silently dropping to cold tier and confusing
/// observers about which tier is active.
///
/// Missing `runtime.json` or absent `concurrency` → `Ok(None)`, the
/// cold path stays in charge.
///
/// Runs in the boot-time background thread chained after
/// `init_entrypoint_validation`. Updates
/// `AgentBootState.warm_pool` (`Disabled` for cold-tier images,
/// `Starting` → `Ready` for warm-pool, `Failed` on entrypoint
/// dependency failure). Process-exit-on-bad-config is preserved —
/// `runtime.json` is part of the immutable image and a malformed
/// file is a build bug.
pub(crate) fn init_warm_pool(boot_state: &Arc<AgentBootState>) {
    let result: Option<Arc<WorkerPool>> = match runtime_config::load() {
        Ok(None) => {
            boot_state.set_warm_pool(ComponentState::Disabled);
            None
        }
        Ok(Some(rc)) => match rc.concurrency {
            None => {
                boot_state.set_warm_pool(ComponentState::Disabled);
                None
            }
            Some(ConcurrencyConfig::WarmProcess(wp)) => {
                boot_state.set_warm_pool(ComponentState::Starting);
                match VALIDATED_ENTRYPOINT.get() {
                    Some(Ok(entry)) => match entry.try_clone() {
                        Ok(cloned) => match WorkerPool::start(wp, Arc::new(cloned), Vec::new()) {
                            Ok(pool) => {
                                // Run the baked `after_start.sh`
                                // readiness probe before
                                // letting traffic in. Pool starts in
                                // `NotReady`; `wait_for_ready` flips it
                                // on success, leaves it `NotReady` on
                                // timeout/exec error so subsequent
                                // dispatches fast-fail with `NotReady`
                                // (host surface: Busy + "warming up"
                                // message) rather than hitting an
                                // unwarmed wrapper.
                                wait_for_after_start(&pool);
                                boot_state.set_warm_pool(ComponentState::Ready);
                                Some(pool)
                            }
                            Err(e) => {
                                eprintln!(
                                    "mvm-guest-agent: warm-process pool start failed: {e}; refusing to boot"
                                );
                                std::process::exit(1);
                            }
                        },
                        Err(e) => {
                            eprintln!(
                                "mvm-guest-agent: warm-process configured but entrypoint clone failed: {e}; refusing to boot"
                            );
                            std::process::exit(1);
                        }
                    },
                    _ => {
                        // Entrypoint validation failed; surface a
                        // matching warm-pool failure rather than
                        // process-exit. Keep the control plane up so
                        // `ReadinessStatus` can report both failures
                        // together.
                        boot_state.set_warm_pool(ComponentState::Failed {
                            message: "entrypoint validation failed".to_string(),
                        });
                        None
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("mvm-guest-agent: invalid /etc/mvm/runtime.json: {e}; refusing to boot");
            std::process::exit(1);
        }
    };
    let _ = WARM_POOL.set(result);
}

/// Run the baked `after_start.sh` readiness probe and gate the
/// worker pool's traffic spigot on its success.
///
/// - On success (or absent script: workload declared no after_start
///   hook), the pool flips to ready and dispatch starts accepting
///   invokes.
/// - On timeout / exec error, the pool stays `NotReady`. The agent
///   keeps the vsock listener up — operators get a host-visible log
///   line + every dispatch returns `Busy` with a "warming up"
///   message. Better than silently dispatching to an unready
///   workload.
fn wait_for_after_start(pool: &Arc<WorkerPool>) {
    let cfg = ReadinessConfig::new(AFTER_START_HOOK)
        .with_timeout(READINESS_TIMEOUT)
        .with_interval(READINESS_INTERVAL);
    match pool.wait_for_ready(&cfg) {
        Ok(()) => {
            eprintln!(
                "mvm-guest-agent: warm-process pool ready (after_start probe `{AFTER_START_HOOK}` ok)"
            );
        }
        Err(e) => {
            eprintln!(
                "mvm-guest-agent: warm-process pool not ready — after_start probe failed: {e}; \
                 dispatches will surface NotReady until manual intervention"
            );
        }
    }
}

/// Scan `/etc/mvm/integrations.d/*.json`, populate
/// `integration_state` with the discovered entries, and spawn the
/// health-check loop iff at least one integration was loaded. Runs
/// on its own background thread so a slow or malformed drop-in
/// cannot delay the accept loop.
///
/// Transitions in `AgentBootState`:
///   `Starting` → `Ready`    (≥ 1 integration loaded; health loop spawned)
///   `Starting` → `Disabled` (no integrations declared)
///
/// `Failed` is not currently produced — `load_dropin_dir` is
/// best-effort per-file (a malformed JSON file is skipped with a
/// stderr log; the rest still load). That upholds the invariant
/// that a malformed integration drop-in does not kill control-plane
/// readiness.
pub(crate) fn init_integrations(
    boot_state: &Arc<AgentBootState>,
    integration_state: &Arc<Mutex<IntegrationState>>,
) {
    boot_state.set_integrations(ComponentState::Starting);
    let entries = integrations::load_dropin_dir(integrations::INTEGRATIONS_DROPIN_DIR);
    let count = entries.len();
    if let Ok(mut s) = integration_state.lock() {
        s.integrations = entries
            .into_iter()
            .map(|e| IntegrationHealth {
                entry: e,
                last_result: None,
            })
            .collect();
    }
    if count > 0 {
        boot_state.set_integrations(ComponentState::Ready);
        let health_state = Arc::clone(integration_state);
        std::thread::spawn(move || integration_health_loop(health_state));
    } else {
        boot_state.set_integrations(ComponentState::Disabled);
    }
}

/// Scan `/etc/mvm/probes.d/*.json`, populate `probe_state` with the
/// discovered entries, and spawn the probe loop iff at least one
/// probe was loaded. Mirrors `init_integrations`.
pub(crate) fn init_probes(boot_state: &Arc<AgentBootState>, probe_state: &Arc<Mutex<ProbeState>>) {
    boot_state.set_probes(ComponentState::Starting);
    let entries = probes::load_probe_dropin_dir(probes::PROBES_DROPIN_DIR);
    let count = entries.len();
    if let Ok(mut s) = probe_state.lock() {
        s.probes = entries
            .into_iter()
            .map(|e| ProbeHealth {
                entry: e,
                last_result: None,
            })
            .collect();
    }
    if count > 0 {
        boot_state.set_probes(ComponentState::Ready);
        let health_state = Arc::clone(probe_state);
        std::thread::spawn(move || probe_health_loop(health_state));
    } else {
        boot_state.set_probes(ComponentState::Disabled);
    }
}
