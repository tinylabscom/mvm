//! The baked-entrypoint call action — boot a microVM and dispatch its
//! `/etc/mvm/entrypoint` over vsock. Reached via `machine run --entrypoint`.
//!
//! Distinct from `mvmctl machine exec` (dev-only, arbitrary shell). This is
//! the production-safe call surface — it dispatches the `RunEntrypoint` vsock
//! verb, which the guest agent serves only by spawning the program named in
//! `/etc/mvm/entrypoint`. There is no shell and no argv override. The only env
//! injected is the substitution env — `HTTP_PROXY` + the opaque secret
//! placeholders — and only when the VM's admitted plan carried secrets; never
//! a raw secret value (those stay in the host substitution endpoint).
//!
//! Behaviour:
//!   - boots a transient microVM from a registered template / manifest slot
//!     (or, with `attach`, dispatches into an already-running named machine),
//!   - waits for the guest agent,
//!   - reads stdin from a file (`-` = mvmctl's own stdin, default empty),
//!   - sends `GuestRequest::RunEntrypoint`,
//!   - streams `EntrypointEvent::Stdout` / `Stderr` events back to
//!     mvmctl's own stdout / stderr as they arrive,
//!   - tears the VM down (unless `keep_alive`),
//!   - exits with the wrapper's exit code (or non-zero on error).
//!
//! `fresh` and `reset` are accepted but informational — the current behaviour
//! matches `fresh` (no warm session reuse). When the session-pool plan lands,
//! the default flips to "reuse warm VM" and `fresh` becomes the opt-out.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::ui;

/// One baked-entrypoint call, decoupled from clap so the `machine run`
/// lifecycle dispatcher can drive it directly. `machine run --entrypoint`
/// builds this from `MachineRunArgs` (source → `source`, `-d`/`--name` →
/// `keep_alive`, `--attach` → `attach`); there is no separate `invoke` verb.
pub(in crate::commands) struct EntrypointCall {
    /// Template name / pre-built manifest slot to boot, resolved the same way
    /// as `machine exec --manifest`. With `attach`, this is the running VM's
    /// name instead.
    pub source: String,
    /// Path to stdin payload, or `-` for mvmctl's own stdin. `None` ⇒ the
    /// no-argument call payload.
    pub stdin: Option<String>,
    /// Wall-clock timeout for the call, in seconds.
    pub timeout: u64,
    /// vCPU count for the booted VM.
    pub cpus: u32,
    /// Memory for the booted VM (MiB).
    pub memory_mib: u32,
    /// Workload IR (`workload.json`) declaring `.secrets`. When set, the
    /// ephemeral VM is admitted so the host spawns the substitution endpoint;
    /// the guest only ever holds the opaque `mvm-secret-<hex>` placeholder.
    pub from_workload_ir: Option<PathBuf>,
    /// Restore the session VM from its post-boot snapshot before the call.
    /// Wired but no-op in this build (session-pool plan).
    pub reset: bool,
    /// Keep the substrate VM alive after the call (warm session). The session
    /// id is printed on stderr. Mapped from `machine run`'s persistence axis.
    pub keep_alive: bool,
    /// Mark the kept-alive session `mode=dev` so subsequent `session exec` /
    /// `run-code` are allowed. No effect without `keep_alive`.
    pub keep_alive_dev: bool,
    /// Attach this call to an existing warm session id (SDK `mv.session(...)`).
    /// Accepted but no-op in this build; a non-empty value warns and falls
    /// back to the transient path.
    pub session: Option<String>,
    /// Dispatch into a specific function within a multi-function app. Accepted
    /// so SDK argv survives; routing lands with per-function dispatch.
    pub r#fn: Option<String>,
    /// Dispatch into an **already-running** machine (booted by
    /// `machine run --name <NAME>`) instead of booting a transient VM. `source`
    /// is the running VM's name. Its substitution endpoint + boot-minted
    /// placeholders are reused; the VM is left running (no teardown).
    pub attach: bool,
}

pub(in crate::commands) fn run_entrypoint(call: EntrypointCall) -> Result<()> {
    if call.attach {
        // Dispatch into an already-running workload by
        // name (booted by `machine run --name <NAME>`), reusing its substitution
        // endpoint + boot-minted placeholders. `dispatch` injects the workload's
        // substitution env (HTTP_PROXY + placeholders) via `substitution_env`,
        // so a secret-declaring entrypoint runs with live egress substitution.
        // No transient boot, no teardown — the VM is the user's to reap.
        let stdin_bytes = read_stdin_payload(call.stdin.as_deref())?;
        ui::info(&format!(
            "entrypoint: dispatching into running workload '{}'",
            call.source
        ));
        let exit_code = dispatch(&call.source, stdin_bytes, call.timeout, None)?;
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }
    if call.reset {
        ui::warn(
            "--reset is wired but no-op in this build (session-pool plan); \
             treating as default behaviour",
        );
    }
    if let Some(id) = &call.session {
        ui::warn(&format!(
            "--session {id} is accepted but no-op in this build \
             (session-pool plan, plan 60 Phase 5c); falling back to a \
             transient VM for this call"
        ));
    }
    if let Some(name) = &call.r#fn {
        ui::warn(&format!(
            "--fn {name} is accepted but no-op in this build \
             (multi-function dispatch lands with ADR-0014 Phase 2); \
             the workload's primary entrypoint will be dispatched"
        ));
    }

    // The entrypoint action targets a *template* / manifest slot. Resolve
    // through the same shared helper as `machine exec --manifest`. Slot-hash
    // and registered-name both resolve to a string the lifecycle helpers
    // consume.
    let template_id = match super::shared::resolve_manifest_arg(&call.source)? {
        super::shared::ManifestArgRef::Name(n) => n,
        super::shared::ManifestArgRef::Slot { slot_hash } => slot_hash,
    };

    let stdin_bytes = read_stdin_payload(call.stdin.as_deref())?;

    let lifecycle_label = if call.keep_alive {
        "warm session"
    } else {
        "transient VM"
    };
    ui::info(&format!(
        "entrypoint: booting {lifecycle_label} for template '{template_id}'"
    ));
    // If the workload declares secrets (its IR was passed via
    // `--from-workload-ir`), admit the lowered plan so the ephemeral VM spawns
    // the substitution endpoint. The closure runs admission inside
    // `boot_session_vm` (the rootfs + vm_name it needs are generated there). No
    // IR / no secrets ⇒ `None`, the unchanged plain-invoke path.
    let admit_closure: Option<Box<crate::exec::SessionAdmit>> =
        super::up::load_workload_ir(call.from_workload_ir.as_deref())?
            .map(|w| super::managed_secrets::lower_workload_secrets(&w))
            .filter(|lowered| !lowered.secrets.is_empty())
            .map(|lowered| {
                let secrets = lowered.secrets;
                let secret_release = lowered.secret_release;
                let backend_name = mvm_backend::backend::AnyBackend::auto_select()
                    .name()
                    .to_string();
                let cpus = call.cpus;
                let mem = call.memory_mib as u64;
                Box::new(
                    move |rootfs: &std::path::Path,
                          vm_name: &str|
                          -> Result<Option<crate::exec::SessionAuditSubstrate>> {
                        let ledger = super::plan_admission::InMemoryNonceLedger::default();
                        let ctx = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
                            tenant: "local",
                            vm_name,
                            backend_name: &backend_name,
                            rootfs_path: rootfs,
                            precomputed_image_sha256: None,
                            cpus,
                            mem_mib: mem,
                            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                            secret_release,
                            secrets: secrets.clone(),
                            auth: mvm_core::plan::AuthPolicy::none(),
                            no_supervisor: false,
                            ledger: &ledger,
                            keys_dir: None,
                            audit_dir: None,
                            policy_dir: None,
                            bundle_pin: None,
                            deps_volume: None,
                            shares: vec![],
                            redaction: mvm_core::policy::RedactionPolicy::default(),
                            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
                        })?;
                        let Some(c) = ctx else { return Ok(None) };
                        // Persist the bare admitted plan to the per-VM state dir
                        // before boot. The macOS substitution endpoint decodes
                        // its secret bindings from `<state_dir>/plan.json` inside
                        // `backend.start()`; `boot_session_vm` only threads the
                        // plan in-memory, so without this on-disk copy the
                        // endpoint silently no-ops on vz/libkrun (the in-memory
                        // thread alone never reaches the disk-reading decode).
                        if super::up::persists_plan_before_start(&backend_name) {
                            super::plan_persist::write_plan(vm_name, &c.admitted.plan)
                                .context("persisting admitted plan for the pre-start egress moat")?;
                        }
                        let plan_json = serde_json::to_string(&c.admitted.signed)
                            .context("serializing admitted plan for the session VM")?;
                        Ok(Some(crate::exec::SessionAuditSubstrate {
                            tenant_id: c.admitted.plan.tenant.0.clone(),
                            plan_json,
                            bundle_json: None,
                        }))
                    },
                ) as Box<crate::exec::SessionAdmit>
            });

    let vm = crate::exec::boot_session_vm(
        &template_id,
        "invoke",
        call.cpus,
        call.memory_mib,
        admit_closure.as_deref(),
    )
    .context("Booting VM for the entrypoint call")?;

    // Register a session record so `mvmctl session ls`
    // sees the call (whether transient or warm). With `--keep-alive`
    // the record outlives the dispatch and `--keep-alive-dev` flips
    // its `mode` so subsequent `session exec` / `run-code` are
    // permitted. Errors registering are logged but don't block the
    // call.
    let mode = if call.keep_alive_dev {
        mvm_core::session::SessionMode::Dev
    } else {
        mvm_core::session::SessionMode::Prod
    };
    let session_id = register_invoke_session(&vm.vm_name, &template_id, mode);

    if !crate::exec::wait_for_agent(&vm.vm_name, 30) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::exec::tear_down_session_vm(crate::exec::SessionVm {
                vm_name: vm.vm_name.clone(),
            })
        }));
        deregister_invoke_session(session_id.as_ref());
        anyhow::bail!("guest agent did not become reachable within 30s");
    }

    // Run the call. Pass the session id so a transport drop coincident
    // with `mvmctl session kill` is attributed as `SessionKilled`
    // rather than a generic I/O error.
    let dispatch_result = dispatch(&vm.vm_name, stdin_bytes, call.timeout, session_id.as_ref());

    // Tear down lifecycle:
    //   - default: kill the VM and drop the session record (matches
    //     `mvmctl exec` semantics, no leaked transient resources).
    //   - `--keep-alive`: leave the VM running and bump the session
    //     record's invoke counter; the user reuses via `mvmctl session
    //     attach` and reaps via `mvmctl session kill` when done.
    if call.keep_alive {
        if let Some(id) = session_id.as_ref() {
            if let Err(e) = mvm_core::session::update_session(id, |r| {
                r.invoke_count = r.invoke_count.saturating_add(1);
                r.last_invoke_at = Some(rfc3339_now());
                Ok(())
            }) {
                tracing::warn!(err = %e, "failed to bump session invoke counter");
            }
            // Print the session id where the user / SDK will look for
            // it. Stderr keeps stdout clean for the function's actual
            // output bytes.
            eprintln!("Session kept alive: {id}");
        }
    } else {
        crate::exec::tear_down_session_vm(crate::exec::SessionVm {
            vm_name: vm.vm_name.clone(),
        });
        deregister_invoke_session(session_id.as_ref());
    }

    match dispatch_result {
        Ok(exit_code) => {
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn rfc3339_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Register a fresh session record for an `mvmctl invoke` call.
/// Returns the id on success, or `None` if registration failed (e.g.
/// no writable runtime dir). Logs warnings on failure but does not
/// abort the invoke — the call should still succeed if the session
/// machinery is unavailable. `mode` selects whether subsequent
/// `mvmctl session exec` / `run-code` calls against this session
/// will be allowed (`Dev`) or refused (`Prod`).
fn register_invoke_session(
    vm_name: &str,
    workload_id: &str,
    mode: mvm_core::session::SessionMode,
) -> Option<mvm_core::session::SessionId> {
    let record = mvm_core::session::SessionRecord::new_running(vm_name, workload_id, mode);
    let id = record.id.clone();
    match mvm_core::session::write_session(&record) {
        Ok(()) => Some(id),
        Err(e) => {
            tracing::warn!(err = %e, "failed to register invoke session");
            None
        }
    }
}

/// Remove the session record for an in-flight `mvmctl invoke`. If the
/// session was already killed externally (state = Killed / Reaped),
/// keep the record so an observer can see the lifecycle terminated.
fn deregister_invoke_session(id: Option<&mvm_core::session::SessionId>) {
    let Some(id) = id else { return };
    // Read current state — if external code marked it Killed, leave
    // the record in place; otherwise remove it.
    match mvm_core::session::read_session(id) {
        Ok(Some(rec)) if rec.state == mvm_core::session::SessionState::Running => {
            if let Err(e) = mvm_core::session::remove_session(id) {
                tracing::warn!(err = %e, "failed to remove invoke session record");
            }
        }
        Ok(_) => {
            // Either not present or in a non-Running state — leave as-is.
        }
        Err(e) => {
            tracing::warn!(err = %e, "failed to read invoke session record");
        }
    }
}

/// Read the stdin payload for the call.
///
/// - `None`: the no-argument call payload `[[], {}]` — the wrapper's wire
///   contract requires a JSON `[args, kwargs]` body, and an empty one is a
///   decode error in the guest, so a bare `invoke` means "call with no args".
/// - `Some("-")`: read everything from mvmctl's own stdin.
/// - `Some(path)`: read the file at `path`.
pub(in crate::commands) fn read_stdin_payload(spec: Option<&str>) -> Result<Vec<u8>> {
    match spec {
        None => Ok(b"[[], {}]".to_vec()),
        Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("Reading stdin from mvmctl's own stdin")?;
            Ok(buf)
        }
        Some(path) => std::fs::read(path).with_context(|| format!("Reading stdin from {path}")),
    }
}

/// Send the `RunEntrypoint` request and stream output back. Returns
/// the wrapper's exit code, or a non-zero placeholder on agent-side
/// errors. The placeholders reuse standard Unix conventions:
/// `124` for timeout (matching `timeout(1)`), `137` for SIGKILL
/// (8+9), `142` for session-killed, `1` for everything else.
///
/// `session_id` (when present) is consulted on transport-level
/// errors: if the session record now reads `state = Killed`, the
/// transport drop is attributed to the kill and `dispatch` returns
/// the SessionKilled exit code (142) instead of propagating the raw
/// I/O error. This is host-side synthesis — the agent itself can't
/// emit `SessionKilled` because by the time the kill takes effect
/// it's already going down.
pub(in crate::commands) fn dispatch(
    vm_name: &str,
    stdin: Vec<u8>,
    timeout_secs: u64,
    session_id: Option<&mvm_core::session::SessionId>,
) -> Result<i32> {
    match dispatch_inner(vm_name, stdin, timeout_secs) {
        Ok(code) => Ok(code),
        Err(err) => {
            if let Some(id) = session_id
                && let Ok(Some(rec)) = mvm_core::session::read_session(id)
                && rec.state == mvm_core::session::SessionState::Killed
            {
                let event = mvm_guest::vsock::EntrypointEvent::Error {
                    kind: mvm_guest::vsock::RunEntrypointError::SessionKilled,
                    message: format!("session {id} killed externally"),
                };
                return Ok(exit_code_for(&event));
            }
            Err(err)
        }
    }
}

fn dispatch_inner(vm_name: &str, stdin: Vec<u8>, timeout_secs: u64) -> Result<i32> {
    let transport = mvm::vsock_transport::for_vm(vm_name)
        .with_context(|| format!("Picking transport for guest agent on '{vm_name}'"))?;
    let mut stream = transport
        .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("Connecting to guest agent on '{vm_name}'"))?;

    let terminal = mvm_guest::vsock::send_run_entrypoint(
        &mut stream,
        stdin,
        timeout_secs,
        // When the VM has a substitution endpoint (the admitted plan
        // carried secrets), inject HTTP_PROXY + the opaque placeholder vars so
        // the workload routes secret-bearing egress through the in-guest
        // forward proxy → host endpoint. Empty when there are no secrets.
        substitution_env(vm_name),
        |event| match event {
            mvm_guest::vsock::EntrypointEvent::Stdout { chunk } => {
                let _ = std::io::stdout().write_all(chunk);
            }
            mvm_guest::vsock::EntrypointEvent::Stderr { chunk } => {
                let _ = std::io::stderr().write_all(chunk);
            }
            mvm_guest::vsock::EntrypointEvent::Control {
                header_json,
                payload,
            } => {
                // Surface fd-3 control records to the operator with a
                // clearly-labelled prefix the user's stderr can't spoof
                // (these come from mvmctl, not the wrapper). A future
                // SDK-facing `--envelope-fd <n>` flag will write raw
                // frames out for structured consumption; until then this
                // human-readable form is the default.
                if payload.is_empty() {
                    let _ = writeln!(std::io::stderr(), "[mvmctl-control] {header_json}");
                } else {
                    let _ = writeln!(
                        std::io::stderr(),
                        "[mvmctl-control] {header_json} (+{} payload bytes)",
                        payload.len()
                    );
                }
            }
            // Terminal events (Exit / Error) are returned by
            // send_run_entrypoint; the handler is only invoked for
            // streaming chunks above.
            _ => {}
        },
    )
    .context("Streaming RunEntrypoint response")?;

    // Flush before potentially exiting.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    Ok(exit_code_for(&terminal))
}

/// The workload launch env that routes secret-bearing egress
/// through the substitution endpoint. Reads the `(guest var, placeholder)`
/// pairs the endpoint minted at boot (`vm_substitution_env_path`); when
/// present, prepends `HTTP(S)_PROXY` pointing at the in-guest forward proxy so
/// outbound requests carrying a placeholder are routed to the host for
/// substitution. Empty (no proxy, no vars) when the VM has no secrets — so a
/// plain workload is unaffected.
fn substitution_env(vm_name: &str) -> Vec<(String, String)> {
    let path = mvm_core::config::vm_substitution_env_path(vm_name);
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    let placeholders: Vec<(String, String)> = serde_json::from_slice(&bytes).unwrap_or_default();
    build_substitution_env(placeholders)
}

/// Pure half of [`substitution_env`]: given the endpoint's minted placeholder
/// vars, prepend `HTTP(S)_PROXY` (the in-guest forward proxy) so the workload
/// routes secret-bearing egress for substitution. Empty placeholders ⇒ empty
/// env (a plain workload is left untouched).
fn build_substitution_env(placeholders: Vec<(String, String)>) -> Vec<(String, String)> {
    if placeholders.is_empty() {
        return Vec::new();
    }
    let proxy = mvm_guest::forward_proxy::proxy_env_url();
    // Both upper- and lower-case forms — toolchains differ on which they read.
    let mut env = vec![
        ("HTTP_PROXY".to_string(), proxy.clone()),
        ("HTTPS_PROXY".to_string(), proxy.clone()),
        ("http_proxy".to_string(), proxy.clone()),
        ("https_proxy".to_string(), proxy),
    ];
    env.extend(placeholders);
    env
}

fn exit_code_for(event: &mvm_guest::vsock::EntrypointEvent) -> i32 {
    use mvm_guest::vsock::{EntrypointEvent, RunEntrypointError};
    match event {
        EntrypointEvent::Exit { code } => *code,
        EntrypointEvent::Error { kind, message } => {
            let (code, label) = match kind {
                RunEntrypointError::Timeout => (124, "timeout"),
                RunEntrypointError::Busy => (1, "busy"),
                RunEntrypointError::PayloadCap => (1, "payload cap exceeded"),
                RunEntrypointError::WrapperCrashed => (137, "wrapper crashed"),
                RunEntrypointError::EntrypointInvalid => (1, "entrypoint invalid"),
                // 142 = 128 + SIGALRM (14). The signal-style mapping
                // matches `WrapperCrashed`'s 137 = 128 + SIGKILL (9)
                // pattern; SIGALRM is repurposed here as a stable
                // "your session was reaped" signal SDKs can match on.
                RunEntrypointError::SessionKilled => (142, "session killed"),
                // Transient — entrypoint validation still in flight.
                // Exit 75 = `EX_TEMPFAIL` so wrapper
                // scripts can branch on "retry safe" vs. the terminal
                // failures above.
                RunEntrypointError::NotReady => (75, "agent not ready"),
                RunEntrypointError::InternalError => (1, "internal error"),
            };
            ui::warn(&format!("invoke: {label}: {message}"));
            code
        }
        // Non-terminal events shouldn't reach this function — the
        // streaming consumer only returns terminal events. Defensive:
        // treat as internal error.
        _ => {
            ui::warn("invoke: dispatcher returned non-terminal event");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_normal_exit_zero() {
        let evt = mvm_guest::vsock::EntrypointEvent::Exit { code: 0 };
        assert_eq!(exit_code_for(&evt), 0);
    }

    #[test]
    fn test_exit_code_normal_exit_preserves_nonzero() {
        let evt = mvm_guest::vsock::EntrypointEvent::Exit { code: 7 };
        assert_eq!(exit_code_for(&evt), 7);
    }

    #[test]
    fn test_exit_code_timeout_maps_to_124() {
        let evt = mvm_guest::vsock::EntrypointEvent::Error {
            kind: mvm_guest::vsock::RunEntrypointError::Timeout,
            message: "killed".into(),
        };
        assert_eq!(exit_code_for(&evt), 124);
    }

    #[test]
    fn test_exit_code_wrapper_crash_maps_to_137() {
        let evt = mvm_guest::vsock::EntrypointEvent::Error {
            kind: mvm_guest::vsock::RunEntrypointError::WrapperCrashed,
            message: "segfault".into(),
        };
        assert_eq!(exit_code_for(&evt), 137);
    }

    #[test]
    fn test_exit_code_session_killed_maps_to_142() {
        // 142 = 128 + SIGALRM (14) — stable signal-style exit code
        // SDKs match on to distinguish "session killed externally"
        // from "wrapper crashed" (137 = 128 + SIGKILL).
        let evt = mvm_guest::vsock::EntrypointEvent::Error {
            kind: mvm_guest::vsock::RunEntrypointError::SessionKilled,
            message: "killed".into(),
        };
        assert_eq!(exit_code_for(&evt), 142);
    }

    #[test]
    fn test_exit_code_busy_payload_invalid_internal_all_map_to_1() {
        use mvm_guest::vsock::RunEntrypointError as E;
        for kind in [
            E::Busy,
            E::PayloadCap,
            E::EntrypointInvalid,
            E::InternalError,
        ] {
            // SessionKilled is excluded — has its own dedicated exit code.
            let evt = mvm_guest::vsock::EntrypointEvent::Error {
                kind,
                message: "x".into(),
            };
            assert_eq!(exit_code_for(&evt), 1, "expected 1 for {kind:?}");
        }
    }

    #[test]
    fn test_read_stdin_none_is_the_no_arg_call() {
        // The wrapper wire contract requires `[args, kwargs]`; a bare invoke
        // sends the explicit no-argument call rather than an empty body.
        let bytes = read_stdin_payload(None).unwrap();
        assert_eq!(bytes, b"[[], {}]");
    }

    #[test]
    fn test_read_stdin_file_returns_contents() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello-stdin").unwrap();
        let bytes = read_stdin_payload(Some(tmp.path().to_str().unwrap())).unwrap();
        assert_eq!(bytes, b"hello-stdin");
    }

    #[test]
    fn test_read_stdin_missing_file_errors() {
        let err = read_stdin_payload(Some("/this/does/not/exist")).unwrap_err();
        assert!(err.to_string().contains("Reading stdin from"));
    }

    #[test]
    fn build_substitution_env_empty_when_no_placeholders() {
        assert!(super::build_substitution_env(Vec::new()).is_empty());
    }

    #[test]
    fn build_substitution_env_prepends_proxy_and_keeps_placeholders() {
        let env = super::build_substitution_env(vec![(
            "OPENAI_API_KEY".to_string(),
            "mvm-secret-abc123".to_string(),
        )]);
        let proxy = mvm_guest::forward_proxy::proxy_env_url();
        // HTTP(S)_PROXY (upper + lower) point at the in-guest forward proxy.
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "HTTP_PROXY")
                .map(|(_, v)| v.as_str()),
            Some(proxy.as_str())
        );
        assert!(env.iter().any(|(k, v)| k == "https_proxy" && *v == proxy));
        // The opaque placeholder var survives (never the value).
        assert!(
            env.iter()
                .any(|(k, v)| k == "OPENAI_API_KEY" && v == "mvm-secret-abc123")
        );
    }
}
