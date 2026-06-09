//! `mvmctl invoke` — boot a microVM and call its baked entrypoint.
//!
//! ADR-007 / plan 41 W3.
//!
//! Distinct from `mvmctl exec` (dev-only, arbitrary shell). `invoke`
//! is the production-safe call surface — it dispatches the
//! `RunEntrypoint` vsock verb, which the guest agent serves only by
//! spawning the program named in `/etc/mvm/entrypoint`. There is no
//! shell and no argv override. The only env injected is the Plan 129
//! substitution env — `HTTP_PROXY` + the opaque secret placeholders —
//! and only when the VM's admitted plan carried secrets; never a raw
//! secret value (those stay in the host substitution endpoint).
//!
//! v1 behaviour:
//!   - boots a transient microVM from a registered template,
//!   - waits for the guest agent,
//!   - reads stdin from a file (`-` = mvmctl's own stdin, default empty),
//!   - sends `GuestRequest::RunEntrypoint`,
//!   - streams `EntrypointEvent::Stdout` / `Stderr` events back to
//!     mvmctl's own stdout / stderr as they arrive,
//!   - tears the VM down,
//!   - exits with the wrapper's exit code (or non-zero on error).
//!
//! `--fresh` and `--reset` are accepted but informational in v1 — the
//! current behaviour matches `--fresh` (no warm session reuse). When
//! the session-pool plan lands, the default flips to "reuse warm VM"
//! and `--fresh` becomes the opt-out for callers who need a clean
//! VM per call.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Template (or pre-built manifest) to boot. Resolves the same way
    /// as `mvmctl exec --manifest <ARG>` (registered name, manifest
    /// path, or manifest directory). Required for v1; warm-session
    /// reuse and arbitrary VM-name targeting come with the
    /// session-pool plan.
    #[arg(value_name = "MANIFEST")]
    pub manifest: String,

    /// Path to stdin payload, or `-` for mvmctl's own stdin. Default:
    /// no stdin (the wrapper sees an empty pipe).
    #[arg(long, value_name = "PATH")]
    pub stdin: Option<String>,

    /// Wall-clock timeout for the call, in seconds. Default 30.
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// vCPU count for the booted VM. Default 2.
    #[arg(long, default_value = "2")]
    pub cpus: u32,

    /// Memory for the booted VM (MiB). Default 512.
    #[arg(long, default_value = "512")]
    pub memory_mib: u32,

    /// Boot a fresh transient VM, run the call, tear down (the v1
    /// default — wired explicitly so future versions can flip the
    /// default to warm-session reuse without breaking scripts).
    #[arg(long, conflicts_with = "reset")]
    pub fresh: bool,

    /// Restore the session VM from its post-boot snapshot before the
    /// next call. Wired but no-op in v1; lands with the session-pool
    /// plan.
    #[arg(long)]
    pub reset: bool,

    /// Keep the substrate VM alive after the call finishes, leaving
    /// a persistent session that subsequent `mvmctl session attach
    /// <id>` calls can dispatch into. The session id is printed on
    /// stderr (`Session kept alive: <id>`) for easy capture. Without
    /// this flag, the VM is torn down immediately after the call —
    /// the default behaviour. Phase 5c.
    #[arg(long)]
    pub keep_alive: bool,

    /// Mark the kept-alive session as `mode=dev` so subsequent
    /// `mvmctl session exec` / `run-code` calls are allowed. Has no
    /// effect without `--keep-alive`. Refused on prod-only
    /// substrates by the wrapper itself if dev capabilities aren't
    /// compiled in.
    #[arg(long, requires = "keep_alive")]
    pub keep_alive_dev: bool,

    /// Attach this call to an existing warm session id. The Python /
    /// TypeScript SDKs pass this when a user wraps `f.remote(...)` in
    /// an `mv.session(...)` context manager, so multiple back-to-back
    /// calls reuse the same warm VM. **Plan 60 Phase 5 Slice E1: the
    /// flag is accepted so the SDK's argv doesn't get rejected at
    /// parse time, but routing into an existing session is wired by
    /// the session-pool plan (Phase 5c).** A non-empty value prints a
    /// warning and the call falls back to the transient-VM path.
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,

    /// Dispatch into a specific function within a multi-function app
    /// (ADR-0014 Phase 2). Single-function apps ignore the selector
    /// because their primary entrypoint is the only one. **Plan 60
    /// Phase 5 Slice E1: the flag is accepted so the SDK's argv
    /// (`--fn <name>` from `WorkloadRef.attr(...)`) doesn't get
    /// rejected; actual routing lands when ADR-0014 Phase 2 wires
    /// per-function dispatch on the agent side.**
    #[arg(long, value_name = "NAME")]
    pub r#fn: Option<String>,

    /// Dispatch into an **already-running** workload (e.g. one booted by
    /// `mvmctl up --name <NAME>`) instead of booting a transient VM. The
    /// positional `MANIFEST` is reinterpreted as the running VM's name. The
    /// workload's substitution endpoint + its boot-minted placeholders
    /// (Plan 129 / ADR-067) are reused, so a secret-declaring `up` workload's
    /// entrypoint runs with live egress substitution. The VM is left running
    /// (no teardown) — reap it with `mvmctl down <NAME>`.
    #[arg(long, conflicts_with_all = ["keep_alive", "fresh", "reset", "no_vm"])]
    pub attach: bool,

    /// **Dev shortcut** — bypass VM boot and run the workload's
    /// wrapper directly on the host. Exercises the full wire contract
    /// (encode → wrapper → user function → encode → decode) without
    /// any Nix or virtualization. Plan 60 Phase 5 Slice E1b. The
    /// `--language` / `--module` / `--function` / `--format` /
    /// `--source-path` flags below carry the per-call info the SDK
    /// would normally bake into `/etc/mvm/wrapper.json` at image
    /// build time; the positional manifest argument is accepted but
    /// ignored.
    ///
    /// **Not for production.** None of the in-VM hardening
    /// (seccomp tier, namespace isolation, RLIMIT_CORE) applies. Use
    /// for SDK iteration, CI smoke, and dev loops on machines
    /// without Linux/KVM/Lima.
    #[arg(long)]
    pub no_vm: bool,

    /// Wrapper language for `--no-vm`. Maps directly to the IR
    /// `Entrypoint::Function.language` field. Required when
    /// `--no-vm` is set; ignored otherwise.
    #[arg(long, value_name = "LANG", requires = "no_vm")]
    pub language: Option<String>,

    /// Module identifier for `--no-vm`. For Python: dotted path
    /// (`pkg.mod`). For Node: module path (`./src/mod.mjs`).
    /// Required when `--no-vm` is set.
    #[arg(long, value_name = "MODULE", requires = "no_vm")]
    pub module: Option<String>,

    /// Function identifier within the module for `--no-vm`.
    /// Required when `--no-vm` is set.
    #[arg(long, value_name = "FUNCTION", requires = "no_vm")]
    pub function: Option<String>,

    /// Wire-format for stdin args + stdout return under `--no-vm`.
    /// One of `json` or `msgpack`. Default `json`.
    #[arg(long, value_name = "FMT", default_value = "json", requires = "no_vm")]
    pub format: String,

    /// Absolute path to the user's source tree for `--no-vm`. The
    /// wrapper imports `<module>` relative to this path. Required
    /// when `--no-vm` is set.
    #[arg(long, value_name = "PATH", requires = "no_vm")]
    pub source_path: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if args.no_vm {
        // Dev shortcut — bypass VM boot and run the wrapper directly
        // on the host. Plan 60 Phase 5 Slice E1b. See
        // `invoke_no_vm.rs` for the full contract. `eprintln!`
        // instead of `ui::warn` because the latter writes to stdout
        // (a pre-existing inconsistency vs `ui::error`); stdout under
        // --no-vm is reserved for the wrapper's encoded return value
        // that the SDK decodes.
        eprintln!(
            "[mvm] --no-vm: bypassing VM boot, running wrapper on the host. \
             Not for production. None of the in-VM hardening applies."
        );
        let stdin_bytes = read_stdin_payload(args.stdin.as_deref())?;
        let exit_code = super::invoke_no_vm::run(&args, stdin_bytes)?;
        std::process::exit(exit_code);
    }
    if args.attach {
        // Plan 129 / ADR-067: dispatch into an already-running workload by
        // name (booted by `mvmctl up --name <NAME>`), reusing its substitution
        // endpoint + boot-minted placeholders. `dispatch` injects the workload's
        // substitution env (HTTP_PROXY + placeholders) via `substitution_env`,
        // so a secret-declaring entrypoint runs with live egress substitution.
        // No transient boot, no teardown — the VM is the user's to reap.
        let stdin_bytes = read_stdin_payload(args.stdin.as_deref())?;
        ui::info(&format!(
            "invoke: dispatching into running workload '{}'",
            args.manifest
        ));
        let exit_code = dispatch(&args.manifest, stdin_bytes, args.timeout, None)?;
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }
    if args.reset {
        ui::warn(
            "--reset is wired but no-op in this build (session-pool plan); \
             treating as default behaviour",
        );
    }
    if let Some(id) = &args.session {
        ui::warn(&format!(
            "--session {id} is accepted but no-op in this build \
             (session-pool plan, plan 60 Phase 5c); falling back to a \
             transient VM for this call"
        ));
    }
    if let Some(name) = &args.r#fn {
        ui::warn(&format!(
            "--fn {name} is accepted but no-op in this build \
             (multi-function dispatch lands with ADR-0014 Phase 2); \
             the workload's primary entrypoint will be dispatched"
        ));
    }

    // v1: invoke targets a *template*. Resolve through the same shared
    // helper as `mvmctl exec --manifest`. Slot-hash and registered-name
    // both resolve to a string the lifecycle helpers consume.
    let template_id = match super::shared::resolve_manifest_arg(&args.manifest)? {
        super::shared::ManifestArgRef::Name(n) => n,
        super::shared::ManifestArgRef::Slot { slot_hash } => slot_hash,
    };

    let stdin_bytes = read_stdin_payload(args.stdin.as_deref())?;

    let lifecycle_label = if args.keep_alive {
        "warm session"
    } else {
        "transient VM"
    };
    ui::info(&format!(
        "invoke: booting {lifecycle_label} for template '{template_id}'"
    ));
    let vm = crate::exec::boot_session_vm(&template_id, "invoke", args.cpus, args.memory_mib)
        .context("Booting VM for invoke")?;

    // Phase 3 + 5c: register a session record so `mvmctl session ls`
    // sees the call (whether transient or warm). With `--keep-alive`
    // the record outlives the dispatch and `--keep-alive-dev` flips
    // its `mode` so subsequent `session exec` / `run-code` are
    // permitted. Errors registering are logged but don't block the
    // call.
    let mode = if args.keep_alive_dev {
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
    let dispatch_result = dispatch(&vm.vm_name, stdin_bytes, args.timeout, session_id.as_ref());

    // Tear down lifecycle:
    //   - default: kill the VM and drop the session record (matches
    //     `mvmctl exec` semantics, no leaked transient resources).
    //   - `--keep-alive`: leave the VM running and bump the session
    //     record's invoke counter; the user reuses via `mvmctl session
    //     attach` and reaps via `mvmctl session kill` when done.
    if args.keep_alive {
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
/// - `None`: empty payload.
/// - `Some("-")`: read everything from mvmctl's own stdin.
/// - `Some(path)`: read the file at `path`.
pub(in crate::commands) fn read_stdin_payload(spec: Option<&str>) -> Result<Vec<u8>> {
    match spec {
        None => Ok(Vec::new()),
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
        // Plan 129: when the VM has a substitution endpoint (the admitted plan
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
                // Phase 4a skeleton: surface fd-3 control records to
                // the operator with a clearly-labelled prefix the
                // user's stderr can't spoof (these come from mvmctl,
                // not the wrapper). A future slice (4d) adds an
                // SDK-facing `--envelope-fd <n>` flag that writes
                // raw frames out for structured consumption; until
                // then this human-readable form is the default.
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

/// Plan 129 — the workload launch env that routes secret-bearing egress
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
                // Plan 76 Phase 2: transient — entrypoint validation
                // still in flight. Exit 75 = `EX_TEMPFAIL` so wrapper
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
    fn attach_flag_parses_and_conflicts_with_boot_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrap {
            #[command(flatten)]
            args: Args,
        }
        // `invoke <name> --attach` parses and sets the flag.
        let w = Wrap::try_parse_from(["x", "myvm", "--attach"]).unwrap();
        assert!(w.args.attach);
        assert_eq!(w.args.manifest, "myvm");
        // --attach is incompatible with the transient-boot flags (it dispatches
        // into an already-running workload, never boots a VM).
        for flag in ["--keep-alive", "--fresh", "--reset", "--no-vm"] {
            assert!(
                Wrap::try_parse_from(["x", "myvm", "--attach", flag]).is_err(),
                "--attach must conflict with {flag}"
            );
        }
    }

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
    fn test_read_stdin_none_is_empty() {
        let bytes = read_stdin_payload(None).unwrap();
        assert!(bytes.is_empty());
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
