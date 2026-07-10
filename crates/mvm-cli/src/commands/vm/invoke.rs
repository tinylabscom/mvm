//! The baked-entrypoint call action — boot a microVM and dispatch its
//! `/etc/mvm/entrypoint` over vsock. Reached via `machine run --entrypoint`.
//!
//! Distinct from `mvmctl machine exec` (dev-only, arbitrary shell). This is
//! the production-safe call surface — it dispatches the `RunEntrypoint` vsock
//! verb, which the guest agent serves only by spawning the program named in
//! `/etc/mvm/entrypoint`. There is no shell and no argv override. Env injection
//! is limited to host-synthesized egress settings: either the substitution env
//! (`HTTP_PROXY` + opaque placeholders) for secret-bearing workloads, or the
//! loopback SOCKS5 vsock proxy env for plain vsock-egress workloads; never a
//! raw secret value.
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
    /// Bytes to pipe into the baked entrypoint's stdin. Empty ⇒ the default
    /// no-argument payload (`[[], {}]`). Populated from host stdin at the
    /// dispatch site when the host is not a TTY.
    pub stdin: Vec<u8>,
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
    /// Explicit ProdSafe agent-verb override to mint into the admitted grant
    /// for the transient entrypoint boot. Empty => use the computed default.
    pub agent_verb_override: Vec<String>,
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

struct EntrypointAdmission {
    context: super::up::AdmissionContext,
    substrate: crate::exec::SessionAuditSubstrate,
}

struct EntrypointAdmissionParams<'a> {
    rootfs: &'a std::path::Path,
    vm_name: &'a str,
    backend_name: &'a str,
    cpus: u32,
    mem_mib: u64,
    lowered_secrets: &'a super::managed_secrets::LoweredPlanSecrets,
    agent_verb_override: &'a [String],
    keep_alive_dev: bool,
}

impl<'a> EntrypointAdmissionParams<'a> {
    fn builder(
        rootfs: &'a std::path::Path,
        vm_name: &'a str,
        backend_name: &'a str,
    ) -> EntrypointAdmissionParamsBuilder<'a> {
        EntrypointAdmissionParamsBuilder {
            rootfs,
            vm_name,
            backend_name,
            cpus: 1,
            mem_mib: 256,
            lowered_secrets: None,
            agent_verb_override: &[],
            keep_alive_dev: false,
        }
    }
}

struct EntrypointAdmissionParamsBuilder<'a> {
    rootfs: &'a std::path::Path,
    vm_name: &'a str,
    backend_name: &'a str,
    cpus: u32,
    mem_mib: u64,
    lowered_secrets: Option<&'a super::managed_secrets::LoweredPlanSecrets>,
    agent_verb_override: &'a [String],
    keep_alive_dev: bool,
}

impl<'a> EntrypointAdmissionParamsBuilder<'a> {
    fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    fn mem_mib(mut self, mem_mib: u64) -> Self {
        self.mem_mib = mem_mib;
        self
    }

    fn lowered_secrets(
        mut self,
        lowered_secrets: &'a super::managed_secrets::LoweredPlanSecrets,
    ) -> Self {
        self.lowered_secrets = Some(lowered_secrets);
        self
    }

    fn agent_verb_override(mut self, agent_verb_override: &'a [String]) -> Self {
        self.agent_verb_override = agent_verb_override;
        self
    }

    fn keep_alive_dev(mut self, keep_alive_dev: bool) -> Self {
        self.keep_alive_dev = keep_alive_dev;
        self
    }

    fn build(self) -> EntrypointAdmissionParams<'a> {
        EntrypointAdmissionParams {
            rootfs: self.rootfs,
            vm_name: self.vm_name,
            backend_name: self.backend_name,
            cpus: self.cpus,
            mem_mib: self.mem_mib,
            lowered_secrets: self
                .lowered_secrets
                .expect("entrypoint admission params require lowered secrets"),
            agent_verb_override: self.agent_verb_override,
            keep_alive_dev: self.keep_alive_dev,
        }
    }
}

fn admit_entrypoint_boot(
    params: EntrypointAdmissionParams<'_>,
) -> Result<Option<EntrypointAdmission>> {
    let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::default();
    let ctx = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
        tenant: "local",
        vm_name: params.vm_name,
        backend_name: params.backend_name,
        rootfs_path: params.rootfs,
        precomputed_image_sha256: None,
        cpus: params.cpus,
        mem_mib: params.mem_mib,
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: params.lowered_secrets.secret_release,
        secrets: params.lowered_secrets.secrets.clone(),
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
        agent_verb_override: params.agent_verb_override.to_vec(),
        restrict_agent_verbs: !params.keep_alive_dev
            && super::agent_verbs::image_is_sealed(params.rootfs),
    })?;
    let Some(ctx) = ctx else { return Ok(None) };

    let mut start_config = mvm_core::vm_backend::VmStartConfig::default();
    let guest_profile = super::up::guest_profile_for_boot(params.keep_alive_dev, params.rootfs);
    super::up::attach_guest_boot_config_for_plan(
        &mut start_config,
        &ctx.admitted.plan,
        &ctx.host_signer_public_path,
        guest_profile,
    )?;
    if super::up::persists_plan_before_start(params.backend_name) {
        super::plan_persist::write_plan(params.vm_name, &ctx.admitted.plan)
            .context("persisting admitted plan for the pre-start egress moat")?;
    }
    let plan_json = serde_json::to_string(&ctx.admitted.signed)
        .context("serializing admitted plan for the session VM")?;
    let bundle_json = ctx
        .policy_bundle
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serializing admitted policy bundle for the session VM")?;
    Ok(Some(EntrypointAdmission {
        substrate: crate::exec::SessionAuditSubstrate {
            tenant_id: ctx.admitted.plan.tenant.0.clone(),
            plan_json,
            bundle_json,
            config_files: start_config.config_files,
        },
        context: ctx,
    }))
}

pub(in crate::commands) fn run_entrypoint(call: EntrypointCall) -> Result<()> {
    if call.attach {
        // Dispatch into an already-running workload by
        // name (booted by `machine run --name <NAME>`), reusing its substitution
        // endpoint + boot-minted placeholders. `dispatch` injects the workload's
        // substitution env (HTTP_PROXY + placeholders) via `substitution_env`,
        // so a secret-declaring entrypoint runs with live egress substitution.
        // No transient boot, no teardown — the VM is the user's to reap.
        let stdin_bytes = if call.stdin.is_empty() {
            b"[[], {}]".to_vec()
        } else {
            call.stdin
        };
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

    let stdin_bytes = if call.stdin.is_empty() {
        b"[[], {}]".to_vec()
    } else {
        call.stdin
    };

    let lifecycle_label = if call.keep_alive {
        "warm session"
    } else {
        "transient VM"
    };
    ui::info(&format!(
        "entrypoint: booting {lifecycle_label} for template '{template_id}'"
    ));
    let lowered_secrets = super::up::load_workload_ir(call.from_workload_ir.as_deref())?
        .map(|w| super::managed_secrets::lower_workload_secrets(&w))
        .filter(|lowered| !lowered.secrets.is_empty())
        .unwrap_or_default();
    let backend_name = mvm_backend::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    let admit_backend = backend_name.clone();
    let cpus = call.cpus;
    let mem = call.memory_mib as u64;
    let agent_verb_override = call.agent_verb_override.clone();
    let keep_alive_dev = call.keep_alive_dev;
    let admit_ctx: std::rc::Rc<std::cell::RefCell<Option<super::up::AdmissionContext>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let ctx_sink = std::rc::Rc::clone(&admit_ctx);
    let admit = move |rootfs: &std::path::Path,
                      vm_name: &str|
          -> Result<Option<crate::exec::SessionAuditSubstrate>> {
        let admitted = admit_entrypoint_boot(
            EntrypointAdmissionParams::builder(rootfs, vm_name, &admit_backend)
                .cpus(cpus)
                .mem_mib(mem)
                .lowered_secrets(&lowered_secrets)
                .agent_verb_override(&agent_verb_override)
                .keep_alive_dev(keep_alive_dev)
                .build(),
        )?;
        let Some(admitted) = admitted else {
            return Ok(None);
        };
        *ctx_sink.borrow_mut() = Some(admitted.context);
        Ok(Some(admitted.substrate))
    };

    let vm = match crate::exec::boot_session_vm(
        &template_id,
        "invoke",
        call.cpus,
        call.memory_mib,
        Some(&admit),
    ) {
        Ok(vm) => {
            let ctx = admit_ctx.borrow_mut().take();
            super::up::emit_launched_if(&ctx, &backend_name);
            if let Some(ctx) = ctx {
                *admit_ctx.borrow_mut() = Some(ctx);
            }
            vm
        }
        Err(e) => {
            let ctx = admit_ctx.borrow_mut().take();
            super::up::emit_failed_if(&ctx, "backend-start", &e);
            return Err(e).context("Booting VM for the entrypoint call");
        }
    };

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

/// Host-side cap on a buffered stdin payload. Mirrors the guest runner's v1
/// inbound cap; over-cap fails closed rather than silently truncating.
const MAX_STDIN_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub(in crate::commands) enum AutoStdinError {
    TooLarge { cap: usize },
    Io(std::io::Error),
}

impl std::fmt::Display for AutoStdinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { cap } => {
                write!(f, "stdin payload exceeds the {cap}-byte limit")
            }
            Self::Io(e) => write!(f, "reading stdin: {e}"),
        }
    }
}
impl std::error::Error for AutoStdinError {}

/// Read one buffered stdin payload, capped. A TTY on stdin is interactive input
/// for the terminal, not a workload payload, so it yields empty and never blocks.
fn read_auto_stdin_from<R: std::io::Read>(
    mut reader: R,
    is_tty: bool,
    cap: usize,
) -> Result<Vec<u8>, AutoStdinError> {
    if is_tty {
        return Ok(Vec::new());
    }
    // Read cap+1 so an exactly-cap payload passes and the first over-cap byte trips.
    let mut buf = Vec::new();
    reader
        .by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(AutoStdinError::Io)?;
    if buf.len() > cap {
        return Err(AutoStdinError::TooLarge { cap });
    }
    Ok(buf)
}

/// Public entry: acquire the caller's stdin payload from the real stdin fd.
pub(in crate::commands) fn read_auto_stdin(is_tty: bool) -> anyhow::Result<Vec<u8>> {
    read_auto_stdin_from(std::io::stdin().lock(), is_tty, MAX_STDIN_BYTES)
        .map_err(|e| anyhow::anyhow!(e))
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
        // Secret-bearing workloads route through the in-guest forward proxy;
        // plain vsock-egress workloads route through the loopback SOCKS5 client.
        workload_egress_env(vm_name),
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

/// The workload launch env that routes egress through the active vsock path.
/// Secret-bearing workloads use the substitution endpoint env; plain workloads
/// use the guest-local SOCKS5 client when the VM booted with vsock egress
/// enabled. Empty when the VM has neither.
fn workload_egress_env(vm_name: &str) -> Vec<(String, String)> {
    let subst = substitution_env(vm_name);
    if !subst.is_empty() {
        return subst;
    }
    vsock_egress_env(vm_name)
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
    let placeholders: Vec<(String, String)> = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    with_egress_ca_env(
        build_substitution_env(placeholders),
        egress_ca_present(vm_name),
    )
}

fn vsock_egress_env(vm_name: &str) -> Vec<(String, String)> {
    if !mvm_core::config::vm_vsock_egress_marker_path(vm_name).is_file() {
        return Vec::new();
    }
    mvm_core::guest_netd::proxy_env_vars("127.0.0.1:1080")
}

/// Whether the per-VM egress CA sidecar exists — i.e. egress substitution
/// provisioned a CA whose PEM the launcher put on the guest kernel cmdline
/// (`mvm.egress_ca=`) and the guest `/init` decoded to `/run/mvm/ca-bundle.crt`.
fn egress_ca_present(vm_name: &str) -> bool {
    mvm_core::config::vm_state_dir(vm_name)
        .join("egress-intermediate.json")
        .exists()
}

/// Point the workload's TLS stack at the guest-side egress CA bundle when one
/// is provisioned. An OCI entrypoint runs under `env_clear()` + the request
/// env, so — unlike a flake `/init` child that inherits the shell exports —
/// these must ride the agent request env. Mirrors the mkGuest egress-ca
/// exports (`SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE` →
/// combined bundle, `NODE_EXTRA_CA_CERTS` → the egress cert alone). No CA
/// provisioned ⇒ env unchanged.
fn with_egress_ca_env(
    env: Vec<(String, String)>,
    egress_ca_present: bool,
) -> Vec<(String, String)> {
    if !egress_ca_present {
        return env;
    }
    let mut ca = vec![
        (
            "SSL_CERT_FILE".to_string(),
            "/run/mvm/ca-bundle.crt".to_string(),
        ),
        (
            "CURL_CA_BUNDLE".to_string(),
            "/run/mvm/ca-bundle.crt".to_string(),
        ),
        (
            "REQUESTS_CA_BUNDLE".to_string(),
            "/run/mvm/ca-bundle.crt".to_string(),
        ),
        (
            "NODE_EXTRA_CA_CERTS".to_string(),
            "/run/mvm/egress-ca.crt".to_string(),
        ),
    ];
    ca.extend(env);
    ca
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
mod auto_stdin_tests {
    use super::{AutoStdinError, read_auto_stdin_from};
    use std::io::Cursor;

    #[test]
    fn tty_stdin_yields_empty_payload() {
        // A terminal on stdin is interactive, not input: never block reading it.
        let got = read_auto_stdin_from(Cursor::new(b"ignored" as &[u8]), true, 1024).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn piped_stdin_under_cap_is_read_whole() {
        let got = read_auto_stdin_from(Cursor::new(b"STDIN-RT-42" as &[u8]), false, 1024).unwrap();
        assert_eq!(got, b"STDIN-RT-42");
    }

    #[test]
    fn piped_stdin_over_cap_fails_closed() {
        let payload = vec![b'x'; 2048];
        let err = read_auto_stdin_from(Cursor::new(&payload[..]), false, 1024).unwrap_err();
        assert!(matches!(err, AutoStdinError::TooLarge { cap: 1024 }));
    }

    #[test]
    fn piped_stdin_exactly_at_cap_passes() {
        let payload = vec![b'x'; 1024];
        let got = read_auto_stdin_from(Cursor::new(&payload[..]), false, 1024).unwrap();
        assert_eq!(got.len(), 1024);
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::vm::host_signer;
    use crate::commands::vm::managed_secrets::LoweredPlanSecrets;
    use mvm_core::util::test_env::TestEnv;

    use super::*;

    #[test]
    fn admit_entrypoint_boot_admits_sealed_images_even_without_secrets() {
        use mvm_build::builder_vm::GuestSidecar;

        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_DATA_DIR", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        let mut sidecar = GuestSidecar::for_oci_run("audit-probe");
        sidecar.accessible = false;
        sidecar.sealed = true;
        sidecar.write_to_dir(dir.path()).expect("write sidecar");

        let lowered_secrets = LoweredPlanSecrets::default();
        let admitted = admit_entrypoint_boot(
            EntrypointAdmissionParams::builder(&rootfs, "invoke-proof-sealed", "firecracker")
                .cpus(1)
                .mem_mib(256)
                .lowered_secrets(&lowered_secrets)
                .agent_verb_override(&["run-entrypoint".into(), "ping".into()])
                .keep_alive_dev(false)
                .build(),
        )
        .expect("admit entrypoint boot")
        .expect("sealed entrypoint boot admitted");

        let verbs = admitted
            .context
            .admitted
            .plan
            .agent_verbs
            .as_ref()
            .expect("sealed entrypoint plan should carry agent verbs");
        assert!(verbs.iter().any(|v| v.as_str() == "run-entrypoint"));
        assert!(verbs.iter().any(|v| v.as_str() == "ping"));
        assert!(
            admitted
                .substrate
                .config_files
                .iter()
                .any(|f| f.name == host_signer::PUBLIC_FILENAME),
            "host signer pubkey must be attached when verb grants are present"
        );
        let policy_file = admitted
            .substrate
            .config_files
            .iter()
            .find(|f| f.name == crate::commands::vm::up::SECURITY_POLICY_FILENAME)
            .expect("security policy must be attached");
        let policy: mvm_core::security::SecurityPolicy =
            serde_json::from_str(&policy_file.content).expect("parse security policy");
        assert_eq!(policy.profile, mvm_core::security::AgentProfile::SealedProd);
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

    #[test]
    fn vsock_egress_env_empty_without_marker() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_DATA_DIR", dir.path());
        assert!(super::vsock_egress_env("plain-vm").is_empty());
    }

    #[test]
    fn vsock_egress_env_emits_http_proxy_vars_when_marker_present() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_DATA_DIR", dir.path());
        let marker = mvm_core::config::vm_vsock_egress_marker_path("plain-vm");
        std::fs::create_dir_all(marker.parent().expect("marker parent"))
            .expect("mkdir marker parent");
        std::fs::write(&marker, b"1").expect("write marker");

        let env = super::vsock_egress_env("plain-vm");
        assert!(
            env.iter()
                .any(|(k, v)| k == "ALL_PROXY" && v == "http://127.0.0.1:1080")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "HTTP_PROXY" && v == "http://127.0.0.1:1080")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "NO_PROXY" && v.contains("127.0.0.1"))
        );
    }

    #[test]
    fn workload_egress_env_prefers_substitution_env_over_plain_vsock_env() {
        let mut env_guard = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env_guard.set("MVM_DATA_DIR", dir.path());

        let marker = mvm_core::config::vm_vsock_egress_marker_path("pref-vm");
        std::fs::create_dir_all(marker.parent().expect("marker parent"))
            .expect("mkdir marker parent");
        std::fs::write(&marker, b"1").expect("write marker");
        let subst = mvm_core::config::vm_substitution_env_path("pref-vm");
        std::fs::create_dir_all(subst.parent().expect("subst parent")).expect("mkdir subst parent");
        std::fs::write(
            &subst,
            serde_json::to_vec(&vec![("OPENAI_API_KEY", "mvm-secret-1")]).expect("json"),
        )
        .expect("write substitution env");

        let env = super::workload_egress_env("pref-vm");
        assert!(env.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(
            env.iter()
                .all(|(_, v)| !v.starts_with("http://127.0.0.1:1080"))
        );
    }

    #[test]
    fn with_egress_ca_env_noop_when_absent() {
        let base = vec![("HTTP_PROXY".to_string(), "http://x".to_string())];
        assert_eq!(super::with_egress_ca_env(base.clone(), false), base);
    }

    #[test]
    fn with_egress_ca_env_prepends_ca_vars_before_existing() {
        let env = super::with_egress_ca_env(
            vec![("OPENAI_API_KEY".to_string(), "mvm-secret".to_string())],
            true,
        );
        // The TLS-trust vars point the workload at the guest-side bundle the
        // /init decode wrote (the OCI entrypoint's env_clear means a shell
        // export would not reach it).
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "SSL_CERT_FILE")
                .map(|(_, v)| v.as_str()),
            Some("/run/mvm/ca-bundle.crt")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "CURL_CA_BUNDLE" && v == "/run/mvm/ca-bundle.crt")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "REQUESTS_CA_BUNDLE" && v == "/run/mvm/ca-bundle.crt")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "NODE_EXTRA_CA_CERTS" && v == "/run/mvm/egress-ca.crt")
        );
        // Existing substitution vars are preserved after the CA prefix.
        assert!(
            env.iter()
                .any(|(k, v)| k == "OPENAI_API_KEY" && v == "mvm-secret")
        );
        let ca_at = env.iter().position(|(k, _)| k == "SSL_CERT_FILE").unwrap();
        let key_at = env.iter().position(|(k, _)| k == "OPENAI_API_KEY").unwrap();
        assert!(ca_at < key_at, "CA vars must precede the placeholder vars");
    }
}
