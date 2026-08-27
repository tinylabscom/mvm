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
//!   - streams `EntrypointEvent::Stdout` / `Stderr` events back to mvmctl's
//!     own stdout / stderr as they arrive, byte for byte, while handing the
//!     same frames to the VM's output capture — which redacts, chains, and
//!     persists a copy of its own. The caller gets the workload's bytes;
//!     `mvmctl machine logs` gets the masked ones; any divergence between the two is
//!     named on stderr rather than left for the caller to discover,
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
    /// What reaches the baked entrypoint's stdin, and when.
    pub stdin: EntrypointStdin,
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
    /// Resolved egress policy for the transient entrypoint boot (from `--net` /
    /// `--allow-host`). Threaded onto the admitted plan and shared vsock
    /// endpoint so a baked entrypoint enforces egress identically to the
    /// transient argv path. Defaults to `deny_all`.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Explicit hypervisor/backend selector passed through from `--hypervisor`.
    /// When `None` the platform-default auto-selection is used.
    pub hypervisor: Option<String>,
}

/// How a call's stdin is supplied.
///
/// The two are not variations on a theme; they are different contracts with
/// the guest. A one-shot payload is complete before the call starts, so the
/// guest writes it and closes the pipe — a workload reading to EOF sees one.
/// A streamed stdin has no such moment, so the guest keeps the pipe open and
/// EOF becomes something the host must send, which is why it needs a signed
/// grant, a lease, and a scan, and a one-shot payload needs none of them.
pub(in crate::commands) enum EntrypointStdin {
    /// Every byte, known before the call. Empty ⇒ the default no-argument
    /// payload (`[[], {}]`), because the wrapper's wire contract needs a JSON
    /// `[args, kwargs]` body and an empty one is a decode error in the guest.
    OneShot(Vec<u8>),
    /// mvmctl's own stdin, carried into the workload while it runs, with the
    /// caller's EOF closing the workload's stdin.
    ///
    /// Requested explicitly (`--stdin -` on the entrypoint action), never
    /// inferred: it is what puts the input grant on the signed plan, and a
    /// plan that carries the grant is one the sealed-production shell refusal
    /// applies to. Inferring it from a piped stdin would move every existing
    /// piped call onto that path without anybody asking.
    Streaming,
}

impl EntrypointStdin {
    /// Whether this call asks for a host→guest stdin stream — the one thing
    /// that puts `host.stream.v1` on the plan.
    fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming)
    }

    /// The payload the `RunEntrypoint` frame carries.
    ///
    /// A streaming call carries none: its bytes arrive as frames afterwards,
    /// and substituting the no-argument body here would put `[[], {}]` in
    /// front of whatever the caller actually piped.
    fn prologue(self) -> Vec<u8> {
        match self {
            Self::OneShot(bytes) if bytes.is_empty() => b"[[], {}]".to_vec(),
            Self::OneShot(bytes) => bytes,
            Self::Streaming => Vec::new(),
        }
    }
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
    network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Whether this call asked for a host→guest stdin stream. The only thing
    /// that puts the input-plane grant on the signed plan.
    stream_stdin: bool,
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stream_stdin: false,
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
    network_policy: mvm_core::network_policy::NetworkPolicy,
    stream_stdin: bool,
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

    fn network_policy(mut self, network_policy: mvm_core::network_policy::NetworkPolicy) -> Self {
        self.network_policy = network_policy;
        self
    }

    fn stream_stdin(mut self, stream_stdin: bool) -> Self {
        self.stream_stdin = stream_stdin;
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
            network_policy: self.network_policy,
            stream_stdin: self.stream_stdin,
        }
    }
}

/// The signed-plan token that says this workload's stdin may be driven from
/// the host. One spelling, parsed from the protocol constant, so a typo here
/// could not quietly mint a grant the gate does not recognise.
fn input_grant_service() -> mvm_contract::protocol::broker::ServiceId {
    mvm_contract::protocol::broker::ServiceId::parse(
        mvm_contract::stream::input::INPUT_GRANT_SERVICE,
    )
    .expect("the input-plane grant token is a valid service id")
}

fn admit_entrypoint_boot(
    params: EntrypointAdmissionParams<'_>,
) -> Result<Option<EntrypointAdmission>> {
    let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::default();
    let ctx = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
        network_mode: crate::commands::machine::preflight_network(),
        tenant: "local",
        vm_name: params.vm_name,
        backend_name: params.backend_name,
        rootfs_path: params.rootfs,
        precomputed_image_sha256: None,
        boot_artifact_identity: None,
        cpus: params.cpus,
        mem_mib: params.mem_mib,
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: params.lowered_secrets.secret_release,
        secrets: params.lowered_secrets.secrets.clone(),
        no_supervisor: false,
        ledger: &ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin: None,
        deps_volume: None,
        shares: vec![],
        redaction: mvm_core::policy::RedactionPolicy::default(),
        network_policy: params.network_policy.clone(),
        agent_verb_override: params.agent_verb_override.to_vec(),
        // An invoke drives the baked entrypoint over agent RPC: no PTY, no
        // ad-hoc argv, so the profile alone decides.
        restrict_agent_verbs: super::agent_verbs::grant_eligible(
            false,
            false,
            params.keep_alive_dev,
        ),
        // Default-deny, and conditional on the caller having asked. A plan
        // carrying this token is a plan whose workload's stdin can be driven
        // from the host; a plan without it leaves that stdin unreachable from
        // outside the guest no matter what the host-side gate would decide.
        services: if params.stream_stdin {
            vec![input_grant_service()]
        } else {
            Vec::new()
        },
        // Resolved from the image beside the rootfs rather than assumed, and
        // resolved on every boot rather than only when the grant is asked for,
        // so the path that feeds the refusal is the ordinary path.
        entrypoint: super::entrypoint_resolve::resolve_for_rootfs(params.rootfs),
        // The entrypoint dispatch path admits a template's own launch and
        // authors no grant of its own; the transient and persistent machine
        // paths are where a user names one.
        grants: None,
        backend_kind: None,
    })?;
    let Some(ctx) = ctx else { return Ok(None) };

    let mut start_config = mvm_core::vm_backend::VmStartConfig::default();
    let guest_profile = super::up::guest_profile_for_boot(params.keep_alive_dev, params.rootfs);
    super::up::attach_guest_boot_config_for_plan(
        &mut start_config,
        ctx.admitted.plan(),
        &ctx.host_signer_public_path,
        guest_profile,
    )?;
    if super::up::persists_plan_before_start(params.backend_name) {
        super::plan_persist::write_plan(params.vm_name, ctx.admitted.plan())
            .context("persisting admitted plan for the pre-start egress moat")?;
    }
    let plan_json = serde_json::to_string(ctx.admitted.signed())
        .context("serializing admitted plan for the session VM")?;
    let bundle_json = ctx
        .policy_bundle
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serializing admitted policy bundle for the session VM")?;
    Ok(Some(EntrypointAdmission {
        substrate: crate::exec::SessionAuditSubstrate {
            tenant_id: ctx.admitted.plan().tenant.0.clone(),
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
        if call.stdin.is_streaming() {
            // The grant lives on the plan the *boot* was admitted under, and
            // that admission happened in whatever process ran `machine run
            // --name`. This one holds no admitted plan for the VM, so there is
            // nothing here that could authorize a write — and a message saying
            // so beats a refusal from three layers down.
            anyhow::bail!(
                "streamed stdin needs the run that boots the workload: the input grant \
                 rides on the plan admitted at boot, and `--attach` dispatches into a \
                 machine another invocation admitted — drop `--attach`, or pipe a \
                 complete payload with `--stdin <PATH>`"
            );
        }
        ui::info(&format!(
            "entrypoint: dispatching into running workload '{}'",
            call.source
        ));
        let exit_code = dispatch(EntrypointDispatch {
            vm_name: &call.source,
            stdin: DispatchStdin::OneShot(call.stdin.prologue()),
            timeout_secs: call.timeout,
            session_id: None,
        })?;
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

    // The entrypoint action targets a manifest slot. Resolve through the same
    // shared helper as `machine exec --manifest`; the slot hash is the string
    // the lifecycle helpers consume.
    let template_id = match super::shared::resolve_manifest_arg(&call.source)? {
        super::shared::ManifestArgRef::Slot { slot_hash } => slot_hash,
        super::shared::ManifestArgRef::WasmModule { .. } => {
            anyhow::bail!("wasm module manifests are not supported for this command")
        }
    };

    let stream_stdin = call.stdin.is_streaming();
    let stdin_prologue = call.stdin.prologue();

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
    let backend_name = if let Some(name) = call.hypervisor.as_deref() {
        mvm_runtime::backend::AnyBackend::require_hypervisor_selectable(name)?;
        mvm_runtime::backend::AnyBackend::from_hypervisor(name)
    } else {
        mvm_runtime::backend::AnyBackend::auto_select()
    }
    .name()
    .to_string();
    let admit_backend = backend_name.clone();
    let cpus = call.cpus;
    let mem = call.memory_mib as u64;
    let agent_verb_override = call.agent_verb_override.clone();
    let keep_alive_dev = call.keep_alive_dev;
    let network_policy = call.network_policy.clone();
    let admit_network_policy = network_policy.clone();
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
                .network_policy(admit_network_policy.clone())
                .stream_stdin(stream_stdin)
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
        &network_policy,
        Some(&admit),
        Some(&backend_name),
    ) {
        Ok(vm) => {
            let ctx = admit_ctx.borrow_mut().take();
            super::up::emit_launched_if(&ctx, &backend_name, true);
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
    //
    // The admitted plan is borrowed across the dispatch because a streamed
    // stdin is opened under it: the gate takes the proof-carrying type, not a
    // copy of the token, so the authority for every byte written here is the
    // plan this very boot was admitted under.
    let admitted = admit_ctx.borrow();
    let dispatch_stdin = match authorize_stdin(stream_stdin, admitted.as_ref(), stdin_prologue) {
        Ok(stdin) => stdin,
        Err(refusal) => {
            crate::exec::tear_down_session_vm(crate::exec::SessionVm {
                vm_name: vm.vm_name.clone(),
            });
            deregister_invoke_session(session_id.as_ref());
            return Err(refusal);
        }
    };
    let dispatch_result = dispatch(EntrypointDispatch {
        vm_name: &vm.vm_name,
        stdin: dispatch_stdin,
        timeout_secs: call.timeout,
        session_id: session_id.as_ref(),
    });
    drop(admitted);

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

/// Decide what this call's stdin may be, now that the boot's admission is
/// known.
///
/// A streamed stdin is the only shape that needs anything from the boot: the
/// grant on the admitted plan is what authorizes a write, so a boot that
/// produced no plan — `--no-supervisor` short-circuits admission — has nothing
/// to write under. Refusing here beats streaming into a workload nothing
/// authorized. A one-shot payload asks for no authority and is unaffected.
fn authorize_stdin<'a>(
    stream_stdin: bool,
    admitted: Option<&'a super::up::AdmissionContext>,
    prologue: Vec<u8>,
) -> Result<DispatchStdin<'a>> {
    match (stream_stdin, admitted) {
        (true, Some(ctx)) => Ok(DispatchStdin::Streaming(&ctx.admitted)),
        (true, None) => anyhow::bail!(
            "streamed stdin needs an admitted plan, and this boot was not admitted \
             (--no-supervisor): the input grant is what authorizes a write, so there \
             is nothing here to write under"
        ),
        (false, _) => Ok(DispatchStdin::OneShot(prologue)),
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
pub(in crate::commands) fn dispatch(call: EntrypointDispatch<'_>) -> Result<i32> {
    let session_id = call.session_id;
    match dispatch_inner(call) {
        Ok(code) => Ok(code),
        Err(err) => {
            if let Some(id) = session_id
                && let Ok(Some(rec)) = mvm_core::session::read_session(id)
                && rec.state == mvm_core::session::SessionState::Killed
            {
                let event = mvm_agentd::vsock::EntrypointEvent::Error {
                    kind: mvm_agentd::vsock::RunEntrypointError::SessionKilled,
                    message: format!("session {id} killed externally"),
                };
                return Ok(exit_code_for(&event));
            }
            Err(err)
        }
    }
}

/// One `RunEntrypoint` dispatch against a reachable guest agent.
pub(in crate::commands) struct EntrypointDispatch<'a> {
    /// The running microVM to dispatch into.
    pub vm_name: &'a str,
    /// What reaches the workload's stdin.
    pub stdin: DispatchStdin<'a>,
    /// Wall-clock kill window for the call.
    pub timeout_secs: u64,
    /// Session record to consult when the transport drops, so an external
    /// `session kill` is reported as one.
    pub session_id: Option<&'a mvm_core::session::SessionId>,
}

/// Stdin as the dispatch sees it, once the caller's request has been resolved
/// against a real admission.
pub(in crate::commands) enum DispatchStdin<'a> {
    /// The complete payload, carried in the `RunEntrypoint` frame itself.
    OneShot(Vec<u8>),
    /// A live stream opened under this boot's admitted plan.
    ///
    /// Holding the [`AdmittedPlan`](mvm_hostd::plan_admission::AdmittedPlan)
    /// rather than a bool is the point: the gate takes the type only admission
    /// mints, so what authorizes these bytes is the same signed, verified,
    /// window-checked plan the VM booted under, not a flag this module set.
    Streaming(&'a mvm_hostd::plan_admission::AdmittedPlan),
}

fn dispatch_inner(call: EntrypointDispatch<'_>) -> Result<i32> {
    let EntrypointDispatch {
        vm_name,
        stdin,
        timeout_secs,
        session_id: _,
    } = call;
    let transport = mvm_runtime::vsock_transport::for_vm(vm_name)
        .with_context(|| format!("Picking transport for guest agent on '{vm_name}'"))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("Connecting to guest agent on '{vm_name}'"))?;

    // Opened before the call is sent, and deliberately: the guest has a stdin
    // to hand frames to only once the entrypoint's child exists, and the pump
    // is built to ride out that window. Opening afterwards would mean opening
    // it from inside the loop that is streaming the workload's output.
    let streamed = match &stdin {
        DispatchStdin::Streaming(admitted) => Some(open_streamed_stdin(vm_name, admitted)?),
        DispatchStdin::OneShot(_) => None,
    };
    let streaming = streamed.is_some();

    // The entrypoint half of the VM's output capture, for this call only.
    let mut capture = mvm_hostd::stream::EntrypointSink::for_vm(vm_name);
    let recorded = capture.is_recorded();
    let mut out = CallOutput::inherited();
    let terminal = mvm_agentd::vsock::send_run_entrypoint_while(
        &mut stream,
        mvm_agentd::vsock::RunEntrypointCall {
            stdin: match stdin {
                DispatchStdin::OneShot(bytes) => bytes,
                // The bytes travel as frames, not in this envelope.
                DispatchStdin::Streaming(_) => Vec::new(),
            },
            timeout_secs,
            // Secret-bearing workloads route through the in-guest forward proxy;
            // plain vsock-egress workloads route through the loopback SOCKS5 client.
            env: workload_egress_env(vm_name),
            // A one-shot dispatch writes its payload once and has no writer
            // behind it, so the guest closes stdin and a read-to-EOF workload
            // exits. A streamed one keeps the pipe open, because the EOF is
            // the host's to send when the caller's own stdin ends.
            stream_input: streaming,
        },
        |event| write_entrypoint_event(event, &mut capture, &mut out),
        // Consulted only when the stream has gone quiet. A guest that dies
        // mid-stream leaves the host socket open, so without this the read
        // blocks forever and the run never returns.
        || mvm_runtime::checkpoint::vm_is_running(vm_name),
    );
    drop(capture);
    // Before the `?`, not after: a call that failed truncated the caller's
    // stdin just as surely as one that succeeded, and propagating first would
    // swallow the only notice saying so.
    if let Some(streamed) = streamed {
        report_streamed_stdin(vm_name, &mut out, streamed.finish());
    }
    let terminal = terminal.context("Streaming RunEntrypoint response")?;

    // After the output, before the exit: the caller has just been handed the
    // workload's own bytes, and this is where it learns whether the copy an
    // operator can read back is the same one.
    out.report(vm_name, recorded);

    // Flush before potentially exiting.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    Ok(exit_code_for(&terminal))
}

/// Open this VM's host→guest stdin route under `admitted` and start pumping
/// the caller's own stdin into it.
///
/// Everything that decides whether this may happen is below the call to
/// [`StreamPlane::open_input`](mvm_hostd::stream::StreamPlane::open_input) —
/// the grant on the signed plan, the single-writer lease, the chain-signed
/// record — so a refusal here is a decision that has already been made and
/// logged, and there is nothing left for this function to check.
fn open_streamed_stdin(
    vm_name: &str,
    admitted: &mvm_hostd::plan_admission::AdmittedPlan,
) -> Result<super::stdin_stream::StdinStream> {
    let plane = mvm_hostd::stream::host_stream_plane().context(
        "this process holds no workload stream plane, so there is no route to open into \
         the workload's stdin",
    )?;
    plane
        .open_input(
            vm_name,
            admitted,
            Box::new(mvm_hostd::stream::VsockInput::new(vm_name)),
        )
        .map_err(|refusal| {
            anyhow::anyhow!("the workload input gate refused this writer: {refusal}")
        })?;
    Ok(super::stdin_stream::StdinStream::start(
        std::sync::Arc::new(super::stdin_stream::PlaneInput::new(plane, vm_name)),
        std::io::stdin(),
    ))
}

/// Tell the caller, on stderr, when the stdin it streamed did not all land.
///
/// Silent on the ordinary outcome — the caller's stdin ended, the workload's
/// stdin was closed — because a notice that fires every time stops being read.
fn report_streamed_stdin(
    vm_name: &str,
    out: &mut CallOutput<'_>,
    report: super::stdin_stream::StreamedInputReport,
) {
    if let Some(reason) = &report.stopped_because {
        notice(
            &mut out.sinks,
            &format!(
                "streamed stdin to {vm_name:?} stopped early after {} byte(s) in {} frame(s): \
                 {reason}",
                report.bytes, report.frames
            ),
        );
        return;
    }
    if !report.reached_eof {
        notice(
            &mut out.sinks,
            &format!(
                "the call ended before your stdin did: {} byte(s) in {} frame(s) reached \
                 {vm_name:?}, and anything after that was not sent",
                report.bytes, report.frames
            ),
        );
    }
}

/// Where a streamed entrypoint event's bytes land. Behind a struct so a test
/// asserts on what the handler wrote and when, rather than on the process's
/// real fds.
struct EventSinks<'a> {
    out: Box<dyn Write + 'a>,
    err: Box<dyn Write + 'a>,
}

impl EventSinks<'static> {
    fn inherited() -> Self {
        Self {
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
        }
    }
}

/// One call's output: the caller's two fds, and a running tally of how the
/// recorded copy diverged from what they were handed.
struct CallOutput<'a> {
    sinks: EventSinks<'a>,
    divergence: RecordedDivergence,
}

impl CallOutput<'static> {
    fn inherited() -> Self {
        Self {
            sinks: EventSinks::inherited(),
            divergence: RecordedDivergence::default(),
        }
    }
}

impl CallOutput<'_> {
    /// Tell the caller, on stderr, how what an operator can read back differs
    /// from what this call printed.
    ///
    /// Silent when the two agree, which is the ordinary case — a notice that
    /// fires on every call stops being read. Prefixed so a script can detect
    /// it without parsing prose, and on stderr so it never lands in the bytes
    /// an SDK is parsing.
    fn report(&mut self, vm_name: &str, recorded: bool) {
        if !recorded {
            notice(
                &mut self.sinks,
                &format!(
                    "this call's output was not recorded: no output capture for microVM \
                     {vm_name:?} in this process, so `mvmctl machine logs {vm_name}` will not show it"
                ),
            );
            return;
        }
        if let Some(line) = self.divergence.describe(vm_name) {
            notice(&mut self.sinks, &line);
        }
    }
}

/// Prefix on the operator notices this command writes. Fixed and greppable:
/// the divergence line is the caller's only signal that the recorded copy is
/// not what it printed, and a script has to be able to detect it.
const NOTICE_PREFIX: &str = "[mvmctl-stream]";

fn notice(sinks: &mut EventSinks<'_>, line: &str) {
    // `eprintln!` panics when the write fails, and `mvmctl … 2>&-` is an
    // ordinary thing for a script to do — a diagnostic must not kill the
    // command it is diagnosing.
    let _ = writeln!(sinks.err, "{NOTICE_PREFIX} {line}");
    let _ = sinks.err.flush();
}

/// How the copy of this call's output that was recorded differs from the copy
/// the caller was handed.
///
/// Counts and rule *names* only. A value that fired a rule is exactly the
/// value that must not travel, so naming it here would reopen the leak the
/// seam closes — and the caller already has the bytes.
#[derive(Default)]
struct RecordedDivergence {
    masked_chunks: u64,
    withheld_chunks: u64,
    /// Chunks that came back [`RecordedCopy::NotRecorded`] after the call
    /// had already been sampled as recorded — the capture's broker was
    /// released mid-dispatch (a teardown racing this call). Tracked
    /// separately from the up-front `recorded` flag because that flag is
    /// sampled once, before the first frame arrives, and cannot see a
    /// release that lands after it.
    dropped_chunks: u64,
    /// Sorted and deduplicated, so the line reads the same across runs.
    rules_fired: std::collections::BTreeSet<&'static str>,
}

impl RecordedDivergence {
    fn note(&mut self, recorded: &mvm_hostd::stream::RecordedCopy) {
        use mvm_hostd::stream::RecordedCopy;
        match recorded {
            RecordedCopy::NotRecorded => {
                self.dropped_chunks = self.dropped_chunks.saturating_add(1);
            }
            RecordedCopy::Identical => {}
            RecordedCopy::Masked { rules_fired } => {
                self.masked_chunks = self.masked_chunks.saturating_add(1);
                self.rules_fired.extend(rules_fired.iter().copied());
            }
            RecordedCopy::Withheld { .. } => {
                self.withheld_chunks = self.withheld_chunks.saturating_add(1);
            }
        }
    }

    /// One line naming the divergence, or `None` when the two copies agree.
    fn describe(&self, vm_name: &str) -> Option<String> {
        if self.masked_chunks == 0 && self.withheld_chunks == 0 && self.dropped_chunks == 0 {
            return None;
        }
        let mut parts = Vec::new();
        if self.dropped_chunks > 0 {
            parts.push(format!(
                "{} chunk(s) went unrecorded because the capture ended mid-call",
                self.dropped_chunks
            ));
        }
        if self.masked_chunks > 0 {
            parts.push(format!(
                "{} chunk(s) masked by: {}",
                self.masked_chunks,
                self.rules_fired
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if self.withheld_chunks > 0 {
            parts.push(format!(
                "{} chunk(s) withheld because the redaction seam could not check them",
                self.withheld_chunks
            ));
        }
        Some(format!(
            "recorded output differs from what this call printed — {}; \
             the bytes above are the workload's own, `mvmctl machine logs {vm_name}` shows the \
             redacted copy",
            parts.join("; ")
        ))
    }
}

/// Write one streamed entrypoint event, as it arrives.
///
/// **Through the capture, and the caller still gets its own bytes.** Every
/// frame is handed to `capture`, which redacts, chains, persists and fans out
/// a copy of its own — that copy is the one an operator reads back, and it is
/// the only copy that leaves this host. What is written to the caller's fds is
/// the workload's own bytes, unchanged: whoever ran this call has code
/// execution inside the workload that produced them, so masking their own
/// return value protects nothing and turns a JSON body into something no
/// parser accepts. The capture is still the only fan-out point — one frame in,
/// one record recorded, one copy written — and its ingest waits on neither a
/// follower nor the disk, so nothing downstream can pace the guest through
/// this loop.
///
/// **Flushed per event, deliberately.** Rust's stdout is block-buffered
/// whenever it is not a terminal, so without this the agent could stream
/// perfectly and `mvmctl … | tee` would still show nothing until exit —
/// reinstating, at the last hop, exactly the buffer-to-exit behaviour the
/// streaming response exists to remove.
fn write_entrypoint_event(
    event: &mvm_agentd::vsock::EntrypointEvent,
    capture: &mut mvm_hostd::stream::EntrypointSink,
    out: &mut CallOutput<'_>,
) {
    use mvm_contract::stream::StreamKind;
    match event {
        mvm_agentd::vsock::EntrypointEvent::Stdout { chunk } => {
            show(capture.ingest(StreamKind::Stdout, chunk), out);
        }
        mvm_agentd::vsock::EntrypointEvent::Stderr { chunk } => {
            show(capture.ingest(StreamKind::Stderr, chunk), out);
        }
        mvm_agentd::vsock::EntrypointEvent::Control {
            header_json,
            payload,
        } => {
            // Surface fd-3 control records to the operator with a
            // clearly-labelled prefix the user's stderr can't spoof
            // (these come from mvmctl, not the wrapper). A future
            // SDK-facing `--envelope-fd <n>` flag will write raw
            // frames out for structured consumption; until then this
            // human-readable form is the default.
            //
            // The header is the record; the fd-3 payload rides along and
            // neither consumer renders it.
            let shown = capture.ingest(StreamKind::Trace, header_json.as_bytes());
            out.divergence.note(&shown.recorded);
            let header = String::from_utf8_lossy(&shown.body);
            if payload.is_empty() {
                let _ = writeln!(out.sinks.err, "[mvmctl-control] {header}");
            } else {
                let _ = writeln!(
                    out.sinks.err,
                    "[mvmctl-control] {header} (+{} payload bytes)",
                    payload.len()
                );
            }
            let _ = out.sinks.err.flush();
        }
        // Terminal events (Exit / Error) are returned by
        // send_run_entrypoint; the handler is only invoked for
        // streaming chunks above.
        _ => {}
    }
}

/// Put one chunk on the fd its channel belongs to, and remember how the
/// recorded copy of it differed.
///
/// Routed by the channel the guest sent the frame on. The recorded copy may
/// have been retagged `Trace` — a chunk the seam would not vouch for is
/// recorded as a marker — but that is a property of the record, not of the
/// bytes the caller asked for, and moving the caller's stdout onto stderr over
/// it would break the very parser this exists to keep whole.
fn show(chunk: mvm_hostd::stream::ShownChunk, out: &mut CallOutput<'_>) {
    use mvm_contract::stream::StreamKind;
    out.divergence.note(&chunk.recorded);
    let sink = match chunk.kind {
        StreamKind::Stdout => &mut out.sinks.out,
        StreamKind::Stderr | StreamKind::Trace => &mut out.sinks.err,
    };
    let _ = sink.write_all(&chunk.body);
    let _ = sink.flush();
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
    mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN)
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
    let proxy = mvm_agentd::forward_proxy::proxy_env_url();
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

fn exit_code_for(event: &mvm_agentd::vsock::EntrypointEvent) -> i32 {
    use mvm_agentd::vsock::{EntrypointEvent, RunEntrypointError};
    match event {
        EntrypointEvent::Exit { code } => *code,
        EntrypointEvent::Error { kind, message } => {
            let (code, label) = match kind {
                RunEntrypointError::Timeout => (124, "timeout"),
                RunEntrypointError::Busy => (1, "busy"),
                RunEntrypointError::PayloadCap => (1, "payload cap exceeded"),
                RunEntrypointError::WrapperCrashed => (137, "wrapper crashed"),
                RunEntrypointError::EntrypointInvalid => (1, "entrypoint invalid"),
                // 130 = 128 + SIGINT (2), the conventional shell status for
                // an explicitly canceled foreground operation. This reports
                // the semantic cancellation, not whichever signal the bounded
                // guest kill ladder ultimately needed.
                RunEntrypointError::Canceled => (130, "canceled"),
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
mod streaming_tests {
    use super::{CallOutput, EventSinks, RecordedDivergence, write_entrypoint_event};
    use mvm_agentd::vsock::EntrypointEvent;
    use mvm_hostd::stream::EntrypointSink;

    /// Sinks over borrowed buffers, so a test reads back exactly what the
    /// handler wrote.
    fn buffers<'a>(out: &'a mut Vec<u8>, err: &'a mut Vec<u8>) -> CallOutput<'a> {
        CallOutput {
            sinks: EventSinks {
                out: Box::new(out),
                err: Box::new(err),
            },
            divergence: RecordedDivergence::default(),
        }
    }

    /// The capture a call gets when no plane in this process holds the VM —
    /// the `--attach`-into-another-process's-machine case, and the default for
    /// the tests here that are about the rendering rather than the recording.
    fn uncaptured() -> EntrypointSink {
        EntrypointSink::unrecorded()
    }

    #[test]
    fn each_entrypoint_channel_goes_to_its_own_fd() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut capture = uncaptured();
            let mut sinks = buffers(&mut out, &mut err);
            write_entrypoint_event(
                &EntrypointEvent::Stdout {
                    chunk: b"to-stdout".to_vec(),
                },
                &mut capture,
                &mut sinks,
            );
            write_entrypoint_event(
                &EntrypointEvent::Stderr {
                    chunk: b"to-stderr".to_vec(),
                },
                &mut capture,
                &mut sinks,
            );
        }
        assert_eq!(out, b"to-stdout");
        assert_eq!(err, b"to-stderr");
    }

    #[test]
    fn a_control_record_is_labelled_and_kept_off_stdout() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut capture = uncaptured();
            let mut sinks = buffers(&mut out, &mut err);
            write_entrypoint_event(
                &EntrypointEvent::Control {
                    header_json: r#"{"event":"ready"}"#.to_string(),
                    payload: vec![1, 2, 3],
                },
                &mut capture,
                &mut sinks,
            );
        }
        assert!(out.is_empty(), "a control record is not workload stdout");
        let rendered = String::from_utf8(err).expect("utf8");
        assert!(rendered.starts_with("[mvmctl-control] "), "{rendered}");
        assert!(rendered.contains("(+3 payload bytes)"), "{rendered}");
    }

    #[test]
    fn an_uncaptured_call_hands_the_workloads_bytes_straight_through() {
        // Nothing is recording this VM here, so there is no second copy to
        // protect and nobody to protect it from — the caller ran the function.
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut capture = uncaptured();
            let mut sinks = buffers(&mut out, &mut err);
            write_entrypoint_event(
                &EntrypointEvent::Stdout {
                    chunk: br#"{"card":"4111111111111111"}"#.to_vec(),
                },
                &mut capture,
                &mut sinks,
            );
        }
        assert_eq!(out, br#"{"card":"4111111111111111"}"#);
    }

    /// A sink that records *when* it was pushed, not just what it holds.
    ///
    /// Buffered bytes prove output was produced; the flush is what proves it
    /// left the process. Rust's stdout is block-buffered off a terminal, so a
    /// handler that writes without flushing produces a `| tee` that shows
    /// nothing until exit — indistinguishable, to the operator, from the
    /// buffer-to-exit agent this whole path replaced.
    #[derive(Default)]
    struct RecordingSink {
        ops: Vec<Op>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Op {
        Wrote(Vec<u8>),
        Flushed,
    }

    impl std::io::Write for &mut RecordingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.ops.push(Op::Wrote(buf.to_vec()));
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.ops.push(Op::Flushed);
            Ok(())
        }
    }

    /// Every chunk is pushed out of the process before the next one is taken,
    /// so a running workload's output is visible while it runs rather than at
    /// exit.
    ///
    /// This is the hop `mvmctl` owns. The other two legs are proven where they
    /// live: the guest pump emitting before the child exits, and
    /// `send_run_entrypoint` invoking this handler once per non-terminal event
    /// rather than collecting them, both in `mvm-agentd`.
    #[test]
    fn output_reaches_the_operator_before_the_child_exits() {
        let mut out = RecordingSink::default();
        let mut err = RecordingSink::default();
        {
            let mut capture = uncaptured();
            let mut sinks = CallOutput {
                sinks: EventSinks {
                    out: Box::new(&mut out),
                    err: Box::new(&mut err),
                },
                divergence: RecordedDivergence::default(),
            };
            for chunk in [&b"first"[..], &b"second"[..]] {
                write_entrypoint_event(
                    &EntrypointEvent::Stdout {
                        chunk: chunk.to_vec(),
                    },
                    &mut capture,
                    &mut sinks,
                );
            }
        }
        assert_eq!(
            out.ops,
            vec![
                Op::Wrote(b"first".to_vec()),
                Op::Flushed,
                Op::Wrote(b"second".to_vec()),
                Op::Flushed,
            ],
            "each chunk must leave the process before the next is handled"
        );
    }

    /// The handler is for streaming chunks only: a terminal event is returned
    /// by `send_run_entrypoint` and rendered by the exit-code path, so nothing
    /// this writes is deferred until one arrives.
    #[test]
    fn a_terminal_event_writes_nothing_through_the_streaming_handler() {
        let mut out = RecordingSink::default();
        let mut err = RecordingSink::default();
        {
            let mut sinks = CallOutput {
                sinks: EventSinks {
                    out: Box::new(&mut out),
                    err: Box::new(&mut err),
                },
                divergence: RecordedDivergence::default(),
            };
            let mut capture = uncaptured();
            write_entrypoint_event(&EntrypointEvent::Exit { code: 0 }, &mut capture, &mut sinks);
        }
        assert!(out.ops.is_empty(), "{:?}", out.ops);
        assert!(err.ops.is_empty(), "{:?}", err.ops);
    }

    #[test]
    fn an_uncaptured_call_says_so_rather_than_leaving_the_operator_to_find_out() {
        // The residual from a `--attach` into a machine some other process
        // booted: the call runs, but `mvmctl machine logs` will not show it.
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut sinks = buffers(&mut out, &mut err);
            sinks.report("detached-vm", false);
        }
        let rendered = String::from_utf8(err).expect("utf8");
        assert!(rendered.starts_with("[mvmctl-stream] "), "{rendered}");
        assert!(rendered.contains("was not recorded"), "{rendered}");
        assert!(rendered.contains("detached-vm"), "{rendered}");
        assert!(out.is_empty(), "a diagnostic never lands on stdout");
    }

    #[test]
    fn a_call_whose_copies_agree_says_nothing() {
        // A notice that fires on every call stops being read. Noted directly
        // against `RecordedCopy::Identical` rather than through `uncaptured()`
        // — that helper's sink answers every frame `NotRecorded`, which is
        // itself something `report` must now surface (see the mid-call-release
        // regression test in `captured_tests`), so it can no longer stand in
        // for "nothing diverged".
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut sinks = buffers(&mut out, &mut err);
            sinks
                .divergence
                .note(&mvm_hostd::stream::RecordedCopy::Identical);
            sinks.report("quiet-vm", true);
        }
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
        assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
    }
}

#[cfg(test)]
mod stdin_grant_tests {
    //! What `machine run --entrypoint --stdin -` asks admission for, and what
    //! admission does about it.
    //!
    //! Driven through [`admit_entrypoint_boot`] rather than through
    //! `admit_plan_for_boot` directly, because the thing worth proving is the
    //! join: the entrypoint action resolves what the image runs *from the
    //! image*, and hands that resolution to the gate. A test that passed the
    //! argv in by hand would prove the gate classifies strings, which was
    //! never in doubt — what was in doubt is whether anything real ever
    //! reaches it.

    use super::{EntrypointAdmissionParams, admit_entrypoint_boot};
    use mvm_build::builder_vm::GuestSidecar;
    use mvm_core::util::test_env::TestEnv;

    /// One image on disk: a rootfs stand-in and the sidecar beside it, which
    /// is everything the host can see about a workload before it boots.
    struct Image {
        rootfs: std::path::PathBuf,
        _dir: tempfile::TempDir,
        _env: TestEnv,
        _home: tempfile::TempDir,
    }

    impl Image {
        /// `argv = None` writes a sidecar with no recorded entrypoint — an
        /// image built before the build path recorded one.
        fn sealed_running(argv: Option<&[&str]>) -> Self {
            let mut env = TestEnv::new();
            let home = tempfile::tempdir().expect("an isolated MVM_HOME");
            env.isolate_mvm_home(home.path());

            let dir = tempfile::tempdir().expect("an image dir");
            let rootfs = dir.path().join("rootfs.ext4");
            std::fs::write(&rootfs, b"rootfs bytes").expect("write the rootfs stand-in");
            let sidecar = GuestSidecar::for_oci_run("stdin-grant", true, true);
            let sidecar = match argv {
                Some(argv) => {
                    sidecar.with_entrypoint_argv(argv.iter().map(|a| (*a).to_string()).collect())
                }
                None => sidecar,
            };
            sidecar.write_to_dir(dir.path()).expect("write the sidecar");

            Self {
                rootfs,
                _dir: dir,
                _env: env,
                _home: home,
            }
        }

        fn admit(
            &self,
            vm: &str,
            stream_stdin: bool,
        ) -> anyhow::Result<Option<super::EntrypointAdmission>> {
            let lowered = super::super::managed_secrets::LoweredPlanSecrets::default();
            admit_entrypoint_boot(
                EntrypointAdmissionParams::builder(&self.rootfs, vm, "firecracker")
                    .lowered_secrets(&lowered)
                    .stream_stdin(stream_stdin)
                    .build(),
            )
        }
    }

    #[test]
    fn a_shell_entrypoint_read_off_the_image_is_refused_the_stdin_grant() {
        // The whole point of the resolver. The argv is not supplied by the
        // test: it is written where a build writes it and read where
        // admission reads it, so this is the refusal firing on a real image
        // rather than on a string a test handed it.
        let image = Image::sealed_running(Some(&["/bin/sh", "-i"]));
        // Matched rather than `expect_err`: the success arm carries the audit
        // substrate, and widening that type's debug surface to satisfy a test
        // assertion is the wrong trade.
        let err = match image.admit("vm-stdin-shell", true) {
            Ok(_) => panic!("a shell entrypoint asking for streamed stdin must be refused"),
            Err(err) => err,
        };

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("shell-shaped"),
            "the refusal must name the reason: {rendered}"
        );
        assert!(rendered.contains("/bin/sh"), "{rendered}");
    }

    #[test]
    fn an_image_that_cannot_say_what_it_runs_is_refused_the_stdin_grant() {
        // Fail closed. An unresolved entrypoint is not a safe one — it is an
        // unchecked one, and admitting on it is what turns the refusal above
        // into a control that reports present and never fires.
        let image = Image::sealed_running(None);
        let err = match image.admit("vm-stdin-unknown", true) {
            Ok(_) => panic!("an unresolvable entrypoint must not be handed a stdin writer"),
            Err(err) => err,
        };

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("cannot say what the workload runs"),
            "the refusal must say it could not tell, not that it found a shell: {rendered}"
        );
    }

    #[test]
    fn a_shell_entrypoint_that_asked_for_nothing_still_boots() {
        // The refusal is scoped to the grant. A shell-entrypoint image with no
        // streamed stdin is the ordinary dev workflow and must be untouched by
        // any of this.
        let image = Image::sealed_running(Some(&["/bin/sh", "-i"]));
        let admitted = image
            .admit("vm-stdin-none", false)
            .expect("a call that asked for no input grant must not be refused")
            .expect("admission ran");
        assert!(
            admitted.context.admitted.plan().services.is_empty(),
            "a call that did not ask for streamed stdin must carry no grant"
        );
    }

    #[test]
    fn a_non_shell_entrypoint_that_asked_for_it_carries_the_grant_on_the_signed_plan() {
        // The other side of default-deny: asking, on an image that resolves to
        // something that is not a shell, actually gets you the token — and the
        // token is on the *signed plan*, which is what the gate reads.
        let image = Image::sealed_running(Some(&["/usr/bin/worker", "--serve"]));
        let admitted = image
            .admit("vm-stdin-granted", true)
            .expect("a non-shell entrypoint may be granted streamed stdin")
            .expect("admission ran");

        let services = &admitted.context.admitted.plan().services;
        assert!(
            mvm_contract::stream::input::grants_input_for(services),
            "the admitted plan must carry the input grant: {services:?}"
        );
    }
}

#[cfg(test)]
mod captured_tests {
    //! What a call leaves behind, read back the way `mvmctl machine logs` reads it.
    //!
    //! Driven against a real plane over a real encrypted transcript: the
    //! entrypoint source's whole reason to exist is that a reader can ask for
    //! one channel and get it, and only an end-to-end read proves the tags
    //! survive the broker, the transcript, and the manifest.

    use super::{CallOutput, EventSinks, RecordedDivergence, write_entrypoint_event};
    use mvm_agentd::vsock::EntrypointEvent;
    use mvm_contract::stream::StreamKind;
    use mvm_core::policy::RedactionPolicy;
    use mvm_core::stream_client::{
        KindFilter, OutputRequest, StreamAvailability, StreamOpts, open_vm_output,
    };
    use mvm_core::util::test_env::TestEnv;
    use mvm_hostd::stream::StreamPlane;
    use mvm_runtime::workload_runner::ConsoleCapture;

    /// A plane holding one VM whose console never appears, so every record in
    /// the capture came from the entrypoint frames this test wrote.
    struct Captured {
        plane: StreamPlane,
        vm: &'static str,
        out: Vec<u8>,
        err: Vec<u8>,
        _env: TestEnv,
        _home: tempfile::TempDir,
    }

    impl Captured {
        /// Attach a plane for `vm`, then run `events` through the same handler
        /// `dispatch` gives `send_run_entrypoint`, closing with the same
        /// end-of-call report `dispatch` writes.
        fn of(vm: &'static str, events: &[EntrypointEvent]) -> Self {
            let mut env = TestEnv::new();
            let home = tempfile::tempdir().expect("tempdir");
            env.isolate_mvm_home(home.path());

            let state = mvm_core::config::vm_state_dir(vm);
            std::fs::create_dir_all(&state).expect("state dir");
            let plane = StreamPlane::new();
            let redaction = RedactionPolicy::default();
            plane
                .attach(&ConsoleCapture {
                    vm_name: vm,
                    console_log: &state.join("console.log"),
                    redaction: &redaction,
                    retention: mvm_core::plan::StreamRetention::Persist,
                })
                .expect("attach a plane");

            let (mut out, mut err) = (Vec::new(), Vec::new());
            {
                let mut capture = plane.entrypoint_sink(vm);
                let recorded = capture.is_recorded();
                let mut sinks = CallOutput {
                    sinks: EventSinks {
                        out: Box::new(&mut out),
                        err: Box::new(&mut err),
                    },
                    divergence: RecordedDivergence::default(),
                };
                for event in events {
                    write_entrypoint_event(event, &mut capture, &mut sinks);
                }
                sinks.report(vm, recorded);
            }
            Self {
                plane,
                vm,
                out,
                err,
                _env: env,
                _home: home,
            }
        }

        /// Seal the capture and replay it, keeping only `kinds`.
        fn recorded(&self, kinds: KindFilter) -> Vec<(StreamKind, Vec<u8>)> {
            self.plane.release(self.vm);
            let request = OutputRequest {
                opts: StreamOpts::builder().kinds(kinds).build(),
                ..OutputRequest::default()
            };
            let mut stream =
                open_vm_output(self.vm, request).expect("the sealed capture must open");
            assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
            let mut out = Vec::new();
            while let Some(record) = stream.next_output().expect("read the sealed capture") {
                out.push((record.kind, record.payload));
            }
            out
        }
    }

    fn stdout(bytes: &[u8]) -> EntrypointEvent {
        EntrypointEvent::Stdout {
            chunk: bytes.to_vec(),
        }
    }

    fn stderr(bytes: &[u8]) -> EntrypointEvent {
        EntrypointEvent::Stderr {
            chunk: bytes.to_vec(),
        }
    }

    #[test]
    fn a_call_that_writes_to_stderr_is_readable_on_the_stderr_channel() {
        // The gap this closes: with a plane up and only the console feeding
        // it, every record was labelled stdout, so `--stream stderr` matched
        // nothing a workload had ever written.
        let captured = Captured::of("invoke-stderr-vm", &[stdout(b"o"), stderr(b"e")]);

        assert_eq!(
            captured.recorded(KindFilter::only(StreamKind::Stderr)),
            vec![(StreamKind::Stderr, b"e".to_vec())],
            "a stderr read must return the stderr frame and nothing else"
        );
    }

    #[test]
    fn the_two_channels_stay_separable_all_the_way_into_the_transcript() {
        let captured = Captured::of("invoke-split-vm", &[stdout(b"o"), stderr(b"e")]);

        assert_eq!(captured.out, b"o", "stdout went to the caller's stdout");
        assert_eq!(captured.err, b"e", "stderr went to the caller's stderr");
        assert_eq!(
            captured.recorded(KindFilter::all()),
            vec![
                (StreamKind::Stdout, b"o".to_vec()),
                (StreamKind::Stderr, b"e".to_vec()),
            ],
            "the capture keeps the channel the guest sent each frame on"
        );
    }

    #[test]
    fn a_frame_is_recorded_once_and_shown_once() {
        // The failure mode of a tee: the frame reaches the capture *and* the
        // caller's fd by two paths, and one of them runs twice.
        let captured = Captured::of(
            "invoke-once-vm",
            &[stdout(b"first "), stdout(b"second"), stderr(b"only")],
        );

        assert_eq!(captured.out, b"first second");
        assert_eq!(captured.err, b"only");
        assert_eq!(
            captured.recorded(KindFilter::all()),
            vec![
                (StreamKind::Stdout, b"first ".to_vec()),
                (StreamKind::Stdout, b"second".to_vec()),
                (StreamKind::Stderr, b"only".to_vec()),
            ],
            "three frames must leave three records, not six"
        );
    }

    /// A JSON body carrying a Luhn-valid number — the shape an SDK parses off
    /// `MachineResult.stdout`, and the shape the curated ruleset matches.
    const JSON_RETURN: &[u8] = br#"{"email":"a@b.com","id":4111111111111111}"#;

    #[test]
    fn a_return_value_reaches_the_caller_whole_while_the_transcript_holds_the_masked_copy() {
        // The correction: whoever ran this call has code execution inside the
        // workload that produced these bytes, so masking their own return
        // value protects nothing — and `{"id":XXX}` is not JSON, so it breaks
        // every SDK that parses the result. The copy that leaves the host is
        // still masked.
        let captured = Captured::of("invoke-json-vm", &[stdout(JSON_RETURN)]);
        let shown = captured.out.clone();

        assert_eq!(
            shown, JSON_RETURN,
            "the caller's own return value must round-trip byte for byte"
        );
        serde_json::from_slice::<serde_json::Value>(&shown)
            .expect("what the caller was handed must still parse as JSON");

        let recorded = captured.recorded(KindFilter::all());
        let (kind, body) = recorded.first().expect("one record").clone();
        assert_eq!(kind, StreamKind::Stdout);
        assert!(
            !body.windows(16).any(|w| w == b"4111111111111111"),
            "the recorded copy must still be masked: {}",
            String::from_utf8_lossy(&body)
        );
        assert_ne!(body, shown);
    }

    #[test]
    fn the_caller_is_told_the_recorded_copy_diverged_and_which_rules_fired() {
        // Divergence the caller cannot detect is the worst of both: their
        // bytes are whole, and they have no way to know an operator reading
        // the same call back sees something else.
        let captured = Captured::of("invoke-divergence-vm", &[stdout(JSON_RETURN)]);

        let rendered = String::from_utf8(captured.err.clone()).expect("utf8");
        assert!(
            rendered.starts_with("[mvmctl-stream] "),
            "a script has to be able to detect this without parsing prose: {rendered}"
        );
        assert!(rendered.contains("recorded output differs"), "{rendered}");
        assert!(rendered.contains("credit_card"), "{rendered}");
        assert!(rendered.contains("email"), "{rendered}");
        assert!(rendered.contains("1 chunk(s) masked"), "{rendered}");
        assert!(
            !rendered.contains("4111111111111111"),
            "naming the rule must not mean quoting the value: {rendered}"
        );
    }

    #[test]
    fn an_fd3_control_record_is_captured_on_the_trace_channel() {
        let captured = Captured::of(
            "invoke-trace-vm",
            &[EntrypointEvent::Control {
                header_json: r#"{"event":"ready"}"#.to_string(),
                payload: vec![1, 2, 3],
            }],
        );

        assert!(captured.out.is_empty());
        assert_eq!(
            captured.recorded(KindFilter::only(StreamKind::Trace)),
            vec![(StreamKind::Trace, br#"{"event":"ready"}"#.to_vec())],
            "the structured record belongs on the trace channel, not stdout"
        );
    }

    #[test]
    fn a_release_mid_call_is_reported_not_swallowed() {
        // `recorded` is sampled once, before the first frame. A teardown that
        // lands between two frames of the same dispatch — `release` sealing
        // the transcript out from under a call still streaming — must not
        // leave the report describing a clean call just because that one
        // early sample was still true.
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let _env = env;
        let vm = "invoke-mid-release-vm";
        let state = mvm_core::config::vm_state_dir(vm);
        std::fs::create_dir_all(&state).expect("state dir");
        let plane = StreamPlane::new();
        let redaction = RedactionPolicy::default();
        plane
            .attach(&ConsoleCapture {
                vm_name: vm,
                console_log: &state.join("console.log"),
                redaction: &redaction,
                retention: mvm_core::plan::StreamRetention::Persist,
            })
            .expect("attach a plane");

        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut capture = plane.entrypoint_sink(vm);
            let recorded = capture.is_recorded();
            assert!(recorded, "the plane just attached this VM");
            let mut sinks = CallOutput {
                sinks: EventSinks {
                    out: Box::new(&mut out),
                    err: Box::new(&mut err),
                },
                divergence: RecordedDivergence::default(),
            };
            write_entrypoint_event(&stdout(b"before"), &mut capture, &mut sinks);
            plane.release(vm); // a teardown racing this call
            write_entrypoint_event(&stdout(b"after"), &mut capture, &mut sinks);
            sinks.report(vm, recorded);
        }

        assert_eq!(
            out, b"beforeafter",
            "the caller still gets its own bytes in full, release or not"
        );
        let rendered = String::from_utf8(err).expect("utf8");
        assert!(
            rendered.contains("went unrecorded"),
            "a chunk dropped by a mid-call release must not be silent: {rendered}"
        );
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
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        let mut sidecar = GuestSidecar::for_oci_run("audit-probe", true, true);
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
            .plan()
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
    fn admit_entrypoint_boot_carries_resolved_allow_list_not_deny_all() {
        use mvm_build::builder_vm::GuestSidecar;
        use mvm_core::network_policy::{HostPort, NetworkPolicy};

        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        let sidecar = GuestSidecar::for_oci_run("egress-probe", true, true);
        sidecar.write_to_dir(dir.path()).expect("write sidecar");

        // A literal-IP allow-list skips DNS resolution in the generated signed
        // policy, so this exercises the real threading without a live resolver.
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("127.0.0.1", 443)]);
        let lowered_secrets = LoweredPlanSecrets::default();
        let admitted = admit_entrypoint_boot(
            EntrypointAdmissionParams::builder(&rootfs, "invoke-proof-allow", "firecracker")
                .cpus(1)
                .mem_mib(256)
                .lowered_secrets(&lowered_secrets)
                .agent_verb_override(&["run-entrypoint".into()])
                .keep_alive_dev(false)
                .network_policy(policy)
                .build(),
        )
        .expect("admit entrypoint boot")
        .expect("entrypoint boot admitted");

        // deny_all resolves to `Some(empty)` rules → no generated bundle; the
        // allow-list resolves to concrete L4 rules → a bundle that pins the host.
        // Its presence proves the resolved policy survived rather than being
        // hardcoded to deny_all.
        let bundle = admitted
            .context
            .policy_bundle
            .as_ref()
            .expect("allow-list admission must generate a signed egress policy bundle");
        assert!(
            bundle
                .egress
                .allow_list
                .iter()
                .any(|(host, port)| host == "127.0.0.1" && *port == 443),
            "generated egress bundle must carry the resolved allow-list host:port"
        );
        assert!(
            bundle
                .network
                .l4
                .iter()
                .any(|r| r.dst_cidr == "127.0.0.1/32" && r.port_lo == 443 && r.port_hi == 443),
            "generated network policy must carry the resolved L4 allow rule"
        );
    }

    #[test]
    fn test_exit_code_normal_exit_zero() {
        let evt = mvm_agentd::vsock::EntrypointEvent::Exit { code: 0 };
        assert_eq!(exit_code_for(&evt), 0);
    }

    #[test]
    fn test_exit_code_normal_exit_preserves_nonzero() {
        let evt = mvm_agentd::vsock::EntrypointEvent::Exit { code: 7 };
        assert_eq!(exit_code_for(&evt), 7);
    }

    #[test]
    fn test_exit_code_timeout_maps_to_124() {
        let evt = mvm_agentd::vsock::EntrypointEvent::Error {
            kind: mvm_agentd::vsock::RunEntrypointError::Timeout,
            message: "killed".into(),
        };
        assert_eq!(exit_code_for(&evt), 124);
    }

    #[test]
    fn test_exit_code_wrapper_crash_maps_to_137() {
        let evt = mvm_agentd::vsock::EntrypointEvent::Error {
            kind: mvm_agentd::vsock::RunEntrypointError::WrapperCrashed,
            message: "segfault".into(),
        };
        assert_eq!(exit_code_for(&evt), 137);
    }

    #[test]
    fn test_exit_code_canceled_maps_to_130() {
        let evt = mvm_agentd::vsock::EntrypointEvent::Error {
            kind: mvm_agentd::vsock::RunEntrypointError::Canceled,
            message: "controller canceled the call".into(),
        };
        assert_eq!(exit_code_for(&evt), 130);
    }

    #[test]
    fn test_exit_code_session_killed_maps_to_142() {
        // 142 = 128 + SIGALRM (14) — stable signal-style exit code
        // SDKs match on to distinguish "session killed externally"
        // from "wrapper crashed" (137 = 128 + SIGKILL).
        let evt = mvm_agentd::vsock::EntrypointEvent::Error {
            kind: mvm_agentd::vsock::RunEntrypointError::SessionKilled,
            message: "killed".into(),
        };
        assert_eq!(exit_code_for(&evt), 142);
    }

    #[test]
    fn test_exit_code_busy_payload_invalid_internal_all_map_to_1() {
        use mvm_agentd::vsock::RunEntrypointError as E;
        for kind in [
            E::Busy,
            E::PayloadCap,
            E::EntrypointInvalid,
            E::InternalError,
        ] {
            // SessionKilled is excluded — has its own dedicated exit code.
            let evt = mvm_agentd::vsock::EntrypointEvent::Error {
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
        let proxy = mvm_agentd::forward_proxy::proxy_env_url();
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
        env.set("MVM_HOME", dir.path());
        assert!(super::vsock_egress_env("plain-vm").is_empty());
    }

    #[test]
    fn vsock_egress_env_emits_http_proxy_vars_when_marker_present() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", dir.path());
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
        env_guard.set("MVM_HOME", dir.path());

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

/// The two ways a call that asked to stream its stdin is turned down, and what
/// the caller is told when the bytes it typed did not all land.
#[cfg(test)]
mod streamed_stdin_tests {
    use super::*;
    use crate::commands::vm::stdin_stream::StreamedInputReport;

    fn streaming_attach_call() -> EntrypointCall {
        EntrypointCall {
            source: "already-running".to_string(),
            stdin: EntrypointStdin::Streaming,
            timeout: 30,
            cpus: 1,
            memory_mib: 256,
            from_workload_ir: None,
            agent_verb_override: Vec::new(),
            reset: false,
            keep_alive: false,
            keep_alive_dev: false,
            session: None,
            r#fn: None,
            attach: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            hypervisor: None,
        }
    }

    #[test]
    fn attaching_to_a_machine_someone_else_admitted_refuses_a_streamed_stdin() {
        // The grant rides on the plan the *boot* was admitted under, and this
        // process holds no such plan. Without the refusal the write is turned
        // down three layers down, where the message cannot say why.
        let error = run_entrypoint(streaming_attach_call())
            .expect_err("no plan here can authorize a write into that machine");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("--attach"), "{rendered}");
        assert!(rendered.contains("input grant"), "{rendered}");
    }

    #[test]
    fn a_one_shot_payload_needs_nothing_from_the_boot() {
        // The refusal must be about the grant, not about streaming being
        // involved anywhere: an unadmitted boot still delivers a payload.
        match authorize_stdin(false, None, b"[[], {}]".to_vec()) {
            Ok(DispatchStdin::OneShot(bytes)) => assert_eq!(bytes, b"[[], {}]"),
            Ok(DispatchStdin::Streaming(_)) => panic!("a one-shot call must not stream"),
            Err(e) => panic!("a one-shot payload asks for no authority: {e:#}"),
        }
    }

    #[test]
    fn an_unadmitted_boot_refuses_a_streamed_stdin() {
        // `--no-supervisor` short-circuits admission, so there is no grant and
        // nothing to write under. Streaming anyway would put the caller's
        // bytes into a workload nothing authorized.
        let error = authorize_stdin(true, None, Vec::new())
            .err()
            .expect("an unadmitted boot has no grant to write under");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("--no-supervisor"), "{rendered}");
        assert!(rendered.contains("admitted plan"), "{rendered}");
    }

    fn rendered_report(report: StreamedInputReport) -> (String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut sinks = CallOutput {
                sinks: EventSinks {
                    out: Box::new(&mut out),
                    err: Box::new(&mut err),
                },
                divergence: RecordedDivergence::default(),
            };
            report_streamed_stdin("call-vm", &mut sinks, report);
        }
        (
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    #[test]
    fn a_writer_that_stopped_early_says_so_with_the_reason() {
        let (out, err) = rendered_report(StreamedInputReport {
            frames: 3,
            bytes: 42,
            reached_eof: false,
            stopped_because: Some("the workload did not take streamed input".to_string()),
        });
        assert!(err.starts_with("[mvmctl-stream] "), "{err}");
        assert!(err.contains("stopped early"), "{err}");
        assert!(err.contains("42 byte(s) in 3 frame(s)"), "{err}");
        assert!(
            err.contains("the workload did not take streamed input"),
            "{err}"
        );
        assert!(out.is_empty(), "a diagnostic never lands on stdout");
    }

    #[test]
    fn a_call_that_ended_before_the_callers_stdin_did_says_so() {
        // The truncation is invisible otherwise: the workload simply saw less
        // than the caller sent.
        let (out, err) = rendered_report(StreamedInputReport {
            frames: 2,
            bytes: 9,
            reached_eof: false,
            stopped_because: None,
        });
        assert!(err.starts_with("[mvmctl-stream] "), "{err}");
        assert!(err.contains("ended before your stdin did"), "{err}");
        assert!(err.contains("9 byte(s) in 2 frame(s)"), "{err}");
        assert!(err.contains("call-vm"), "{err}");
        assert!(out.is_empty(), "a diagnostic never lands on stdout");
    }

    #[test]
    fn a_stream_that_ran_to_the_end_says_nothing() {
        // A notice that fires every time stops being read.
        let (out, err) = rendered_report(StreamedInputReport {
            frames: 5,
            bytes: 100,
            reached_eof: true,
            stopped_because: None,
        });
        assert!(err.is_empty(), "{err}");
        assert!(out.is_empty(), "{out}");
    }
}
