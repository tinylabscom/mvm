//! Guest vsock agent — runs inside the microVM, listens on
//! `GUEST_AGENT_PORT` (5252).
//!
//! Handles host-to-guest requests (Ping, WorkerStatus, SleepPrep, Wake, etc.)
//! and reports real system metrics via a background monitoring thread.
//!
//! ## Usage
//!
//! ```text
//! mvm-guest-agent [OPTIONS]
//!
//! Options:
//!   --config <path>            JSON config file (default: /etc/mvm/agent.json)
//!   --port <port>              Vsock port to listen on (default: 5252)
//!   --busy-threshold <float>   Load average threshold for busy (default: 0.1)
//!   --sample-interval <secs>   Monitoring sample interval (default: 5)
//!   --help, -h                 Print usage
//! ```

use rand::TryRng;
#[path = "mvm-guest-agent/boot.rs"]
mod boot;
#[path = "mvm-guest-agent/config.rs"]
mod config;
#[path = "mvm-guest-agent/globals.rs"]
mod globals;
#[path = "mvm-guest-agent/handlers.rs"]
mod handlers;
#[path = "mvm-guest-agent/health.rs"]
mod health;
#[path = "mvm-guest-agent/init.rs"]
mod init;
#[path = "mvm-guest-agent/interactive.rs"]
mod interactive;
#[path = "mvm-guest-agent/monitoring.rs"]
mod monitoring;
#[path = "mvm-guest-agent/port_forward.rs"]
mod port_forward;
#[path = "mvm-guest-agent/probe.rs"]
mod probe;
#[path = "mvm-guest-agent/signals.rs"]
mod signals;
#[path = "mvm-guest-agent/socket.rs"]
mod socket;
#[path = "mvm-guest-agent/state.rs"]
mod state;
#[path = "mvm-guest-agent/transport.rs"]
mod transport;

use ed25519_dalek::SigningKey;
use std::io::Write;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use mvm_agentd::vsock::{
    AuthenticatedSession, GuestRequest, GuestResponse, HOST_SIGNER_PUBKEY_PATH, TrafficPlane,
    TrustDecision, VERB_TRUST_POLICY_PATH, current_uid, enforce_verb_grant, is_verb_trust_baseline,
    launch_requires_grant, load_host_signer_verifying_key, load_pinned_verb_grant,
    load_verb_trust_policy, trust_decision, workload_privilege_refusal,
};

#[derive(Debug, Clone, Copy)]
struct ConnectionLimits {
    total: usize,
    data: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            total: 64,
            data: 48,
        }
    }
}

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_DATA_REQUESTS: AtomicUsize = AtomicUsize::new(0);

struct CounterGuard {
    counter: &'static AtomicUsize,
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire(counter: &'static AtomicUsize, limit: usize) -> Option<CounterGuard> {
    let mut active = counter.load(Ordering::Acquire);
    loop {
        if active >= limit {
            return None;
        }
        match counter.compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Some(CounterGuard { counter }),
            Err(observed) => active = observed,
        }
    }
}

use crate::boot::{init_entrypoint_validation, init_integrations, init_probes, init_warm_pool};
use crate::config::parse_config;
use crate::globals::{
    DEFAULT_SHUTDOWN_GRACE, HOT_BUSY_THRESHOLD_BITS, HOT_SAMPLE_INTERVAL_SECS, RELOAD_REQUESTED,
    SHUTDOWN_REQUESTED,
};
use crate::monitoring::monitoring_loop;
use crate::signals::{apply_reload, install_signal_handlers, shutdown_subsystems};
use crate::socket::{AuthenticatedWriter, close, write_response};
use crate::state::{ActivationState, AgentBootState, AgentState, IntegrationState, ProbeState};
use crate::transport::{AgentListener, accept_control, bind_listener};

use handlers::{
    handle_cancel_extension, handle_checkpoint_integrations, handle_close_stream_input,
    handle_entrypoint_status, handle_fs_diff, handle_fs_list, handle_fs_mkdir, handle_fs_move,
    handle_fs_read, handle_fs_remove, handle_fs_stat, handle_fs_write, handle_integration_status,
    handle_mount_volume, handle_ping, handle_post_restore, handle_primed_status,
    handle_probe_status, handle_proc_kill, handle_proc_list, handle_proc_send_input,
    handle_proc_signal, handle_proc_start, handle_proc_wait, handle_readiness_status,
    handle_resource_usage, handle_run_entrypoint_request, handle_run_extension, handle_sleep_prep,
    handle_start_unix_socket_forward, handle_stream_input, handle_unmount_volume,
    handle_update_idle_timeout, handle_wake, handle_worker_status,
};
use interactive::{
    handle_console_close, handle_console_open, handle_console_resize, handle_exec,
    handle_exec_batch, handle_run_code, handle_run_detached,
};

/// Shared references every per-verb handler needs: the state Arcs
/// threaded through `accept`, plus the connection file itself. Most
/// handlers only touch one or two fields; the handful of streaming
/// verbs (`Exec`, `RunEntrypoint`, `RunCode`, `ProcWait`) write
/// intermediate frames to `file` before returning their terminal
/// response.
struct HandlerCtx<'a> {
    file: &'a mut dyn Write,
    state: &'a Arc<Mutex<AgentState>>,
    integration_state: &'a Arc<Mutex<IntegrationState>>,
    probe_state: &'a Arc<Mutex<ProbeState>>,
    boot_state: &'a Arc<AgentBootState>,
}

fn send_authenticated_response(
    file: &mut std::fs::File,
    session: &mut AuthenticatedSession,
    response: &GuestResponse,
) {
    let mut sink = AuthenticatedWriter::new(file, session);
    write_response(&mut sink, response);
}

fn handle_client(
    fd: RawFd,
    state: &Arc<Mutex<AgentState>>,
    integration_state: &Arc<Mutex<IntegrationState>>,
    probe_state: &Arc<Mutex<ProbeState>>,
    boot_state: &Arc<AgentBootState>,
    guest_signing_key: &SigningKey,
) {
    // SAFETY: fd comes from accept and is a valid file descriptor owned by this function.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let Some(host_signer_key) = boot_state.host_signer_key() else {
        eprintln!("mvm-guest-agent: rejecting control connection without a pinned host key");
        return;
    };
    let mut session =
        match AuthenticatedSession::guest(&mut file, guest_signing_key.clone(), &host_signer_key) {
            Ok(session) => session,
            // A peer that hangs up part-way through the handshake did not fail
            // to authenticate — it produced no signature at all, and the read
            // hit end-of-stream. On this socket that is the host's readiness
            // poll, which connects on a backoff while the guest boots and drops
            // each probe once it has its answer. Reporting it as a failed
            // authentication put a security-relevant line on every healthy
            // boot, which is how a real one gets skipped.
            Err(error) if error.is_peer_hangup() => {
                eprintln!(
                    "mvm-guest-agent: control peer disconnected before completing the \
                     handshake (readiness probe); no session opened"
                );
                return;
            }
            Err(error) => {
                eprintln!("mvm-guest-agent: authenticated control handshake failed: {error}");
                return;
            }
        };

    // The authenticated session handshake is the mandatory prelude. A legacy
    // ProtocolHello may still be sent by an older helper for capability
    // negotiation, but it is no longer the security boundary.
    let mut hello_seen = true;
    let req = loop {
        let req: GuestRequest = match session.read(&mut file) {
            Ok(req) => req,
            Err(error) => {
                eprintln!("mvm-guest-agent: rejected control frame: {error}");
                return;
            }
        };

        match req {
            GuestRequest::ProtocolHello {
                host_protocol_version,
                min_supported_version,
                host_version,
                requested_capabilities,
            } => {
                let resp = mvm_agentd::vsock::protocol_hello_response(
                    host_protocol_version,
                    min_supported_version,
                    &host_version,
                    &requested_capabilities,
                );
                if matches!(resp, GuestResponse::ProtocolHelloAck { .. }) {
                    hello_seen = true;
                }
                send_authenticated_response(&mut file, &mut session, &resp);
            }
            other => {
                if !hello_seen {
                    let resp = GuestResponse::ProtocolMismatch {
                        host_protocol_version: 0,
                        agent_protocol_version: mvm_agentd::vsock::PROTOCOL_VERSION,
                        required_action: mvm_agentd::vsock::ProtocolUpgradeAction::UpgradeHost,
                        message: "guest agent requires protocol_hello before any other request"
                            .to_string(),
                    };
                    send_authenticated_response(&mut file, &mut session, &resp);
                    return;
                }
                break other;
            }
        }
    };

    // Initramfs PID-1 activation gate.  Before `ActivateEnvironment`
    // is accepted and applied, only `ActivateEnvironment` may pass; every
    // other operational verb is refused with `NotActivated`.  After a
    // failure the agent stays in `Failed` and reports the reason.
    if init::is_pid1() {
        match boot_state.activation_state() {
            ActivationState::Awaiting | ActivationState::Activating
                if !matches!(req, GuestRequest::ActivateEnvironment { .. }) =>
            {
                let resp = GuestResponse::NotActivated;
                send_authenticated_response(&mut file, &mut session, &resp);
                return;
            }
            ActivationState::Failed { ref message } => {
                let resp = GuestResponse::ActivateEnvironmentError {
                    message: message.clone(),
                };
                send_authenticated_response(&mut file, &mut session, &resp);
                return;
            }
            _ => {}
        }
    }

    let active_profile = boot_state.profile;

    // Profile gate. Reject dev-only verbs in sealed-prod *before*
    // the per-variant handler runs. The gate returns a typed
    // `UnsupportedInProfile` response so an SDK can branch on
    // capability without parsing message text — this sits at the
    // protocol layer in addition to the per-handler policy checks
    // (dispatcher allowlists are not enough by themselves) and the
    // Runtime profile and signed-grant checks are the load-bearing boundary
    // for DevOnly verbs; handler code is shared by every guest artifact.
    if !req.allowed_in(active_profile) {
        let resp = GuestResponse::UnsupportedInProfile {
            profile: active_profile,
            verb: req.verb_name().to_string(),
        };
        send_authenticated_response(&mut file, &mut session, &resp);
        return;
    }

    // Fail-closed when the measured verb-trust policy required a grant that was
    // not validly pinned. Baseline verbs (protocol-hello, ping, readiness-status)
    // pass through so the host can still observe liveness; all other control RPCs
    // are refused with the same VerbNotAuthorized shape as the verb-grant gate.
    let (trust_denied, verb_grant) = boot_state.grant_state();
    if trust_denied && !is_verb_trust_baseline(req.kind_name()) {
        let resp = GuestResponse::VerbNotAuthorized {
            verb: req.kind_name().to_string(),
        };
        send_authenticated_response(&mut file, &mut session, &resp);
        return;
    }

    if let Some(resp) = enforce_verb_grant(&req, verb_grant.as_ref()) {
        send_authenticated_response(&mut file, &mut session, &resp);
        return;
    }

    // No workload code runs as root. The privilege drop during activation is
    // the mechanism; this is the backstop that makes a boot path which never
    // reached that drop fail closed and name itself, rather than silently
    // running the workload with uid 0.
    if let Some(resp) = workload_privilege_refusal(&req, current_uid()) {
        send_authenticated_response(&mut file, &mut session, &resp);
        return;
    }

    let limits = ConnectionLimits::default();
    let _data_guard = if req.verb().traffic_plane() == TrafficPlane::Data {
        let Some(guard) = try_acquire(&ACTIVE_DATA_REQUESTS, limits.data) else {
            send_authenticated_response(
                &mut file,
                &mut session,
                &GuestResponse::Error {
                    message: "guest data plane is at its concurrency limit".to_string(),
                },
            );
            return;
        };
        Some(guard)
    } else {
        None
    };

    let resp = {
        let mut sink = AuthenticatedWriter::new(&mut file, &mut session);
        let mut ctx = HandlerCtx {
            file: &mut sink,
            state,
            integration_state,
            probe_state,
            boot_state,
        };

        match req {
            // The hello-prelude loop above guarantees `req` is not a
            // ProtocolHello, but keep an explicit, loud panic to catch
            // future loop refactors that would silently let a hello fall
            // through. Returning `Error` here would mask the bug.
            GuestRequest::ProtocolHello { .. } => {
                unreachable!("protocol hello reached operational dispatch")
            }

            GuestRequest::ActivateEnvironment(env) => {
                match init::apply_activation(&env, boot_state) {
                    Ok(()) => {
                        // Universal initramfs: the workload root was just
                        // pivoted into place. Start entrypoint validation and
                        // the warm pool in the background so activation stays
                        // fast, while keeping the chained dependency order.
                        if init::is_pid1() {
                            let bs = Arc::clone(boot_state);
                            std::thread::spawn(move || {
                                init_entrypoint_validation(&bs);
                                init_warm_pool(&bs);
                            });
                        }
                        GuestResponse::ActivateEnvironmentAck
                    }
                    Err(e) => {
                        let message = e.to_string();
                        boot_state.set_activation(ActivationState::Failed {
                            message: message.clone(),
                        });
                        GuestResponse::ActivateEnvironmentError { message }
                    }
                }
            }

            GuestRequest::Ping => handle_ping(),
            GuestRequest::ResourceUsage => handle_resource_usage(),
            GuestRequest::WorkerStatus => handle_worker_status(&mut ctx),
            GuestRequest::SleepPrep { drain_timeout_secs } => handle_sleep_prep(drain_timeout_secs),
            GuestRequest::Wake => handle_wake(&mut ctx),
            GuestRequest::IntegrationStatus => handle_integration_status(&mut ctx),
            GuestRequest::CheckpointIntegrations { integrations } => {
                handle_checkpoint_integrations(integrations)
            }
            GuestRequest::ProbeStatus => handle_probe_status(&mut ctx),
            GuestRequest::PrimedStatus => handle_primed_status(),
            GuestRequest::PostRestore {
                token,
                hostname,
                host_epoch_secs,
                grant_envelope,
            } => handle_post_restore(
                &mut ctx,
                token,
                hostname.as_deref(),
                host_epoch_secs,
                grant_envelope,
            ),

            GuestRequest::Exec {
                command,
                stdin,
                timeout_secs,
            } => handle_exec(&mut ctx, command, stdin, timeout_secs),

            GuestRequest::ExecBatch {
                stages,
                commands,
                timeout_secs,
            } => handle_exec_batch(stages, commands, timeout_secs),

            GuestRequest::RunCode { code, timeout_secs } => {
                handle_run_code(&mut ctx, code, timeout_secs)
            }

            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs,
                env,
                stream_input,
            } => handle_run_entrypoint_request(&mut ctx, stdin, timeout_secs, env, stream_input),

            GuestRequest::RunExtension { dispatch } => handle_run_extension(ctx.file, dispatch),
            GuestRequest::CancelExtension { cancellation } => handle_cancel_extension(cancellation),

            // The host→guest half of the stream plane. Admission happened on
            // the host, at the gate that holds the signed plan; what reaches
            // here is bytes it already cleared, in the order it cleared them.
            GuestRequest::StreamInput(frame) => handle_stream_input(frame),
            GuestRequest::CloseStreamInput(close) => handle_close_stream_input(close),

            GuestRequest::RunDetached { argv, env } => handle_run_detached(argv, env),

            GuestRequest::FsDiff => handle_fs_diff(),

            GuestRequest::StartUnixSocketForward {
                guest_path,
                host_vsock_port,
                socket_mode,
            } => handle_start_unix_socket_forward(guest_path, host_vsock_port, socket_mode),

            // PTY-over-vsock console. The profile and signed-grant gates above
            // reject this DevOnly verb before the handler is reached when the
            // run is not eligible.
            GuestRequest::ConsoleOpen {
                cols,
                rows,
                env,
                argv,
            } => handle_console_open(cols, rows, env, argv),

            GuestRequest::ConsoleClose { session_id } => handle_console_close(session_id),

            GuestRequest::ConsoleResize {
                session_id,
                cols,
                rows,
            } => handle_console_resize(session_id, cols, rows),

            // Report whether boot-time entrypoint validation succeeded.
            // Used by `mvmctl doctor` against a
            // running guest. Prod-safe — no inputs, no secrets in the
            // response (just a path + reason string).
            GuestRequest::EntrypointStatus => handle_entrypoint_status(),

            // Structured readiness snapshot. Cheap — a single mutex
            // lock + struct copy. Designed to be the
            // verb a host polls during `mvmctl wait <vm> --for ...`
            // without back-pressure on the rest of the agent.
            GuestRequest::ReadinessStatus => handle_readiness_status(&mut ctx),

            // FS RPC verbs. Production-safe surface backed by
            // `mvm_agentd::fs_rpc::handle_with_defaults`: every path
            // routes through `mvm_core::crypto::policy::PathPolicy` (deny
            // list + canonicalization), per-call caps gate read/write
            // sizes, and `FsResult::Error` carries a typed `kind` so
            // the host can branch without parsing message text.
            GuestRequest::FsRead {
                path,
                offset,
                length,
                ..
            } => handle_fs_read(path, offset, length),
            GuestRequest::FsWrite {
                path,
                content,
                mode,
                create_parents,
                offset,
                truncate,
                ..
            } => handle_fs_write(
                path,
                content,
                mode,
                create_parents,
                offset.unwrap_or(0),
                truncate,
            ),
            GuestRequest::FsList { path, .. } => handle_fs_list(path),
            GuestRequest::FsStat {
                path,
                follow_symlinks,
            } => handle_fs_stat(path, follow_symlinks),
            GuestRequest::FsMkdir {
                path,
                mode,
                parents,
            } => handle_fs_mkdir(path, mode, parents),
            GuestRequest::FsRemove {
                path, recursive, ..
            } => handle_fs_remove(path, recursive),
            GuestRequest::FsMove { from, to, .. } => handle_fs_move(from, to),

            // Process control verbs. The profile and signed-grant gates above
            // enforce their DevOnly classification before dispatch.
            GuestRequest::ProcStart {
                argv,
                env,
                cwd,
                stdin,
                timeout_secs: _, // applied during ProcWait
            } => handle_proc_start(argv, env, cwd, stdin),
            GuestRequest::ProcList => handle_proc_list(),
            GuestRequest::ProcSignal { pid_token, signum } => handle_proc_signal(pid_token, signum),
            GuestRequest::ProcSendInput { pid_token, bytes } => {
                handle_proc_send_input(pid_token, bytes)
            }
            GuestRequest::ProcKill { pid_token } => handle_proc_kill(pid_token),
            GuestRequest::ProcWait {
                pid_token,
                timeout_secs,
            } => handle_proc_wait(&mut ctx, pid_token, timeout_secs),

            // virtio-fs volume mount/unmount. Production-safe; every
            // host-supplied path runs through
            // `mvm_core::crypto::policy::MountPathPolicy` before any
            // mount(2) syscall. Real handler lives in `mvm_agentd::volume`.
            GuestRequest::MountVolume {
                volume_name,
                guest_path,
                read_only,
            } => handle_mount_volume(volume_name, guest_path, read_only),
            GuestRequest::UnmountVolume { guest_path, force } => {
                handle_unmount_volume(guest_path, force)
            }

            // Substrate-side mirror of `mvmctl session set-timeout`. If
            // the warm-process pool is active (tier-2 dispatch), the
            // agent updates its idle-recycle threshold and a recycler
            // thread reaps individual workers idle past the new
            // timeout — keeping the VM up while pruning waste. If no pool
            // is active, the verb is a no-op acknowledged with
            // `applied_secs = 0`; the host-side reaper remains the only
            // enforcement on cold-path-only builds.
            GuestRequest::UpdateIdleTimeout { secs } => handle_update_idle_timeout(secs),
        }
    };
    send_authenticated_response(&mut file, &mut session, &resp);
}

#[derive(Clone)]
struct GuestServer {
    state: Arc<Mutex<AgentState>>,
    integration_state: Arc<Mutex<IntegrationState>>,
    probe_state: Arc<Mutex<ProbeState>>,
    boot_state: Arc<AgentBootState>,
    guest_signing_key: Arc<SigningKey>,
}

impl GuestServer {
    fn handle_inline(&self, fd: RawFd, connection_guard: CounterGuard) {
        let _connection_guard = connection_guard;
        handle_client(
            fd,
            &self.state,
            &self.integration_state,
            &self.probe_state,
            &self.boot_state,
            &self.guest_signing_key,
        );
    }

    fn spawn_handler(&self, fd: RawFd, connection_guard: CounterGuard) {
        let server = self.clone();
        std::thread::spawn(move || server.handle_inline(fd, connection_guard));
    }
}

fn acquire_connection_slot(fd: RawFd) -> Option<CounterGuard> {
    let limits = ConnectionLimits::default();
    let Some(connection_guard) = try_acquire(&ACTIVE_CONNECTIONS, limits.total) else {
        eprintln!("mvm-guest-agent: rejecting connection at concurrency limit");
        // SAFETY: fd was returned by accept and ownership has not been passed
        // to a File or another thread.
        unsafe {
            close(fd);
        }
        return None;
    };
    Some(connection_guard)
}

/// Serve PID-1 activation synchronously so the mount, identity, capability,
/// bounding-set, and `no_new_privs` transition occurs before any thread is
/// created. Linux credentials are per-thread; doing this in a worker would
/// harden only that worker and leave later handlers with different credentials.
fn serve_until_activated(listener: &AgentListener, server: &GuestServer) -> bool {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            return false;
        }
        let Some(cfd) = accept_control(listener) else {
            continue;
        };
        server.boot_state.mark_first_accept();
        let Some(connection_guard) = acquire_connection_slot(cfd) else {
            continue;
        };
        server.handle_inline(cfd, connection_guard);
        if matches!(
            server.boot_state.activation_state(),
            ActivationState::Activated
        ) {
            return true;
        }
    }
}

fn main() {
    let cfg = parse_config();

    // Resolve the active vsock profile from the baked image config.
    // The policy file lives on a dm-verity rootfs for sealed-prod
    // images, so its `profile` field can't be widened at runtime —
    // flipping it would break the
    // verity hash and the kernel panics in `mvm-verity-init` before
    // userspace. Absence of `/etc/mvm/security.json` is treated as an
    // unprovisioned dev image (`SecurityPolicy::dev_defaults`).
    let active_profile = mvm_agentd::builder_agent::load_security_policy()
        .ok()
        .flatten()
        .map(|p| p.profile)
        .unwrap_or_else(|| mvm_core::security::SecurityPolicy::dev_defaults().profile);

    // PID-1 initramfs setup: mount early filesystems and install the
    // SIGCHLD reaper before the control plane comes up.  On non-PID-1
    // boots this is a no-op.
    init::early_setup();

    // Install signal handlers BEFORE vsock bind + background init.
    // Same handlers fire whether we're mid-warmup
    // or steady-state; better to wire them up before any work that
    // might want clean teardown.
    install_signal_handlers();

    // Bind the control-plane listener: AF_VSOCK on microVM backends,
    // AF_UNIX on the shared-kernel container tier (see transport.rs).
    let listener = match bind_listener(cfg.port) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!(
                "failed to bind control-plane listener (port {}): {e}",
                cfg.port
            );
            std::process::exit(1);
        }
    };

    // Record boot time for startup grace period tracking.
    let boot_at = std::time::Instant::now();

    // Shared readiness state. Created AFTER vsock bind+listen so
    // `mark_vsock_bound` stamps an accurate
    // `vsock_bound_ms`. Cloned into every handler thread via
    // `Arc::clone` — the inner Mutex serialises the few writes
    // (`set_entrypoint`, `set_warm_pool`, …) without measurable
    // contention because writes only fire at boot completion events.
    let pinned_verb_grant = load_pinned_verb_grant(
        std::path::Path::new("/run/mvm/verb-grant.json"),
        std::path::Path::new(HOST_SIGNER_PUBKEY_PATH),
        chrono::Utc::now(),
    );
    // Resolve the host-signer trust anchor once at boot and hold it for the
    // agent's lifetime. PostRestore re-pin verifies incoming envelopes against
    // this anchor, never against the self-attested key inside the envelope.
    let boot_host_signer_key =
        match load_host_signer_verifying_key(std::path::Path::new(HOST_SIGNER_PUBKEY_PATH)) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("mvm-guest-agent: host-signer pubkey invalid, no re-pin anchor: {e}");
                None
            }
        };
    let boot_state_val = AgentBootState::new(active_profile, boot_at);
    // Initialise verb_grant + trust_denied under the inner lock so the
    // same path is used by both boot-time init and PostRestore re-pin.
    {
        if let Ok(mut s) = boot_state_val.inner.lock() {
            s.verb_grant = pinned_verb_grant.clone();
            s.host_signer_key = boot_host_signer_key;
        }
    }
    let policy = load_verb_trust_policy(std::path::Path::new(VERB_TRUST_POLICY_PATH));
    let launch_req = std::fs::read_to_string("/proc/cmdline")
        .map(|cmdline| launch_requires_grant(&cmdline))
        .unwrap_or(false);
    match trust_decision(policy.as_ref(), pinned_verb_grant.is_some(), launch_req) {
        TrustDecision::Serve => {}
        TrustDecision::ObserveGap => {
            eprintln!(
                "mvm-guest-agent: verb-trust policy present but no valid grant pinned (observe mode)"
            );
        }
        TrustDecision::FailClosed => {
            eprintln!(
                "mvm-guest-agent: verb-trust policy requires a grant but none pinned — refusing control RPCs"
            );
            if let Ok(mut s) = boot_state_val.inner.lock() {
                s.trust_denied = true;
            }
        }
    }
    let boot_state = Arc::new(boot_state_val);
    let mut guest_seed = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut guest_seed)
        .expect("SysRng entropy for guest signing key");
    let guest_signing_key = Arc::new(SigningKey::from_bytes(&guest_seed));
    boot_state.mark_vsock_bound();

    // On legacy per-rootfs boots the agent is not PID 1 and the workload
    // root is already in place, so validate the entrypoint and start the warm
    // pool now. On the universal initramfs path validation is deferred until
    // after `ActivateEnvironment` pivots into the workload rootfs; running it
    // here would validate the initramfs root, which has no
    // `/etc/mvm/entrypoint`.
    if !init::is_pid1() {
        let bs = Arc::clone(&boot_state);
        std::thread::spawn(move || {
            init_entrypoint_validation(&bs);
            init_warm_pool(&bs);
        });
    }

    let state = Arc::new(Mutex::new(AgentState::new()));
    // Seed the hot-reloadable atomics from the boot-time config so
    // monitoring_loop picks up the same values it would have with
    // the prior captured-by-value shape.
    HOT_BUSY_THRESHOLD_BITS.store(cfg.busy_threshold.to_bits(), Ordering::Release);
    HOT_SAMPLE_INTERVAL_SECS.store(cfg.sample_interval_secs, Ordering::Release);

    let integration_state = Arc::new(Mutex::new(IntegrationState {
        integrations: Vec::new(),
    }));
    let probe_state = Arc::new(Mutex::new(ProbeState { probes: Vec::new() }));

    let server = GuestServer {
        state: Arc::clone(&state),
        integration_state: Arc::clone(&integration_state),
        probe_state: Arc::clone(&probe_state),
        boot_state: Arc::clone(&boot_state),
        guest_signing_key: Arc::clone(&guest_signing_key),
    };

    // PID 1 must activate synchronously. `apply_activation` changes Linux
    // credentials and capability sets, which are per-thread at the kernel
    // boundary; no background or request thread may exist before it returns.
    if init::is_pid1() && serve_until_activated(&listener, &server) {
        init::start_orphan_reaper();
    }

    if !SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
        let monitor_state = Arc::clone(&state);
        std::thread::spawn(move || monitoring_loop(monitor_state));

        // Defer integration and probe scans to background threads, but only
        // after PID-1 activation has completed its privilege transition.
        {
            let bs = Arc::clone(&boot_state);
            let s = Arc::clone(&integration_state);
            std::thread::spawn(move || init_integrations(&bs, &s));
        }
        {
            let bs = Arc::clone(&boot_state);
            let s = Arc::clone(&probe_state);
            std::thread::spawn(move || init_probes(&bs, &s));
        }
    }

    // Port forwarders are started on-demand via StartPortForward requests
    // from the host (works with all backends, no config drive needed).

    // Every accepted connection gets its own bounded worker so a long-running
    // data stream cannot prevent Ping, readiness, sleep, or shutdown requests
    // from being accepted. Data dispatch has a lower cap than total dispatch,
    // reserving capacity for control traffic.
    //
    // Poll `SHUTDOWN_REQUESTED` between accepts and after each
    // `accept()` return (signals deliver `EINTR` so accept
    // returns < 0, which already triggers the bottom-of-loop check).
    // Once the flag flips, break out and drain via
    // `shutdown_subsystems`.
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            break;
        }
        // Apply pending SIGHUP-driven config reload.
        // Compare-and-swap to false so a concurrent SIGHUP between
        // the load and the apply isn't lost (it'll re-set the flag
        // and we'll pick it up on the next iteration).
        if RELOAD_REQUESTED
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            apply_reload();
        }
        // Accept one control connection; the transport applies its own
        // peer authorization (the vsock host-CID gate, or the unix socket
        // directory boundary — see transport.rs). `None` covers both EINTR
        // and a rejected peer: re-check the shutdown flag and retry.
        let Some(cfd) = accept_control(&listener) else {
            if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                break;
            }
            // Same fast-path for SIGHUP — apply the reload on the
            // next iteration's compare_exchange.
            continue;
        };
        // Stamp first-accept timing once. Idempotent inside
        // `AgentBootState` — subsequent calls are no-ops.
        boot_state.mark_first_accept();
        let Some(connection_guard) = acquire_connection_slot(cfd) else {
            continue;
        };
        server.spawn_handler(cfd, connection_guard);
    }

    // Close the listening socket so any in-flight accept on a
    // peer thread (warm-process accept-thread-per-conn mode) wakes.
    if let AgentListener::Vsock(fd) = listener {
        // SAFETY: fd was created by socket() and is owned by us. The AF_UNIX
        // variant closes on drop.
        unsafe {
            close(fd);
        }
    }
    shutdown_subsystems(DEFAULT_SHUTDOWN_GRACE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::GuestCapability;
    use mvm_core::security::AgentProfile;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn data_plane_limit_reserves_control_plane_capacity() {
        let limits = ConnectionLimits::default();
        assert_eq!(limits.total, 64);
        assert_eq!(limits.data, 48);
        assert!(limits.total - limits.data >= 16);
    }

    #[test]
    fn counter_guard_enforces_and_releases_capacity() {
        static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        TEST_COUNTER.store(0, Ordering::Release);

        let first = try_acquire(&TEST_COUNTER, 2).expect("first slot");
        let second = try_acquire(&TEST_COUNTER, 2).expect("second slot");
        assert!(try_acquire(&TEST_COUNTER, 2).is_none());
        drop(first);
        let replacement = try_acquire(&TEST_COUNTER, 2).expect("released slot");
        drop(second);
        drop(replacement);
        assert_eq!(TEST_COUNTER.load(Ordering::Acquire), 0);
    }

    #[test]
    fn handle_client_requires_authenticated_control() {
        let (mut host, guest) = UnixStream::pair().expect("unix stream pair");
        host.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        host.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");

        let state = Arc::new(Mutex::new(AgentState::new()));
        let integration_state = Arc::new(Mutex::new(IntegrationState {
            integrations: vec![],
        }));
        let probe_state = Arc::new(Mutex::new(ProbeState { probes: vec![] }));
        // handle_client takes `&Arc<AgentBootState>` (carrying
        // profile + boot_at + readiness) instead of a bare
        // boot_at + active_profile.
        let boot_state = Arc::new(AgentBootState::new(
            AgentProfile::Dev,
            std::time::Instant::now(),
        ));
        boot_state.mark_vsock_bound();
        let host_key = SigningKey::from_bytes(&[7u8; 32]);
        let guest_key = SigningKey::from_bytes(&[9u8; 32]);
        boot_state
            .inner
            .lock()
            .expect("boot state lock")
            .host_signer_key = Some(host_key.verifying_key());

        let handle = std::thread::spawn(move || {
            handle_client(
                guest.into_raw_fd(),
                &state,
                &integration_state,
                &probe_state,
                &boot_state,
                &guest_key,
            );
        });

        let mut session = AuthenticatedSession::host(&mut host, "test-control", host_key)
            .expect("authenticated host session");
        session
            .write(
                &mut host,
                &GuestRequest::ProtocolHello {
                    host_protocol_version: mvm_agentd::vsock::PROTOCOL_VERSION,
                    min_supported_version: mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
                    host_version: "test-host".to_string(),
                    requested_capabilities: vec![GuestCapability::Ping],
                },
            )
            .expect("write protocol hello");

        let ack: GuestResponse = session.read(&mut host).expect("read protocol ack");
        assert!(matches!(
            ack,
            GuestResponse::ProtocolHelloAck {
                capabilities,
                ..
            } if capabilities == vec![GuestCapability::Ping]
        ));

        session
            .write(&mut host, &GuestRequest::Ping)
            .expect("write ping");
        let pong: GuestResponse = session.read(&mut host).expect("read pong");
        assert!(matches!(pong, GuestResponse::Pong));

        // An operational request owns the authenticated connection. The
        // agent closes it after replying, so a caller cannot carry a
        // pre-restore session (including its sequence numbers) into a later
        // request; the next request must perform a fresh handshake.
        let _ = session.write(&mut host, &GuestRequest::Ping);
        let reused = session.read::<GuestResponse>(&mut host);
        assert!(reused.is_err(), "operational sessions must not be reusable");

        handle.join().expect("handle_client thread");
    }

    /// A control connection without the pinned host identity must fail during
    /// the authenticated session handshake, before request dispatch begins.
    #[test]
    fn handle_client_rejects_control_without_pinned_host_key() {
        let (mut host, guest) = UnixStream::pair().expect("unix stream pair");
        host.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        host.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");

        let state = Arc::new(Mutex::new(AgentState::new()));
        let integration_state = Arc::new(Mutex::new(IntegrationState {
            integrations: vec![],
        }));
        let probe_state = Arc::new(Mutex::new(ProbeState { probes: vec![] }));
        let boot_state = Arc::new(AgentBootState::new(
            AgentProfile::Dev,
            std::time::Instant::now(),
        ));
        boot_state.mark_vsock_bound();
        let host_key = SigningKey::from_bytes(&[7u8; 32]);
        let guest_key = SigningKey::from_bytes(&[9u8; 32]);

        let handle = std::thread::spawn(move || {
            handle_client(
                guest.into_raw_fd(),
                &state,
                &integration_state,
                &probe_state,
                &boot_state,
                &guest_key,
            );
        });

        let result = AuthenticatedSession::host(&mut host, "untrusted-control", host_key);
        assert!(
            result.is_err(),
            "agent must refuse an unpinned host identity"
        );

        handle.join().expect("handle_client thread");
    }
}
