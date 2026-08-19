//! `mvm-network-endpoint` — the per-VM secret-substitution moat.
//! Spawned per-VM by the backend, it is the one process that holds
//! the workload's secrets in the clear: it opens the host's encrypted secret +
//! binding stores, builds the per-VM `SubstitutionService`, and serves the
//! guest→host substitution channel. The guest only ever holds the opaque
//! `mvm-secret-<hex>` placeholder; the real credential is substituted here and
//! reaches the wire via the host forward leg — never the guest.
//!
//! Process contract:
//! 1. The backend writes an `EndpointConfig` JSON on stdin and closes it.
//! 2. The endpoint opens the stores, mints placeholders, and writes ONE JSON
//!    line to **stdout** — the `[(guest var, placeholder)]` pairs the backend
//!    injects into the guest launch env — then flushes. This is the ready
//!    handshake: the backend reads that line before booting the guest.
//! 3. The endpoint binds its listener and serves until the backend kills it.
//!
//! All logging goes to **stderr** so stdout carries exactly the one handshake
//! line. Sibling to `mvm-broker` / `mvm-host-signer` in the process moat.
//!
//! Self-confinement: because this process simultaneously holds plaintext
//! secrets and parses untrusted guest bytes, it applies mvm's Landlock +
//! seccomp-BPF confinement to itself before serving the first guest byte
//! (Linux only — the same self-moat the firecracker-bridge uses). The
//! confinement is fail-closed: if it cannot be applied on a supporting kernel,
//! the endpoint exits rather than serve secrets unconfined.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use tracing::{info, warn};

use mvm_hostd::keyholder::secret_placeholder_env;
use mvm_hostd::supervisor::flowmux::{FlowMuxSession, registry::RegistryLimits};
use mvm_hostd::supervisor::network_endpoint::{
    EgressMode, EndpointConfig, EndpointHandshake, EndpointTransport, ResolverBackend, assemble,
    build_audit_recorder, fingerprint_bound_secrets, parse,
};

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-network-endpoint stdin read failed")?;
    Ok(buf)
}

fn main() -> Result<()> {
    // First statement in the process: a panic before this line would
    // print its payload unredacted.
    mvm_hostd::panic_hook::install("substitution-endpoint");
    // This process holds the workload's secrets in the clear; a backend that
    // died must not leave it serving as an orphan. Exit the instant the parent
    // is gone (macOS / SIGKILL gap the spawn-side attach misses).
    mvm_hostd::parent_death::exit_when_orphaned();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let raw = read_stdin_blocking()?;
    let cfg = parse(&raw).context("mvm-network-endpoint config parse failed")?;
    info!(
        tenant_id = %cfg.tenant_id,
        secrets = cfg.secrets.len(),
        "mvm-network-endpoint config loaded"
    );

    // Bind BEFORE the handshake so the backend knows the endpoint is reachable
    // the moment it reads the ready line — no listen/connect race at boot. The
    // terminator listener binds here too when configured, so the nft redirect
    // target is live before the guest boots.
    let bound = bind_transport(&cfg.transport)?;
    let terminator = bind_terminator(cfg.terminator_listen)?;
    let session_readiness = bind_session_readiness(cfg.session_ready_socket.as_deref())?;
    // Always assembled. The one mode that skipped it was `raw`, which is gone:
    // a FlowMux guest can open a typed HTTP flow at any point in its life, and
    // deciding at boot that it will not is the kind of guess that leaves a
    // placeholder with nothing to resolve it.
    let assembled = Some(assemble(&cfg).context("assembling substitution service")?);
    mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
        &cfg,
        assembled.is_some(),
    )?;

    // Ready handshake: report the minted (guest var → placeholder) pairs on
    // stdout so the backend can set them in the guest launch env, then boot.
    // Values are never reported — only opaque placeholders.
    //
    // The same line carries the input-gate fingerprints. This is the one
    // process that holds these secrets in the clear, so it is the only place
    // their recognisable shape can be computed without moving plaintext
    // anywhere; what crosses is a length, a rolling hash and a category each.
    // A VM serving raw egress assembled nothing and has no secrets to
    // fingerprint.
    let handed_len = assembled
        .as_ref()
        .map(|(_, handed)| handed.len())
        .unwrap_or_default();
    let handshake = EndpointHandshake {
        env: assembled
            .as_ref()
            .map(|(_, handed)| secret_placeholder_env(handed))
            .unwrap_or_default(),
        input_fingerprints: fingerprint_bound_secrets(&cfg)
            .context("fingerprinting the endpoint's secrets")?,
    };
    let fingerprinted = handshake.input_fingerprints.len();
    let line = serde_json::to_string(&handshake).context("serializing the ready handshake")?;
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{line}").context("writing handshake line")?;
        stdout.flush().context("flushing handshake line")?;
    }
    info!(
        handed = handed_len,
        fingerprinted, "placeholders handed; serving"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-subst-endpoint")
        .build()
        .context("tokio runtime build failed")?;

    // One configured deadline for the forward leg AND the untrusted guest socket
    // (terminator). The UDS/vsock path already honors this via HardenedForwarder.
    let forward_timeout = std::time::Duration::from_secs(cfg.forward_timeout_secs);

    // Self-confine before serving any guest byte. The runtime's worker threads
    // are already spawned (multi-thread `build()` spawns them eagerly), and the
    // listeners are bound above — so the broad setup is done. `clone`/`clone3`
    // stay in the allowlist anyway because tokio spawns blocking
    // threads lazily during serve (the vsock accept loop and the resolver run
    // on `spawn_blocking`). We confine from inside `block_on` so the policy
    // applies to the runtime thread that drives the accept loop. Fail-closed:
    // any confinement error aborts before the first guest connection.
    runtime.block_on(async move {
        confine_endpoint(&cfg)?;
        serve(
            &cfg,
            assembled.map(|(service, _)| service),
            bound,
            terminator,
            session_readiness,
            forward_timeout,
        )
        .await
    })
}

/// The one extra Landlock/seccomp grant `Remote` needs beyond `Local`: the
/// fleet-secrets daemon's UDS path, or `None` when resolving locally. Kept as
/// a standalone, non-platform-gated function (rather than inlined into
/// `confine_endpoint`, whose real body is Linux-only) so the `Remote ⇒
/// Some(uds)` decision is unit-testable on every contributor host, not just
/// Linux CI — see `ConfinementSpec::network_endpoint`'s doc for what this
/// grants once it reaches the confinement builder.
fn resolver_uds_path(cfg: &EndpointConfig) -> Option<&std::path::Path> {
    match &cfg.resolver {
        ResolverBackend::Local => None,
        ResolverBackend::Remote { uds_path, .. } => Some(uds_path.as_path()),
    }
}

/// Apply mvm's self-confinement (Landlock FS + seccomp-BPF) to the endpoint.
///
/// Linux-only effect; on macOS/Windows the jailer's `confine_self` stub errors,
/// so we skip the call there (the bin must still compile + run on contributor
/// hosts for tests). The store dirs granted read access are resolved exactly as
/// `assemble` resolves them, so the confinement matches the resolver's runtime
/// reads. Fail-closed per the jailer's partial-confinement contract: on error
/// we return it up to `main`, which exits nonzero before serving secrets.
#[cfg(target_os = "linux")]
fn confine_endpoint(cfg: &EndpointConfig) -> Result<()> {
    use mvm_hostd::jailer::{ConfinementSpec, confine_self};
    use mvm_hostd::supervisor::network_endpoint::resolve_store_dirs;

    let (secret_dir, binding_dir) =
        resolve_store_dirs(cfg).context("resolve substitution-endpoint store dirs")?;
    // The audit recorder (when the host signer key is present) reads the key
    // and appends to the per-tenant audit log; grant both so the confined
    // endpoint can chain-sign substitution events. `resolver_uds_path` widens
    // the grant with the ONE resolver socket when (and only when) `cfg.resolver`
    // is `Remote` — `Local` leaves the confinement unchanged.
    let spec = ConfinementSpec::network_endpoint(
        secret_dir,
        binding_dir,
        mvm_core::config::mvm_audit_dir(),
        mvm_core::config::mvm_keys_dir(),
        resolver_uds_path(cfg),
    );
    confine_self(&spec).context("confine substitution endpoint")?;
    info!("substitution endpoint self-confined (landlock + seccomp)");
    Ok(())
}

/// macOS/Windows: no kernel LSM. The jailer stub errors rather than run
/// unconfined, so callers on those hosts must not reach it; we no-op so the bin
/// (and its tests) build and run. Production endpoints only ever run on Linux.
/// Still calls `resolver_uds_path` (result discarded) so the decision function
/// is exercised — and therefore testable — on every host, matching the parity
/// the jailer module keeps for its own types.
#[cfg(not(target_os = "linux"))]
fn confine_endpoint(cfg: &EndpointConfig) -> Result<()> {
    let _ = resolver_uds_path(cfg);
    Ok(())
}

/// A bound, listening transport. QEMU uses an AF_VSOCK listener; the in-process
/// VMMs (Firecracker/libkrun) route guest→host through a per-port UDS the VMM
/// proxies. The std `UnixListener` is converted to its tokio form inside the
/// runtime (binding here, outside the runtime, keeps the ready handshake
/// race-free).
enum Bound {
    Uds(std::os::unix::net::UnixListener),
    #[cfg(target_os = "linux")]
    Vsock(mvm_hostd::supervisor::network_endpoint_proxy::vsock::VsockListener),
}

fn bind_transport(transport: &EndpointTransport) -> Result<Bound> {
    match transport {
        EndpointTransport::Uds { path } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create UDS parent {}", parent.display()))?;
            }
            let listener = std::os::unix::net::UnixListener::bind(path)
                .with_context(|| format!("UDS bind on {} failed", path.display()))?;
            listener.set_nonblocking(true)?;
            info!(uds_path = %path.display(), "substitution endpoint bound (uds)");
            Ok(Bound::Uds(listener))
        }
        EndpointTransport::Vsock { port } => {
            #[cfg(target_os = "linux")]
            {
                use mvm_hostd::supervisor::network_endpoint_proxy::vsock::VsockListener;
                let listener = VsockListener::bind(*port)
                    .with_context(|| format!("AF_VSOCK bind on port {port} failed"))?;
                info!(port = *port, "substitution endpoint bound (vsock)");
                Ok(Bound::Vsock(listener))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = port;
                anyhow::bail!("vsock substitution transport is linux-only");
            }
        }
    }
}

/// Bind the transparent egress terminator's TCP listener, if configured. Bound
/// here (outside the runtime, set non-blocking) so it's reachable before the
/// ready handshake.
fn bind_terminator(addr: Option<std::net::SocketAddr>) -> Result<Option<std::net::TcpListener>> {
    let Some(addr) = addr else {
        return Ok(None);
    };
    let listener = std::net::TcpListener::bind(addr)
        .with_context(|| format!("terminator TCP bind on {addr} failed"))?;
    listener.set_nonblocking(true)?;
    info!(terminator_addr = %addr, "egress terminator bound");
    Ok(Some(listener))
}

/// A host-local event listener for launch readiness. It is bound before the
/// process-ready handshake, exactly like the guest transport, so the launcher
/// can connect without a listen race after the guest starts.
struct BoundSessionReadiness(std::os::unix::net::UnixListener);

fn bind_session_readiness(path: Option<&std::path::Path>) -> Result<Option<BoundSessionReadiness>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create readiness socket parent {}", parent.display()))?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("session readiness bind on {} failed", path.display()))?;
    listener
        .set_nonblocking(true)
        .context("set session readiness listener nonblocking")?;
    Ok(Some(BoundSessionReadiness(listener)))
}

/// Run the primary substitution accept loop, plus the terminator accept loop
/// when one is bound, until a listener errors (or the process is killed). The
/// loops run concurrently: a terminated guest reaches the substitution channel
/// (placeholder-bearing requests) AND the redirected terminator path.
async fn serve(
    cfg: &EndpointConfig,
    service: Option<
        std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
    >,
    bound: Bound,
    terminator: Option<std::net::TcpListener>,
    session_readiness: Option<BoundSessionReadiness>,
    forward_timeout: std::time::Duration,
) -> Result<()> {
    let (session_ready_tx, session_ready_rx) = tokio::sync::watch::channel(false);
    let readiness_task = session_readiness.map(|BoundSessionReadiness(std_listener)| {
        tokio::spawn(serve_session_readiness(std_listener, session_ready_rx))
    });
    // Spawn the terminator loop first so it's accepting while the primary loop
    // owns the task.
    let terminator_task = match terminator {
        Some(std_listener) => {
            let service = service
                .as_ref()
                .context("terminator configured without a substitution service")?;
            let listener = tokio::net::TcpListener::from_std(std_listener)
                .context("adopting terminator TCP listener into the tokio runtime")?;
            Some(tokio::spawn(
                std::sync::Arc::clone(service).serve_terminator(listener, forward_timeout),
            ))
        }
        None => None,
    };

    match cfg.egress_mode {
        // Default, secret-bearing path: framed WireRequest substitution.
        EgressMode::Wire => {
            let service =
                service.context("wire egress configured without a substitution service")?;
            serve_wire(service, bound, forward_timeout).await?;
        }
        // Authenticated FlowMux session: the converged single networking path.
        EgressMode::FlowMux => serve_flowmux(cfg, service, bound, session_ready_tx).await?,
    }

    if let Some(task) = terminator_task {
        task.abort();
    }
    if let Some(task) = readiness_task {
        task.abort();
    }
    Ok(())
}

async fn serve_session_readiness(
    std_listener: std::os::unix::net::UnixListener,
    ready: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = tokio::net::UnixListener::from_std(std_listener)
        .context("adopting session readiness listener into the tokio runtime")?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accepting a session readiness waiter")?;
        let waiter_ready = ready.clone();
        tokio::spawn(async move {
            if let Err(e) = notify_session_waiter(stream, waiter_ready).await {
                warn!(error = %e, "could not notify a session readiness waiter");
            }
        });
    }
}

async fn notify_session_waiter(
    mut stream: tokio::net::UnixStream,
    mut ready: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if !*ready.borrow() {
        ready
            .changed()
            .await
            .context("authenticated-session notifier closed")?;
    }
    stream
        .write_all(&[1])
        .await
        .context("write authenticated-session readiness signal")
}

/// The WireRequest substitution serve loop over the adopted listener.
async fn serve_wire(
    service: std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
    bound: Bound,
    _forward_timeout: std::time::Duration,
) -> Result<()> {
    match bound {
        Bound::Uds(std_listener) => {
            let listener = tokio::net::UnixListener::from_std(std_listener)
                .context("adopting UDS listener into the tokio runtime")?;
            service.serve(listener).await;
        }
        #[cfg(target_os = "linux")]
        Bound::Vsock(listener) => service.serve_vsock(listener).await,
    }
    Ok(())
}

/// The authenticated FlowMux serve loop over the adopted listener.
///
/// Accepts for the life of the VM, like the Wire and raw loops beside it, and
/// runs each accepted connection as its own authenticated session. Two reasons
/// it cannot accept just once. The guest's `FlowMuxReconnectClient` re-dials
/// after a session dies, so a listener that is gone after the first accept
/// turns one dropped session into permanent, unrecoverable loss of networking.
/// And a guest runs more than one FlowMux client — `mvm-egress-client` and the
/// addon DNS resolver each own a session — so a single accept would starve
/// whichever lost the race.
///
/// Concurrent sessions all authenticate against the same pinned guest key, so
/// accepting several does not widen who may connect; it only stops the endpoint
/// from being a single-shot.
///
/// The UDS listener is bound non-blocking (`bind_transport`, so the Wire and
/// raw loops can adopt it into tokio), which means it must be adopted here too
/// rather than accepted on a blocking thread — a blocking accept on it returns
/// `EAGAIN` immediately and forever.
async fn serve_flowmux(
    cfg: &EndpointConfig,
    service: Option<
        std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
    >,
    bound: Bound,
    session_ready: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let identity = cfg
        .flowmux_identity
        .as_ref()
        .context("flowmux egress configured without identity")?;

    // Decode once, up front: bad key material is a config error that should
    // fail the endpoint immediately, not surface as a puzzling handshake
    // failure on whichever session happens to connect first.
    let host_key = decode_signing_key(&identity.host_signing_key_base64)
        .context("decode FlowMux host signing key")?;
    let guest_anchor = decode_verifying_key(&identity.guest_verifying_key_base64)
        .context("decode FlowMux guest verifying key")?;
    let session_id = identity.session_id.clone();
    let recorder = build_audit_recorder(&cfg.tenant_id).map(std::sync::Arc::new);

    let listener = FlowMuxListener::adopt(bound)?;
    let mut consecutive_accept_errors = 0_u32;
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => {
                consecutive_accept_errors = 0;
                stream
            }
            Err(e) => {
                // A single failed accept is not a reason to take the VM's
                // networking down; a listener that fails every time is, and
                // spinning on it would burn a core silently.
                consecutive_accept_errors += 1;
                warn!(
                    error = %e,
                    consecutive = consecutive_accept_errors,
                    "FlowMux accept failed"
                );
                if consecutive_accept_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    return Err(anyhow::Error::new(e).context(format!(
                        "FlowMux listener failed {MAX_CONSECUTIVE_ACCEPT_ERRORS} times in a row"
                    )));
                }
                continue;
            }
        };

        // RegistryLimits uses defaults here because the spawner does not yet
        // thread the admitted plan's limits through cfg.network_policy /
        // NetworkLimits. Built per session so one session's accounting cannot
        // be spent by another.
        let limits = RegistryLimits::default();
        let gate = cfg
            .network_policy
            .as_ref()
            .map(mvm_hostd::supervisor::network_endpoint::build_egress_gate)
            .unwrap_or_else(mvm_runtime::vmm::egress_gate::EgressGate::default_deny);
        let host_key = host_key.clone();
        let session_id = session_id.clone();
        let recorder = recorder.clone();
        let substitution = service.clone();
        let marker = cfg.session_marker.clone();
        let session_ready = session_ready.clone();
        tokio::task::spawn_blocking(move || {
            let served = FlowMuxSession::accept_with(
                stream,
                mvm_hostd::supervisor::flowmux::FlowMuxAccept::new(
                    &session_id,
                    host_key,
                    guest_anchor,
                    limits,
                    gate,
                )
                .with_recorder(recorder)
                .with_substitution(substitution),
            )
            .context("accept FlowMux session")
            .and_then(|mut session| {
                // A session that authenticated is the first evidence a guest
                // actually reached this endpoint. Recorded before serving, so
                // a session that dies mid-life does not retract the fact that
                // one was established.
                record_session_established(marker.as_deref());
                let _ = session_ready.send(true);
                session.serve().context("serve FlowMux session")
            });
            // One session ending is ordinary — the guest reconnects. Log it
            // and keep accepting rather than taking the endpoint down with it.
            if let Err(e) = served {
                warn!(error = %format!("{e:#}"), "FlowMux session ended");
            }
        });
    }
}

/// Record that a guest completed an authenticated session.
///
/// Best-effort by design. The marker is a launch-time readiness signal, not an
/// authorization input: a guest is already authenticated by the time this runs,
/// so failing to write it must not tear down a working session. A write that
/// does not land shows up as a launch that refuses, which is the safe way round.
fn record_session_established(marker: Option<&std::path::Path>) {
    let Some(path) = marker else {
        return;
    };
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!(path = %parent.display(), error = %e, "could not create the session marker dir");
        return;
    }
    if let Err(e) = std::fs::write(path, b"1") {
        warn!(path = %path.display(), error = %e, "could not record the FlowMux session");
    }
}

/// How many back-to-back accept failures mean the listener itself is broken
/// rather than one connection being unlucky.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 16;

/// The FlowMux accept side of a [`Bound`].
///
/// Exists because the two transports need opposite treatment: the UDS listener
/// is non-blocking and must be driven by the reactor, while the vsock listener
/// is blocking and must be kept off the reactor. Each accepted connection is
/// handed on as a **blocking** `std::os::unix::net::UnixStream`, which is what
/// `FlowMuxSession` reads and writes on its `spawn_blocking` thread.
enum FlowMuxListener {
    Uds(tokio::net::UnixListener),
    #[cfg(target_os = "linux")]
    Vsock(std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::vsock::VsockListener>),
}

impl FlowMuxListener {
    fn adopt(bound: Bound) -> Result<Self> {
        match bound {
            Bound::Uds(listener) => Ok(Self::Uds(
                tokio::net::UnixListener::from_std(listener)
                    .context("adopting the FlowMux UDS listener into the tokio runtime")?,
            )),
            #[cfg(target_os = "linux")]
            Bound::Vsock(listener) => Ok(Self::Vsock(std::sync::Arc::new(listener))),
        }
    }

    async fn accept(&self) -> std::io::Result<std::os::unix::net::UnixStream> {
        match self {
            Self::Uds(listener) => {
                let (stream, _) = listener.accept().await?;
                // Back to blocking for the session thread: the accepted end
                // inherits the listener's non-blocking flag on some platforms,
                // and a non-blocking read there surfaces as a spurious
                // handshake failure rather than as a wait.
                let stream = stream.into_std()?;
                stream.set_nonblocking(false)?;
                Ok(stream)
            }
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => {
                use mvm_hostd::supervisor::network_endpoint_proxy::vsock;
                use std::os::fd::FromRawFd;
                let listener = std::sync::Arc::clone(listener);
                let fd = tokio::task::spawn_blocking(move || vsock::accept(listener.raw_fd()))
                    .await
                    .map_err(std::io::Error::other)??;
                // SAFETY: `fd` is an owned connected stream socket from
                // accept(2); wrapping it in UnixStream is the same fd-wrapping
                // technique the WireRequest vsock path uses.
                Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) })
            }
        }
    }
}

fn decode_signing_key(base64: &str) -> Result<ed25519_dalek::SigningKey> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .context("base64-decode signing key")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn decode_verifying_key(base64: &str) -> Result<ed25519_dalek::VerifyingKey> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .context("base64-decode verifying key")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying key must be 32 bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|e| anyhow::anyhow!("invalid verifying key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{SecretBinding, SecretSource};
    use std::path::PathBuf;

    fn uds_cfg() -> EndpointConfig {
        EndpointConfig {
            tenant_id: "local".into(),
            secrets: Vec::new(),
            transport: EndpointTransport::Uds {
                path: "/tmp/mvm-network-endpoint-test.sock".into(),
            },
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            forward_timeout_secs: 30,
            proxy_https: None,
            proxy_http: None,
            no_proxy: None,
            secret_store_dir: None,
            binding_store_dir: None,
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: Some(mvm_core::policy::network_policy::NetworkPolicy::allow_list(
                vec![mvm_core::policy::network_policy::HostPort::new(
                    "142.250.72.14",
                    443,
                )],
            )),
            egress_mode: EgressMode::Wire,
            resolver: ResolverBackend::default(),
            session_marker: None,
            session_ready_socket: None,
            flowmux_identity: None,
        }
    }

    /// A minimal `EndpointConfig`, varying only `resolver`, for exercising
    /// `resolver_uds_path`'s decision logic. Field values otherwise don't
    /// matter — this test never spawns or serves.
    fn config_with_resolver(resolver: ResolverBackend) -> EndpointConfig {
        EndpointConfig {
            tenant_id: "acme".into(),
            secrets: vec![],
            transport: EndpointTransport::Uds {
                path: PathBuf::from("/tmp/mvm-network-endpoint-test.sock"),
            },
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            forward_timeout_secs: 30,
            proxy_https: None,
            proxy_http: None,
            no_proxy: None,
            secret_store_dir: None,
            binding_store_dir: None,
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: None,
            egress_mode: EgressMode::Wire,
            resolver,
            flowmux_identity: None,
            session_marker: None,
            session_ready_socket: None,
        }
    }

    #[test]
    fn secrets_without_a_substitution_service_refuse_the_launch() {
        let mut cfg = uds_cfg();
        cfg.secrets.push(SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        });
        let err = mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
            &cfg, false,
        )
        .expect_err("a secret-bearing endpoint with no substitution must refuse");
        let message = format!("{err:#}");
        assert!(
            message.contains("nothing to resolve them"),
            "got: {message}"
        );
    }

    #[test]
    fn secrets_with_a_substitution_service_are_admitted() {
        let mut cfg = uds_cfg();
        cfg.secrets.push(SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        });
        assert!(
            mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
                &cfg, true
            )
            .is_ok()
        );
    }

    #[test]
    fn a_secretless_endpoint_needs_no_substitution_service() {
        let cfg = uds_cfg();
        assert!(
            mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
                &cfg, false
            )
            .is_ok()
        );
    }

    #[test]
    fn resolver_uds_path_is_none_for_local_backend() {
        let cfg = config_with_resolver(ResolverBackend::Local);
        assert!(resolver_uds_path(&cfg).is_none());
    }

    #[test]
    fn resolver_uds_path_is_some_for_remote_backend() {
        let uds = PathBuf::from("/run/mvmd/tenant-vault/resolver.sock");
        let cfg = config_with_resolver(ResolverBackend::Remote {
            uds_path: uds.clone(),
            timeout_secs: 5,
        });
        assert_eq!(resolver_uds_path(&cfg), Some(uds.as_path()));
    }

    #[test]
    fn flowmux_config_round_trips_through_json() {
        use base64::Engine as _;
        let host_key = [1u8; 32];
        let guest_key = [2u8; 32];
        let cfg = EndpointConfig {
            tenant_id: "tenant".into(),
            secrets: Vec::new(),
            transport: EndpointTransport::Uds {
                path: PathBuf::from("/tmp/mvm-flowmux-test.sock"),
            },
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            forward_timeout_secs: 30,
            proxy_https: None,
            proxy_http: None,
            no_proxy: None,
            secret_store_dir: None,
            binding_store_dir: None,
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: None,
            egress_mode: EgressMode::FlowMux,
            resolver: ResolverBackend::default(),
            session_marker: None,
            session_ready_socket: None,
            flowmux_identity: Some(mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity {
                session_id: "s".into(),
                host_signing_key_base64: base64::engine::general_purpose::STANDARD.encode(host_key),
                guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(guest_key),
            }),
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: EndpointConfig = parse(json.as_bytes()).unwrap();
        assert_eq!(parsed.egress_mode, EgressMode::FlowMux);
        let id = parsed.flowmux_identity.unwrap();
        assert_eq!(id.session_id, "s");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(id.host_signing_key_base64)
                .unwrap(),
            host_key
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(id.guest_verifying_key_base64)
                .unwrap(),
            guest_key
        );
    }
}
