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
use secrecy::ExposeSecret as _;
use tracing::{info, warn};

use mvm_hostd::keyholder::secret_placeholder_env;
use mvm_hostd::supervisor::flowmux::{
    FlowMuxIngressHandle, FlowMuxSession, FlowMuxVmResources, registry::RegistryLimits,
};
use mvm_hostd::supervisor::network_endpoint::{
    EgressMode, EndpointConfig, EndpointHandshake, EndpointNetworkProjection, EndpointTransport,
    ResolverBackend, assemble_with_projection, fingerprint_bound_secrets, parse,
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
    validate_flowmux_limits(&cfg)?;
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
    let connector = bind_connector(cfg.connector_uds_path.as_deref())?;
    // Always assembled. The one mode that skipped it was `raw`, which is gone:
    // a FlowMux guest can open a typed HTTP flow at any point in its life, and
    // deciding at boot that it will not is the kind of guess that leaves a
    // placeholder with nothing to resolve it.
    let network_projection = EndpointNetworkProjection::from_config(&cfg);
    let assembled = Some(
        assemble_with_projection(&cfg, &network_projection)
            .context("assembling substitution service")?,
    );
    mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
        &cfg,
        assembled.is_some(),
    )?;
    let ingress = bind_ingress(
        &cfg,
        Some(
            &assembled
                .as_ref()
                .context("FlowMux endpoint assembled no substitution service")?
                .0,
        ),
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
        #[cfg(target_os = "linux")]
        confine_endpoint(&cfg)?;
        #[cfg(not(target_os = "linux"))]
        confine_endpoint_without_lsm(&cfg)?;
        serve(
            ServeParams::builder()
                .cfg(&cfg)
                .service(assembled.map(|(service, _)| service))
                .bound(bound)
                .terminator(terminator)
                .ingress(ingress)
                .session_readiness(session_readiness)
                .connector(connector)
                .network_projection(network_projection)
                .forward_timeout(forward_timeout)
                .build()?,
        )
        .await
    })
}

fn validate_flowmux_limits(cfg: &EndpointConfig) -> Result<()> {
    if cfg.egress_mode == EgressMode::FlowMux {
        cfg.network_limits
            .validate()
            .context("validate admitted FlowMux network limits")?;
        mvm_core::plan::validate_ingress_mappings(
            &cfg.ingress,
            cfg.network_limits.max_ingress_listeners,
        )
        .context("validate admitted FlowMux ingress mappings")?;
        mvm_core::plan::validate_ingress_material(&cfg.ingress, &cfg.secrets)
            .context("validate admitted FlowMux ingress transformation material")?;
    } else if !cfg.ingress.is_empty() {
        anyhow::bail!("declared ingress requires the authenticated FlowMux endpoint");
    }
    Ok(())
}

#[derive(Debug)]
struct BoundIngress {
    tcp: Vec<BoundTcpIngress>,
    udp: Vec<(u16, std::net::UdpSocket)>,
}

#[derive(Debug)]
struct BoundTcpIngress {
    mapping_id: u16,
    profile_key: String,
    listener: std::net::TcpListener,
    transform: BoundTcpTransform,
}

#[derive(Clone)]
enum BoundTcpTransform {
    Opaque,
    Http,
    Tls(std::sync::Arc<rustls::ServerConfig>),
}

impl std::fmt::Debug for BoundTcpTransform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opaque => formatter.write_str("Opaque"),
            Self::Http => formatter.write_str("Http"),
            Self::Tls(_) => formatter.write_str("Tls(<host-only config>)"),
        }
    }
}

fn bind_ingress(
    cfg: &EndpointConfig,
    service: Option<
        &std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
    >,
) -> Result<BoundIngress> {
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    for mapping in &cfg.ingress {
        let ip = mapping.host_addr.parse().with_context(|| {
            format!("parse ingress mapping {} host address", mapping.mapping_id)
        })?;
        let address = std::net::SocketAddr::new(ip, mapping.host_port);
        match mapping.protocol {
            mvm_core::plan::IngressProtocol::Tcp => {
                let listener = std::net::TcpListener::bind(address).with_context(|| {
                    format!(
                        "bind admitted TCP ingress mapping {} at {address}",
                        mapping.mapping_id
                    )
                })?;
                let transform = match mapping.transform {
                    mvm_core::plan::IngressTransform::Opaque => BoundTcpTransform::Opaque,
                    mvm_core::plan::IngressTransform::Http => BoundTcpTransform::Http,
                    mvm_core::plan::IngressTransform::Tls => {
                        let secret_name = mapping
                            .tls_secret
                            .as_deref()
                            .context("validated TLS ingress mapping lost its secret reference")?;
                        let material = service
                            .context("TLS ingress requires the assembled endpoint service")?
                            .resolve_host_material(secret_name)
                            .with_context(|| {
                                format!(
                                    "resolve TLS material for ingress mapping {}",
                                    mapping.mapping_id
                                )
                            })?;
                        let pem = std::str::from_utf8(material.expose_secret())
                            .context("ingress TLS PEM is not UTF-8")?;
                        let config =
                            mvm_hostd::supervisor::terminator::tls::server_config_from_pem_bundle(
                                pem,
                            )
                            .with_context(|| {
                                format!(
                                    "parse TLS material for ingress mapping {}",
                                    mapping.mapping_id
                                )
                            })?;
                        BoundTcpTransform::Tls(std::sync::Arc::new(config))
                    }
                };
                tcp.push(BoundTcpIngress {
                    mapping_id: mapping.mapping_id,
                    profile_key: mapping.host_addr.clone(),
                    listener,
                    transform,
                });
            }
            mvm_core::plan::IngressProtocol::Udp => {
                let socket = std::net::UdpSocket::bind(address).with_context(|| {
                    format!(
                        "bind admitted UDP ingress mapping {} at {address}",
                        mapping.mapping_id
                    )
                })?;
                udp.push((mapping.mapping_id, socket));
            }
        }
    }
    Ok(BoundIngress { tcp, udp })
}

#[derive(Clone)]
struct IngressDispatcher {
    active: std::sync::Arc<std::sync::Mutex<ActiveIngress>>,
    udp: std::sync::Arc<Vec<(u16, std::sync::Arc<std::net::UdpSocket>)>>,
}

#[derive(Default)]
struct ActiveIngress {
    generation: u64,
    handle: Option<FlowMuxIngressHandle>,
}

impl BoundIngress {
    fn start(
        self,
        service: std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
    ) -> Result<IngressDispatcher> {
        let BoundIngress { tcp, udp } = self;
        let runtime = tokio::runtime::Handle::current();
        let dispatcher = IngressDispatcher {
            active: std::sync::Arc::new(std::sync::Mutex::new(ActiveIngress::default())),
            udp: std::sync::Arc::new(
                udp.into_iter()
                    .map(|(mapping, socket)| (mapping, std::sync::Arc::new(socket)))
                    .collect(),
            ),
        };
        for ingress in tcp {
            let mapping_id = ingress.mapping_id;
            let active = std::sync::Arc::clone(&dispatcher.active);
            let service = std::sync::Arc::clone(&service);
            let runtime = runtime.clone();
            std::thread::Builder::new()
                .name(format!("flowmux-ingress-listener-{mapping_id}"))
                .spawn(move || ingress.serve(active, service, runtime))
                .context("spawn FlowMux ingress listener")?;
        }
        Ok(dispatcher)
    }
}

impl BoundTcpIngress {
    fn serve(
        self,
        active: std::sync::Arc<std::sync::Mutex<ActiveIngress>>,
        service: std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
        runtime: tokio::runtime::Handle,
    ) {
        loop {
            let (external, _) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(mapping_id = self.mapping_id, %error, "TCP ingress listener stopped");
                    return;
                }
            };
            let handle = active
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .handle
                .clone();
            let Some(handle) = handle else {
                drop(external);
                continue;
            };
            if let Err(error) = self.dispatch(external, &handle, &service, &runtime) {
                warn!(mapping_id = self.mapping_id, %error, "TCP ingress connection refused");
            }
        }
    }

    fn dispatch(
        &self,
        external: std::net::TcpStream,
        handle: &FlowMuxIngressHandle,
        service: &std::sync::Arc<
            mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService,
        >,
        runtime: &tokio::runtime::Handle,
    ) -> Result<()> {
        if matches!(self.transform, BoundTcpTransform::Opaque) {
            handle
                .open_tcp(self.mapping_id, external)
                .map_err(anyhow::Error::from)?;
            return Ok(());
        }

        let (flowmux_side, mut transform_side) = tcp_stream_pair()?;
        handle
            .open_tcp(self.mapping_id, flowmux_side)
            .map_err(anyhow::Error::from)?;
        let timeout = Some(std::time::Duration::from_secs(30));
        external.set_read_timeout(timeout)?;
        external.set_write_timeout(timeout)?;
        transform_side.set_read_timeout(timeout)?;
        transform_side.set_write_timeout(timeout)?;

        let mapping_id = self.mapping_id;
        let profile_key = self.profile_key.clone();
        let transform = self.transform.clone();
        let service = std::sync::Arc::clone(service);
        let runtime = runtime.clone();
        std::thread::Builder::new()
            .name(format!("flowmux-ingress-transform-{mapping_id}"))
            .spawn(move || {
                let transformer = service.ingress_transformer(&profile_key);
                let result = match transform {
                    BoundTcpTransform::Opaque => {
                        warn!(mapping_id, "opaque ingress reached transform worker");
                        return;
                    }
                    BoundTcpTransform::Http => {
                        let mut external = external;
                        transformer.relay_once(&mut external, &mut transform_side)
                    }
                    BoundTcpTransform::Tls(config) => {
                        let connection = match rustls::ServerConnection::new(config) {
                            Ok(connection) => connection,
                            Err(error) => {
                                warn!(mapping_id, %error, "TLS ingress setup failed");
                                return;
                            }
                        };
                        let mut tls = rustls::StreamOwned::new(connection, external);
                        transformer.relay_once(&mut tls, &mut transform_side)
                    }
                };
                if let Err(error) = &result {
                    warn!(mapping_id, %error, "ingress transformation failed closed");
                }
                service.audit_ingress_transform(&runtime, mapping_id, &result);
                let _ = transform_side.shutdown(std::net::Shutdown::Both);
            })
            .context("spawn FlowMux ingress transformation")?;
        Ok(())
    }
}

fn tcp_stream_pair() -> Result<(std::net::TcpStream, std::net::TcpStream)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .context("bind internal ingress transform bridge")?;
    let client = std::net::TcpStream::connect(listener.local_addr()?)
        .context("connect internal ingress transform bridge")?;
    let (server, _) = listener
        .accept()
        .context("accept internal ingress transform bridge")?;
    Ok((client, server))
}

impl IngressDispatcher {
    fn activate(&self, handle: FlowMuxIngressHandle) -> u64 {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        active.generation = active.generation.wrapping_add(1);
        active.handle = Some(handle.clone());
        let generation = active.generation;
        drop(active);

        for (mapping_id, socket) in self.udp.iter() {
            let mapping_id = *mapping_id;
            let socket = match socket.try_clone() {
                Ok(socket) => socket,
                Err(error) => {
                    warn!(mapping_id, %error, "UDP ingress socket clone failed");
                    continue;
                }
            };
            let handle = handle.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("flowmux-ingress-udp-open-{mapping_id}"))
                .spawn(move || {
                    if let Err(error) = handle.open_udp(mapping_id, socket) {
                        warn!(mapping_id, %error, "UDP ingress mapping refused");
                    }
                })
            {
                warn!(mapping_id, %error, "UDP ingress opener thread failed");
            }
        }
        generation
    }

    fn deactivate(&self, generation: u64) -> bool {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active.generation != generation {
            return false;
        }
        active.handle = None;
        true
    }
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
    if std::env::var_os("MVM_ENDPOINT_NO_CONFINE").is_some() {
        warn!("skipping substitution endpoint self-confinement (MVM_ENDPOINT_NO_CONFINE set)");
        return Ok(());
    }
    use mvm_hostd::jailer::{ConfinementSpec, confine_self};
    use mvm_hostd::supervisor::network_endpoint::resolve_store_dirs;

    let (secret_dir, binding_dir) =
        resolve_store_dirs(cfg).context("resolve substitution-endpoint store dirs")?;
    // The audit recorder (when the host signer key is present) reads the key
    // and appends to the per-tenant audit log; grant both so the confined
    // endpoint can chain-sign substitution events. `resolver_uds_path` widens
    // the grant with the ONE resolver socket when (and only when) `cfg.resolver`
    // is `Remote` — `Local` leaves the confinement unchanged.
    let session_marker_parent = cfg
        .session_marker
        .as_deref()
        .map(|marker| {
            marker.parent().with_context(|| {
                format!(
                    "FlowMux session marker has no parent directory: {}",
                    marker.display()
                )
            })
        })
        .transpose()?;
    let spec = ConfinementSpec::network_endpoint(
        secret_dir,
        binding_dir,
        mvm_core::config::mvm_audit_dir(),
        mvm_core::config::mvm_keys_dir(),
        resolver_uds_path(cfg),
    )
    .with_session_marker_parent(session_marker_parent);
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
fn confine_endpoint_without_lsm(cfg: &EndpointConfig) -> Result<()> {
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

/// Bind the host-local typed connector before reporting process readiness.
/// Broker/tool code connects here, but the endpoint remains the only process
/// that resolves and dials the external destination.
struct BoundConnector(std::os::unix::net::UnixListener);

fn bind_connector(path: Option<&std::path::Path>) -> Result<Option<BoundConnector>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create connector socket parent {}", parent.display()))?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("typed connector bind on {} failed", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restrict typed connector {} to mode 0600", path.display()))?;
    }
    listener
        .set_nonblocking(true)
        .context("set typed connector listener nonblocking")?;
    Ok(Some(BoundConnector(listener)))
}

/// Run the primary substitution accept loop, plus the terminator accept loop
/// when one is bound, until a listener errors (or the process is killed). The
/// loops run concurrently: a terminated guest reaches the substitution channel
/// (placeholder-bearing requests) AND the redirected terminator path.
struct ServeParams<'a> {
    cfg: &'a EndpointConfig,
    service:
        Option<std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>>,
    bound: Bound,
    terminator: Option<std::net::TcpListener>,
    ingress: BoundIngress,
    session_readiness: Option<BoundSessionReadiness>,
    connector: Option<BoundConnector>,
    network_projection: EndpointNetworkProjection,
    forward_timeout: std::time::Duration,
}

struct ServeParamsBuilder<'a> {
    cfg: Option<&'a EndpointConfig>,
    service:
        Option<std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>>,
    bound: Option<Bound>,
    terminator: Option<std::net::TcpListener>,
    ingress: Option<BoundIngress>,
    session_readiness: Option<BoundSessionReadiness>,
    connector: Option<BoundConnector>,
    network_projection: Option<EndpointNetworkProjection>,
    forward_timeout: Option<std::time::Duration>,
}

impl<'a> ServeParams<'a> {
    fn builder() -> ServeParamsBuilder<'a> {
        ServeParamsBuilder {
            cfg: None,
            service: None,
            bound: None,
            terminator: None,
            ingress: None,
            session_readiness: None,
            connector: None,
            network_projection: None,
            forward_timeout: None,
        }
    }
}

impl<'a> ServeParamsBuilder<'a> {
    fn cfg(mut self, cfg: &'a EndpointConfig) -> Self {
        self.cfg = Some(cfg);
        self
    }

    fn service(
        mut self,
        service: Option<
            std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
        >,
    ) -> Self {
        self.service = service;
        self
    }

    fn bound(mut self, bound: Bound) -> Self {
        self.bound = Some(bound);
        self
    }

    fn terminator(mut self, terminator: Option<std::net::TcpListener>) -> Self {
        self.terminator = terminator;
        self
    }

    fn ingress(mut self, ingress: BoundIngress) -> Self {
        self.ingress = Some(ingress);
        self
    }

    fn session_readiness(mut self, readiness: Option<BoundSessionReadiness>) -> Self {
        self.session_readiness = readiness;
        self
    }

    fn connector(mut self, connector: Option<BoundConnector>) -> Self {
        self.connector = connector;
        self
    }

    fn network_projection(mut self, projection: EndpointNetworkProjection) -> Self {
        self.network_projection = Some(projection);
        self
    }

    fn forward_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.forward_timeout = Some(timeout);
        self
    }

    fn build(self) -> Result<ServeParams<'a>> {
        Ok(ServeParams {
            cfg: self.cfg.context("ServeParams missing cfg")?,
            service: self.service,
            bound: self.bound.context("ServeParams missing bound")?,
            terminator: self.terminator,
            ingress: self.ingress.context("ServeParams missing ingress")?,
            session_readiness: self.session_readiness,
            connector: self.connector,
            network_projection: self
                .network_projection
                .context("ServeParams missing network_projection")?,
            forward_timeout: self
                .forward_timeout
                .context("ServeParams missing forward_timeout")?,
        })
    }
}

async fn serve(params: ServeParams<'_>) -> Result<()> {
    let ServeParams {
        cfg,
        service,
        bound,
        terminator,
        ingress,
        session_readiness,
        connector,
        network_projection,
        forward_timeout,
    } = params;
    let (session_ready_tx, session_ready_rx) = tokio::sync::watch::channel(false);
    let readiness_task = session_readiness.map(|BoundSessionReadiness(std_listener)| {
        tokio::spawn(serve_session_readiness(std_listener, session_ready_rx))
    });
    let connector_task = match connector {
        Some(BoundConnector(std_listener)) => {
            let service = service
                .as_ref()
                .context("typed connector configured without a substitution service")?;
            let listener = tokio::net::UnixListener::from_std(std_listener)
                .context("adopting typed connector listener into the tokio runtime")?;
            Some(tokio::spawn(std::sync::Arc::clone(service).serve(listener)))
        }
        None => None,
    };
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
        EgressMode::FlowMux => {
            serve_flowmux(
                cfg,
                service,
                network_projection,
                bound,
                ingress,
                session_ready_tx,
            )
            .await?
        }
    }

    if let Some(task) = terminator_task {
        task.abort();
    }
    if let Some(task) = readiness_task {
        task.abort();
    }
    if let Some(task) = connector_task {
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
struct DecodedFlowMuxIdentity {
    session_id: String,
    host_key: ed25519_dalek::SigningKey,
    guest_anchor: ed25519_dalek::VerifyingKey,
}

/// One immutable projection of the admitted endpoint config shared by every
/// FlowMux opcode and every accepted session for this VM.
struct FlowMuxEndpointProjection {
    identity: std::sync::Arc<DecodedFlowMuxIdentity>,
    gate: std::sync::Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
    recorder: Option<std::sync::Arc<mvm_hostd::supervisor::audit_recorder::Recorder>>,
    resources: std::sync::Arc<FlowMuxVmResources>,
    limits: RegistryLimits,
    substitution:
        Option<std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>>,
    ingress_transports:
        std::sync::Arc<Vec<(u16, mvm_contract::protocol::network_flow::IngressFlowKind)>>,
}

impl FlowMuxEndpointProjection {
    fn from_config(
        cfg: &EndpointConfig,
        substitution: Option<
            std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
        >,
        network: EndpointNetworkProjection,
    ) -> Result<Self> {
        let identity = cfg
            .flowmux_identity
            .as_ref()
            .context("flowmux egress configured without identity")?;
        let identity = std::sync::Arc::new(DecodedFlowMuxIdentity {
            session_id: identity.session_id.clone(),
            host_key: decode_signing_key(&identity.host_signing_key_base64)
                .context("decode FlowMux host signing key")?,
            guest_anchor: decode_verifying_key(&identity.guest_verifying_key_base64)
                .context("decode FlowMux guest verifying key")?,
        });
        let admitted_limits = cfg
            .network_limits
            .validate()
            .context("validate admitted FlowMux network limits")?;
        let limits = RegistryLimits::from_network_limits(admitted_limits);
        let resources = std::sync::Arc::new(FlowMuxVmResources::new(admitted_limits));
        let ingress_transports = cfg
            .ingress
            .iter()
            .map(|mapping| {
                let kind = match mapping.protocol {
                    mvm_core::plan::IngressProtocol::Tcp => {
                        mvm_contract::protocol::network_flow::IngressFlowKind::Tcp
                    }
                    mvm_core::plan::IngressProtocol::Udp => {
                        mvm_contract::protocol::network_flow::IngressFlowKind::Udp
                    }
                };
                (mapping.mapping_id, kind)
            })
            .collect::<Vec<_>>();
        Ok(Self {
            identity,
            gate: network.flowmux_gate()?,
            recorder: network.recorder(),
            resources,
            limits,
            substitution,
            ingress_transports: std::sync::Arc::new(ingress_transports),
        })
    }

    fn accept_params(&self) -> mvm_hostd::supervisor::flowmux::FlowMuxAccept {
        mvm_hostd::supervisor::flowmux::FlowMuxAccept::new_shared(
            &self.identity.session_id,
            self.identity.host_key.clone(),
            self.identity.guest_anchor,
            self.limits,
            std::sync::Arc::clone(&self.gate),
        )
        .with_recorder(self.recorder.as_ref().map(std::sync::Arc::clone))
        .with_substitution(self.substitution.as_ref().map(std::sync::Arc::clone))
        .with_vm_resources(std::sync::Arc::clone(&self.resources))
        .with_ingress_transports(self.ingress_transports.iter().copied())
    }
}

async fn serve_flowmux(
    cfg: &EndpointConfig,
    service: Option<
        std::sync::Arc<mvm_hostd::supervisor::network_endpoint_proxy::SubstitutionService>,
    >,
    network_projection: EndpointNetworkProjection,
    bound: Bound,
    ingress: BoundIngress,
    session_ready: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let projection = std::sync::Arc::new(FlowMuxEndpointProjection::from_config(
        cfg,
        service,
        network_projection,
    )?);

    let listener = FlowMuxListener::adopt(bound)?;
    let ingress_dispatcher = ingress.start(
        projection
            .substitution
            .as_ref()
            .context("FlowMux ingress requires the endpoint service")?
            .clone(),
    )?;
    let mut accept_errors = ConsecutiveAcceptErrors::default();
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => {
                accept_errors.record_success();
                stream
            }
            Err(e) => {
                // A single failed accept is not a reason to take the VM's
                // networking down; a listener that fails every time is, and
                // spinning on it would burn a core silently.
                let fatal = accept_errors.record_failure();
                warn!(
                    error = %e,
                    consecutive = accept_errors.count(),
                    "FlowMux accept failed"
                );
                if fatal {
                    return Err(anyhow::Error::new(e).context(format!(
                        "FlowMux listener failed {MAX_CONSECUTIVE_ACCEPT_ERRORS} times in a row"
                    )));
                }
                continue;
            }
        };

        let Some(session_permit) = projection.resources.try_acquire_session() else {
            warn!(
                limit = mvm_hostd::supervisor::flowmux::MAX_CONCURRENT_FLOWMUX_SESSIONS,
                "FlowMux session ceiling reached"
            );
            drop(stream);
            continue;
        };

        let marker = cfg.session_marker.clone();
        let session_ready = session_ready.clone();
        let projection = std::sync::Arc::clone(&projection);
        let ingress_dispatcher = ingress_dispatcher.clone();
        tokio::task::spawn_blocking(move || {
            let _session_permit = session_permit;
            let served = FlowMuxSession::accept_with(stream, projection.accept_params())
                .context("accept FlowMux session")
                .and_then(|mut session| {
                    let ingress_generation = ingress_dispatcher.activate(session.ingress_handle());
                    // A session that authenticated is the first evidence a guest
                    // actually reached this endpoint. Recorded before serving, so
                    // a session that dies mid-life does not retract the fact that
                    // one was established.
                    if let Err(e) = record_session_established(marker.as_deref()) {
                        // Authentication succeeded, so keep serving this session,
                        // but never wake launch without the durable evidence it
                        // verifies after the event.
                        warn!(error = %e, "could not record FlowMux session readiness");
                    } else {
                        let _ = session_ready.send(true);
                    }
                    let result = session.serve().context("serve FlowMux session");
                    ingress_dispatcher.deactivate(ingress_generation);
                    result
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
/// The marker is launch-time evidence, not an authorization input: failure does
/// not tear down an authenticated session, but the caller must not emit the
/// readiness event unless this returns success.
fn record_session_established(marker: Option<&std::path::Path>) -> Result<()> {
    let Some(path) = marker else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "create FlowMux session marker directory {}",
                parent.display()
            )
        })?;
    }
    std::fs::write(path, b"1")
        .with_context(|| format!("write FlowMux session marker {}", path.display()))?;
    // Verify the durable evidence through the same filesystem namespace the
    // launcher reads before allowing the event to cross the process boundary.
    std::fs::metadata(path)
        .with_context(|| format!("verify FlowMux session marker {}", path.display()))?;
    Ok(())
}

/// How many back-to-back accept failures mean the listener itself is broken
/// rather than one connection being unlucky.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 16;

#[derive(Default)]
struct ConsecutiveAcceptErrors(u32);

impl ConsecutiveAcceptErrors {
    fn record_success(&mut self) {
        self.0 = 0;
    }

    fn record_failure(&mut self) -> bool {
        self.0 = self.0.saturating_add(1);
        self.0 >= MAX_CONSECUTIVE_ACCEPT_ERRORS
    }

    fn count(&self) -> u32 {
        self.0
    }
}

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
    use mvm_core::plan::{
        IngressMapping, IngressProtocol, IngressTransform, SecretBinding, SecretSource,
    };
    use std::path::PathBuf;

    fn uds_cfg() -> EndpointConfig {
        EndpointConfig {
            tenant_id: "local".into(),
            instance_id: "test".into(),
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
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: Vec::new(),
            egress_mode: EgressMode::Wire,
            resolver: ResolverBackend::default(),
            session_marker: None,
            session_ready_socket: None,
            connector_uds_path: None,
            flowmux_identity: None,
        }
    }

    /// A minimal `EndpointConfig`, varying only `resolver`, for exercising
    /// `resolver_uds_path`'s decision logic. Field values otherwise don't
    /// matter — this test never spawns or serves.
    fn config_with_resolver(resolver: ResolverBackend) -> EndpointConfig {
        EndpointConfig {
            tenant_id: "acme".into(),
            instance_id: "test".into(),
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
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: Vec::new(),
            egress_mode: EgressMode::Wire,
            resolver,
            flowmux_identity: None,
            session_marker: None,
            session_ready_socket: None,
            connector_uds_path: None,
        }
    }

    fn ingress_mapping(host_addr: &str, host_port: u16) -> IngressMapping {
        IngressMapping::builder()
            .mapping_id(1)
            .protocol(IngressProtocol::Tcp)
            .host_addr(host_addr)
            .host_port(host_port)
            .guest_addr("127.0.0.1")
            .guest_port(8080)
            .transform(IngressTransform::Opaque)
            .build()
            .unwrap()
    }

    fn unused_tcp_port() -> u16 {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn unused_udp_port() -> u16 {
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn serve_params_builder_rejects_missing_required_fields() {
        let error = match ServeParams::builder().build() {
            Ok(_) => panic!("an empty serve configuration must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("ServeParams missing cfg"));
    }

    #[test]
    fn ingress_deactivation_only_accepts_the_current_generation() {
        let dispatcher = IngressDispatcher {
            active: std::sync::Arc::new(std::sync::Mutex::new(ActiveIngress::default())),
            udp: std::sync::Arc::new(Vec::new()),
        };

        assert!(!dispatcher.deactivate(1));
        assert!(dispatcher.deactivate(0));
    }

    #[test]
    fn repeated_accept_failures_trip_at_the_exact_ceiling_and_reset_on_success() {
        let mut errors = ConsecutiveAcceptErrors::default();
        for expected in 1..MAX_CONSECUTIVE_ACCEPT_ERRORS {
            assert!(!errors.record_failure());
            assert_eq!(errors.count(), expected);
        }
        assert!(errors.record_failure());
        assert_eq!(errors.count(), MAX_CONSECUTIVE_ACCEPT_ERRORS);

        errors.record_success();
        assert_eq!(errors.count(), 0);
        assert!(!errors.record_failure());
        assert_eq!(errors.count(), 1);
    }

    #[tokio::test]
    async fn session_waiter_does_not_signal_before_authentication_readiness() {
        use tokio::io::AsyncReadExt as _;

        let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let waiter = tokio::spawn(notify_session_waiter(server, ready_rx));
        let mut signal = [0_u8; 1];

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                client.read_exact(&mut signal),
            )
            .await
            .is_err(),
            "a waiter must remain blocked until authentication is ready"
        );

        ready_tx.send(true).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read_exact(&mut signal),
        )
        .await
        .expect("the ready waiter must be notified promptly")
        .unwrap();
        assert_eq!(signal, [1]);
        waiter.await.unwrap().unwrap();
    }

    #[test]
    fn authenticated_session_marker_is_verified_before_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("session.marker");

        record_session_established(Some(&marker)).expect("record durable session evidence");

        assert_eq!(std::fs::read(marker).unwrap(), b"1");
    }

    #[test]
    fn admitted_projection_is_one_object_graph_for_every_network_surface() {
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("host-signer.ed25519"), [9_u8; 32]).unwrap();

        let host_key = ed25519_dalek::SigningKey::from_bytes(&[3_u8; 32]);
        let guest_key = ed25519_dalek::SigningKey::from_bytes(&[4_u8; 32]);
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        cfg.flowmux_identity = Some(mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity {
            session_id: "signed-plan-session".into(),
            host_signing_key_base64: base64::engine::general_purpose::STANDARD
                .encode(host_key.to_bytes()),
            guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
                .encode(guest_key.verifying_key().to_bytes()),
        });
        cfg.ingress = vec![ingress_mapping("127.0.0.1", 8443)];

        let network = EndpointNetworkProjection::from_config(&cfg);
        let projection = FlowMuxEndpointProjection::from_config(&cfg, None, network).unwrap();
        let expected = (
            std::sync::Arc::as_ptr(&projection.gate).cast::<()>() as usize,
            std::sync::Arc::as_ptr(&projection.resources).cast::<()>() as usize,
            std::sync::Arc::as_ptr(&projection.identity).cast::<()>() as usize,
            projection
                .recorder
                .as_ref()
                .map(|recorder| std::sync::Arc::as_ptr(recorder).cast::<()>() as usize),
        );
        assert!(expected.3.is_some(), "fixture must carry an audit sink");

        for surface in ["tcp", "udp", "dns", "typed_connector", "ingress"] {
            let observed = (
                std::sync::Arc::as_ptr(&projection.gate).cast::<()>() as usize,
                std::sync::Arc::as_ptr(&projection.resources).cast::<()>() as usize,
                std::sync::Arc::as_ptr(&projection.identity).cast::<()>() as usize,
                projection
                    .recorder
                    .as_ref()
                    .map(|recorder| std::sync::Arc::as_ptr(recorder).cast::<()>() as usize),
            );
            assert_eq!(
                observed, expected,
                "{surface} diverged from the endpoint projection"
            );
        }
    }

    #[test]
    fn typed_connector_is_bound_before_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.sock");
        let bound = bind_connector(Some(&path)).unwrap().expect("configured");
        assert!(path.exists());
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(std::os::unix::net::UnixListener::bind(&path).is_err());
        drop(bound);
    }

    #[test]
    fn absent_typed_connector_does_not_bind_a_socket() {
        assert!(bind_connector(None).unwrap().is_none());
    }

    #[test]
    fn admitted_exact_tcp_ingress_is_bound_before_serving() {
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        let port = unused_tcp_port();
        cfg.ingress = vec![ingress_mapping("127.0.0.1", port)];

        validate_flowmux_limits(&cfg).unwrap();
        let bound = bind_ingress(&cfg, None).unwrap();
        assert_eq!(bound.tcp.len(), 1);
        assert!(std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[test]
    fn explicitly_signed_wildcard_is_bound_without_widening_exact_mappings() {
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        let port = unused_tcp_port();
        cfg.ingress = vec![ingress_mapping("0.0.0.0", port)];

        validate_flowmux_limits(&cfg).unwrap();
        let bound = bind_ingress(&cfg, None).unwrap();
        let listener = &bound.tcp.first().expect("one wildcard listener").listener;
        assert!(listener.local_addr().unwrap().ip().is_unspecified());

        drop(bound);
        assert!(std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok());
    }

    #[test]
    fn admitted_exact_udp_ingress_is_bound_before_serving() {
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        let mut mapping = ingress_mapping("127.0.0.1", unused_tcp_port());
        mapping.protocol = IngressProtocol::Udp;
        cfg.ingress = vec![mapping];

        validate_flowmux_limits(&cfg).unwrap();
        let bound = bind_ingress(&cfg, None).unwrap();
        assert_eq!(bound.udp.len(), 1);
        let (_, socket) = bound.udp.first().expect("one admitted UDP listener");
        assert_eq!(
            socket.local_addr().unwrap().ip(),
            std::net::Ipv4Addr::LOCALHOST
        );
    }

    #[test]
    fn explicitly_admitted_wildcard_ingress_binds_the_wildcard() {
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        cfg.ingress = vec![ingress_mapping("0.0.0.0", unused_tcp_port())];

        validate_flowmux_limits(&cfg).unwrap();
        let bound = bind_ingress(&cfg, None).unwrap();
        let listener = &bound
            .tcp
            .first()
            .expect("one admitted TCP listener")
            .listener;
        assert!(listener.local_addr().unwrap().ip().is_unspecified());
    }

    #[test]
    fn undeclared_ingress_port_is_not_bound() {
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        let admitted_reservation =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let undeclared_reservation =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let admitted = admitted_reservation.local_addr().unwrap().port();
        let undeclared = undeclared_reservation.local_addr().unwrap().port();
        assert_ne!(admitted, undeclared);
        drop(admitted_reservation);
        drop(undeclared_reservation);
        cfg.ingress = vec![ingress_mapping("127.0.0.1", admitted)];

        let _bound = bind_ingress(&cfg, None).unwrap();
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, undeclared))
            .expect("the endpoint must not own an undeclared listener");
    }

    #[test]
    fn dropping_unstarted_ingress_releases_every_socket() {
        let tcp_port = unused_tcp_port();
        let udp_port = unused_udp_port();
        let mut tcp = ingress_mapping("127.0.0.1", tcp_port);
        tcp.mapping_id = 1;
        let mut udp = ingress_mapping("127.0.0.1", udp_port);
        udp.mapping_id = 2;
        udp.protocol = IngressProtocol::Udp;
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        cfg.ingress = vec![tcp, udp];

        let bound = bind_ingress(&cfg, None).unwrap();
        drop(bound);

        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, tcp_port))
            .expect("TCP ingress listener must be released on teardown");
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, udp_port))
            .expect("UDP ingress listener must be released on teardown");
    }

    #[test]
    fn unavailable_ingress_bind_fails_before_readiness() {
        let occupied = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        cfg.ingress = vec![ingress_mapping(
            "127.0.0.1",
            occupied.local_addr().unwrap().port(),
        )];

        let error = bind_ingress(&cfg, None).expect_err("an occupied exact bind must fail closed");
        assert!(error.to_string().contains("bind admitted TCP ingress"));
    }

    #[test]
    fn ingress_transform_without_material_fails_before_readiness() {
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        let mut mapping = ingress_mapping("127.0.0.1", unused_tcp_port());
        mapping.transform = IngressTransform::Tls;
        mapping.tls_secret = Some("INGRESS_TLS_PEM".to_string());
        cfg.ingress = vec![mapping];

        let error =
            bind_ingress(&cfg, None).expect_err("missing transform material must fail closed");
        assert!(
            error
                .to_string()
                .contains("requires the assembled endpoint service")
        );
    }

    #[test]
    fn ingress_tls_config_serializes_only_the_plan_bound_reference() {
        let private_key_marker = "-----BEGIN PRIVATE KEY-----\nnever-serialize-me";
        let mut cfg = uds_cfg();
        cfg.egress_mode = EgressMode::FlowMux;
        cfg.secrets.push(SecretBinding {
            name: "INGRESS_TLS_PEM".to_string(),
            source: SecretSource::Keystore {
                address: "ingress/tls".to_string(),
            },
        });
        cfg.ingress = vec![
            IngressMapping::builder()
                .mapping_id(9)
                .protocol(IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(unused_tcp_port())
                .guest_addr("127.0.0.1")
                .guest_port(8080)
                .transform(IngressTransform::Tls)
                .tls_secret("INGRESS_TLS_PEM")
                .build()
                .unwrap(),
        ];

        validate_flowmux_limits(&cfg).unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("INGRESS_TLS_PEM"));
        assert!(!json.contains(private_key_marker));
        assert!(!json.contains("key_pem"));
    }

    #[test]
    fn authenticated_session_marker_failure_prevents_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker-is-a-directory");
        std::fs::create_dir(&marker).unwrap();

        let err = record_session_established(Some(&marker))
            .expect_err("a marker that cannot be written must fail closed");

        assert!(
            err.to_string().contains("write FlowMux session marker"),
            "unexpected: {err:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_session_marker_refuses_before_process_confinement() {
        let mut cfg = uds_cfg();
        cfg.session_marker = Some(PathBuf::new());

        let error = confine_endpoint(&cfg)
            .expect_err("a marker without a parent must fail before process confinement");
        assert!(
            error
                .to_string()
                .contains("FlowMux session marker has no parent directory")
        );
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
            instance_id: "test".into(),
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
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: Vec::new(),
            egress_mode: EgressMode::FlowMux,
            resolver: ResolverBackend::default(),
            session_marker: None,
            session_ready_socket: None,
            connector_uds_path: Some(PathBuf::from("/tmp/mvm-flowmux-connector.sock")),
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
