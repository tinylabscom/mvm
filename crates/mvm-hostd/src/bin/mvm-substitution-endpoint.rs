//! `mvm-substitution-endpoint` — the per-VM secret-substitution moat.
//! Spawned per-VM by the backend, it is the one process that holds
//! the workload's secrets in the clear: it opens the host's encrypted secret +
//! binding stores, builds the per-VM [`SubstitutionService`], and serves the
//! guest→host substitution channel. The guest only ever holds the opaque
//! `mvm-secret-<hex>` placeholder; the real credential is substituted here and
//! reaches the wire via the host forward leg — never the guest.
//!
//! Process contract:
//! 1. The backend writes an [`EndpointConfig`] JSON on stdin and closes it.
//! 2. The endpoint opens the stores, mints placeholders, and writes ONE JSON
//!    line to **stdout** — the `[(guest var, placeholder)]` pairs the backend
//!    injects into the guest launch env — then flushes. This is the ready
//!    handshake: the backend reads that line before booting the guest.
//! 3. The endpoint binds its listener and serves until the backend kills it.
//!
//! All logging goes to **stderr** so stdout carries exactly the one handshake
//! line. Sibling to `mvm-broker` / `mvm-host-signer` in the process moat.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use tracing::info;

use mvm_hostd::keyholder::secret_placeholder_env;
use mvm_hostd::supervisor::substitution_endpoint::{EndpointTransport, assemble, parse};

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-substitution-endpoint stdin read failed")?;
    Ok(buf)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let raw = read_stdin_blocking()?;
    let cfg = parse(&raw).context("mvm-substitution-endpoint config parse failed")?;
    info!(
        tenant_id = %cfg.tenant_id,
        secrets = cfg.secrets.len(),
        "mvm-substitution-endpoint config loaded"
    );

    let (service, handed) = assemble(&cfg).context("assembling substitution service")?;

    // Bind BEFORE the handshake so the backend knows the endpoint is reachable
    // the moment it reads the ready line — no listen/connect race at boot. The
    // terminator listener binds here too when configured, so the nft redirect
    // target is live before the guest boots.
    let bound = bind_transport(&cfg.transport)?;
    let terminator = bind_terminator(cfg.terminator_listen)?;

    // Ready handshake: report the minted (guest var → placeholder) pairs on
    // stdout so the backend can set them in the guest launch env, then boot.
    // Values are never reported — only opaque placeholders.
    let env = secret_placeholder_env(&handed);
    let line = serde_json::to_string(&env).context("serializing handed placeholders")?;
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{line}").context("writing handshake line")?;
        stdout.flush().context("flushing handshake line")?;
    }
    info!(handed = handed.len(), "placeholders handed; serving");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-subst-endpoint")
        .build()
        .context("tokio runtime build failed")?;

    // One configured deadline for the forward leg AND the untrusted guest socket
    // (terminator). The UDS/vsock path already honors this via ReqwestForwarder.
    let forward_timeout = std::time::Duration::from_secs(cfg.forward_timeout_secs);
    runtime.block_on(serve(service, bound, terminator, forward_timeout))
}

/// A bound, listening transport. QEMU uses an AF_VSOCK listener; the in-process
/// VMMs (Firecracker/libkrun) route guest→host through a per-port UDS the VMM
/// proxies. The std `UnixListener` is converted to its tokio form inside the
/// runtime (binding here, outside the runtime, keeps the ready handshake
/// race-free).
enum Bound {
    Uds(std::os::unix::net::UnixListener),
    #[cfg(target_os = "linux")]
    Vsock(mvm_hostd::supervisor::substitution_proxy::vsock::VsockListener),
}

fn bind_transport(transport: &EndpointTransport) -> Result<Bound> {
    match transport {
        EndpointTransport::Uds { path } => {
            let listener = std::os::unix::net::UnixListener::bind(path)
                .with_context(|| format!("UDS bind on {} failed", path.display()))?;
            listener.set_nonblocking(true)?;
            info!(uds_path = %path.display(), "substitution endpoint bound (uds)");
            Ok(Bound::Uds(listener))
        }
        EndpointTransport::Vsock { port } => {
            #[cfg(target_os = "linux")]
            {
                use mvm_hostd::supervisor::substitution_proxy::vsock::VsockListener;
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
/// ready handshake — the nft redirect target must be live before the guest
/// boots. Linux-only: the terminator recovers the original destination via
/// `SO_ORIGINAL_DST`, an `SOL_IP` getsockopt with no portable equivalent.
fn bind_terminator(addr: Option<std::net::SocketAddr>) -> Result<Option<std::net::TcpListener>> {
    let Some(addr) = addr else {
        return Ok(None);
    };
    #[cfg(target_os = "linux")]
    {
        let listener = std::net::TcpListener::bind(addr)
            .with_context(|| format!("terminator TCP bind on {addr} failed"))?;
        listener.set_nonblocking(true)?;
        info!(terminator_addr = %addr, "egress terminator bound");
        Ok(Some(listener))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        anyhow::bail!("egress terminator (terminator_listen) is linux-only");
    }
}

/// Run the primary substitution accept loop, plus the terminator accept loop
/// when one is bound, until a listener errors (or the process is killed). The
/// loops run concurrently: a terminated guest reaches the substitution channel
/// (placeholder-bearing requests) AND the redirected terminator path.
async fn serve(
    service: std::sync::Arc<mvm_hostd::supervisor::substitution_proxy::SubstitutionService>,
    bound: Bound,
    terminator: Option<std::net::TcpListener>,
    forward_timeout: std::time::Duration,
) -> Result<()> {
    // Spawn the terminator loop first so it's accepting while the primary loop
    // owns the task. On non-Linux `terminator` is always None (bind bails).
    #[cfg(target_os = "linux")]
    let terminator_task = match terminator {
        Some(std_listener) => {
            let listener = tokio::net::TcpListener::from_std(std_listener)
                .context("adopting terminator TCP listener into the tokio runtime")?;
            Some(tokio::spawn(
                std::sync::Arc::clone(&service).serve_terminator(listener, forward_timeout),
            ))
        }
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let _ = (terminator, forward_timeout);

    match bound {
        Bound::Uds(std_listener) => {
            let listener = tokio::net::UnixListener::from_std(std_listener)
                .context("adopting UDS listener into the tokio runtime")?;
            service.serve(listener).await;
        }
        #[cfg(target_os = "linux")]
        Bound::Vsock(listener) => service.serve_vsock(listener).await,
    }

    #[cfg(target_os = "linux")]
    if let Some(task) = terminator_task {
        task.abort();
    }
    Ok(())
}
