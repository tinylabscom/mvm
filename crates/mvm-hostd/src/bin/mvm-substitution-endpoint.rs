//! `mvm-substitution-endpoint` — the per-VM secret-substitution moat (Plan 129
//! / ADR-067). Spawned per-VM by the backend, it is the one process that holds
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
//! line. Sibling to `mvm-broker` / `mvm-host-signer` (ADR-066 §3 process moat).

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
    // the moment it reads the ready line — no listen/connect race at boot.
    let bound = bind_transport(&cfg.transport)?;

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

    runtime.block_on(serve(service, bound))
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

/// Run the accept loop until the listener errors (or the process is killed).
async fn serve(
    service: std::sync::Arc<mvm_hostd::supervisor::substitution_proxy::SubstitutionService>,
    bound: Bound,
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
