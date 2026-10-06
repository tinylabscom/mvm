//! Post-confinement self-test: exercise, at startup, the system-call paths a
//! confined helper otherwise reaches only lazily, mid-session.
//!
//! Every gap the seccomp allowlist has had was found the same way: a path that
//! runs only on first use — the resolver reading `/etc/hosts`, the audit
//! recorder locking its log, the C library opening a file with `open` rather
//! than `openat` — met the filter minutes into a session, and the helper died
//! of `SIGSYS` long after its last log line. The self-test runs those paths
//! right after the filter is installed, on the thread that installed it, under
//! exactly the filter that will serve. A gap then kills the helper at startup,
//! and the refusal reporter names the probe that hit it.
//!
//! The probes run in process rather than in a forked child. The helper is
//! multi-threaded by the time it confines itself (its async runtime is up), and
//! a forked copy of a multi-threaded process may only make async-signal-safe
//! calls — which rules out the resolver, the allocator, and thread creation,
//! the very paths worth probing. Running them in place costs nothing extra:
//! a refused call kills the helper either way, and doing it before the ready
//! handshake means the launcher reports it before any guest boots.
//!
//! A probe that returns an error proves the filter let every call it made
//! through — a refusal never returns. Such errors are reported, not fatal: a
//! host with no `/etc/pki`, or a resolver that cannot answer for `localhost`,
//! is a property of the host, not of the filter.

use std::io;
use std::path::{Path, PathBuf};

use crate::jailer::refusal_report::ProbeLabel;

/// One named probe.
type ProbeFn<'a> = Box<dyn FnOnce() -> io::Result<()> + 'a>;

/// A sequence of probes run after confinement.
pub struct ConfinementSelfTest<'a> {
    probes: Vec<(&'static str, ProbeFn<'a>)>,
}

/// What a completed self-test observed. Reaching this value at all means no
/// probe was refused by the filter.
#[derive(Debug)]
pub struct SelfTestReport {
    /// Every probe that ran, in order.
    pub ran: Vec<&'static str>,
    /// Probes whose calls the filter allowed but which still failed.
    pub errored: Vec<(&'static str, io::Error)>,
}

impl Default for ConfinementSelfTest<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ConfinementSelfTest<'a> {
    /// An empty self-test.
    #[must_use]
    pub fn new() -> Self {
        Self { probes: Vec::new() }
    }

    /// Append a probe. `name` is what a refusal during it is attributed to.
    #[must_use]
    pub fn probe(mut self, name: &'static str, run: impl FnOnce() -> io::Result<()> + 'a) -> Self {
        self.probes.push((name, Box::new(run)));
        self
    }

    /// The probes `mvm-network-endpoint` needs: what it does after
    /// confinement, on the threads it confines.
    ///
    /// - `thread-spawn`: a session's relay threads.
    /// - `blocking-pool`: the async runtime's blocking pool, where every
    ///   FlowMux session runs.
    /// - `clock-and-entropy`: timers, and the randomness each session
    ///   handshake draws.
    /// - `name-resolution`: the C library resolver the egress gate calls, its
    ///   resolver initialisation (the path that once needed `uname`), and the
    ///   UDP upstream socket setup the FlowMux resolver performs.
    /// - `tls-trust-store`: the certificate directory walk the forward leg's
    ///   trust store performs.
    /// - `file-append`: the audit recorder's create, lock, sync and segment
    ///   rotation, in the audit directory itself.
    /// - `socket-accept`: listen, connect and accept on a Unix socket, as the
    ///   FlowMux, readiness and connector listeners do.
    #[must_use]
    pub fn network_endpoint(audit_dir: &'a Path, runtime: &'a tokio::runtime::Handle) -> Self {
        Self::new()
            .probe("thread-spawn", spawn_and_join_a_thread)
            .probe("blocking-pool", move || blocking_pool_round_trip(runtime))
            .probe("clock-and-entropy", read_clock_and_entropy)
            .probe("name-resolution", resolve_without_traffic)
            .probe("tls-trust-store", || {
                walk_certificate_dirs(&TRUST_STORE_DIRS.map(PathBuf::from))
            })
            .probe("file-append", move || append_sync_and_rotate_in(audit_dir))
            .probe("socket-accept", accept_on_an_abstract_socket)
    }

    /// Run every probe in order on the calling thread.
    ///
    /// Returns only if the filter refused nothing; a refused call kills the
    /// process from inside the probe, after the refusal reporter has named it.
    pub fn run(self) -> SelfTestReport {
        let mut report = SelfTestReport {
            ran: Vec::with_capacity(self.probes.len()),
            errored: Vec::new(),
        };
        for (name, probe) in self.probes {
            let outcome = {
                let _label = ProbeLabel::enter(name);
                probe()
            };
            report.ran.push(name);
            if let Err(error) = outcome {
                report.errored.push((name, error));
            }
        }
        report
    }
}

/// Where the forward leg's trust store looks for CA certificates on the
/// distributions mvm supports. The confinement grants read on their parents.
const TRUST_STORE_DIRS: [&str; 2] = ["/etc/ssl/certs", "/etc/pki/tls/certs"];

fn spawn_and_join_a_thread() -> io::Result<()> {
    std::thread::Builder::new()
        .name("confinement-self-test".into())
        .spawn(|| ())?
        .join()
        .map_err(|_| io::Error::other("self-test thread panicked"))
}

/// Must be called outside the runtime's own `block_on`: it blocks the calling
/// thread on the runtime, which a thread already driving it cannot do.
fn blocking_pool_round_trip(runtime: &tokio::runtime::Handle) -> io::Result<()> {
    // `spawn_blocking` is called inside the future so it runs in the
    // runtime's context; as a bare argument it would run before `block_on`
    // entered it.
    runtime
        .block_on(async { tokio::task::spawn_blocking(|| ()).await })
        .map_err(io::Error::other)
}

fn read_clock_and_entropy() -> io::Result<()> {
    let _ = std::time::Instant::now();
    let _ = std::time::SystemTime::now();
    let _: [u8; 32] = rand::random();
    Ok(())
}

/// Resolver set-up without a query leaving the host: `localhost` is answered
/// from `/etc/hosts`, `res_init` parses `resolv.conf` without sending, and a
/// connected UDP socket sends nothing until written to.
fn resolve_without_traffic() -> io::Result<()> {
    use std::net::ToSocketAddrs as _;

    let _ = ("localhost", 0u16).to_socket_addrs()?;
    // SAFETY: `res_init` takes no arguments and only (re)reads resolver
    // configuration into the C library's own state.
    unsafe { libc::res_init() };
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let upstream = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 53));
    let socket = crate::supervisor::dns_resolver::connected_upstream_socket(
        upstream,
        std::time::Duration::from_secs(1),
    )?;
    let _ = socket.local_addr()?;
    Ok(())
}

/// Walk each directory the way a trust-store loader does: list it, follow
/// each entry to its target, and read the first certificate file found.
fn walk_certificate_dirs(dirs: &[PathBuf]) -> io::Result<()> {
    use std::io::Read as _;

    for dir in dirs.iter().filter(|dir| dir.exists()) {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            // A dangling link is skipped here exactly as a loader skips it.
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if metadata.is_file() {
                let mut head = [0u8; 64];
                let _ = std::fs::File::open(&path)?.read(&mut head)?;
                break;
            }
        }
    }
    Ok(())
}

/// The audit recorder's write path, on a scratch file in the audit directory
/// that is removed again: create the directory if needed, open for append,
/// take the exclusive lock, sync, rename as segment rotation does, unlink.
fn append_sync_and_rotate_in(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::create_dir_all(dir)?;
    let pid = std::process::id();
    let scratch = dir.join(format!(".confinement-self-test-{pid}"));
    let rotated = dir.join(format!(".confinement-self-test-{pid}.rotated"));
    let result = (|| {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&scratch)?;
        crate::supervisor::audit_file::flock_exclusive(&file)?;
        file.sync_data()?;
        std::fs::rename(&scratch, &rotated)?;
        std::fs::remove_file(&rotated)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&scratch);
        let _ = std::fs::remove_file(&rotated);
    }
    result
}

/// A Unix socket round trip in the abstract namespace, which touches no
/// filesystem path the confinement would have to grant.
fn accept_on_an_abstract_socket() -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt as _;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

    let name = format!("mvm-confinement-self-test-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = UnixListener::bind_addr(&address)?;
    let _client = UnixStream::connect_addr(&address)?;
    let (accepted, _) = listener.accept()?;
    accepted.set_nonblocking(true)
}
