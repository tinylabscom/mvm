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
//! The probes run in process rather than in a forked child. The helper starts
//! its async runtime right after confining itself, and a forked copy of a
//! multi-threaded process may only make async-signal-safe calls — which rules
//! out the resolver, the allocator, and thread creation, the very paths worth
//! probing. Running them in place costs nothing extra: a refused call kills the
//! helper either way, and doing it before the ready handshake means the
//! launcher reports it before any guest boots.
//!
//! Most probes are best-effort. A probe that returns an error proves the filter
//! let every call it made through — a refusal never returns. Such errors are
//! reported, not fatal: a host with no `/etc/pki`, or a resolver that cannot
//! answer for `localhost`, is a property of the host, not of the filter.
//!
//! A *required* probe is different: its error is a confinement failure and
//! ends the self-test. The runtime-thread probe is one. Confinement that holds
//! on the thread that applied it and not on the runtime threads that serve
//! sessions would pass every other probe, because they all run on the
//! confining thread.

use std::io;
use std::path::{Path, PathBuf};

use crate::jailer::refusal_report::ProbeLabel;

/// One named probe.
type ProbeFn<'a> = Box<dyn FnOnce() -> io::Result<()> + 'a>;

/// Whether a probe's error is reported or ends the self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    BestEffort,
    Required,
}

/// A sequence of probes run after confinement.
pub struct ConfinementSelfTest<'a> {
    probes: Vec<(&'static str, Severity, ProbeFn<'a>)>,
}

/// A required probe failed: the process is not confined the way it must be.
#[derive(Debug, thiserror::Error)]
#[error("confinement self-test probe {probe:?} failed: {source}")]
pub struct SelfTestFailure {
    /// The probe that failed.
    pub probe: &'static str,
    /// What it observed.
    #[source]
    pub source: io::Error,
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

    /// Append a best-effort probe. `name` is what a refusal during it is
    /// attributed to; an error it returns is reported, not fatal.
    #[must_use]
    pub fn probe(mut self, name: &'static str, run: impl FnOnce() -> io::Result<()> + 'a) -> Self {
        self.probes
            .push((name, Severity::BestEffort, Box::new(run)));
        self
    }

    /// Append a required probe: an error it returns ends the self-test with a
    /// `SelfTestFailure`, and the caller must not go on to serve.
    #[must_use]
    pub fn require(
        mut self,
        name: &'static str,
        run: impl FnOnce() -> io::Result<()> + 'a,
    ) -> Self {
        self.probes.push((name, Severity::Required, Box::new(run)));
        self
    }

    /// The probes `mvm-network-endpoint` needs: what it does after
    /// confinement, on the threads it confines.
    ///
    /// - `thread-spawn`: a session's relay threads.
    /// - `blocking-pool`: the async runtime's blocking pool, where every
    ///   FlowMux session runs.
    /// - `runtime-threads` (required): both confinement layers hold on a
    ///   runtime worker thread and on a blocking-pool thread that worker
    ///   starts, which is where sessions are actually served.
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
            .require("runtime-threads", move || {
                confinement_covers_runtime_threads(runtime)
            })
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
    /// A required probe's error stops the run and is returned.
    pub fn run(self) -> Result<SelfTestReport, SelfTestFailure> {
        let mut report = SelfTestReport {
            ran: Vec::with_capacity(self.probes.len()),
            errored: Vec::new(),
        };
        for (name, severity, probe) in self.probes {
            let outcome = {
                let _label = ProbeLabel::enter(name);
                probe()
            };
            report.ran.push(name);
            match (outcome, severity) {
                (Ok(()), _) => {}
                (Err(source), Severity::Required) => {
                    return Err(SelfTestFailure {
                        probe: name,
                        source,
                    });
                }
                (Err(error), Severity::BestEffort) => report.errored.push((name, error)),
            }
        }
        Ok(report)
    }
}

/// A path no confinement spec grants. Opening it is refused by Landlock on a
/// confined thread and succeeds on one outside the ruleset.
const UNGRANTED_PATH: &str = "/";

/// Fail unless the calling thread runs under both confinement layers: the
/// seccomp filter (the kernel reports filter mode for it) and the Landlock
/// ruleset (it is refused a directory no spec grants).
///
/// Both layers are per-thread kernel state, so this answers for the calling
/// thread only. Run it on each kind of thread that will do the process's work.
pub fn require_calling_thread_confined() -> io::Result<()> {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("unnamed");

    // SAFETY: PR_GET_SECCOMP takes no pointer arguments and only reports the
    // calling thread's seccomp mode.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode < 0 {
        return Err(io::Error::other(format!(
            "thread {name:?}: reading the seccomp mode failed: {}",
            io::Error::last_os_error()
        )));
    }
    if u32::try_from(mode).ok() != Some(libc::SECCOMP_MODE_FILTER) {
        return Err(io::Error::other(format!(
            "thread {name:?} runs without the seccomp filter (mode {mode})"
        )));
    }

    match std::fs::File::open(UNGRANTED_PATH) {
        Err(error) if error.raw_os_error() == Some(libc::EACCES) => Ok(()),
        Ok(_) => Err(io::Error::other(format!(
            "thread {name:?} opened {UNGRANTED_PATH}: it runs outside the Landlock ruleset"
        ))),
        Err(error) => Err(io::Error::other(format!(
            "thread {name:?}: opening {UNGRANTED_PATH} failed with {error}, not the Landlock refusal"
        ))),
    }
}

/// Check confinement on a runtime worker, and on a blocking-pool thread that
/// worker starts. A FlowMux session is a task that hands its socket to
/// `spawn_blocking`, so these are the threads guest bytes are parsed on.
///
/// Only a multi-thread runtime has workers to check, so any other flavour is
/// refused rather than reported as covered. Each check also confirms it left
/// the calling thread, so a task that ran on the caller cannot vouch for a
/// worker.
fn confinement_covers_runtime_threads(runtime: &tokio::runtime::Handle) -> io::Result<()> {
    if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(io::Error::other(
            "the runtime has no worker threads, so checking it proves nothing",
        ));
    }
    let caller = std::thread::current().id();
    let off_the_caller = move |kind: &str| {
        if std::thread::current().id() == caller {
            return Err(io::Error::other(format!(
                "the {kind} check ran on the confining thread, so it proves nothing"
            )));
        }
        require_calling_thread_confined()
            .map_err(|error| io::Error::other(format!("on a runtime {kind} thread: {error}")))
    };
    let worker = runtime.spawn(async move {
        off_the_caller("worker")?;
        tokio::task::spawn_blocking(move || off_the_caller("blocking-pool"))
            .await
            .map_err(io::Error::other)?
    });
    runtime.block_on(worker).map_err(io::Error::other)?
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
/// each entry to its target, and read the first certificate file that opens.
///
/// The loader records an entry it cannot read and moves on, so the probe does
/// too. That matters under Landlock: on Debian-family hosts most entries are
/// links into `/usr/share/ca-certificates`, which the ruleset does not grant,
/// and the bundle file beside them is what actually loads. Only a directory in
/// which nothing could be read is reported.
fn walk_certificate_dirs(dirs: &[PathBuf]) -> io::Result<()> {
    use std::io::Read as _;

    for dir in dirs.iter().filter(|dir| dir.exists()) {
        let mut last_error = None;
        let mut read_one = false;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            // A dangling link is skipped here exactly as a loader skips it.
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let mut head = [0u8; 64];
            match std::fs::File::open(&path).and_then(|mut file| file.read(&mut head)) {
                Ok(_) => {
                    read_one = true;
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        if let (false, Some(error)) = (read_one, last_error) {
            return Err(error);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The harness's threads are unconfined, so the check must refuse them —
    /// this is what it reports for a runtime worker that escaped confinement.
    #[test]
    fn an_unconfined_thread_fails_the_confinement_check() {
        let error = require_calling_thread_confined()
            .expect_err("a test-harness thread runs without the filter");
        assert!(
            error
                .to_string()
                .contains("runs without the seccomp filter"),
            "{error}"
        );
    }

    /// Run in an unconfined process, the runtime-thread probe names the worker
    /// it found outside confinement rather than passing on the caller's state.
    #[test]
    fn the_runtime_thread_probe_reports_an_unconfined_worker() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .expect("runtime");
        let error = confinement_covers_runtime_threads(runtime.handle())
            .expect_err("an unconfined worker must fail the probe");
        assert!(
            error.to_string().contains("on a runtime worker thread"),
            "{error}"
        );
    }

    /// A runtime without workers cannot vouch for them, and the probe says so
    /// instead of passing.
    #[test]
    fn the_runtime_thread_probe_refuses_a_runtime_without_workers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let error = confinement_covers_runtime_threads(runtime.handle())
            .expect_err("a current-thread runtime has no worker to check");
        assert!(error.to_string().contains("proves nothing"), "{error}");
    }

    #[test]
    fn a_required_probe_failure_stops_the_run() {
        let failure = ConfinementSelfTest::new()
            .probe("best-effort", || Err(io::Error::other("host lacks a file")))
            .require("required", || Err(io::Error::other("thread unconfined")))
            .probe("never-runs", || Ok(()))
            .run()
            .expect_err("a required probe failed");
        assert_eq!(failure.probe, "required");
        assert!(
            failure.to_string().contains("thread unconfined"),
            "{failure}"
        );
    }

    #[test]
    fn best_effort_probe_failures_are_reported_and_the_run_continues() {
        let report = ConfinementSelfTest::new()
            .probe("best-effort", || Err(io::Error::other("host lacks a file")))
            .require("required", || Ok(()))
            .run()
            .expect("no required probe failed");
        assert_eq!(report.ran, ["best-effort", "required"]);
        assert_eq!(report.errored.len(), 1);
        assert_eq!(report.errored[0].0, "best-effort");
    }
}
