//! Host-side builder dispatch routing — the compatibility-adapter seam.
//!
//! The builder VM's stable API is the typed `mvm-builderd` request set
//! (`builderd_protocol`), driven from the host by `builderd_client::BuilderdClient`.
//! The legacy controlled-shell-job channel (`builder_protocol::HostVmRequest::Run`,
//! dispatched by `persistent_builder`) is being migrated onto that typed client
//! one operation at a time.
//!
//! Typed operations live here as `run_*` (one connection, one op) + `try_typed_*`
//! (route-decide then dispatch): `flake_check` and `build` (guest image).
//!
//! This module is the decision seam for that migration. A host build path asks
//! [`resolve_route`] whether a given dispatch should use the typed `mvm-builderd`
//! route or fall back to the legacy shell-job channel, and emits
//! [`legacy_shell_diagnostic`] whenever the legacy channel is taken — so the
//! remaining shell surface stays visible and shrinkable (the
//! `xtask check-builder-shell-job-sites` allowlist is the static counterpart).
//!
//! The phasing is "opt-in, then default": today the typed route is taken only
//! when the daemon is reachable *and* the caller opted in via
//! [`BUILDERD_TYPED_OPT_IN_ENV`]; once a typed operation is proven over the wire,
//! flipping its default is a one-line change here rather than a scatter of
//! call-site edits.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::builderd::{
    BuilderdReadiness, builderd_control_socket_candidates, probe_builderd_readiness,
};
use crate::builderd_client::{
    BuilderdClient, BuilderdClientError, OperationEvent, OperationOutcome,
};
use crate::builderd_protocol::{BuilderRequest, OperationId};

/// Opt-in env flag letting a host build path prefer the typed `mvm-builderd`
/// route when the daemon is reachable. Off by default during the migration.
pub const BUILDERD_TYPED_OPT_IN_ENV: &str = "MVM_BUILDERD_TYPED";

/// Readiness-probe timeout when deciding whether to route typed: the daemon
/// answers a handshake immediately or it isn't there.
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Per-read timeout for a typed flake-check operation. `connect` arms this as
/// the socket read timeout for the whole exchange, and the daemon runs
/// `nix flake check` synchronously before the terminal reply, so it must
/// comfortably exceed a real flake evaluation.
const FLAKE_CHECK_OP_TIMEOUT: Duration = Duration::from_secs(600);

/// Which channel a host-side builder dispatch takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderRoute {
    /// Typed request over vsock to the resident `mvm-builderd`.
    Typed,
    /// Legacy controlled-shell-job channel (the compatibility adapter).
    LegacyShell,
}

/// Resolve the dispatch route: typed only when the daemon is reachable **and**
/// the caller opted in; otherwise the legacy shell channel. Pure so the
/// opt-in-then-default phasing is a one-line change once a typed op is proven.
pub fn resolve_route(daemon_reachable: bool, typed_opt_in: bool) -> BuilderRoute {
    if daemon_reachable && typed_opt_in {
        BuilderRoute::Typed
    } else {
        BuilderRoute::LegacyShell
    }
}

/// Read the typed opt-in flag from an env getter (`1`/`true`/`yes`,
/// case-insensitive, whitespace-trimmed). Injected rather than reading the
/// process env directly so it is unit-testable.
pub fn typed_opt_in(getter: impl Fn(&str) -> Option<String>) -> bool {
    matches!(
        getter(BUILDERD_TYPED_OPT_IN_ENV)
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// The structured diagnostic emitted whenever a dispatch takes the legacy
/// shell-job channel, naming the job so the remaining shell surface is visible.
pub fn legacy_shell_diagnostic(job_label: &str) -> String {
    format!(
        "builder dispatch via legacy shell-job channel (job {job_label}); \
         not yet migrated to the typed mvm-builderd route"
    )
}

/// Verdict of a typed flake check run through the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlakeCheckVerdict {
    /// `nix flake check` passed.
    Valid,
    /// `nix flake check` failed; carries the daemon's failure message.
    Invalid {
        /// The daemon's failure detail (a stderr tail), for the user.
        message: String,
    },
}

/// Outcome of attempting a typed flake check.
pub enum FlakeCheckDispatch {
    /// The typed route was taken; carries the daemon result (or a transport
    /// error once we had committed to the typed path).
    Took(Result<FlakeCheckVerdict, BuilderdClientError>),
    /// Not routed typed (caller not opted in, or no ready daemon) — the
    /// caller should use its legacy in-VM path.
    Fellback,
}

/// Find the control socket of a running builder VM under `vms_root`, if any.
/// Returns the first (sorted) builder directory with a present control socket;
/// readiness is the caller's call.
pub fn resolve_running_builder_socket(vms_root: &Path) -> Option<PathBuf> {
    let mut sockets: Vec<PathBuf> = std::fs::read_dir(vms_root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|d| d.is_dir())
        .filter_map(|d| {
            builderd_control_socket_candidates(&d)
                .into_iter()
                .find(|p| p.exists())
        })
        .collect();
    sockets.sort();
    sockets.into_iter().next()
}

/// Run a typed `FlakeCheck` against the daemon at `socket_path`: connect, send
/// the op, and map its terminal outcome onto a [`FlakeCheckVerdict`].
pub fn run_flake_check(
    socket_path: &Path,
    flake_path: &str,
    timeout: Duration,
) -> Result<FlakeCheckVerdict, BuilderdClientError> {
    let mut client = BuilderdClient::connect(socket_path, timeout)?;
    let request = BuilderRequest::FlakeCheck {
        op: OperationId::new(),
        flake_path: flake_path.to_string(),
    };
    let mut discard = |_event: OperationEvent| {};
    match client.run_operation(&request, &mut discard)? {
        OperationOutcome::Completed => Ok(FlakeCheckVerdict::Valid),
        OperationOutcome::Failed { message, .. } => Ok(FlakeCheckVerdict::Invalid { message }),
        other => Err(BuilderdClientError::Protocol {
            detail: format!("unexpected flake-check outcome: {other:?}"),
        }),
    }
}

/// Route a flake check: take the typed daemon path when the caller opted in
/// (`MVM_BUILDERD_TYPED`) **and** a ready builder daemon is reachable under
/// `vms_root`; otherwise fall back (emitting the compat diagnostic). Flake
/// check has no host-side legacy equivalent that honours the no-host-nix
/// invariant, so the caller's fallback is its existing in-VM shell path.
pub fn try_typed_flake_check(vms_root: &Path, flake_path: &str) -> FlakeCheckDispatch {
    let opt_in = typed_opt_in(|k| std::env::var(k).ok());
    let socket = resolve_running_builder_socket(vms_root);
    let reachable = socket.as_deref().is_some_and(|s| {
        matches!(
            probe_builderd_readiness(s, READINESS_PROBE_TIMEOUT),
            BuilderdReadiness::Ready { .. }
        )
    });
    match resolve_route(reachable, opt_in) {
        BuilderRoute::Typed => {
            let socket = socket.expect("reachable implies a resolved socket");
            FlakeCheckDispatch::Took(run_flake_check(&socket, flake_path, FLAKE_CHECK_OP_TIMEOUT))
        }
        BuilderRoute::LegacyShell => {
            tracing::debug!(
                target: "mvm::builder",
                "{}",
                legacy_shell_diagnostic("flake-check")
            );
            FlakeCheckDispatch::Fellback
        }
    }
}

/// Per-read timeout for a typed guest-image build. A `nix build` of a guest
/// image is far heavier than an eval check (cold-cache realisation), so this is
/// generous — it bounds a hung daemon, not a slow-but-progressing build.
const BUILD_OP_TIMEOUT: Duration = Duration::from_secs(3600);

/// Verdict of a typed guest-image build run through the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildVerdict {
    /// `nix build` produced an out-path.
    Built {
        /// The `/nix/store/...` out-path inside the builder VM (provenance).
        store_path: String,
        /// The directory the built image's host-facing artifacts (`vmlinux`,
        /// `rootfs.ext4`) were exported into. When the caller passed an
        /// `output_dir` under the `/job` share, this is that host-readable
        /// path; when it didn't, the daemon exported nothing and this equals
        /// `store_path` (a builder-VM-internal path the host cannot read).
        artifact_dir: String,
    },
    /// `nix build` failed; carries the daemon's failure message (a stderr tail).
    Failed {
        /// The daemon's failure detail, for the user.
        message: String,
    },
}

/// Outcome of attempting a typed guest-image build.
pub enum BuildDispatch {
    /// The typed route was taken; carries the daemon result (or a transport
    /// error once committed to the typed path).
    Took(Result<BuildVerdict, BuilderdClientError>),
    /// Not routed typed (caller not opted in, or no ready daemon) — the caller
    /// should use its legacy in-VM build path.
    Fellback,
}

/// Run a typed `BuildGuestImage` against the daemon at `socket_path`: connect,
/// send the op, and map its terminal outcome onto a [`BuildVerdict`].
pub fn run_build(
    socket_path: &Path,
    flake_ref: &str,
    attr_path: &str,
    output_dir: Option<&str>,
    timeout: Duration,
) -> Result<BuildVerdict, BuilderdClientError> {
    let mut client = BuilderdClient::connect(socket_path, timeout)?;
    let request = BuilderRequest::BuildGuestImage {
        op: OperationId::new(),
        flake_ref: flake_ref.to_string(),
        attr_path: attr_path.to_string(),
        fingerprint: None,
        output_dir: output_dir.map(str::to_string),
    };
    let mut discard = |_event: OperationEvent| {};
    match client.run_operation(&request, &mut discard)? {
        // On export the daemon sets `artifact_path` to the requested output dir
        // (host-readable); with no export it equals the store path.
        OperationOutcome::Artifact {
            store_path,
            artifact_path,
        } => Ok(BuildVerdict::Built {
            store_path: store_path.unwrap_or_else(|| artifact_path.clone()),
            artifact_dir: artifact_path,
        }),
        OperationOutcome::Failed { message, .. } => Ok(BuildVerdict::Failed { message }),
        other => Err(BuilderdClientError::Protocol {
            detail: format!("unexpected build outcome: {other:?}"),
        }),
    }
}

/// Route a guest-image build: take the typed daemon path when the caller opted
/// in (`MVM_BUILDERD_TYPED`) **and** a ready builder daemon is reachable under
/// `vms_root`; otherwise fall back (emitting the compat diagnostic) to the
/// caller's legacy in-VM build path.
pub fn try_typed_build(
    vms_root: &Path,
    flake_ref: &str,
    attr_path: &str,
    output_dir: Option<&str>,
) -> BuildDispatch {
    let opt_in = typed_opt_in(|k| std::env::var(k).ok());
    let socket = resolve_running_builder_socket(vms_root);
    let reachable = socket.as_deref().is_some_and(|s| {
        matches!(
            probe_builderd_readiness(s, READINESS_PROBE_TIMEOUT),
            BuilderdReadiness::Ready { .. }
        )
    });
    match resolve_route(reachable, opt_in) {
        BuilderRoute::Typed => {
            let socket = socket.expect("reachable implies a resolved socket");
            BuildDispatch::Took(run_build(
                &socket,
                flake_ref,
                attr_path,
                output_dir,
                BUILD_OP_TIMEOUT,
            ))
        }
        BuilderRoute::LegacyShell => {
            tracing::debug!(
                target: "mvm::builder",
                "{}",
                legacy_shell_diagnostic("build-guest-image")
            );
            BuildDispatch::Fellback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_route_needs_both_reachable_and_opt_in() {
        assert_eq!(resolve_route(true, true), BuilderRoute::Typed);
        assert_eq!(resolve_route(true, false), BuilderRoute::LegacyShell);
        assert_eq!(resolve_route(false, true), BuilderRoute::LegacyShell);
        assert_eq!(resolve_route(false, false), BuilderRoute::LegacyShell);
    }

    #[test]
    fn opt_in_parses_truthy_values_case_insensitively() {
        let on = |v: &str| {
            let v = v.to_string();
            typed_opt_in(move |_| Some(v.clone()))
        };
        assert!(on("1"));
        assert!(on("true"));
        assert!(on("TRUE"));
        assert!(on("  yes  "));
        assert!(!on("0"));
        assert!(!on("false"));
        assert!(!on("off"));
        assert!(!on(""));
        // Absent var → not opted in.
        assert!(!typed_opt_in(|_| None));
    }

    #[test]
    fn legacy_diagnostic_names_the_job() {
        let msg = legacy_shell_diagnostic("job-7f3a");
        assert!(msg.contains("job-7f3a"));
        assert!(msg.contains("legacy shell-job channel"));
        assert!(msg.contains("mvm-builderd"));
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use crate::builderd::{
        OpExecResult, OpExecutor, builderd_control_socket_path, serve_connection_with_executor,
    };
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Daemon-side stand-in: every op subprocess exits with a fixed code and
    /// emits a fixed stdout (build ops read their out-path from stdout).
    struct FakeExec {
        exit: i32,
        stdout: String,
    }
    impl OpExecutor for FakeExec {
        fn run(&self, _argv: &[String]) -> std::io::Result<OpExecResult> {
            Ok(OpExecResult {
                exit_code: self.exit,
                stdout: self.stdout.clone(),
                stderr_tail: "flake eval boom".to_string(),
            })
        }
    }

    /// Serve exactly one connection (handshake + one op) with a fake executor
    /// that emits `stdout`.
    fn serve_one_full(socket: PathBuf, exit: i32, stdout: String) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = serve_connection_with_executor(&mut stream, &FakeExec { exit, stdout });
            }
        })
    }

    /// Serve one connection with empty stdout (sufficient for flake check, whose
    /// verdict is exit-code-driven).
    fn serve_one(socket: PathBuf, exit: i32) -> thread::JoinHandle<()> {
        serve_one_full(socket, exit, String::new())
    }

    #[test]
    fn typed_flake_check_clean_exit_is_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        let h = serve_one(sock.clone(), 0);
        let verdict = run_flake_check(&sock, "/flake", Duration::from_secs(5)).unwrap();
        assert_eq!(verdict, FlakeCheckVerdict::Valid);
        h.join().unwrap();
    }

    #[test]
    fn typed_flake_check_nonzero_exit_is_invalid_with_message() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        let h = serve_one(sock.clone(), 1);
        match run_flake_check(&sock, "/flake", Duration::from_secs(5)).unwrap() {
            FlakeCheckVerdict::Invalid { message } => assert!(message.contains("boom")),
            other => panic!("expected Invalid, got {other:?}"),
        }
        h.join().unwrap();
    }

    #[test]
    fn typed_build_clean_exit_with_out_path_is_built() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        // The daemon's nix build prints the out-path on stdout.
        let h = serve_one_full(sock.clone(), 0, "/nix/store/aaaa-img\n".to_string());
        // No output_dir → the daemon exports nothing (FakeExec runs no real
        // copy), so artifact_dir == store_path.
        match run_build(
            &sock,
            "path:.",
            "packages.default",
            None,
            Duration::from_secs(5),
        )
        .unwrap()
        {
            BuildVerdict::Built {
                store_path,
                artifact_dir,
            } => {
                assert_eq!(store_path, "/nix/store/aaaa-img");
                assert_eq!(artifact_dir, "/nix/store/aaaa-img");
            }
            other => panic!("expected Built, got {other:?}"),
        }
        h.join().unwrap();
    }

    #[test]
    fn typed_build_nonzero_exit_is_failed_with_message() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        let h = serve_one(sock.clone(), 1);
        match run_build(&sock, "path:.", "x", None, Duration::from_secs(5)).unwrap() {
            BuildVerdict::Failed { message } => assert!(message.contains("boom"), "{message}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        h.join().unwrap();
    }

    #[test]
    fn run_build_on_missing_socket_is_not_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("absent.sock");
        let err = run_build(&sock, "path:.", "x", None, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, BuilderdClientError::NotReady { .. }));
    }

    #[test]
    fn run_flake_check_on_missing_socket_is_not_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("absent.sock");
        let err = run_flake_check(&sock, "/flake", Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, BuilderdClientError::NotReady { .. }));
    }

    #[test]
    fn resolve_socket_finds_a_present_control_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let vms = tmp.path();
        // Short dir name keeps the bound socket path under macOS's SUN_LEN.
        let vmdir = vms.join("b");
        std::fs::create_dir_all(&vmdir).unwrap();
        // No socket yet.
        assert!(resolve_running_builder_socket(vms).is_none());
        // Bind the libkrun-style control socket directly under the vm dir
        // (a real candidate; the Vz candidate nests one dir deeper).
        let sock = builderd_control_socket_path(&vmdir);
        let _listener = UnixListener::bind(&sock).unwrap();
        assert_eq!(resolve_running_builder_socket(vms), Some(sock));
    }
}
