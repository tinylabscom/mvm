//! Host-side builder dispatch routing — the compatibility-adapter seam.
//!
//! The builder VM's stable API is the typed `mvm-builderd` request set
//! (`builderd_protocol`), driven from the host by `builderd_client::BuilderdClient`.
//! The controlled-shell-job channel (`builder_protocol::HostVmRequest::Run`,
//! dispatched by `persistent_builder`) is still the only channel for generic
//! builder jobs; it is being migrated onto that typed client one operation at
//! a time.
//!
//! Typed operations live here as `run_*` (one connection, one op) + `try_typed_*`
//! (route-decide then dispatch): `flake_check` and `build` (guest image).
//!
//! A typed operation takes the daemon whenever one is reachable. There is no
//! route flag and no opt-in: reachability is the whole decision, and a caller
//! that finds no daemon runs its own in-VM path instead. `xtask
//! check-builder-shell-job-sites` is the static counterpart, keeping the
//! remaining shell surface visible and shrinkable.
//!
//! The **build** route is typed-only: a reachable daemon builds guest images
//! and there is no in-VM shell build to fall back to (the caller drops to the
//! single-shot builder instead).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::builderd::{
    BuilderdReadiness, builderd_control_socket_candidates, probe_builderd_readiness,
};
use crate::builderd_client::{
    BuilderdClient, BuilderdClientError, OperationEvent, OperationOutcome,
};
use crate::builderd_protocol::{BuilderRequest, OperationId};

/// Readiness-probe timeout when deciding whether to route typed: the daemon
/// answers a handshake immediately or it isn't there.
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Per-read timeout for a typed flake-check operation. `connect` arms this as
/// the socket read timeout for the whole exchange, and the daemon runs
/// `nix flake check` synchronously before the terminal reply, so it must
/// comfortably exceed a real flake evaluation.
const FLAKE_CHECK_OP_TIMEOUT: Duration = Duration::from_secs(600);

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
    /// No ready daemon — the caller should use its own in-VM path.
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

/// Route a flake check: take the typed daemon path whenever a ready builder
/// daemon is reachable under `vms_root`, otherwise report that nothing was
/// dispatched. Flake check has no host-side equivalent that honours the
/// no-host-nix invariant, so the caller's other path is its in-VM shell run.
pub fn try_typed_flake_check(vms_root: &Path, flake_path: &str) -> FlakeCheckDispatch {
    let socket = resolve_running_builder_socket(vms_root);
    let reachable = socket.as_deref().is_some_and(|s| {
        matches!(
            probe_builderd_readiness(s, READINESS_PROBE_TIMEOUT),
            BuilderdReadiness::Ready { .. }
        )
    });
    if !reachable {
        return FlakeCheckDispatch::Fellback;
    }
    let socket = socket.expect("reachable implies a resolved socket");
    FlakeCheckDispatch::Took(run_flake_check(&socket, flake_path, FLAKE_CHECK_OP_TIMEOUT))
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

/// Render a streamed build event for the user's terminal. Log chunks pass
/// through verbatim — they already carry nix's derivation-prefixed lines (e.g.
/// `linux>   CC   kernel/fork.o`) — and progress becomes a concise
/// percent-and-label line. Empty log chunks render to nothing. Pure so the
/// formatting is unit-tested without touching a daemon or stderr.
fn render_build_event(event: &OperationEvent) -> Option<String> {
    match event {
        OperationEvent::Log { text } => (!text.is_empty()).then(|| text.clone()),
        OperationEvent::Progress { fraction, label } => {
            let pct = (fraction.clamp(0.0, 1.0) * 100.0).round() as u32;
            Some(format!("[build {pct:>3}%] {label}\n"))
        }
    }
}

/// Run a typed `BuildGuestImage` against the daemon at `socket_path`: connect,
/// send the op, stream its progress/log to stderr, and map its terminal outcome
/// onto a [`BuildVerdict`].
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
    // Stream the daemon's progress/log to stderr so the typed route is as
    // visible as the legacy in-VM build — without it a cold guest-image build
    // (e.g. a from-source kernel) shows nothing and reads as a hang.
    let mut to_stderr = |event: OperationEvent| {
        if let Some(rendered) = render_build_event(&event) {
            let mut err = std::io::stderr();
            let _ = err.write_all(rendered.as_bytes());
            let _ = err.flush();
        }
    };
    match client.run_operation(&request, &mut to_stderr)? {
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

/// Route a guest-image build to the typed daemon whenever a ready builder
/// daemon is reachable under `vms_root`; otherwise `Fellback` so the caller
/// drops to its single-shot builder. There is no legacy in-VM shell build for
/// guest images any more — typed is the only persistent build path.
pub fn try_typed_build(
    vms_root: &Path,
    flake_ref: &str,
    attr_path: &str,
    output_dir: Option<&str>,
) -> BuildDispatch {
    let socket = resolve_running_builder_socket(vms_root);
    let reachable = socket.as_deref().is_some_and(|s| {
        matches!(
            probe_builderd_readiness(s, READINESS_PROBE_TIMEOUT),
            BuilderdReadiness::Ready { .. }
        )
    });
    if reachable {
        let socket = socket.expect("reachable implies a resolved socket");
        BuildDispatch::Took(run_build(
            &socket,
            flake_ref,
            attr_path,
            output_dir,
            BUILD_OP_TIMEOUT,
        ))
    } else {
        BuildDispatch::Fellback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_build_event_passes_log_text_through_verbatim() {
        // Log chunks already carry nix's derivation-prefixed lines; surface them
        // unchanged so the typed route is as visible as the legacy in-VM build.
        let ev = OperationEvent::Log {
            text: "linux>   CC      kernel/fork.o\n".to_string(),
        };
        assert_eq!(
            render_build_event(&ev).as_deref(),
            Some("linux>   CC      kernel/fork.o\n")
        );
    }

    #[test]
    fn render_build_event_drops_empty_log_chunks() {
        let ev = OperationEvent::Log {
            text: String::new(),
        };
        assert_eq!(render_build_event(&ev), None);
    }

    #[test]
    fn render_build_event_formats_progress_as_percent_and_label() {
        let ev = OperationEvent::Progress {
            fraction: 0.42,
            label: "building workload kernel".to_string(),
        };
        assert_eq!(
            render_build_event(&ev).as_deref(),
            Some("[build  42%] building workload kernel\n")
        );
    }

    #[test]
    fn render_build_event_clamps_out_of_range_progress() {
        let over = OperationEvent::Progress {
            fraction: 1.9,
            label: "done".to_string(),
        };
        assert_eq!(
            render_build_event(&over).as_deref(),
            Some("[build 100%] done\n")
        );
        let under = OperationEvent::Progress {
            fraction: -0.5,
            label: "starting".to_string(),
        };
        assert_eq!(
            render_build_event(&under).as_deref(),
            Some("[build   0%] starting\n")
        );
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use crate::builderd::{
        OpExecResult, OpExecutor, builderd_control_socket_path, serve_connection_with_executor,
    };
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    fn bind_unix_listener(path: &Path) -> Option<UnixListener> {
        match UnixListener::bind(path) {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping test: sandbox denied binding Unix socket {}: {err}",
                    path.display()
                );
                None
            }
            Err(err) => panic!("binding Unix socket {} failed: {err}", path.display()),
        }
    }

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
    fn serve_one_full(socket: PathBuf, exit: i32, stdout: String) -> thread::JoinHandle<bool> {
        let Some(listener) = bind_unix_listener(&socket) else {
            return thread::spawn(|| false);
        };
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = serve_connection_with_executor(&mut stream, &FakeExec { exit, stdout });
                return true;
            }
            false
        })
    }

    /// Serve one connection with empty stdout (sufficient for flake check, whose
    /// verdict is exit-code-driven).
    fn serve_one(socket: PathBuf, exit: i32) -> thread::JoinHandle<bool> {
        serve_one_full(socket, exit, String::new())
    }

    #[test]
    fn typed_flake_check_clean_exit_is_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        let h = serve_one(sock.clone(), 0);
        let verdict = match run_flake_check(&sock, "/flake", Duration::from_secs(5)) {
            Ok(verdict) => verdict,
            Err(BuilderdClientError::NotReady { .. }) if !h.join().unwrap() => return,
            Err(err) => panic!("run flake check: {err}"),
        };
        assert_eq!(verdict, FlakeCheckVerdict::Valid);
        assert!(h.join().unwrap());
    }

    #[test]
    fn typed_flake_check_nonzero_exit_is_invalid_with_message() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        let h = serve_one(sock.clone(), 1);
        match match run_flake_check(&sock, "/flake", Duration::from_secs(5)) {
            Ok(verdict) => verdict,
            Err(BuilderdClientError::NotReady { .. }) if !h.join().unwrap() => return,
            Err(err) => panic!("run flake check: {err}"),
        } {
            FlakeCheckVerdict::Invalid { message } => assert!(message.contains("boom")),
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(h.join().unwrap());
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
        ) {
            Ok(verdict) => match verdict {
                BuildVerdict::Built {
                    store_path,
                    artifact_dir,
                } => {
                    assert_eq!(store_path, "/nix/store/aaaa-img");
                    assert_eq!(artifact_dir, "/nix/store/aaaa-img");
                }
                other => panic!("expected Built, got {other:?}"),
            },
            Err(BuilderdClientError::NotReady { .. }) if !h.join().unwrap() => return,
            Err(err) => panic!("run build: {err}"),
        }
        assert!(h.join().unwrap());
    }

    #[test]
    fn typed_build_nonzero_exit_is_failed_with_message() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("vsock-21473.sock");
        let h = serve_one(sock.clone(), 1);
        match match run_build(&sock, "path:.", "x", None, Duration::from_secs(5)) {
            Ok(verdict) => verdict,
            Err(BuilderdClientError::NotReady { .. }) if !h.join().unwrap() => return,
            Err(err) => panic!("run build: {err}"),
        } {
            BuildVerdict::Failed { message } => assert!(message.contains("boom"), "{message}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(h.join().unwrap());
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
        // (a real candidate; the HVF candidate nests one dir deeper).
        let sock = builderd_control_socket_path(&vmdir);
        let Some(_listener) = bind_unix_listener(&sock) else {
            return;
        };
        assert_eq!(resolve_running_builder_socket(vms), Some(sock));
    }
}
