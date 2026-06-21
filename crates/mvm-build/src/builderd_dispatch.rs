//! Host-side routing of build/eval work through the resident builder daemon
//! ([`crate::builderd_client::BuilderdClient`]) instead of the legacy
//! shell-in-the-VM channel.
//!
//! This is the first production consumer of the typed daemon API: `mvmctl
//! validate` (flake check). It is opt-in (`MVM_BUILDERD_DISPATCH=1`) and falls
//! back to the legacy shell path when the daemon is not reachable, so the
//! default behaviour is unchanged while the routing is proven per backend. A
//! flake check is the simplest operation to route — it produces no artifact, so
//! there is no output-share reconciliation to do (that lands with the build-op
//! routing).

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::builderd::{
    BuilderdReadiness, builderd_control_socket_candidates, probe_builderd_readiness,
};
use crate::builderd_client::{
    BuilderdClient, BuilderdClientError, OperationEvent, OperationOutcome,
};
use crate::builderd_protocol::{BuilderRequest, OperationId};

/// Bounded handshake probe when deciding whether a daemon is usable. Short: a
/// reachable resident daemon answers immediately; an absent one must not stall
/// the CLI before it falls back.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Default wall-clock budget for a routed flake check. `nix flake check` is not
/// instant; this matches the legacy shell path's open-ended wait closely enough
/// while still bounding a hung daemon.
const FLAKE_CHECK_TIMEOUT: Duration = Duration::from_secs(900);

/// Verdict of a flake check routed through the builder daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlakeCheckVerdict {
    /// The flake checked clean.
    Valid,
    /// The flake check failed; carries the daemon's human-readable detail.
    Invalid { message: String },
}

/// Map a terminal [`OperationOutcome`] to a flake-check verdict. A flake check
/// only ever resolves to `Completed` (valid) or `Failed` (invalid); any other
/// terminal is a protocol surprise the daemon should never emit for this op, so
/// it is an error rather than a silent pass. Pure — unit-tested without a
/// daemon.
pub fn classify_flake_check_outcome(
    outcome: OperationOutcome,
) -> Result<FlakeCheckVerdict, String> {
    match outcome {
        OperationOutcome::Completed => Ok(FlakeCheckVerdict::Valid),
        OperationOutcome::Failed { message, .. } => Ok(FlakeCheckVerdict::Invalid { message }),
        OperationOutcome::Cancelled => Err("flake check cancelled".to_string()),
        other => Err(format!(
            "flake check produced an unexpected outcome: {other:?}"
        )),
    }
}

/// Find a running builder VM whose resident daemon answers a handshake, and
/// return its control-socket path. Scans the builder-VM state root and probes
/// each candidate socket; the first `Ready` daemon wins. `None` ⇒ no usable
/// daemon (the normal "builder VM down" state) ⇒ caller falls back to the
/// legacy shell path.
pub fn resolve_ready_builder_socket() -> Option<PathBuf> {
    let vms_root = crate::builder_vm::builder_vm_cache_dir().join("vms");
    resolve_ready_builder_socket_in(&vms_root, |sock| {
        probe_builderd_readiness(sock, PROBE_TIMEOUT)
    })
}

/// [`resolve_ready_builder_socket`] with the state root and the readiness probe
/// injected, so the scan logic is unit-tested without a real daemon.
pub fn resolve_ready_builder_socket_in(
    vms_root: &Path,
    probe: impl Fn(&Path) -> BuilderdReadiness,
) -> Option<PathBuf> {
    let entries = std::fs::read_dir(vms_root).ok()?;
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    // Deterministic order so a multi-builder host resolves the same socket
    // across invocations.
    dirs.sort();
    for dir in dirs {
        for sock in builderd_control_socket_candidates(&dir) {
            if !sock.exists() {
                continue;
            }
            if matches!(probe(&sock), BuilderdReadiness::Ready { .. }) {
                return Some(sock);
            }
        }
    }
    None
}

/// Run a flake check against the daemon at `socket`. `flake_path` is a path the
/// builder VM can resolve (the same ref the legacy `nix flake check` ran with
/// inside the VM). `log` receives the daemon's streamed log lines so the user
/// still sees `nix` progress.
pub fn flake_check_via_builderd(
    socket: &Path,
    flake_path: &str,
    log: &mut dyn FnMut(&str),
) -> Result<FlakeCheckVerdict, BuilderdClientError> {
    let mut client = BuilderdClient::connect(socket, FLAKE_CHECK_TIMEOUT)?;
    let request = BuilderRequest::FlakeCheck {
        op: OperationId::new(),
        flake_path: flake_path.to_string(),
    };
    let mut sink = |event: OperationEvent| {
        if let OperationEvent::Log { text } = event {
            log(&text);
        }
    };
    let outcome = client.run_operation(&request, &mut sink)?;
    classify_flake_check_outcome(outcome).map_err(|detail| BuilderdClientError::Protocol { detail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builderd_protocol::FailureCategory;

    #[test]
    fn completed_outcome_is_valid() {
        assert_eq!(
            classify_flake_check_outcome(OperationOutcome::Completed),
            Ok(FlakeCheckVerdict::Valid)
        );
    }

    #[test]
    fn failed_outcome_is_invalid_with_message() {
        let out = OperationOutcome::Failed {
            category: FailureCategory::NixEval,
            message: "attribute 'foo' missing".to_string(),
            retryable: false,
        };
        assert_eq!(
            classify_flake_check_outcome(out),
            Ok(FlakeCheckVerdict::Invalid {
                message: "attribute 'foo' missing".to_string()
            })
        );
    }

    #[test]
    fn unexpected_outcome_is_an_error() {
        let out = OperationOutcome::Artifact {
            artifact_path: "/out/x".to_string(),
            store_path: None,
        };
        assert!(classify_flake_check_outcome(out).is_err());
        assert!(classify_flake_check_outcome(OperationOutcome::Cancelled).is_err());
    }

    #[test]
    fn resolve_skips_dirs_without_a_ready_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        // Two builder dirs, neither with a socket file → nothing resolves.
        std::fs::create_dir_all(tmp.path().join("vm-a")).unwrap();
        std::fs::create_dir_all(tmp.path().join("vm-b")).unwrap();
        let got = resolve_ready_builder_socket_in(tmp.path(), |_| BuilderdReadiness::NotRunning);
        assert_eq!(got, None);
    }

    #[test]
    fn resolve_returns_the_first_ready_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vm-ready");
        std::fs::create_dir_all(&dir).unwrap();
        // Create the libkrun-shape candidate socket file so `.exists()` passes.
        let sock = builderd_control_socket_candidates(&dir)[0].clone();
        std::fs::write(&sock, b"").unwrap();
        let got = resolve_ready_builder_socket_in(tmp.path(), |s| {
            if s == sock {
                BuilderdReadiness::Ready { version: 1 }
            } else {
                BuilderdReadiness::NotRunning
            }
        });
        assert_eq!(got, Some(sock));
    }

    #[test]
    fn resolve_ignores_a_present_but_unready_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vm-stale");
        std::fs::create_dir_all(&dir).unwrap();
        let sock = builderd_control_socket_candidates(&dir)[0].clone();
        std::fs::write(&sock, b"").unwrap();
        let got = resolve_ready_builder_socket_in(tmp.path(), |_| BuilderdReadiness::Unreachable {
            detail: "stale".to_string(),
        });
        assert_eq!(got, None);
    }
}
