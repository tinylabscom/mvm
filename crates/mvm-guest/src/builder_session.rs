//! The in-house-VMM builder's host↔guest build session, over one vsock stream.
//!
//! A builder VM booted by the in-house VMM (HVF/KVM) has no host-mounted share, so
//! a whole build is driven over a single vsock connection using the
//! [`builder_transfer`](crate::builder_transfer) file primitive plus a few control
//! messages. The sequence on one stream, in order (no interleaving, so each side
//! always knows what to read next):
//!
//! 1. host → guest: the source tree (`/work`) as a transfer.
//! 2. host → guest: the host-binary tree (`/mvm-bins`) as a transfer.
//! 3. host → guest: a [`BuildRequest`].
//! 4. guest → host: zero or more [`SessionEvent::Log`] lines.
//! 5. guest → host: [`SessionEvent::Done`] carrying the [`BuildOutcome`].
//! 6. guest → host (only on success): the artifact tree (`/out`) as a transfer.
//!
//! The guest is untrusted on the return leg, so step 6's receive is the
//! path-sanitized [`builder_transfer::receive_into`] — a hostile guest cannot
//! write outside the host's artifact dir.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::builder_transfer::{read_msg, receive_into, send_dir, write_msg};

/// What the host asks the builder guest to build. `flake_ref`/`attr` are the
/// same validated inputs the existing builder agent takes; the guest resolves
/// them against the staged `/work` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    pub flake_ref: String,
    pub attr: String,
    pub timeout_secs: Option<u64>,
}

/// Terminal result of a build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BuildOutcome {
    /// The build succeeded; the artifact tree follows on the stream.
    Success,
    /// The build failed; no artifact tree follows.
    Failure { message: String },
}

/// A guest→host event during/after the build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEvent {
    /// A streamed build log line.
    Log { line: String },
    /// The build finished with this outcome (last control message).
    Done { outcome: BuildOutcome },
}

/// What the guest's build closure returns: the outcome, the directory to stream
/// back as `/out` on success, and any log lines to surface to the host.
pub struct BuildProduct {
    pub outcome: BuildOutcome,
    /// Directory whose tree is streamed to the host on success. Ignored on failure.
    pub out_dir: PathBuf,
    pub logs: Vec<String>,
}

/// Host side: drive a full build over `stream`. Sends `/work` + `/mvm-bins`,
/// sends the request, surfaces each log line via `on_log`, and on success
/// receives the artifact tree into `out_dir` (path-sanitized). Returns the
/// outcome.
pub fn drive_build<S: Read + Write>(
    stream: &mut S,
    work_dir: &Path,
    mvm_bins_dir: &Path,
    request: &BuildRequest,
    out_dir: &Path,
    mut on_log: impl FnMut(&str),
) -> Result<BuildOutcome> {
    send_dir(stream, work_dir)?;
    send_dir(stream, mvm_bins_dir)?;
    write_msg(stream, request)?;
    loop {
        match read_msg::<_, SessionEvent>(stream)? {
            SessionEvent::Log { line } => on_log(&line),
            SessionEvent::Done { outcome } => {
                if matches!(outcome, BuildOutcome::Success) {
                    receive_into(stream, out_dir)?;
                }
                return Ok(outcome);
            }
        }
    }
}

/// Guest side: serve one build session on `stream`. Receives `/work` +
/// `/mvm-bins` into the given destinations, reads the request, runs `build`, then
/// streams the logs + outcome (+ the artifact tree on success) back.
pub fn serve_build<S, F>(
    stream: &mut S,
    work_dest: &Path,
    mvm_bins_dest: &Path,
    build: F,
) -> Result<()>
where
    S: Read + Write,
    F: FnOnce(&Path, &Path, &BuildRequest) -> BuildProduct,
{
    receive_into(stream, work_dest)?;
    receive_into(stream, mvm_bins_dest)?;
    let request: BuildRequest = read_msg(stream)?;
    let product = build(work_dest, mvm_bins_dest, &request);
    for line in &product.logs {
        write_msg(stream, &SessionEvent::Log { line: line.clone() })?;
    }
    write_msg(
        stream,
        &SessionEvent::Done {
            outcome: product.outcome.clone(),
        },
    )?;
    if matches!(product.outcome, BuildOutcome::Success) {
        send_dir(stream, &product.out_dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn request() -> BuildRequest {
        BuildRequest {
            flake_ref: ".".into(),
            attr: "packages.aarch64-linux.default".into(),
            timeout_secs: Some(600),
        }
    }

    /// Full happy path over a real socket pair: the host sends `/work` +
    /// `/mvm-bins` and a request; the guest "builds" (here: copies `/work` into an
    /// `/out` dir) and streams logs + the artifact tree back; the host receives the
    /// artifacts.
    #[test]
    fn drives_a_build_and_receives_artifacts() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("flake.nix"), b"{ outputs = ...; }").unwrap();
        std::fs::create_dir_all(work.path().join("src")).unwrap();
        std::fs::write(work.path().join("src/app.py"), b"print('hi')").unwrap();
        let bins = tempfile::tempdir().unwrap();
        std::fs::write(bins.path().join("mvm-host-vm-init"), b"ELF...").unwrap();

        // Guest server thread: build = copy /work into a fresh /out, emit a log.
        let guest_handle = thread::spawn(move || {
            let work_dest = tempfile::tempdir().unwrap();
            let bins_dest = tempfile::tempdir().unwrap();
            serve_build(
                &mut guest,
                work_dest.path(),
                bins_dest.path(),
                |work_in, bins_in, req| {
                    // The guest saw the staged trees + the request.
                    assert!(work_in.join("flake.nix").exists());
                    assert!(bins_in.join("mvm-host-vm-init").exists());
                    assert_eq!(req.attr, "packages.aarch64-linux.default");
                    // "Build": produce an artifact dir.
                    let out = tempfile::tempdir().unwrap();
                    std::fs::write(out.path().join("vmlinux"), b"KERNEL").unwrap();
                    std::fs::write(out.path().join("rootfs.ext4"), vec![9u8; 2048]).unwrap();
                    let out_dir = out.keep();
                    BuildProduct {
                        outcome: BuildOutcome::Success,
                        out_dir,
                        logs: vec!["building default".into(), "done".into()],
                    }
                },
            )
            .unwrap();
        });

        let out = tempfile::tempdir().unwrap();
        let mut logs = Vec::new();
        let outcome = drive_build(
            &mut host,
            work.path(),
            bins.path(),
            &request(),
            out.path(),
            |l| logs.push(l.to_string()),
        )
        .unwrap();
        guest_handle.join().unwrap();

        assert_eq!(outcome, BuildOutcome::Success);
        assert_eq!(logs, vec!["building default", "done"]);
        // The artifacts streamed back.
        assert_eq!(
            std::fs::read(out.path().join("vmlinux")).unwrap(),
            b"KERNEL"
        );
        assert_eq!(
            std::fs::read(out.path().join("rootfs.ext4")).unwrap(),
            vec![9u8; 2048]
        );
    }

    /// A failing build streams the failure outcome and **no** artifact tree; the
    /// host's `out_dir` stays empty.
    #[test]
    fn a_failed_build_streams_no_artifacts() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("flake.nix"), b"broken").unwrap();
        let bins = tempfile::tempdir().unwrap();
        std::fs::write(bins.path().join("x"), b"x").unwrap();

        let guest_handle = thread::spawn(move || {
            let wd = tempfile::tempdir().unwrap();
            let bd = tempfile::tempdir().unwrap();
            serve_build(&mut guest, wd.path(), bd.path(), |_w, _b, _r| {
                BuildProduct {
                    outcome: BuildOutcome::Failure {
                        message: "nix build exit 1".into(),
                    },
                    out_dir: PathBuf::new(),
                    logs: vec!["error: eval failed".into()],
                }
            })
            .unwrap();
        });

        let out = tempfile::tempdir().unwrap();
        let outcome = drive_build(
            &mut host,
            work.path(),
            bins.path(),
            &request(),
            out.path(),
            |_| {},
        )
        .unwrap();
        guest_handle.join().unwrap();

        assert_eq!(
            outcome,
            BuildOutcome::Failure {
                message: "nix build exit 1".into()
            }
        );
        // Nothing was written to the host artifact dir.
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}
