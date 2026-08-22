//! Wire types for the long-lived host VM's vsock dispatch channel.
//!
//! The host dispatches Nix-build jobs over vsock into a persistent
//! libkrun VM, booted once per builder session. The channel is a
//! backend-agnostic dispatch surface — the same long-lived libkrun VM
//! serves both Nix builds and nested Firecracker workload spawns. The
//! `Workload*` variants below are stubbed (the guest-side arm panics
//! with `unimplemented!()` until their payloads are wired).
//!
//! The channel inherits the existing sealed-frame envelope
//! (see [`mvm_core::net::session::SealedFrame`]) — no new key
//! material is introduced.
//!
//! ## Frame size cap
//!
//! Framing reuses [`mvm_agentd::vsock::read_frame`] /
//! [`mvm_agentd::vsock::write_frame`], which enforce a pre-deserialize
//! `MAX_FRAME_SIZE` of 256 KiB (`crates/mvm-agentd/src/vsock.rs:65`).
//! That bound is amply sufficient for `HostVmRequest` — its
//! largest variant (`HostVmRequest::Run`) carries a
//! [`crate::builder_vm::BuilderJob`] whose variants are tiny
//! (`Flake { flake_ref: String, attr_path: String }` and
//! `Install { spec_path: PathBuf }`, both fitting in a few hundred
//! bytes). The 256 KiB cap already provides the property we want
//! (reject `length_prefix > cap` before allocating), so this channel
//! inherits it rather than introduce a looser per-channel cap. The
//! wire-cap regression is exercised explicitly by the fuzz seed in
//! `crates/mvm-agentd/fuzz/fuzz_targets/fuzz_builder_request.rs`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::builder_vm::BuilderJob;

/// Per-dispatch identifier the host stamps before sending a
/// [`HostVmRequest::Run`] and the guest echoes in the matching
/// [`HostVmResponse::Result`]. `Uuid` v4 because the host
/// generates these; the guest only ever validates that the response
/// `job_id` matches the request it's correlating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(pub Uuid);

impl JobId {
    /// Mint a fresh job id. Used by the host's dispatch path.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Per-workload identifier the host stamps when starting a nested
/// Firecracker workload microVM inside the long-lived libkrun host
/// VM. Mirrors [`JobId`]'s shape but lives in its own newtype so the
/// dispatch loop can keep build jobs and workloads in separate
/// tables without conflating identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadId(pub Uuid);

impl WorkloadId {
    /// Mint a fresh workload id. Used by the host's dispatch path.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for WorkloadId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WorkloadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Inbound message sent host → guest over the persistent VM's
/// dispatch vsock port. Tagged-enum on the wire; every variant
/// carries `#[serde(deny_unknown_fields)]` so a future host
/// shipping a new variant against an old guest fails closed
/// instead of silently dropping fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostVmRequest {
    /// Dispatch a single build into the running VM. The host has
    /// already staged the job dir contents (cmd.sh / install_spec /
    /// etc.) under `job_dir_relpath`, which is a relative path
    /// inside the `/job` virtio-fs share. The guest exec's the job,
    /// streams `stderr` via [`HostVmResponse::StderrChunk`], and
    /// terminates the round with [`HostVmResponse::Result`].
    Run {
        /// Host-generated identifier echoed in every
        /// [`HostVmResponse`] for this dispatch.
        job_id: JobId,
        /// The job to execute. Same shape as the single-shot
        /// path's `BuilderJob`; the guest's dispatch loop converts
        /// it into the same exec args the single-shot path uses.
        job: BuilderJob,
        /// Relative path inside the `/job` virtio-fs share where
        /// the host already staged this job's artifacts. The guest
        /// resolves it as `/job/<job_dir_relpath>`.
        job_dir_relpath: String,
    },

    /// Tell the guest's dispatch loop to exit cleanly. Triggered
    /// by `mvmctl persistent-builder stop` or the supervisor's idle timer.
    ///
    /// Empty struct variant rather than unit so
    /// `#[serde(deny_unknown_fields)]` actually rejects extra
    /// fields on the wire — serde's deny_unknown_fields is a
    /// no-op on unit variants of internally-tagged enums. Wire
    /// shape is identical (`{"kind":"shutdown"}`).
    Shutdown {},

    /// Start a workload microVM inside the host VM. The guest's
    /// dispatch loop hands this to a
    /// `WorkloadVmm` backend (Firecracker today; the fields are
    /// generic microVM concepts, not Firecracker-shaped, so a
    /// second VMM is a pure addition — see
    /// `mvm-host-vm-init/src/workload.rs`).
    ///
    /// All paths are resolved *inside the host VM* (the guest), not
    /// on the outer host: `kernel_path` / `rootfs_path` point at
    /// files the host already staged into a share the guest can
    /// see, and `vsock_socket_dir` is where the guest creates the
    /// per-workload state dir + vsock UDS.
    WorkloadStart {
        /// Host-minted identifier the guest echoes in
        /// [`HostVmResponse::WorkloadStarted`] and keys the
        /// per-workload state dir on.
        workload_id: WorkloadId,
        /// Absolute path (inside the host VM) to the workload
        /// kernel image the VMM boots.
        kernel_path: String,
        /// Absolute path (inside the host VM) to the workload root
        /// filesystem image, attached as the single root drive.
        rootfs_path: String,
        /// Directory (inside the host VM) under which the guest
        /// creates the workload's vsock UDS. The per-workload state
        /// dir is derived from `workload_id`; this is the parent
        /// the VMM's vsock socket lands in.
        vsock_socket_dir: String,
        /// Number of vCPUs for the workload microVM.
        vcpus: u32,
        /// Guest RAM for the workload microVM, in MiB.
        memory_mib: u32,
        /// Extra kernel command-line tokens appended to the VMM's
        /// base cmdline. The host supplies `root=` / `init=` /
        /// dm-verity roothash here. A single space-joined string
        /// (not `Vec<String>`) so the guest's no-serde hand-rolled
        /// parser stays simple.
        kernel_cmdline_extras: String,
    },

    /// Stop a running workload microVM. The guest-side
    /// SIGTERM/wait/cleanup path is not yet wired.
    WorkloadStop {
        /// Echo of the matching [`HostVmRequest::WorkloadStart::workload_id`].
        workload_id: WorkloadId,
    },

    /// Query a workload microVM's lifecycle status. The guest-side
    /// check (process alive, vsock reachable, etc.) is not yet wired.
    WorkloadStatus {
        /// Echo of the matching [`HostVmRequest::WorkloadStart::workload_id`].
        workload_id: WorkloadId,
    },
}

/// Outbound message sent guest → host over the same vsock conn.
/// Every variant carries the originating `job_id` (except
/// [`HostVmResponse::Bye`]) so the host can demux concurrent
/// dispatches in V2+ — V1 serializes via the supervisor's dispatch
/// mutex, but the wire is shaped for the looser case so V2 doesn't
/// break compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostVmResponse {
    /// A line of stderr from the running job. Sent as soon as the
    /// guest reads it; the host plumbs these into its existing
    /// `<vm_state_dir>/console.log` capture so debugging UX stays
    /// uniform across single-shot and persistent modes. The
    /// trailing newline is stripped by the guest.
    StderrChunk {
        /// Echo of the [`HostVmRequest::Run::job_id`] this chunk
        /// belongs to.
        job_id: JobId,
        /// One line of stderr (no trailing `\n`).
        line: String,
    },

    /// The job terminated. Final message for a given dispatch; the
    /// host releases the dispatch mutex and returns control to its
    /// caller.
    Result {
        /// Echo of the [`HostVmRequest::Run::job_id`].
        job_id: JobId,
        /// Process exit code from the inner build command. Zero
        /// means success; non-zero is a build failure (not a
        /// dispatch failure — that's signaled via a closed vsock
        /// conn).
        exit_code: i32,
        /// Last `n` lines of stderr, capped at a small bound so
        /// the response frame fits comfortably under the 256 KiB
        /// framing cap. Useful for log-on-failure callers that
        /// don't want to keep the streaming buffer.
        stderr_tail: String,
        /// Boot timings for the VM this dispatch ran in. Populated
        /// only on the supervisor's *first* dispatch (cold boot);
        /// subsequent dispatches in the same persistent VM session
        /// see `None` — there is no second cold boot to time.
        ///
        /// `Box` keeps the [`HostVmResponse`] enum's stack size
        /// dominated by the common [`Self::StderrChunk`] variant
        /// instead of the heavy 11-field [`BootTimingsWire`] —
        /// clippy's `large_enum_variant` lint. Wire shape is
        /// unaffected (still serializes as a bare object or
        /// `null`).
        boot_timings: Option<Box<BootTimingsWire>>,
        /// Per-dispatch timings. Populated on every dispatch.
        job_timings: JobTimings,
    },

    /// Graceful acknowledgement of [`HostVmRequest::Shutdown`].
    /// Sent right before the guest's dispatch loop returns and the
    /// VM powers off.
    ///
    /// Empty struct variant for the same reason as
    /// [`HostVmRequest::Shutdown`] — gives `deny_unknown_fields`
    /// something to enforce against.
    Bye {},

    /// Acknowledgement that a workload microVM has been spawned inside
    /// the host VM.
    WorkloadStarted {
        /// Echo of the originating [`HostVmRequest::WorkloadStart::workload_id`].
        workload_id: WorkloadId,
        /// PID of the spawned VMM process *inside the host VM*. The
        /// host tracks it for the workload lifecycle (stop / status /
        /// crash recovery).
        pid: u32,
    },

    /// Acknowledgement that a workload microVM has shut down and its
    /// state dir was cleaned up.
    WorkloadStopped {
        /// Echo of the originating [`HostVmRequest::WorkloadStop::workload_id`].
        workload_id: WorkloadId,
    },

    /// Workload lifecycle status report.
    WorkloadStatusReport {
        /// Echo of the originating [`HostVmRequest::WorkloadStatus::workload_id`].
        workload_id: WorkloadId,
        /// One of `"running"`, `"stopped"`, `"not_found"`. A typed
        /// enum is deferred until the host actually consumes the
        /// distinction; the closed string set is asserted by
        /// the guest-side emitter tests.
        status: String,
    },

    /// A workload lifecycle operation failed.
    /// Fail-closed negative path: the guest always sends a typed
    /// frame (spawn error, state-dir collision, parse failure)
    /// rather than dropping the connection, so the host can
    /// distinguish a real failure from a transport EOF.
    WorkloadFailed {
        /// Echo of the originating request's `workload_id`.
        workload_id: WorkloadId,
        /// Human-readable failure reason for logs / surfacing.
        error: String,
    },
}

/// Per-dispatch timings, in milliseconds. Independent of
/// [`BootTimingsWire`] (which is per-VM-boot); these stamp the
/// portions of a dispatch that aren't VM boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobTimings {
    /// Time between the host writing the [`HostVmRequest::Run`]
    /// frame and the guest's dispatch loop reading it.
    pub dispatch_ms: u64,
    /// Time spent inside the build subprocess proper (between
    /// fork-exec and `waitpid` returning).
    pub build_ms: u64,
    /// Time spent on per-job teardown (namespace tear-down,
    /// scratch dir cleanup) before the dispatch loop returns to
    /// accept the next request.
    pub teardown_ms: u64,
}

/// Wire-shape mirror of `mvm-host-vm-init`'s `BootTimings` struct
/// (`crates/mvm-host-vm-init/src/boot_timings.rs`). The init crate
/// is binary-only and keeps its struct `pub(crate)`; this mirror
/// lives in a publicly-importable spot so the host's response
/// deserializer doesn't depend on builder-init internals. The two
/// structs are kept field-identical by the round-trip test in this
/// module + the existing field-order assertion in
/// `boot_timings::tests::to_json_emits_all_fields_in_stable_order`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootTimingsWire {
    pub init_start_ms: Option<u64>,
    pub pseudofs_ready_ms: Option<u64>,
    pub nix_device_ready_ms: Option<u64>,
    pub nix_seeded_ms: Option<u64>,
    pub nix_mounted_ms: Option<u64>,
    /// `/nix-path-registration` loaded into
    /// `/nix/var/nix/db` so the in-VM `nix build` skips
    /// re-substituting seeded paths. `None` on subsequent boots
    /// where the marker is present and registration is skipped.
    pub nix_db_loaded_ms: Option<u64>,
    pub modules_ready_ms: Option<u64>,
    pub virtiofs_ready_ms: Option<u64>,
    pub network_ready_ms: Option<u64>,
    pub job_start_ms: Option<u64>,
    pub job_end_ms: Option<u64>,
    pub poweroff_start_ms: Option<u64>,
}

// ============================================================================
// Host-side reader
// ============================================================================

/// Outcome of trying to read a [`HostVmResponse`] from a builder
/// VM's vsock dispatch socket. Modelled explicitly because the
/// "guest exited without sending anything" case is a normal,
/// non-error outcome while the guest-side send code is being wired:
/// it isn't sending yet, and old cached dev images will continue not
/// to send for some time after it lands.
#[derive(Debug)]
pub enum HostVmResponseRead {
    /// A complete, well-formed response arrived.
    Frame(HostVmResponse),
    /// The connection was opened but the guest closed it without
    /// sending any bytes (clean EOF). Callers should fall back to
    /// the legacy file-based result path.
    EmptyEof,
    /// The read timed out before a full frame arrived. Callers
    /// should treat this the same as `EmptyEof` while the guest-side
    /// send code is unwired (the legacy file path is the
    /// authoritative source); once the guest reliably sends, a
    /// timeout becomes a real signal worth surfacing.
    Timeout,
}

/// Connect to the libkrun-managed Unix socket for
/// [`mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT`] and read
/// one framed [`HostVmResponse`] within `timeout`.
///
/// The framing reader reuses [`mvm_agentd::vsock::read_frame`],
/// which enforces the same 256 KiB pre-deserialize cap
/// [`HostVmResponse`] inherits — see this module's header docs.
///
/// `socket_path` is `<vm_state_dir>/vsock-<BUILDER_DISPATCH_PORT>.sock`
/// — the file libkrun creates when the krun context is configured
/// via `add_vsock_port(BUILDER_DISPATCH_PORT)`.
pub fn read_host_vm_response_from_socket(
    socket_path: &std::path::Path,
    timeout: std::time::Duration,
) -> std::io::Result<HostVmResponseRead> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    Ok(read_host_vm_response(&mut stream))
}

/// Read one framed [`HostVmResponse`] from any `UnixStream`-like
/// stream. Returns [`HostVmResponseRead::EmptyEof`] on clean EOF
/// before any bytes arrive, [`HostVmResponseRead::Timeout`] on
/// `WouldBlock`/`TimedOut`, and propagates other I/O or serde
/// failures by reading them as Timeout-equivalent (the caller's
/// fallback path is the same — we don't want a corrupted/partial
/// frame to fail the whole build when the file-based path still
/// has the authoritative answer).
///
/// Separated from [`read_host_vm_response_from_socket`] so unit
/// tests can drive the wire with a `UnixStream::pair()` without
/// going through libkrun. The two layers compose: the
/// `from_socket` variant is `connect` + this.
pub fn read_host_vm_response(stream: &mut std::os::unix::net::UnixStream) -> HostVmResponseRead {
    match mvm_agentd::vsock::read_frame::<HostVmResponse>(stream) {
        Ok(resp) => HostVmResponseRead::Frame(resp),
        Err(e) => {
            // anyhow::Error chains the io::Error underneath when
            // read_exact failed. Walk the chain to classify.
            let src = e.source();
            if let Some(io_err) = src.and_then(|s| s.downcast_ref::<std::io::Error>()) {
                match io_err.kind() {
                    std::io::ErrorKind::UnexpectedEof => {
                        return HostVmResponseRead::EmptyEof;
                    }
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        return HostVmResponseRead::Timeout;
                    }
                    _ => {}
                }
            }
            // Default to Timeout so callers always have a fallback
            // path. Logging the underlying error is the caller's
            // responsibility.
            HostVmResponseRead::Timeout
        }
    }
}

/// Write one framed [`HostVmResponse`] to a `UnixStream`. Mirror
/// of [`read_host_vm_response`] — exists so unit tests of the
/// reader can produce real wire bytes via the same framing
/// `mvm-host-vm-init` uses (the actual guest emit hand-rolls the JSON
/// to keep builder-init's dep tree small). The pair-test using this
/// writer + the reader locks in the regression so the guest emit lands
/// against a known-good host reader.
pub fn write_host_vm_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: &HostVmResponse,
) -> std::io::Result<()> {
    mvm_agentd::vsock::write_frame(stream, response)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_run() -> HostVmRequest {
        HostVmRequest::Run {
            job_id: JobId(Uuid::nil()),
            job: BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            job_dir_relpath: "00000000-0000-0000-0000-000000000000".to_string(),
        }
    }

    fn sample_install_run() -> HostVmRequest {
        HostVmRequest::Run {
            job_id: JobId::new(),
            job: BuilderJob::Install {
                spec_path: PathBuf::from("/job/install_spec.json"),
            },
            job_dir_relpath: "deadbeef".to_string(),
        }
    }

    fn sample_result() -> HostVmResponse {
        HostVmResponse::Result {
            job_id: JobId(Uuid::nil()),
            exit_code: 0,
            stderr_tail: "warning: foo\nwarning: bar".to_string(),
            boot_timings: Some(Box::new(BootTimingsWire {
                init_start_ms: Some(0),
                pseudofs_ready_ms: Some(12),
                nix_device_ready_ms: Some(18),
                nix_seeded_ms: None,
                nix_mounted_ms: Some(220),
                nix_db_loaded_ms: Some(225),
                modules_ready_ms: Some(35),
                virtiofs_ready_ms: Some(48),
                network_ready_ms: Some(250),
                job_start_ms: Some(260),
                job_end_ms: Some(8400),
                poweroff_start_ms: Some(8410),
            })),
            job_timings: JobTimings {
                dispatch_ms: 3,
                build_ms: 8132,
                teardown_ms: 11,
            },
        }
    }

    fn roundtrip<T>(value: &T) -> T
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let bytes = serde_json::to_vec(value).expect("serialize");
        let back: T = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(value, &back, "wire roundtrip mismatch");
        back
    }

    #[test]
    fn host_vm_request_run_roundtrips() {
        roundtrip(&sample_run());
    }

    #[test]
    fn host_vm_request_install_run_roundtrips() {
        roundtrip(&sample_install_run());
    }

    #[test]
    fn host_vm_request_shutdown_roundtrips() {
        roundtrip(&HostVmRequest::Shutdown {});
    }

    #[test]
    fn host_vm_response_result_roundtrips() {
        roundtrip(&sample_result());
    }

    #[test]
    fn host_vm_response_bye_roundtrips() {
        roundtrip(&HostVmResponse::Bye {});
    }

    #[test]
    fn unit_like_variants_serialize_without_data_field() {
        // `Shutdown {}` and `Bye {}` are empty struct
        // variants (not unit) so deny_unknown_fields actually fires
        // on them. Make sure the wire shape stays identical to what
        // a true unit variant would have produced — single `kind`
        // field, no extras.
        assert_eq!(
            serde_json::to_string(&HostVmRequest::Shutdown {}).unwrap(),
            r#"{"kind":"shutdown"}"#
        );
        assert_eq!(
            serde_json::to_string(&HostVmResponse::Bye {}).unwrap(),
            r#"{"kind":"bye"}"#
        );
    }

    #[test]
    fn host_vm_response_stderr_chunk_roundtrips() {
        roundtrip(&HostVmResponse::StderrChunk {
            job_id: JobId::new(),
            line: "[mvm] nix build: 12/47 derivations".to_string(),
        });
    }

    // Workload variant round-trips with the real spawn config payload.

    fn sample_workload_start() -> HostVmRequest {
        HostVmRequest::WorkloadStart {
            workload_id: WorkloadId(Uuid::nil()),
            kernel_path: "/job/workload/vmlinux".to_string(),
            rootfs_path: "/job/workload/rootfs.ext4".to_string(),
            vsock_socket_dir: "/var/lib/mvm/workloads".to_string(),
            vcpus: 2,
            memory_mib: 1024,
            kernel_cmdline_extras: "root=/dev/vda ro init=/init".to_string(),
        }
    }

    #[test]
    fn workload_id_serializes_as_bare_uuid_string() {
        let id = WorkloadId(Uuid::nil());
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
    }

    #[test]
    fn host_vm_request_workload_start_roundtrips() {
        roundtrip(&sample_workload_start());
    }

    #[test]
    fn host_vm_request_workload_stop_roundtrips() {
        roundtrip(&HostVmRequest::WorkloadStop {
            workload_id: WorkloadId(Uuid::nil()),
        });
    }

    #[test]
    fn host_vm_request_workload_status_roundtrips() {
        roundtrip(&HostVmRequest::WorkloadStatus {
            workload_id: WorkloadId(Uuid::nil()),
        });
    }

    #[test]
    fn host_vm_response_workload_started_roundtrips() {
        roundtrip(&HostVmResponse::WorkloadStarted {
            workload_id: WorkloadId(Uuid::nil()),
            pid: 4242,
        });
    }

    #[test]
    fn host_vm_response_workload_stopped_roundtrips() {
        roundtrip(&HostVmResponse::WorkloadStopped {
            workload_id: WorkloadId(Uuid::nil()),
        });
    }

    #[test]
    fn host_vm_response_workload_status_report_roundtrips() {
        roundtrip(&HostVmResponse::WorkloadStatusReport {
            workload_id: WorkloadId(Uuid::nil()),
            status: "running".to_string(),
        });
    }

    #[test]
    fn host_vm_response_workload_failed_roundtrips() {
        roundtrip(&HostVmResponse::WorkloadFailed {
            workload_id: WorkloadId(Uuid::nil()),
            error: "spawn /usr/bin/firecracker: No such file or directory".to_string(),
        });
    }

    #[test]
    fn workload_variants_emit_snake_case_kind_tags() {
        // Wire stability — the host and guest agree on these
        // snake_case strings. Wire-format breaks here mean an
        // upgrade-order bug in production.
        assert_eq!(
            serde_json::to_value(sample_workload_start()).unwrap()["kind"],
            "workload_start"
        );
        assert_eq!(
            serde_json::to_value(HostVmRequest::WorkloadStop {
                workload_id: WorkloadId(Uuid::nil())
            })
            .unwrap()["kind"],
            "workload_stop"
        );
        assert_eq!(
            serde_json::to_value(HostVmRequest::WorkloadStatus {
                workload_id: WorkloadId(Uuid::nil())
            })
            .unwrap()["kind"],
            "workload_status"
        );
        assert_eq!(
            serde_json::to_value(HostVmResponse::WorkloadStarted {
                workload_id: WorkloadId(Uuid::nil()),
                pid: 1,
            })
            .unwrap()["kind"],
            "workload_started"
        );
        assert_eq!(
            serde_json::to_value(HostVmResponse::WorkloadFailed {
                workload_id: WorkloadId(Uuid::nil()),
                error: "boom".to_string(),
            })
            .unwrap()["kind"],
            "workload_failed"
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_workload_start_field() {
        // A *complete* workload_start payload plus one extra field —
        // exercises deny_unknown_fields specifically (not a missing-field
        // error). The fail-closed contract: a future host shipping a
        // new field against an old guest is rejected rather than
        // silently launching with the field dropped.
        let bad = serde_json::json!({
            "kind": "workload_start",
            "workload_id": "00000000-0000-0000-0000-000000000000",
            "kernel_path": "/job/workload/vmlinux",
            "rootfs_path": "/job/workload/rootfs.ext4",
            "vsock_socket_dir": "/var/lib/mvm/workloads",
            "vcpus": 2,
            "memory_mib": 1024,
            "kernel_cmdline_extras": "root=/dev/vda ro",
            "future_field": 42,
        });
        let res: Result<HostVmRequest, _> = serde_json::from_value(bad);
        assert!(
            res.is_err(),
            "deny_unknown_fields must reject future_field on workload_start, got {:?}",
            res
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_workload_started_field() {
        let bad = serde_json::json!({
            "kind": "workload_started",
            "workload_id": "00000000-0000-0000-0000-000000000000",
            "pid": 7,
            "future_field": "rogue",
        });
        let res: Result<HostVmResponse, _> = serde_json::from_value(bad);
        assert!(
            res.is_err(),
            "deny_unknown_fields must reject future_field on workload_started, got {:?}",
            res
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_workload_failed_field() {
        let bad = serde_json::json!({
            "kind": "workload_failed",
            "workload_id": "00000000-0000-0000-0000-000000000000",
            "error": "boom",
            "future_field": true,
        });
        let res: Result<HostVmResponse, _> = serde_json::from_value(bad);
        assert!(
            res.is_err(),
            "deny_unknown_fields must reject future_field on workload_failed, got {:?}",
            res
        );
    }

    #[test]
    fn job_timings_roundtrips() {
        roundtrip(&JobTimings {
            dispatch_ms: 1,
            build_ms: 2,
            teardown_ms: 3,
        });
    }

    #[test]
    fn job_id_serializes_as_bare_uuid_string() {
        // `#[serde(transparent)]` should drop the newtype wrapper
        // so the wire is just the UUID's hyphenated string.
        let id = JobId(Uuid::nil());
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_request_field() {
        // deny_unknown_fields is the wire-version-safety tactic — an
        // old guest seeing a new field on Run fails closed instead of
        // silently dropping it.
        let bad = serde_json::json!({
            "kind": "run",
            "job_id": "00000000-0000-0000-0000-000000000000",
            "job": { "Flake": { "flake_ref": "x", "attr_path": "y" } },
            "job_dir_relpath": "z",
            "future_field": 42,
        });
        let res: Result<HostVmRequest, _> = serde_json::from_value(bad);
        assert!(
            res.is_err(),
            "deny_unknown_fields should have rejected future_field, got {:?}",
            res
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_response_field() {
        let bad = serde_json::json!({
            "kind": "bye",
            "future_field": "noisy",
        });
        let res: Result<HostVmResponse, _> = serde_json::from_value(bad);
        assert!(
            res.is_err(),
            "deny_unknown_fields should have rejected future_field on Bye, got {:?}",
            res
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_job_timings_field() {
        let bad = serde_json::json!({
            "dispatch_ms": 1,
            "build_ms": 2,
            "teardown_ms": 3,
            "future_field": 4,
        });
        let res: Result<JobTimings, _> = serde_json::from_value(bad);
        assert!(res.is_err(), "got {:?}", res);
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_boot_timings_field() {
        let bad = serde_json::json!({
            "init_start_ms": 0,
            "pseudofs_ready_ms": 12,
            "nix_device_ready_ms": 18,
            "nix_seeded_ms": null,
            "nix_mounted_ms": 220,
            "modules_ready_ms": 35,
            "virtiofs_ready_ms": 48,
            "network_ready_ms": 250,
            "job_start_ms": 260,
            "job_end_ms": 8400,
            "poweroff_start_ms": 8410,
            "future_field": 9999,
        });
        let res: Result<BootTimingsWire, _> = serde_json::from_value(bad);
        assert!(res.is_err(), "got {:?}", res);
    }

    #[test]
    fn boot_timings_wire_parses_builder_init_json_shape() {
        // Lock-step compatibility: this JSON is the exact wire-shape
        // `mvm-host-vm-init`'s `BootTimings::to_json` emits (see the
        // `to_json_emits_all_fields_in_stable_order` test in
        // `crates/mvm-host-vm-init/src/boot_timings.rs`). If anyone
        // changes either side, this test fails and that's the
        // signal to re-sync the structs.
        let init_json = "{\"init_start_ms\":0,\
            \"pseudofs_ready_ms\":12,\
            \"nix_device_ready_ms\":18,\
            \"nix_seeded_ms\":null,\
            \"nix_mounted_ms\":220,\
            \"nix_db_loaded_ms\":225,\
            \"modules_ready_ms\":35,\
            \"virtiofs_ready_ms\":48,\
            \"network_ready_ms\":250,\
            \"job_start_ms\":260,\
            \"job_end_ms\":8400,\
            \"poweroff_start_ms\":8410}";
        let parsed: BootTimingsWire =
            serde_json::from_str(init_json).expect("must parse builder-init JSON shape");
        assert_eq!(parsed.init_start_ms, Some(0));
        assert_eq!(parsed.nix_seeded_ms, None);
        assert_eq!(parsed.nix_db_loaded_ms, Some(225));
        assert_eq!(parsed.poweroff_start_ms, Some(8410));
    }

    #[test]
    fn read_host_vm_response_roundtrips_through_unix_stream_pair() {
        // Host-side wire: when the guest sends a HostVmResponse over
        // the dispatch socket, the host reader should decode it
        // byte-for-byte. Pair of UnixStreams stands in for the
        // libkrun-managed socket.
        use std::os::unix::net::UnixStream;
        let (mut a, mut b) = UnixStream::pair().expect("socketpair");
        let response = sample_result();
        write_host_vm_response(&mut a, &response).expect("write");
        drop(a); // signal EOF after the single frame
        let read = read_host_vm_response(&mut b);
        match read {
            HostVmResponseRead::Frame(got) => assert_eq!(got, response),
            other => panic!("expected Frame, got {other:?}"),
        }
    }

    #[test]
    fn read_host_vm_response_returns_empty_eof_on_clean_close() {
        // The guest-send wiring transition expects this: the host
        // opens a vsock conn, but no guest send code is wired yet,
        // so the conn closes without bytes. Reader must signal
        // EmptyEof so the caller falls back to the legacy file
        // path instead of failing the build.
        use std::os::unix::net::UnixStream;
        let (a, mut b) = UnixStream::pair().expect("socketpair");
        drop(a);
        match read_host_vm_response(&mut b) {
            HostVmResponseRead::EmptyEof => {}
            other => panic!("expected EmptyEof, got {other:?}"),
        }
    }

    #[test]
    fn read_host_vm_response_returns_timeout_when_peer_idle() {
        // Reader's set_read_timeout(...) elapses without the peer
        // writing anything. Classify as Timeout (not Err) so the
        // caller's fallback path runs the same as EmptyEof.
        use std::os::unix::net::UnixStream;
        use std::time::Duration;
        let (_a, mut b) = UnixStream::pair().expect("socketpair");
        b.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set_read_timeout");
        match read_host_vm_response(&mut b) {
            HostVmResponseRead::Timeout => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn read_host_vm_response_handles_streamed_chunks() {
        // Guest writes a Result preceded by a StderrChunk over the
        // same conn; the reader picks up the first frame. This
        // documents that the reader reads ONE frame and stops —
        // multi-frame streaming is a later concern (the persistent
        // dispatch loop reads many).
        use std::os::unix::net::UnixStream;
        let (mut a, mut b) = UnixStream::pair().expect("socketpair");
        let chunk = HostVmResponse::StderrChunk {
            job_id: JobId(Uuid::nil()),
            line: "[mvm] building".to_string(),
        };
        let final_result = sample_result();
        write_host_vm_response(&mut a, &chunk).expect("chunk");
        write_host_vm_response(&mut a, &final_result).expect("result");
        drop(a);
        match read_host_vm_response(&mut b) {
            HostVmResponseRead::Frame(got) => assert_eq!(got, chunk),
            other => panic!("expected first frame to be the chunk, got {other:?}"),
        }
    }

    #[test]
    fn frame_cap_blocks_adversarial_length_prefix() {
        // A malicious or corrupted client setting
        // `length_prefix = u32::MAX` must
        // be rejected BEFORE the host allocates that many bytes.
        // The framing reader in `mvm_agentd::vsock::read_frame`
        // enforces this for every caller that uses the existing
        // length-prefix wire, which this protocol does. We
        // exercise it here to keep the regression visible from
        // this crate's test suite without depending on the fuzz
        // harness running in CI.
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (mut a, mut b) = UnixStream::pair().expect("socketpair");
        // Write a length prefix that's larger than 256 KiB but
        // small enough that send + buffering don't block. Pad with
        // a few zero bytes so the connection doesn't EOF
        // immediately.
        let oversize: u32 = (512 * 1024) as u32;
        a.write_all(&oversize.to_be_bytes()).expect("write len");
        a.write_all(&[0u8; 16]).expect("write tail");
        a.shutdown(std::net::Shutdown::Write).expect("close");

        let res = mvm_agentd::vsock::read_frame::<serde_json::Value>(&mut b);
        assert!(
            res.is_err(),
            "oversized frame must be rejected before allocation"
        );
        let msg = format!("{:?}", res.err().unwrap());
        assert!(
            msg.contains("Frame too large") || msg.contains("too large"),
            "error should mention size, got: {msg}"
        );
    }
}
