//! Boot-time validation of `/etc/mvm/entrypoint`.
//!
//! `RunEntrypoint` runs only the program named by this marker file. The
//! agent reads the marker once at boot, resolves it through `realpath`,
//! and asserts the resolved binary lives on the verity-protected rootfs
//! under `/usr/lib/mvm/wrappers/` with the expected ownership and mode.
//! Any failure refuses subsequent `RunEntrypoint` requests with
//! `RunEntrypointError::EntrypointInvalid`.
//!
//! The validation is encapsulated as a policy struct so unit tests can
//! point it at a temporary directory tree. Production callers use
//! [`EntrypointPolicy::production`].

use std::fs::{File, Metadata};
use std::io::{Read, Seek};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Policy describing where the entrypoint marker lives and what shape
/// the resolved binary must have.
#[derive(Debug, Clone)]
pub struct EntrypointPolicy {
    /// Path to the marker file whose contents are an absolute path to
    /// the wrapper binary.
    pub marker_path: PathBuf,
    /// The resolved wrapper path must start with this prefix.
    pub allowed_prefix: PathBuf,
    /// If `Some`, the resolved wrapper must live on the same filesystem
    /// (same `dev_t`) as this reference path. The reference is the
    /// verity rootfs in production. `None` skips the check (test only).
    pub same_fs_as: Option<PathBuf>,
    /// Required `st_mode & 0o7777` of the resolved wrapper.
    pub required_mode: u32,
    /// Required `st_uid` of the resolved wrapper.
    pub required_uid: u32,
    /// Required `st_gid` of the resolved wrapper.
    pub required_gid: u32,
    /// When true, a `#!/bin/sh` style shebang on the resolved wrapper is
    /// allowed. Sealed rootfs images currently bake the entrypoint as a
    /// shell script under `/etc/mvm/entrypoint` rather than a wrapper
    /// path, so the fallback policy needs to accept it.
    pub allow_shell_shebang: bool,
}

impl EntrypointPolicy {
    /// Production policy: read `/etc/mvm/entrypoint`; resolved binary
    /// must live under `/usr/lib/mvm/wrappers/` on the same filesystem
    /// as `/usr`, owned root, mode 0555. (Read-only: mkGuest's rootfs
    /// hardening pass strips owner-write from baked files, and the agent
    /// binary itself is 0555 — owner-write would be the anomaly here.)
    pub fn production() -> Self {
        Self {
            marker_path: PathBuf::from("/etc/mvm/entrypoint"),
            allowed_prefix: PathBuf::from("/usr/lib/mvm/wrappers/"),
            same_fs_as: Some(PathBuf::from("/usr")),
            required_mode: 0o555,
            required_uid: 0,
            required_gid: 0,
            allow_shell_shebang: false,
        }
    }

    /// Fallback policy for sealed images that bake the entrypoint as a
    /// script directly inside `/etc/mvm/entrypoint`. mkGuest currently emits
    /// this shape for `entrypoint.command` images, so the agent treats the
    /// marker file itself as the executable. The same ownership, mode, and
    /// same-filesystem checks apply; only the path prefix and the shebang
    /// restriction are relaxed.
    pub fn sealed_script_marker() -> Self {
        Self {
            marker_path: PathBuf::from("/etc/mvm/entrypoint"),
            allowed_prefix: PathBuf::from("/etc/mvm/"),
            same_fs_as: Some(PathBuf::from("/etc/mvm")),
            // mkGuest currently emits the script marker as 0755, so the
            // fallback policy accepts either 0555 or 0755. Immutable baked
            // files are still read-only in practice because the rootfs is
            // mounted ro; tightening this to 0555 can follow the wrapper
            // layout migration in mkGuest.
            required_mode: 0o755,
            required_uid: 0,
            required_gid: 0,
            allow_shell_shebang: true,
        }
    }

    /// Validate the policy against the live filesystem. On success
    /// returns the resolved wrapper path plus a held-open file handle
    /// (used at spawn time as `/proc/self/fd/<n>` to defeat TOCTOU
    /// between validation and spawn).
    pub fn validate(&self) -> Result<ValidatedEntrypoint, ValidationError> {
        let raw = std::fs::read_to_string(&self.marker_path).map_err(|e| {
            ValidationError::ReadMarker {
                path: self.marker_path.clone(),
                // The kind is kept alongside the rendered message: an absent
                // marker means the image offers no entrypoint, while one that
                // exists and cannot be read is a real misconfiguration. Only
                // `to_string()` was retained before, so the two were
                // indistinguishable downstream and both counted as failures.
                kind: e.kind(),
                source: e.to_string(),
            }
        })?;

        // Sealed-script shortcut: mkGuest currently bakes the entrypoint as a
        // shebang script directly inside the marker file. Treat the marker
        // itself as the executable, applying the same ownership, mode, and
        // same-filesystem checks as a wrapper path.
        if self.allow_shell_shebang && raw.starts_with("#!") {
            let resolved = self.marker_path.clone();
            if !resolved.starts_with(&self.allowed_prefix) {
                return Err(ValidationError::OutsideAllowedPrefix {
                    resolved,
                    allowed_prefix: self.allowed_prefix.clone(),
                });
            }
            let metadata = std::fs::metadata(&resolved).map_err(|e| ValidationError::Stat {
                path: resolved.clone(),
                source: e.to_string(),
            })?;
            check_metadata(
                &metadata,
                &resolved,
                self.required_uid,
                self.required_gid,
                self.required_mode,
            )?;
            if let Some(reference) = &self.same_fs_as {
                let reference_meta =
                    std::fs::metadata(reference).map_err(|e| ValidationError::Stat {
                        path: reference.clone(),
                        source: e.to_string(),
                    })?;
                if metadata.dev() != reference_meta.dev() {
                    return Err(ValidationError::DifferentFilesystem {
                        resolved: resolved.clone(),
                        reference: reference.clone(),
                        resolved_dev: metadata.dev(),
                        reference_dev: reference_meta.dev(),
                    });
                }
            }
            let file = File::open(&resolved).map_err(|e| ValidationError::Open {
                path: resolved.clone(),
                source: e.to_string(),
            })?;
            return Ok(ValidatedEntrypoint {
                resolved,
                file,
                use_resolved_path: true,
            });
        }

        let stated = PathBuf::from(raw.trim());
        if !stated.is_absolute() {
            return Err(ValidationError::NotAbsolute { path: stated });
        }

        let resolved =
            std::fs::canonicalize(&stated).map_err(|e| ValidationError::Canonicalize {
                path: stated.clone(),
                source: e.to_string(),
            })?;

        if !resolved.starts_with(&self.allowed_prefix) {
            return Err(ValidationError::OutsideAllowedPrefix {
                resolved,
                allowed_prefix: self.allowed_prefix.clone(),
            });
        }

        let metadata = std::fs::metadata(&resolved).map_err(|e| ValidationError::Stat {
            path: resolved.clone(),
            source: e.to_string(),
        })?;

        check_metadata(
            &metadata,
            &resolved,
            self.required_uid,
            self.required_gid,
            self.required_mode,
        )?;

        if let Some(reference) = &self.same_fs_as {
            let reference_meta =
                std::fs::metadata(reference).map_err(|e| ValidationError::Stat {
                    path: reference.clone(),
                    source: e.to_string(),
                })?;
            if metadata.dev() != reference_meta.dev() {
                return Err(ValidationError::DifferentFilesystem {
                    resolved,
                    reference: reference.clone(),
                    resolved_dev: metadata.dev(),
                    reference_dev: reference_meta.dev(),
                });
            }
        }

        let mut file = File::open(&resolved).map_err(|e| ValidationError::Open {
            path: resolved.clone(),
            source: e.to_string(),
        })?;
        if !self.allow_shell_shebang {
            check_no_shell_shebang(&mut file, &resolved)?;
        }

        Ok(ValidatedEntrypoint {
            resolved,
            file,
            use_resolved_path: false,
        })
    }
}

fn check_metadata(
    metadata: &Metadata,
    path: &Path,
    required_uid: u32,
    required_gid: u32,
    required_mode: u32,
) -> Result<(), ValidationError> {
    if !metadata.file_type().is_file() {
        return Err(ValidationError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != required_uid || metadata.gid() != required_gid {
        return Err(ValidationError::WrongOwnership {
            path: path.to_path_buf(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        });
    }
    let perm_bits = metadata.mode() & 0o7777;
    if perm_bits & 0o6000 != 0 {
        return Err(ValidationError::SetuidOrSetgid {
            path: path.to_path_buf(),
            mode: perm_bits,
        });
    }
    if perm_bits != required_mode {
        return Err(ValidationError::WrongMode {
            path: path.to_path_buf(),
            mode: perm_bits,
            required: required_mode,
        });
    }
    Ok(())
}

fn check_no_shell_shebang(file: &mut File, path: &Path) -> Result<(), ValidationError> {
    const SHEBANG_SCAN_BYTES: usize = 256;
    let mut prefix = [0u8; SHEBANG_SCAN_BYTES];
    let len = file
        .read(&mut prefix)
        .map_err(|e| ValidationError::ReadEntrypoint {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;
    file.rewind().map_err(|e| ValidationError::ReadEntrypoint {
        path: path.to_path_buf(),
        source: e.to_string(),
    })?;
    if let Some(shell) = mvm_contract::entrypoint::detect_shell_shebang(&prefix[..len]) {
        return Err(ValidationError::ShellEntrypoint {
            path: path.to_path_buf(),
            shell: shell.shell,
        });
    }
    Ok(())
}

/// Result of a successful [`EntrypointPolicy::validate`]. Holds the
/// resolved path plus an open file handle. The file handle stays
/// alive for the lifetime of the agent so spawning via
/// `/proc/self/fd/<n>` is TOCTOU-safe — the kernel pins the inode.
#[derive(Debug)]
pub struct ValidatedEntrypoint {
    pub resolved: PathBuf,
    pub file: File,
    /// When true, spawn the entrypoint via its resolved filesystem path
    /// instead of `/proc/self/fd/<n>`. Needed for sealed-script markers
    /// whose interpreter chain relies on file capabilities on the rootfs.
    pub use_resolved_path: bool,
}

impl ValidatedEntrypoint {
    /// Clone by `dup`-ing the held file descriptor. The new
    /// `ValidatedEntrypoint` owns an independent FD pointing at the
    /// same inode — useful for handing the same validated wrapper to
    /// a long-lived owner (e.g., `worker_pool::WorkerPool`) without
    /// reaching into a shared static.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            resolved: self.resolved.clone(),
            file: self.file.try_clone()?,
            use_resolved_path: self.use_resolved_path,
        })
    }
}

/// Reasons validation can fail. The agent surfaces these to the host
/// as `RunEntrypointError::EntrypointInvalid` with a short message.
#[derive(Debug)]
pub enum ValidationError {
    ReadMarker {
        path: PathBuf,
        /// Kind of the underlying I/O error. `NotFound` means the image
        /// declares no entrypoint at all; anything else is a marker that
        /// exists and could not be read.
        kind: std::io::ErrorKind,
        source: String,
    },
    NotAbsolute {
        path: PathBuf,
    },
    Canonicalize {
        path: PathBuf,
        source: String,
    },
    OutsideAllowedPrefix {
        resolved: PathBuf,
        allowed_prefix: PathBuf,
    },
    Stat {
        path: PathBuf,
        source: String,
    },
    NotRegularFile {
        path: PathBuf,
    },
    WrongOwnership {
        path: PathBuf,
        uid: u32,
        gid: u32,
    },
    SetuidOrSetgid {
        path: PathBuf,
        mode: u32,
    },
    WrongMode {
        path: PathBuf,
        mode: u32,
        required: u32,
    },
    DifferentFilesystem {
        resolved: PathBuf,
        reference: PathBuf,
        resolved_dev: u64,
        reference_dev: u64,
    },
    Open {
        path: PathBuf,
        source: String,
    },
    ReadEntrypoint {
        path: PathBuf,
        source: String,
    },
    ShellEntrypoint {
        path: PathBuf,
        shell: String,
    },
}

impl ValidationError {
    /// True when the marker shows the image simply does not expose a
    /// per-call entrypoint *wrapper* — it bakes its entrypoint as PID 1's
    /// boot command instead (the shape every `command`/`shell` image emits
    /// today; mkGuest does not yet produce a `/usr/lib/mvm/wrappers/`
    /// wrapper — see the wrapper-model plan). This is a clean "RunEntrypoint
    /// not offered" state, NOT a failure.
    ///
    /// Two shapes count, and only two. A non-absolute marker (a script body or
    /// a relative path, never a wrapper path), and a marker that is not there
    /// at all — an image declaring no entrypoint has no file to read, which is
    /// the plainest form of "not offered" there is.
    ///
    /// Everything else stays a hard failure: a marker that exists and cannot be
    /// read is a real misconfiguration, and one that *is* an absolute path but
    /// fails the ownership / mode / prefix / same-fs checks is a
    /// misconfiguration or a tamper.
    ///
    /// The absent case was missing, so `machine wait` exited 65 with
    /// `entrypoint failed: read entrypoint marker /etc/mvm/entrypoint: No such
    /// file or directory` against any guest that declares no entrypoint —
    /// reporting a component that does not apply as one that failed.
    pub fn is_entrypoint_not_offered(&self) -> bool {
        matches!(
            self,
            ValidationError::NotAbsolute { .. }
                | ValidationError::ReadMarker {
                    kind: std::io::ErrorKind::NotFound,
                    ..
                }
        )
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::ReadMarker { path, source, .. } => {
                write!(f, "read entrypoint marker {}: {source}", path.display())
            }
            ValidationError::NotAbsolute { path } => {
                write!(
                    f,
                    "entrypoint marker contents not absolute: {}",
                    path.display()
                )
            }
            ValidationError::Canonicalize { path, source } => {
                write!(f, "canonicalize {}: {source}", path.display())
            }
            ValidationError::OutsideAllowedPrefix {
                resolved,
                allowed_prefix,
            } => write!(
                f,
                "resolved entrypoint {} is outside allowed prefix {}",
                resolved.display(),
                allowed_prefix.display()
            ),
            ValidationError::Stat { path, source } => {
                write!(f, "stat {}: {source}", path.display())
            }
            ValidationError::NotRegularFile { path } => {
                write!(f, "{} is not a regular file", path.display())
            }
            ValidationError::WrongOwnership { path, uid, gid } => write!(
                f,
                "{} has uid={uid} gid={gid} (must be 0/0)",
                path.display()
            ),
            ValidationError::SetuidOrSetgid { path, mode } => write!(
                f,
                "{} has setuid/setgid bits set (mode {mode:o})",
                path.display()
            ),
            ValidationError::WrongMode {
                path,
                mode,
                required,
            } => write!(
                f,
                "{} has mode {mode:o} (must be {required:o})",
                path.display()
            ),
            ValidationError::DifferentFilesystem {
                resolved,
                reference,
                resolved_dev,
                reference_dev,
            } => write!(
                f,
                "{} is on a different filesystem ({resolved_dev}) than {} ({reference_dev})",
                resolved.display(),
                reference.display()
            ),
            ValidationError::Open { path, source } => {
                write!(f, "open {}: {source}", path.display())
            }
            ValidationError::ReadEntrypoint { path, source } => {
                write!(f, "read entrypoint {}: {source}", path.display())
            }
            ValidationError::ShellEntrypoint { path, shell } => write!(
                f,
                "{} uses shell interpreter {shell:?}; production entrypoints must not be shell wrappers",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// Per-call runner — executes the validated entrypoint with stdin piped in,
// stdout/stderr captured under caps, timeout enforced, output returned for
// the host-side handler to emit as `EntrypointEvent`s.
// ============================================================================

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::stream_pump::{CapturedOutput, Pump, PumpOutcome, RetainingSink};
use crate::vsock::EntrypointEvent;

/// Per-call resource caps. v1: 1 MiB on each stream.
///
/// `stdout_max` / `stderr_max` bound how much of a stream may sit in guest
/// memory at once. Past that bound the oldest held chunks are evicted and the
/// loss is reported as a gap record; the workload is never stopped and a write
/// is never refused. On the streaming path the held chunks are events on their
/// way to the consumer, so an eviction there is output the consumer never
/// receives — these caps decide what is dropped from emission, not only how
/// long a tail is kept.
#[derive(Debug, Clone, Copy)]
pub struct CallCaps {
    /// Maximum bytes accepted for the wrapper's stdin. The one cap that still
    /// refuses: an over-sized request payload is rejected before spawn.
    pub stdin_max: usize,
    /// Maximum bytes retained from the wrapper's stdout.
    pub stdout_max: usize,
    /// Maximum bytes retained from the wrapper's stderr.
    pub stderr_max: usize,
    /// Maximum bytes captured from the wrapper's fd-3 control channel.
    /// Excess bytes are silently dropped
    /// — control-channel overflow does not kill the wrapper, since
    /// the channel is for structured records the host correlates by
    /// kind, not for unbounded user output.
    pub fd3_max: usize,
    /// Grace period between SIGTERM and SIGKILL on timeout / cap breach.
    pub kill_grace_period: Duration,
    /// Polling interval while waiting for exit.
    pub poll_interval: Duration,
}

impl CallCaps {
    /// Default v1 caps: 1 MiB / stream, 2 s SIGTERM→SIGKILL grace, 50 ms poll.
    pub fn v1() -> Self {
        Self {
            stdin_max: 1024 * 1024,
            stdout_max: 1024 * 1024,
            stderr_max: 1024 * 1024,
            fd3_max: 1024 * 1024,
            kill_grace_period: Duration::from_secs(2),
            poll_interval: Duration::from_millis(50),
        }
    }
}

impl Default for CallCaps {
    fn default() -> Self {
        Self::v1()
    }
}

/// Kernel-enforced resource ceilings applied to a child before `execve`.
///
/// Wall time and byte-stream limits remain in [`CallCaps`]; these ceilings
/// bound resources the stream pump cannot control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessResourceLimits {
    /// Maximum process address space in bytes.
    pub address_space_bytes: u64,
    /// Maximum CPU time in milliseconds. The kernel limit is rounded up to a
    /// whole second so every positive admitted budget remains executable.
    pub cpu_millis: u32,
}

/// Cloneable, process-local cancellation signal for one admitted call.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request cancellation. Repeated requests are idempotent.
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// One control-channel record parsed from the wrapper's fd-3 stream.
/// Wire format (length-prefixed JSON header + length-prefixed payload)
/// is documented at `mvm_agentd::vsock::EntrypointEvent::Control`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecord {
    pub header_json: String,
    pub payload: Vec<u8>,
}

impl From<ControlRecord> for EntrypointEvent {
    /// Every route from a record to the wire runs through here, so the frame
    /// budget applies to all of them: a record that cannot be framed is
    /// replaced by a bounded notice instead of overflowing the writer, which
    /// would end the call early and discard everything behind it.
    fn from(record: ControlRecord) -> Self {
        crate::stream_pump::control_within_frame_budget(record.header_json, record.payload)
    }
}

/// One run of the validated wrapper, as a value.
///
/// Grouped rather than passed positionally because the streaming form takes a
/// sink on top of these, and six same-shaped arguments are how call sites
/// start transposing them.
pub struct EntrypointCall<'a> {
    /// The boot-validated wrapper to run.
    pub entrypoint: &'a ValidatedEntrypoint,
    /// Working directory for the call — its private TMPDIR in production.
    pub cwd: &'a Path,
    /// Bytes piped to the wrapper's stdin, which is then closed.
    pub stdin: &'a [u8],
    /// Wall-clock budget before the kill ladder starts.
    pub timeout: Duration,
    pub caps: CallCaps,
    /// Optional kernel resource ceilings. Ordinary entrypoint calls retain
    /// their existing behavior; admitted extensions always set this value.
    pub resource_limits: Option<ProcessResourceLimits>,
    /// Optional controller-owned cancellation signal.
    pub cancellation: Option<CancellationToken>,
    /// Environment injected after `env_clear()`.
    pub env: Vec<(String, String)>,
    /// Keep the child's stdin open after `stdin` is written, handing it to
    /// [`crate::stream_input::InputDesk`] so admitted host frames can keep
    /// feeding it until the host closes the stream.
    ///
    /// `false` closes stdin immediately, which is what makes a read-to-EOF
    /// workload terminate. Opting in is therefore also opting into "this call
    /// ends when the host says so, or when the deadline does".
    pub stream_input: bool,
}

/// How one run of the wrapper ended, carrying nothing it produced.
///
/// [`CallOutcome`] is this plus the buffered form's [`CapturedOutput`]. The
/// streaming form has no buffers to attach: every byte already left through
/// the sink as it was read.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// Wrapper exited normally with the given code.
    Exited { code: i32 },
    /// Wrapper exceeded the wall-clock timeout. Killed.
    Timeout,
    /// The owning controller canceled the call. Killed.
    Canceled,
    /// The request payload exceeded `stdin_max`; the wrapper was never
    /// spawned.
    StdinCap,
    /// `Command::spawn` itself failed.
    SpawnFailed { message: String },
    /// Wrapper exited via signal (segfault, OOM kill, etc.).
    WrapperCrashed { signal: i32 },
}

impl From<PumpOutcome> for RunOutcome {
    fn from(outcome: PumpOutcome) -> Self {
        match outcome {
            PumpOutcome::Exited(code) => RunOutcome::Exited { code },
            PumpOutcome::Crashed { signal } => RunOutcome::WrapperCrashed { signal },
            PumpOutcome::Timeout => RunOutcome::Timeout,
            PumpOutcome::Canceled => RunOutcome::Canceled,
        }
    }
}

/// Outcome of running the wrapper. The caller maps this to the
/// `EntrypointEvent` stream sent back over vsock.
///
/// There is no output-cap variant: a stream past its bound prunes and reports
/// a gap in [`CapturedOutput::gaps`], so how much a workload said is never a
/// way for its call to end.
#[derive(Debug)]
pub enum CallOutcome {
    /// Wrapper exited normally with the given code.
    Exited { code: i32, output: CapturedOutput },
    /// Wrapper exceeded the wall-clock timeout. Killed.
    Timeout { output: CapturedOutput },
    /// The owning controller canceled the call.
    Canceled { output: CapturedOutput },
    /// The request payload exceeded `stdin_max`; the wrapper was never
    /// spawned, so there is nothing captured to report.
    StdinCap,
    /// `Command::spawn` itself failed.
    SpawnFailed { message: String },
    /// Wrapper exited via signal (segfault, OOM kill, etc.).
    WrapperCrashed { signal: i32, output: CapturedOutput },
}

/// Run the validated wrapper and collect everything it produced.
///
/// The buffered form of [`execute_streaming`], and nothing more: it passes a
/// [`RetainingSink`] and folds what that kept into a [`CallOutcome`]. Callers
/// that answer with one value at the end of a call want this; callers that
/// have somewhere to put a byte the moment it exists want the streaming form,
/// because retention here is bounded and streaming is not.
pub fn execute(
    entrypoint: &ValidatedEntrypoint,
    cwd: &Path,
    stdin_data: &[u8],
    timeout: Duration,
    caps: CallCaps,
    env: Vec<(String, String)>,
) -> CallOutcome {
    let call = EntrypointCall {
        entrypoint,
        cwd,
        stdin: stdin_data,
        timeout,
        caps,
        resource_limits: None,
        cancellation: None,
        env,
        stream_input: false,
    };
    let mut retained = RetainingSink::new(&caps);
    let outcome = execute_streaming(&call, &mut |event| retained.accept(event));
    let output = retained.finish();
    match outcome {
        RunOutcome::Exited { code } => CallOutcome::Exited { code, output },
        RunOutcome::Timeout => CallOutcome::Timeout { output },
        RunOutcome::Canceled => CallOutcome::Canceled { output },
        RunOutcome::WrapperCrashed { signal } => CallOutcome::WrapperCrashed { signal, output },
        RunOutcome::StdinCap => CallOutcome::StdinCap,
        RunOutcome::SpawnFailed { message } => CallOutcome::SpawnFailed { message },
    }
}

/// Run the validated wrapper, handing every event to `sink` as the kernel
/// produces it.
///
/// The one place a workload's child is spawned and pumped. Output moves
/// through [`crate::stream_pump`], which emits stdout, stderr, and fd-3
/// control records without waiting for the child, so a `sink` that writes
/// somewhere is what makes a long-running workload observable while it runs.
/// Nothing is capped on the way out — [`CallCaps`]'s stream bounds govern
/// retention, and this form retains nothing. Kills the wrapper on timeout
/// only, never for producing too much output, and always reaps the child
/// before returning.
///
/// `sink` runs on the pump's own loop, which is also where the child's
/// deadline is checked. A sink that can block for an unbounded time must not
/// be passed directly — see [`crate::entrypoint_stream::stream_call`], which
/// exists to put one on the other side of a channel.
pub fn execute_streaming(
    call: &EntrypointCall<'_>,
    sink: &mut dyn FnMut(EntrypointEvent),
) -> RunOutcome {
    let EntrypointCall {
        entrypoint,
        cwd,
        stdin: stdin_data,
        timeout,
        caps,
        resource_limits: _resource_limits,
        cancellation,
        env,
        stream_input,
    } = call;
    if stdin_data.len() > caps.stdin_max {
        return RunOutcome::StdinCap;
    }
    if cancellation
        .as_ref()
        .is_some_and(CancellationToken::is_requested)
    {
        return RunOutcome::Canceled;
    }

    // On Linux `spawn_path` references the validation fd by number via
    // `/proc/self/fd/<n>`. `install_fd3_in_child` plants the
    // control-channel pipe write end at fd 3 with `dup2(write_raw, 3)`
    // in the post-fork pre-exec hook, which closes whatever sat at fd
    // 3. If the validation fd is at fd 3 the dup2 silently destroys it
    // and the kernel sees a pipe write end at /proc/self/fd/3, which
    // it refuses with EACCES. Dup the validation fd above fd 3 first
    // so the two channels can't collide. The guard keeps the dup
    // alive across `cmd.spawn()` so the child inherits it.
    #[cfg(target_os = "linux")]
    let _spawn_fd_guard = match dup_above_fd3(&entrypoint.file) {
        Ok(fd) => fd,
        Err(e) => {
            return RunOutcome::SpawnFailed {
                message: format!("dup entrypoint fd above 3: {e}"),
            };
        }
    };
    #[cfg(target_os = "linux")]
    let program = {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", _spawn_fd_guard.as_raw_fd()))
    };
    #[cfg(not(target_os = "linux"))]
    let program = spawn_path(entrypoint);

    // RLIMIT_CORE=0 in the parent: child inherits, so a wrapper crash
    // doesn't write process memory containing in-flight payload bytes
    // to disk.
    set_no_core_dumps();

    // Open a pipe for the fd-3 control channel. The child
    // gets the write end at fd 3 (via `pre_exec` + `dup2`); the parent
    // reads the read end on a drain thread and parses the framed
    // record stream into `ControlRecord`s.
    let (fd3_read, fd3_write_for_child) = match make_fd3_pipe() {
        Ok(pair) => pair,
        Err(e) => {
            return RunOutcome::SpawnFailed {
                message: format!("create fd-3 pipe: {e}"),
            };
        }
    };

    // The workload launches under `env_clear()`, then only the explicitly
    // injected vars are added back (e.g. HTTP_PROXY + secret
    // placeholder vars). `env` arrives from the host over the authenticated
    // agent frame, but a malformed entry must never crash the agent:
    // `Command::env` panics if a key is empty / contains '=' or NUL, or a
    // value contains NUL, so drop those rather than pass them through.
    let safe_env = env
        .iter()
        .filter(|(k, v)| {
            !k.is_empty() && !k.contains('=') && !k.contains('\0') && !v.contains('\0')
        })
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect::<Vec<_>>();

    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(&program);
    cmd.current_dir(cwd)
        .env_clear()
        .envs(safe_env)
        // Put the wrapper into its own process group so a kill-signal
        // can be delivered to every process the wrapper might fork
        // (e.g. a shell that exec'd `sleep`). Without this, SIGKILL to
        // the wrapper leaves grandchildren holding our stdout/stderr
        // pipes open until they finish naturally.
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Move `fd3_write_for_child` into the closure so the child inherits
    // a known raw fd, then `dup2` it onto fd 3 and clear FD_CLOEXEC so
    // it survives `execve(2)`. Both raw fds are then closed in the
    // child's address space; the parent retains its own copies.
    //
    // The same closure empties the workload's capability bounding set. The
    // agent retains CAP_KILL and CAP_SYS_TIME to reap children and fix a
    // restored clock; the workload needs neither, and this is the last point
    // at which anything runs on its behalf.
    use std::os::fd::AsRawFd;
    let write_raw = fd3_write_for_child.as_raw_fd();
    // SAFETY: closure runs in the post-fork pre-exec child. Only async-
    // signal-safe libc calls are used (dup2, fcntl, close, prctl). No Rust
    // allocator calls.
    unsafe {
        #[cfg(target_os = "linux")]
        let resource_limits = *_resource_limits;
        cmd.pre_exec(move || {
            install_fd3_in_child(write_raw)?;
            #[cfg(target_os = "linux")]
            if let Some(limits) = resource_limits {
                apply_process_resource_limits(limits)?;
            }
            crate::guest_mount::drop_workload_capability_bounding_set()
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // pipe fds are closed via Drop on the OwnedFd values.
            return RunOutcome::SpawnFailed {
                message: format!("spawn {}: {}", program.display(), e),
            };
        }
    };

    // Claim the child before it can exit, so PID 1's orphan reaper records
    // its status for us rather than discarding it. Held until this call
    // returns, by which point the child has been waited on.
    let _owned = crate::child_wait::OwnedChild::new(child.id());

    // Drop the parent's copy of the write end so the child is the
    // only writer. Without this, reading the read end blocks
    // forever because the kernel sees a writer (us) still has it
    // open.
    drop(fd3_write_for_child);

    // Pipe the one-shot payload. A write error here means the wrapper already
    // died or closed its stdin; treat as soft failure and continue to
    // wait/drain for whatever it did emit.
    if let Some(mut pipe) = child.stdin.take() {
        let _ = pipe.write_all(stdin_data);
        if *stream_input {
            // The host intends to keep writing, so the fd survives this scope
            // and the EOF is the host's to send. `Pump::run` finds no stdin
            // left on the `Child` and has nothing to close.
            crate::stream_input::InputDesk::open(pipe);
        }
        // Otherwise dropping `pipe` closes stdin; without that the wrapper may
        // block forever on read.
    }

    // Nothing here waits for the child to die before output moves: the pump
    // hands each read straight to `sink`.
    let mut pump = Pump::new(caps)
        .control_channel(fd3_read)
        .deadline(Instant::now() + *timeout);
    if let Some(token) = cancellation {
        pump = pump.cancellation(token.clone());
    }
    let outcome = pump.run(&mut child, sink);

    if *stream_input {
        // The child is reaped. A desk left open would answer the next host
        // frame as if a workload were still reading it.
        crate::stream_input::InputDesk::abandon();
    }
    outcome.into()
}

#[cfg(target_os = "linux")]
fn apply_process_resource_limits(limits: ProcessResourceLimits) -> std::io::Result<()> {
    let address_space = libc::rlim_t::try_from(limits.address_space_bytes)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let cpu_seconds = u64::from(limits.cpu_millis).div_ceil(1000).max(1);
    let cpu = libc::rlim_t::try_from(cpu_seconds)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let address_limit = libc::rlimit {
        rlim_cur: address_space,
        rlim_max: address_space,
    };
    let cpu_limit = libc::rlimit {
        rlim_cur: cpu,
        rlim_max: cpu,
    };
    // SAFETY: setrlimit reads each fully initialized stack value during the
    // syscall. This function is called only by the post-fork pre-exec hook and
    // performs no allocation after constructing the values above.
    unsafe {
        if libc::setrlimit(libc::RLIMIT_AS, &address_limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Create an `O_CLOEXEC` pipe and return `(read_end, write_end)` as
/// `OwnedFd`s. The write end is what the child inherits at fd 3; the
/// read end stays in the parent. Both are CLOEXEC by default — the
/// child's fd 3 has CLOEXEC cleared in `install_fd3_in_child`.
///
/// Linux gets the atomic `pipe2(O_CLOEXEC)`; macOS (dev hosts only —
/// production guests are Linux) falls back to `pipe(2)` + `fcntl
/// FD_CLOEXEC`. The non-atomic fallback is acceptable for tests; it
/// would race with a concurrent fork in production, but production
/// runs the Linux branch.
fn make_fd3_pipe() -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds: [libc::c_int; 2] = [-1, -1];

    #[cfg(target_os = "linux")]
    let rc = {
        // SAFETY: pipe2 is a syscall, not stateful. Returns 0 on success.
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }
    };
    #[cfg(not(target_os = "linux"))]
    let rc = {
        // SAFETY: same — pipe(2) writes two fds and returns 0.
        unsafe { libc::pipe(fds.as_mut_ptr()) }
    };

    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // On non-Linux, set FD_CLOEXEC on both ends now (a brief window
    // between pipe(2) and fcntl is non-atomic — see doc-comment above).
    // SAFETY: fcntl(F_GETFD/F_SETFD) takes a raw fd and an int; `fds` were
    // just returned by pipe(2) above and are valid here, and the F_GETFD
    // result is checked (`flags >= 0`) before reuse. No memory is dereferenced.
    #[cfg(not(target_os = "linux"))]
    unsafe {
        for fd in fds {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }

    // SAFETY: pipe returned success; both fds are valid and ours to own.
    let read = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    Ok((read, write))
}

/// Post-fork, pre-exec: place the child's write-end at fd 3 and clear
/// `FD_CLOEXEC` on it so the wrapper inherits an open fd 3 across
/// `execve`. Async-signal-safe.
fn install_fd3_in_child(write_raw: libc::c_int) -> std::io::Result<()> {
    // SAFETY: this runs in the post-fork pre-exec child. Only async-
    // signal-safe calls are used.
    unsafe {
        if write_raw != 3 {
            // dup2 does an atomic close-and-rename; safe even if fd 3
            // happened to already be open (it won't, in this code path
            // — Command's piped stdio uses fds 0/1/2).
            if libc::dup2(write_raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Close the original raw fd; the child only needs fd 3
            // going forward.
            libc::close(write_raw);
        }
        // Clear FD_CLOEXEC on fd 3 so the inherited fd survives the
        // `execve` syscall. pipe2(O_CLOEXEC) sets CLOEXEC on both
        // ends; we explicitly clear it here.
        let flags = libc::fcntl(3, libc::F_GETFD);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set `RLIMIT_CORE = 0` on the calling process. Children inherit this
/// rlimit at fork+exec, so a wrapper crash doesn't dump core. Best-effort:
/// we log but don't fail the call if the syscall is denied.
pub(crate) fn set_no_core_dumps() {
    // SAFETY: setrlimit reads one `rlimit` through the pointer for the duration
    // of the call; `&zero` is a fully-initialized stack value that outlives it,
    // and the return code is checked below.
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = libc::setrlimit(libc::RLIMIT_CORE, &zero);
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("entrypoint: setrlimit(RLIMIT_CORE,0) failed: {err}");
        }
    }
}

/// Duplicate `original`'s raw fd onto the lowest available fd >= 4.
/// The returned `OwnedFd` must outlive `Command::spawn` so the child
/// inherits the dup and the kernel can resolve
/// `/proc/self/fd/<n>` against it at execve time.
///
/// `execute` uses this to hold the validation fd above the
/// control-channel slot at fd 3 — see the comment in `execute` for
/// the EACCES failure mode this avoids.
#[cfg(target_os = "linux")]
fn dup_above_fd3(original: &std::fs::File) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = original.as_raw_fd();
    // F_DUPFD (NOT CLOEXEC): the dup must survive `execve` so an
    // interpreter-script runner works. A shebang runner makes the kernel
    // re-exec `<interp> /proc/self/fd/<n>`; a CLOEXEC fd is closed across
    // that second execve, so the interpreter can't reopen the script
    // (ENOENT — the `mvmctl invoke` failure mode). Leaving CLOEXEC clear
    // lets the interpreter reopen /proc/self/fd/<n>, which still resolves
    // to the SAME boot-validated inode the agent holds open — so TOCTOU
    // safety is preserved, not weakened. The fd is read-only to a
    // world-readable (0555) wrapper, so leaking it into the runner + its
    // children grants nothing. ELF runners are unaffected (the kernel
    // reads the image during the first execve).
    // SAFETY: fcntl is async-signal-safe; arguments are validated.
    let new_raw = unsafe { libc::fcntl(raw, libc::F_DUPFD, 4) };
    if new_raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a positive raw fd; we own it.
    Ok(unsafe { OwnedFd::from_raw_fd(new_raw) })
}

/// Resolve the path the parent passes to `Command::new`.
///
/// On Linux, `/proc/self/fd/<n>` referencing the held-open validation
/// fd defeats TOCTOU between policy validation and spawn. On other
/// platforms (macOS dev/test), fall back to the canonicalized path —
/// production guests are always Linux so the fallback is for unit
/// tests only.
///
/// Note: `execute` does its own `dup_above_fd3` rather than calling
/// this directly, because the control-channel pipe at fd 3 collides
/// with a validation fd at fd 3. `worker_pool::spawn_worker` does not
/// install a fd-3 channel and so uses this function unchanged.
pub(crate) fn spawn_path(entrypoint: &ValidatedEntrypoint) -> PathBuf {
    if entrypoint.use_resolved_path {
        return entrypoint.resolved.clone();
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", entrypoint.file.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        entrypoint.resolved.clone()
    }
}

/// Deliver `signal` to the child's whole process group.
///
/// Negating the pid is what makes this reach descendants: the child is its own
/// group leader (`.process_group(0)` at spawn), so `kill(-pgid, …)` hits the
/// wrapper plus anything it forked — e.g. a shell that exec'd a long-running
/// `sleep`, which would otherwise survive and hold the output pipes open.
pub(crate) fn signal_process_group(child: &Child, signal: libc::c_int) {
    let pgid = child.id() as i32;
    // SAFETY: kill performs no memory access; the negated pgid names the
    // child's process group (it is the group leader via process_group(0)).
    unsafe {
        libc::kill(-pgid, signal);
    }
}

/// Blocking SIGTERM → grace → SIGKILL → reap.
///
/// Callers that must keep servicing something else while the child winds down
/// cannot use this — it owns the calling thread for up to `grace`. The stream
/// pump drives the same ladder step-by-step from its own loop for exactly that
/// reason.
pub(crate) fn kill_and_reap(child: &mut Child, grace: Duration) {
    signal_process_group(child, libc::SIGTERM);
    let escalate_at = Instant::now() + grace;
    while Instant::now() < escalate_at {
        if let Ok(Some(_)) = crate::child_wait::try_wait(child) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    signal_process_group(child, libc::SIGKILL);
    let _ = crate::child_wait::wait(child);
}

#[cfg(unix)]
pub(crate) fn signal_of(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(0)
}

#[cfg(not(unix))]
pub(crate) fn signal_of(_status: &std::process::ExitStatus) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    /// Create an isolated rootfs-like tree under a temp dir:
    ///   <tmp>/etc/mvm/entrypoint  → marker file
    ///   <tmp>/usr/lib/mvm/wrappers/<name>  → wrapper binary
    /// Returns (tmp_root, marker_path, wrapper_path).
    fn make_tree(
        wrapper_mode: u32,
        wrapper_content: &[u8],
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let etc_mvm = tmp.path().join("etc/mvm");
        let wrappers = tmp.path().join("usr/lib/mvm/wrappers");
        std::fs::create_dir_all(&etc_mvm).unwrap();
        std::fs::create_dir_all(&wrappers).unwrap();

        let wrapper = wrappers.join("python-runner");
        let mut f = std::fs::File::create(&wrapper).unwrap();
        f.write_all(wrapper_content).unwrap();
        let mut perms = std::fs::metadata(&wrapper).unwrap().permissions();
        perms.set_mode(wrapper_mode);
        std::fs::set_permissions(&wrapper, perms).unwrap();

        let marker = etc_mvm.join("entrypoint");
        std::fs::write(&marker, format!("{}\n", wrapper.display())).unwrap();

        (tmp, marker, wrapper)
    }

    fn test_policy(marker: PathBuf, allowed_prefix: PathBuf, mode: u32) -> EntrypointPolicy {
        let (uid, gid) = marker
            .is_file()
            .then(|| std::fs::read_to_string(&marker).ok())
            .flatten()
            .and_then(|marker_body| {
                marker_body
                    .lines()
                    .next()
                    .map(str::trim)
                    .filter(|line| line.starts_with('/'))
                    .map(PathBuf::from)
            })
            .and_then(|wrapper_path| {
                std::fs::symlink_metadata(&wrapper_path)
                    .ok()
                    .map(|metadata| (metadata.uid(), metadata.gid()))
            })
            .unwrap_or_else(|| (nix_compat_geteuid(), nix_compat_getegid()));
        // On macOS, /tmp resolves through a /private/... symlink, so
        // tempdir paths canonicalize away from their as-given form.
        // Match that resolution in the allowed_prefix so prefix checks
        // compare apples to apples.
        let allowed_prefix = std::fs::canonicalize(&allowed_prefix).unwrap_or(allowed_prefix);
        EntrypointPolicy {
            marker_path: marker,
            allowed_prefix,
            // Tests run unprivileged; can't satisfy a same-fs-as check
            // against a path outside the temp tree, and the unit tests
            // are about policy logic not filesystem topology.
            same_fs_as: None,
            required_mode: mode,
            required_uid: uid,
            required_gid: gid,
            allow_shell_shebang: false,
        }
    }

    fn nix_compat_geteuid() -> u32 {
        // SAFETY: geteuid is async-signal-safe and never fails.
        unsafe { libc::geteuid() }
    }

    fn nix_compat_getegid() -> u32 {
        // SAFETY: getegid is async-signal-safe and never fails.
        unsafe { libc::getegid() }
    }

    #[test]
    fn test_validate_happy_path() {
        let (tmp, marker, wrapper) = make_tree(0o555, b"#!/usr/bin/env python3\nprint('ok')\n");
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o555);
        let validated = policy.validate().expect("validate should succeed");
        assert_eq!(validated.resolved, std::fs::canonicalize(&wrapper).unwrap());
    }

    #[test]
    fn test_validate_rejects_shell_shebang() {
        let (tmp, marker, _wrapper) = make_tree(0o555, b"#!/bin/sh\necho no\n");
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o555);
        match policy.validate() {
            Err(ValidationError::ShellEntrypoint { shell, .. }) => {
                assert_eq!(shell, "sh");
            }
            other => panic!("expected ShellEntrypoint, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_rejects_env_shell_shebang() {
        let (tmp, marker, _wrapper) = make_tree(0o555, b"#!/usr/bin/env -S bash -eu\n");
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o555);
        match policy.validate() {
            Err(ValidationError::ShellEntrypoint { shell, .. }) => {
                assert_eq!(shell, "bash");
            }
            other => panic!("expected ShellEntrypoint, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_missing_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = test_policy(
            tmp.path().join("etc/mvm/entrypoint"),
            tmp.path().join("usr/lib/mvm/wrappers"),
            0o755,
        );
        match policy.validate() {
            Err(ValidationError::ReadMarker { .. }) => {}
            other => panic!("expected ReadMarker, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_marker_is_not_offered_rather_than_failed() {
        // An image that declares no entrypoint has no marker file. That is the
        // plainest "not offered" there is, and treating it as a failure made
        // `machine wait` exit 65 on every such guest.
        let err = ValidationError::ReadMarker {
            path: PathBuf::from("/etc/mvm/entrypoint"),
            kind: std::io::ErrorKind::NotFound,
            source: "No such file or directory (os error 2)".to_string(),
        };
        assert!(err.is_entrypoint_not_offered());
    }

    #[test]
    fn an_unreadable_marker_stays_a_failure() {
        // The marker exists and cannot be read: a real misconfiguration, and
        // the case that must not be swept into "not offered" along with the
        // absent one.
        let err = ValidationError::ReadMarker {
            path: PathBuf::from("/etc/mvm/entrypoint"),
            kind: std::io::ErrorKind::PermissionDenied,
            source: "Permission denied (os error 13)".to_string(),
        };
        assert!(!err.is_entrypoint_not_offered());
    }

    #[test]
    fn test_validate_relative_path_in_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/mvm")).unwrap();
        let marker = tmp.path().join("etc/mvm/entrypoint");
        std::fs::write(&marker, "wrappers/python-runner\n").unwrap();
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
        match policy.validate() {
            Err(ValidationError::NotAbsolute { .. }) => {}
            other => panic!("expected NotAbsolute, got {other:?}"),
        }
    }

    #[test]
    fn script_marker_classifies_as_not_offered_not_failed() {
        // A boot-script image bakes a shell script at /etc/mvm/entrypoint
        // (what `command`/`shell` mkGuest images emit), not an absolute
        // wrapper path. The agent must treat that as "RunEntrypoint not
        // offered", never a hard validation failure.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/mvm")).unwrap();
        let marker = tmp.path().join("etc/mvm/entrypoint");
        std::fs::write(&marker, "#!/bin/sh\nexec /bin/sleep infinity\n").unwrap();
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
        let err = policy
            .validate()
            .expect_err("script marker is not a wrapper");
        assert!(
            err.is_entrypoint_not_offered(),
            "script marker must classify as not-offered, got {err:?}"
        );
    }

    #[test]
    fn security_failure_is_not_classified_as_not_offered() {
        // A marker that IS an absolute path but fails an ownership/mode/prefix
        // check is a real failure, never silently downgraded to "not offered".
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("usr/lib/mvm/wrappers")).unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/mvm")).unwrap();
        let outside = tmp.path().join("usr/bin/evil");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(&outside, "x").unwrap();
        let marker = tmp.path().join("etc/mvm/entrypoint");
        std::fs::write(&marker, format!("{}\n", outside.display())).unwrap();
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
        let err = policy
            .validate()
            .expect_err("path outside the allowed prefix");
        assert!(
            !err.is_entrypoint_not_offered(),
            "a real security failure must stay a failure, got {err:?}"
        );
    }

    #[test]
    fn test_validate_outside_prefix() {
        let (tmp, marker, _wrapper) = make_tree(0o755, b"#!/bin/sh\n");
        // Lock prefix to a sibling dir that doesn't include the wrapper.
        let policy = test_policy(marker, tmp.path().join("usr/lib/something-else"), 0o755);
        match policy.validate() {
            Err(ValidationError::OutsideAllowedPrefix { .. }) => {}
            other => panic!("expected OutsideAllowedPrefix, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_wrong_mode() {
        let (tmp, marker, _wrapper) = make_tree(0o644, b"#!/bin/sh\n");
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o555);
        match policy.validate() {
            Err(ValidationError::WrongMode { mode, required, .. }) => {
                assert_eq!(mode, 0o644);
                assert_eq!(required, 0o555);
            }
            other => panic!("expected WrongMode, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_setuid_rejected() {
        let (tmp, marker, wrapper) = make_tree(0o4755, b"#!/bin/sh\n");
        let mode = std::fs::metadata(&wrapper)
            .expect("wrapper metadata")
            .permissions()
            .mode()
            & 0o7777;
        if mode & 0o4000 == 0 {
            eprintln!(
                "skipping setuid rejection test: host filesystem kept {:o} instead of a setuid mode",
                mode
            );
            return;
        }
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
        match policy.validate() {
            Err(ValidationError::SetuidOrSetgid { mode, .. }) => {
                assert_eq!(mode & 0o6000, 0o4000);
            }
            other => panic!("expected SetuidOrSetgid, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_marker_pointing_at_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/mvm")).unwrap();
        std::fs::create_dir_all(tmp.path().join("usr/lib/mvm/wrappers")).unwrap();
        let dir = tmp.path().join("usr/lib/mvm/wrappers");
        let marker = tmp.path().join("etc/mvm/entrypoint");
        std::fs::write(&marker, format!("{}\n", dir.display())).unwrap();
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
        match policy.validate() {
            Err(ValidationError::NotRegularFile { .. }) => {}
            other => panic!("expected NotRegularFile, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_marker_canonicalize_failure() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/mvm")).unwrap();
        let marker = tmp.path().join("etc/mvm/entrypoint");
        std::fs::write(&marker, "/nonexistent/path/that/cannot/resolve\n").unwrap();
        let policy = test_policy(marker, PathBuf::from("/nonexistent"), 0o755);
        match policy.validate() {
            Err(ValidationError::Canonicalize { .. }) => {}
            other => panic!("expected Canonicalize, got {other:?}"),
        }
    }

    #[test]
    fn test_production_policy_constants() {
        let p = EntrypointPolicy::production();
        assert_eq!(p.marker_path, PathBuf::from("/etc/mvm/entrypoint"));
        assert_eq!(p.allowed_prefix, PathBuf::from("/usr/lib/mvm/wrappers/"));
        assert_eq!(p.same_fs_as, Some(PathBuf::from("/usr")));
        assert_eq!(p.required_mode, 0o555);
        assert_eq!(p.required_uid, 0);
        assert_eq!(p.required_gid, 0);
    }
}
