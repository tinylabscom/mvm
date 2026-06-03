//! Boot-time validation of `/etc/mvm/runner`. ADR-007 / plan 41 W2.
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
}

impl EntrypointPolicy {
    /// Production policy: read `/etc/mvm/runner`; resolved binary
    /// must live under `/usr/lib/mvm/wrappers/` on the same filesystem
    /// as `/usr`, owned root, mode 0555. (Read-only: mkGuest's rootfs
    /// hardening pass strips owner-write from baked files, and the agent
    /// binary itself is 0555 — owner-write would be the anomaly here.)
    ///
    /// The marker is `/etc/mvm/runner`, NOT `/etc/mvm/entrypoint`:
    /// `/etc/mvm/entrypoint` is PID 1's boot command (a shell script
    /// `/init` sources), which can't double as a bare-absolute-path
    /// marker. Function workloads write `/etc/mvm/runner` =
    /// `/usr/lib/mvm/wrappers/runner`; command workloads omit it and the
    /// (non-fatal) marker read fails benignly since they never call
    /// `RunEntrypoint`.
    pub fn production() -> Self {
        Self {
            marker_path: PathBuf::from("/etc/mvm/runner"),
            allowed_prefix: PathBuf::from("/usr/lib/mvm/wrappers/"),
            same_fs_as: Some(PathBuf::from("/usr")),
            required_mode: 0o555,
            required_uid: 0,
            required_gid: 0,
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
                source: e.to_string(),
            }
        })?;
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

        let file = File::open(&resolved).map_err(|e| ValidationError::Open {
            path: resolved.clone(),
            source: e.to_string(),
        })?;

        Ok(ValidatedEntrypoint { resolved, file })
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

/// Result of a successful [`EntrypointPolicy::validate`]. Holds the
/// resolved path plus an open file handle. The file handle stays
/// alive for the lifetime of the agent so spawning via
/// `/proc/self/fd/<n>` is TOCTOU-safe — the kernel pins the inode.
#[derive(Debug)]
pub struct ValidatedEntrypoint {
    pub resolved: PathBuf,
    pub file: File,
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
        })
    }
}

/// Reasons validation can fail. The agent surfaces these to the host
/// as `RunEntrypointError::EntrypointInvalid` with a short message.
#[derive(Debug)]
pub enum ValidationError {
    ReadMarker {
        path: PathBuf,
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
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::ReadMarker { path, source } => {
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
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// Per-call runner — executes the validated entrypoint with stdin piped in,
// stdout/stderr captured under caps, timeout enforced, output returned for
// the host-side handler to emit as `EntrypointEvent`s. ADR-007 / plan 41 W2.
// ============================================================================

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Per-call resource caps. Plan 41 W2 v1: 1 MiB on each stream.
#[derive(Debug, Clone, Copy)]
pub struct CallCaps {
    /// Maximum bytes accepted for the wrapper's stdin.
    pub stdin_max: usize,
    /// Maximum bytes captured from the wrapper's stdout.
    pub stdout_max: usize,
    /// Maximum bytes captured from the wrapper's stderr.
    pub stderr_max: usize,
    /// Maximum bytes captured from the wrapper's fd-3 control channel
    /// (Plan-0010 §B4 / phase 4b). Excess bytes are silently dropped
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

/// One control-channel record parsed from the wrapper's fd-3 stream.
/// Wire format (length-prefixed JSON header + length-prefixed payload)
/// is documented at `mvm_guest::vsock::EntrypointEvent::Control`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecord {
    pub header_json: String,
    pub payload: Vec<u8>,
}

/// Outcome of running the wrapper. The caller maps this to the
/// `EntrypointEvent` stream sent back over vsock.
#[derive(Debug)]
pub enum CallOutcome {
    /// Wrapper exited normally with the given code.
    Exited {
        code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        controls: Vec<ControlRecord>,
    },
    /// Wrapper exceeded the wall-clock timeout. Killed.
    Timeout {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        controls: Vec<ControlRecord>,
    },
    /// One of the streams exceeded its cap. Killed.
    PayloadCap {
        stream: PayloadCapStream,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        controls: Vec<ControlRecord>,
    },
    /// `Command::spawn` itself failed.
    SpawnFailed { message: String },
    /// Wrapper exited via signal (segfault, OOM kill, etc.).
    WrapperCrashed {
        signal: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        controls: Vec<ControlRecord>,
    },
}

/// Which stream's cap was breached. `Stdin` means the request payload
/// itself exceeded `stdin_max`; the wrapper was never spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCapStream {
    Stdin,
    Stdout,
    Stderr,
}

/// Run the validated wrapper with the given stdin, timeout, and caps.
/// Drains stdout and stderr concurrently into capped buffers; kills the
/// wrapper on timeout or cap breach. Always reaps the child before
/// returning.
pub fn execute(
    entrypoint: &ValidatedEntrypoint,
    cwd: &Path,
    stdin_data: &[u8],
    timeout: Duration,
    caps: CallCaps,
) -> CallOutcome {
    if stdin_data.len() > caps.stdin_max {
        return CallOutcome::PayloadCap {
            stream: PayloadCapStream::Stdin,
            stdout: Vec::new(),
            stderr: Vec::new(),
            controls: Vec::new(),
        };
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
            return CallOutcome::SpawnFailed {
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
    // to disk. ADR-007 / plan 41 M11.
    set_no_core_dumps();

    // Phase 4b: open a pipe for the fd-3 control channel. The child
    // gets the write end at fd 3 (via `pre_exec` + `dup2`); the parent
    // reads the read end on a drain thread and parses the framed
    // record stream into `ControlRecord`s.
    let (fd3_read, fd3_write_for_child) = match make_fd3_pipe() {
        Ok(pair) => pair,
        Err(e) => {
            return CallOutcome::SpawnFailed {
                message: format!("create fd-3 pipe: {e}"),
            };
        }
    };

    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(&program);
    cmd.current_dir(cwd)
        .env_clear()
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
    use std::os::fd::AsRawFd;
    let write_raw = fd3_write_for_child.as_raw_fd();
    // SAFETY: closure runs in the post-fork pre-exec child. Only async-
    // signal-safe libc calls are used (dup2, fcntl, close). No Rust
    // allocator calls.
    unsafe {
        cmd.pre_exec(move || install_fd3_in_child(write_raw));
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // pipe fds are closed via Drop on the OwnedFd values.
            return CallOutcome::SpawnFailed {
                message: format!("spawn {}: {}", program.display(), e),
            };
        }
    };

    // Drop the parent's copy of the write end so the child is the
    // only writer. Without this, reading the read end blocks
    // forever because the kernel sees a writer (us) still has it
    // open.
    drop(fd3_write_for_child);

    // Pipe stdin and close. A write error here means the wrapper
    // already died or closed its stdin; treat as soft failure and
    // continue to wait/drain for whatever it did emit.
    if let Some(mut pipe) = child.stdin.take() {
        let _ = pipe.write_all(stdin_data);
        // Dropping `pipe` closes stdin; without that the wrapper may
        // block forever on read.
    }

    let breach_flag = Arc::new(AtomicBool::new(false));
    let stdout_handle = drain_capped(
        child.stdout.take().expect("piped"),
        caps.stdout_max,
        Arc::clone(&breach_flag),
        PayloadCapStream::Stdout,
    );
    let stderr_handle = drain_capped(
        child.stderr.take().expect("piped"),
        caps.stderr_max,
        Arc::clone(&breach_flag),
        PayloadCapStream::Stderr,
    );
    let fd3_handle = drain_fd3(fd3_read, caps.fd3_max);

    let deadline = Instant::now() + timeout;
    let outcome = poll_for_exit(&mut child, deadline, &caps, &breach_flag);

    let (stdout, stdout_breach) = stdout_handle.join().unwrap_or_else(|_| (Vec::new(), None));
    let (stderr, stderr_breach) = stderr_handle.join().unwrap_or_else(|_| (Vec::new(), None));
    let controls = fd3_handle.join().unwrap_or_default();
    // Stream attribution: prefer whichever drain reported the breach.
    // If both did (rare), surface stdout — picked because runaway
    // stdout is the more common shape. The flag the poll loop watched
    // is a coarse Boolean; this attribution is only used by the
    // CallOutcome::PayloadCap arm below.
    let breached_stream = stdout_breach.or(stderr_breach);

    match outcome {
        ChildOutcome::Exited(status) => {
            if let Some(code) = status.code() {
                CallOutcome::Exited {
                    code,
                    stdout,
                    stderr,
                    controls,
                }
            } else {
                let signal = signal_of(&status);
                CallOutcome::WrapperCrashed {
                    signal,
                    stdout,
                    stderr,
                    controls,
                }
            }
        }
        ChildOutcome::Timeout => CallOutcome::Timeout {
            stdout,
            stderr,
            controls,
        },
        ChildOutcome::PayloadCap => CallOutcome::PayloadCap {
            stream: breached_stream.unwrap_or(PayloadCapStream::Stdout),
            stdout,
            stderr,
            controls,
        },
    }
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
    // reads the image during the first execve). ADR-007 hardened-exec note.
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

enum ChildOutcome {
    Exited(std::process::ExitStatus),
    Timeout,
    PayloadCap,
}

fn poll_for_exit(
    child: &mut Child,
    deadline: Instant,
    caps: &CallCaps,
    breach_flag: &Arc<AtomicBool>,
) -> ChildOutcome {
    loop {
        // Highest priority: cap breach takes precedence over timeout
        // (a breach is a corrupt-input signal, timeout is just slow).
        if breach_flag.load(Ordering::SeqCst) {
            kill_and_reap(child, caps.kill_grace_period);
            return ChildOutcome::PayloadCap;
        }
        match child.try_wait() {
            Ok(Some(status)) => return ChildOutcome::Exited(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_and_reap(child, caps.kill_grace_period);
                    return ChildOutcome::Timeout;
                }
                std::thread::sleep(caps.poll_interval);
            }
            Err(_) => {
                // try_wait returned an error — the child is in some
                // bad state. Best effort: kill and report timeout.
                kill_and_reap(child, caps.kill_grace_period);
                return ChildOutcome::Timeout;
            }
        }
    }
}

pub(crate) fn kill_and_reap(child: &mut Child, grace: Duration) {
    // Negate the pid to address the entire process group — the child
    // is its own process group leader (see `.process_group(0)` above),
    // so `kill(-pgid, ...)` reaches the wrapper plus any descendants
    // (e.g. a shell that exec'd a long-running `sleep`).
    let pgid = child.id() as i32;
    // SAFETY: kill is async-signal-safe.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    let escalate_at = Instant::now() + grace;
    while Instant::now() < escalate_at {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.wait();
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(0)
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> i32 {
    0
}

/// Drain the parent end of the fd-3 pipe and parse framed control
/// records. Frame layout (Plan-0010 §B4):
///
/// ```text
///   header_len:  u32 LE   (4 bytes; max 64 KiB)
///   header_json: bytes    (header_len bytes; UTF-8 JSON)
///   payload_len: u32 LE   (4 bytes)
///   payload:     bytes    (payload_len bytes)
/// ```
///
/// Reads until EOF (child closes its fd 3) or `total_max` bytes have
/// been consumed — whichever comes first. Once the cap is hit we
/// stop reading and return whatever records we've fully parsed; the
/// channel is for structured records the host correlates by kind, so
/// dropping further records on overflow is preferable to killing the
/// wrapper. Header sizes >64 KiB are refused (frame-corruption signal).
///
/// Records that are partially received at EOF / cap are silently
/// dropped — the host already accepts a streaming response that can
/// terminate at any point.
fn drain_fd3(read_fd: std::os::fd::OwnedFd, total_max: usize) -> JoinHandle<Vec<ControlRecord>> {
    /// Per-frame header limit (defense in depth — the wrapper writes
    /// short envelope JSON, not arbitrary blobs in the header).
    const HEADER_MAX: usize = 64 * 1024;

    std::thread::spawn(move || {
        let file = std::fs::File::from(read_fd);
        let mut reader = std::io::BufReader::new(file);
        let mut records: Vec<ControlRecord> = Vec::new();
        let mut consumed: usize = 0;

        // Parse loop: each frame is `header_len:u32 LE` + header bytes
        // + `payload_len:u32 LE` + payload bytes. Any read that returns
        // EOF (Ok(0)) on the first read of a frame ends the loop
        // cleanly; an EOF mid-frame discards the partial frame.
        loop {
            // header length
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(_) => break, // EOF or transient I/O error
            }
            let header_len = u32::from_le_bytes(len_buf) as usize;
            if header_len > HEADER_MAX {
                break; // refuse oversized header — likely corrupt
            }
            consumed = consumed.saturating_add(4 + header_len);
            if consumed > total_max {
                break;
            }

            let mut header_bytes = vec![0u8; header_len];
            if reader.read_exact(&mut header_bytes).is_err() {
                break; // partial header → drop this and any later
            }
            let header_json = match String::from_utf8(header_bytes) {
                Ok(s) => s,
                Err(_) => break, // non-UTF-8 header → corrupt; stop
            };

            // payload length
            if reader.read_exact(&mut len_buf).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(len_buf) as usize;
            consumed = consumed.saturating_add(4 + payload_len);
            if consumed > total_max {
                break;
            }

            let mut payload = vec![0u8; payload_len];
            if reader.read_exact(&mut payload).is_err() {
                break;
            }

            records.push(ControlRecord {
                header_json,
                payload,
            });
        }

        records
    })
}

fn drain_capped<R: Read + Send + 'static>(
    reader: R,
    cap: usize,
    breach_flag: Arc<AtomicBool>,
    stream: PayloadCapStream,
) -> JoinHandle<(Vec<u8>, Option<PayloadCapStream>)> {
    std::thread::spawn(move || {
        let mut buf: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
        let mut reader = std::io::BufReader::new(reader);
        let mut chunk = [0u8; 4096];
        let mut breached: Option<PayloadCapStream> = None;
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let space = cap.saturating_sub(buf.len());
                    if space == 0 || space < n {
                        let take = space;
                        if take > 0 {
                            buf.extend_from_slice(&chunk[..take]);
                        }
                        breached = Some(stream);
                        breach_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
        (buf, breached)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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
        let uid = nix_compat_geteuid();
        let gid = nix_compat_getegid();
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
        let (tmp, marker, wrapper) = make_tree(0o555, b"#!/bin/sh\necho ok\n");
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o555);
        let validated = policy.validate().expect("validate should succeed");
        assert_eq!(validated.resolved, std::fs::canonicalize(&wrapper).unwrap());
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
        let (tmp, marker, _wrapper) = make_tree(0o4755, b"#!/bin/sh\n");
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
        assert_eq!(p.marker_path, PathBuf::from("/etc/mvm/runner"));
        assert_eq!(p.allowed_prefix, PathBuf::from("/usr/lib/mvm/wrappers/"));
        assert_eq!(p.same_fs_as, Some(PathBuf::from("/usr")));
        assert_eq!(p.required_mode, 0o555);
        assert_eq!(p.required_uid, 0);
        assert_eq!(p.required_gid, 0);
    }
}
