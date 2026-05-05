//! Boot-time validation of `/etc/mvm/entrypoint`. ADR-007 / plan 41 W2.
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
    /// Production policy: read `/etc/mvm/entrypoint`; resolved binary
    /// must live under `/usr/lib/mvm/wrappers/` on the same filesystem
    /// as `/usr`, owned root, mode 0755.
    pub fn production() -> Self {
        Self {
            marker_path: PathBuf::from("/etc/mvm/entrypoint"),
            allowed_prefix: PathBuf::from("/usr/lib/mvm/wrappers/"),
            same_fs_as: Some(PathBuf::from("/usr")),
            required_mode: 0o755,
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
            kill_grace_period: Duration::from_secs(2),
            poll_interval: Duration::from_millis(50),
        }
    }
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
    },
    /// Wrapper exceeded the wall-clock timeout. Killed.
    Timeout { stdout: Vec<u8>, stderr: Vec<u8> },
    /// One of the streams exceeded its cap. Killed.
    PayloadCap {
        stream: PayloadCapStream,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// `Command::spawn` itself failed.
    SpawnFailed { message: String },
    /// Wrapper exited via signal (segfault, OOM kill, etc.).
    WrapperCrashed {
        signal: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
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
        };
    }

    let program = spawn_path(entrypoint);

    // RLIMIT_CORE=0 in the parent: child inherits, so a wrapper crash
    // doesn't write process memory containing in-flight payload bytes
    // to disk. ADR-007 / plan 41 M11.
    set_no_core_dumps();

    use std::os::unix::process::CommandExt;
    let mut child = match Command::new(&program)
        .current_dir(cwd)
        .env_clear()
        // Put the wrapper into its own process group so a kill-signal
        // can be delivered to every process the wrapper might fork
        // (e.g. a shell that exec'd `sleep`). Without this, SIGKILL to
        // the wrapper leaves grandchildren holding our stdout/stderr
        // pipes open until they finish naturally.
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return CallOutcome::SpawnFailed {
                message: format!("spawn {}: {}", program.display(), e),
            };
        }
    };

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

    let deadline = Instant::now() + timeout;
    let outcome = poll_for_exit(&mut child, deadline, &caps, &breach_flag);

    let (stdout, stdout_breach) = stdout_handle.join().unwrap_or_else(|_| (Vec::new(), None));
    let (stderr, stderr_breach) = stderr_handle.join().unwrap_or_else(|_| (Vec::new(), None));
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
                }
            } else {
                let signal = signal_of(&status);
                CallOutcome::WrapperCrashed {
                    signal,
                    stdout,
                    stderr,
                }
            }
        }
        ChildOutcome::Timeout => CallOutcome::Timeout { stdout, stderr },
        ChildOutcome::PayloadCap => CallOutcome::PayloadCap {
            stream: breached_stream.unwrap_or(PayloadCapStream::Stdout),
            stdout,
            stderr,
        },
    }
}

/// Set `RLIMIT_CORE = 0` on the calling process. Children inherit this
/// rlimit at fork+exec, so a wrapper crash doesn't dump core. Best-effort:
/// we log but don't fail the call if the syscall is denied.
fn set_no_core_dumps() {
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

/// Resolve the path the parent passes to `Command::new`.
///
/// On Linux, `/proc/self/fd/<n>` referencing the held-open validation
/// fd defeats TOCTOU between policy validation and spawn. On other
/// platforms (macOS dev/test), fall back to the canonicalized path —
/// production guests are always Linux so the fallback is for unit
/// tests only.
fn spawn_path(entrypoint: &ValidatedEntrypoint) -> PathBuf {
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

fn kill_and_reap(child: &mut Child, grace: Duration) {
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
        let (tmp, marker, wrapper) = make_tree(0o755, b"#!/bin/sh\necho ok\n");
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
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
        let policy = test_policy(marker, tmp.path().join("usr/lib/mvm/wrappers"), 0o755);
        match policy.validate() {
            Err(ValidationError::WrongMode { mode, required, .. }) => {
                assert_eq!(mode, 0o644);
                assert_eq!(required, 0o755);
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
        assert_eq!(p.marker_path, PathBuf::from("/etc/mvm/entrypoint"));
        assert_eq!(p.allowed_prefix, PathBuf::from("/usr/lib/mvm/wrappers/"));
        assert_eq!(p.same_fs_as, Some(PathBuf::from("/usr")));
        assert_eq!(p.required_mode, 0o755);
        assert_eq!(p.required_uid, 0);
        assert_eq!(p.required_gid, 0);
    }

    // -------------------------------------------------------------------
    // Runner tests — drive `execute` against shell scripts in a temp dir.
    // These exercise the per-call lifecycle (spawn, drain, poll, kill)
    // without any of the production policy constraints.
    // -------------------------------------------------------------------

    fn make_wrapper_script(content: &str) -> (tempfile::TempDir, ValidatedEntrypoint) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("wrapper.sh");
        let mut f = std::fs::File::create(&script).unwrap();
        write!(f, "{}", content).unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        let resolved = std::fs::canonicalize(&script).unwrap();
        let file = std::fs::File::open(&resolved).unwrap();
        let validated = ValidatedEntrypoint { resolved, file };
        (tmp, validated)
    }

    fn caps_with_timeout(stdout_max: usize, stderr_max: usize) -> CallCaps {
        CallCaps {
            stdin_max: 1024 * 1024,
            stdout_max,
            stderr_max,
            kill_grace_period: Duration::from_millis(500),
            poll_interval: Duration::from_millis(20),
        }
    }

    #[test]
    fn test_execute_zero_exit_captures_stdout_stderr() {
        let (tmp, entry) =
            make_wrapper_script("#!/bin/sh\necho hello-out\necho hello-err 1>&2\nexit 0\n");
        let outcome = execute(
            &entry,
            tmp.path(),
            b"",
            Duration::from_secs(5),
            caps_with_timeout(1024, 1024),
        );
        match outcome {
            CallOutcome::Exited {
                code,
                stdout,
                stderr,
            } => {
                assert_eq!(code, 0);
                assert_eq!(stdout, b"hello-out\n");
                assert_eq!(stderr, b"hello-err\n");
            }
            other => panic!("expected Exited(0), got {other:?}"),
        }
    }

    #[test]
    fn test_execute_nonzero_exit_preserved() {
        let (tmp, entry) = make_wrapper_script("#!/bin/sh\nexit 7\n");
        let outcome = execute(
            &entry,
            tmp.path(),
            b"",
            Duration::from_secs(5),
            caps_with_timeout(1024, 1024),
        );
        match outcome {
            CallOutcome::Exited { code, .. } => assert_eq!(code, 7),
            other => panic!("expected Exited(7), got {other:?}"),
        }
    }

    #[test]
    fn test_execute_stdin_piped_to_wrapper() {
        let (tmp, entry) = make_wrapper_script("#!/bin/sh\ncat\n");
        let outcome = execute(
            &entry,
            tmp.path(),
            b"echo this back",
            Duration::from_secs(5),
            caps_with_timeout(1024, 1024),
        );
        match outcome {
            CallOutcome::Exited { code, stdout, .. } => {
                assert_eq!(code, 0);
                assert_eq!(stdout, b"echo this back");
            }
            other => panic!("expected Exited(0) with echoed stdin, got {other:?}"),
        }
    }

    #[test]
    fn test_execute_timeout_kills_wrapper() {
        let (tmp, entry) = make_wrapper_script("#!/bin/sh\nsleep 10\n");
        let started = Instant::now();
        let outcome = execute(
            &entry,
            tmp.path(),
            b"",
            Duration::from_millis(200),
            caps_with_timeout(1024, 1024),
        );
        let elapsed = started.elapsed();
        match outcome {
            CallOutcome::Timeout { .. } => {
                // Bound: 200 ms timeout + 500 ms grace + slack. If it
                // takes longer than 5 s the test is broken, not slow.
                assert!(elapsed < Duration::from_secs(5), "timeout took {elapsed:?}");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn test_execute_stdin_cap_rejects_before_spawn() {
        // No script needed — the cap check runs before spawn. A
        // missing-script ValidatedEntrypoint would fail the spawn,
        // but we shouldn't even get there.
        let (tmp, entry) = make_wrapper_script("#!/bin/sh\nexit 0\n");
        let mut huge = Vec::with_capacity(2048);
        huge.resize(2048, b'A');
        let mut caps = caps_with_timeout(1024, 1024);
        caps.stdin_max = 1024;
        let outcome = execute(&entry, tmp.path(), &huge, Duration::from_secs(5), caps);
        match outcome {
            CallOutcome::PayloadCap {
                stream: PayloadCapStream::Stdin,
                stdout,
                stderr,
            } => {
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());
            }
            other => panic!("expected PayloadCap(Stdin), got {other:?}"),
        }
    }

    #[test]
    fn test_execute_stdout_cap_kills_wrapper() {
        // Wrapper produces unbounded output; stdout_max is 1 KiB.
        // Drain thread sets the breach flag; poll loop kills the
        // wrapper. `exec yes` replaces the shell with `yes` so the
        // pid we kill is the actual producer, not a forwarding shell.
        let (tmp, entry) = make_wrapper_script("#!/bin/sh\nexec yes A\n");
        let mut caps = caps_with_timeout(1024, 1024);
        caps.poll_interval = Duration::from_millis(10);
        let started = Instant::now();
        let outcome = execute(&entry, tmp.path(), b"", Duration::from_secs(10), caps);
        let elapsed = started.elapsed();
        match outcome {
            CallOutcome::PayloadCap {
                stream: PayloadCapStream::Stdout,
                stdout,
                ..
            } => {
                assert_eq!(stdout.len(), 1024, "stdout truncated to cap");
                assert!(elapsed < Duration::from_secs(2), "kill took {elapsed:?}");
            }
            other => panic!("expected PayloadCap(Stdout), got {other:?}"),
        }
    }

    #[test]
    fn test_execute_spawn_failed_when_program_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = tmp.path().join("does-not-exist");
        // Create a *file* so File::open succeeds during construction
        // of ValidatedEntrypoint, then delete it so spawn fails.
        std::fs::File::create(&bogus).unwrap();
        let resolved = std::fs::canonicalize(&bogus).unwrap();
        let file = std::fs::File::open(&resolved).unwrap();
        std::fs::remove_file(&resolved).unwrap();
        let entry = ValidatedEntrypoint { resolved, file };
        let outcome = execute(
            &entry,
            tmp.path(),
            b"",
            Duration::from_secs(5),
            caps_with_timeout(1024, 1024),
        );
        // Linux uses /proc/self/fd/<n> which still resolves through
        // the held fd even after the path is unlinked, so spawn may
        // succeed and then immediately fail with ENOEXEC. macOS uses
        // the resolved path, which is gone, so spawn fails outright.
        // Either way we expect spawn-failed or a non-success outcome.
        match outcome {
            CallOutcome::SpawnFailed { .. } => {}
            CallOutcome::Exited { code, .. } if code != 0 => {}
            CallOutcome::WrapperCrashed { .. } => {}
            other => {
                panic!("expected SpawnFailed / nonzero Exited / WrapperCrashed, got {other:?}")
            }
        }
    }
}
