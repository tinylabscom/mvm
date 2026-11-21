//! Read-only coordinator process observation and legacy service-mode types.
//! Observation uses one connected socket, never a service manager or launcher.
//!
//! A verified connection says who answered. It is not readiness, current
//! authority, or permission to commit, and it does not confine anything from
//! another process of the same user.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// The template every managed coordinator is an instance of.
pub const UNIT_PREFIX: &str = "mvm-policy-coordinator@";
const UNIT_SUFFIX: &str = ".service";
/// systemd's limit on a unit name.
const MAX_UNIT_NAME_BYTES: usize = 255;
/// The argument a unit's `ExecStart=` passes ahead of its home.
pub const MANAGED_HOME_FLAG: &str = "--managed-home";
/// Version of the [`CoordinatorStatus`] reply.
pub const STATUS_PROTOCOL: u32 = 1;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod process_tests;

/// A detached coordinator's reply bound to the kernel peer on one connection.
///
/// This is process observation, not service provenance, readiness, current
/// authority, permission to commit, or confinement from same-user processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessObservation {
    pub pid: u32,
    pub uid: u32,
    pub home: PathBuf,
}

/// Observe an existing detached coordinator without creating any local state.
///
/// No service manager is required or queried. One five-second absolute budget
/// covers the nonblocking connection and bounded status exchange.
///
/// # Errors
///
/// The platform cannot bind the peer, the canonical home or socket is missing,
/// the deadline expires, or the reply does not match the connected process.
pub fn process_status(home: &Path) -> Result<ProcessObservation> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        process_status_until(
            home,
            std::time::Instant::now() + super::coordinator::STATUS_TIMEOUT,
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = home;
        anyhow::bail!("coordinator process observation is unsupported on this platform")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_status_until(home: &Path, deadline: std::time::Instant) -> Result<ProcessObservation> {
    let budget = || {
        ensure!(
            std::time::Instant::now() < deadline,
            "coordinator observation deadline expired"
        );
        Ok::<_, anyhow::Error>(())
    };
    budget()?;
    ensure!(
        home.is_absolute() && home.canonicalize()? == home && home.is_dir(),
        "coordinator home must be an existing canonical directory"
    );
    budget()?;
    let stream = connect_without_waiting(&super::coordinator::socket_path(home))
        .context("connecting to coordinator socket")?;
    let peer = peer_credentials(&stream).context("reading coordinator kernel peer identity")?;
    require_observation_peer(peer)?;
    budget()?;
    let status = super::coordinator::exchange_status(stream, deadline)?;
    budget()?;
    ensure!(
        status
            == CoordinatorStatus {
                protocol: STATUS_PROTOCOL,
                pid: peer.pid,
                uid: peer.uid,
                home: home.to_path_buf(),
                lifetime: Lifetime::Detached,
            },
        "coordinator reply does not match the connected detached process"
    );
    Ok(ProcessObservation {
        pid: peer.pid,
        uid: peer.uid,
        home: home.to_path_buf(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_observation_peer(peer: PeerProcess) -> Result<()> {
    ensure!(peer.pid != 0, "coordinator socket has no usable peer PID");
    ensure!(
        peer.uid == rustix::process::geteuid().as_raw(),
        "coordinator socket belongs to another user"
    );
    Ok(())
}

/// The user, state root and unit one managed coordinator is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedIdentity {
    uid: u32,
    home: PathBuf,
    unit: String,
}

impl ManagedIdentity {
    /// Derive the unit that owns `home` for `uid`.
    ///
    /// # Errors
    ///
    /// `home` is not an absolute, canonical, UTF-8 path to an existing
    /// directory, or its unit name would exceed systemd's limit.
    pub fn for_home(uid: u32, home: &Path) -> Result<Self> {
        ensure!(home.is_absolute(), "coordinator home must be absolute");
        let canonical = home
            .canonicalize()
            .with_context(|| format!("canonicalizing coordinator home {}", home.display()))?;
        ensure!(
            canonical == home,
            "coordinator home {} is not canonical (it resolves to {})",
            home.display(),
            canonical.display()
        );
        let text = home.to_str().context("coordinator home is not UTF-8")?;
        let unit = format!("{UNIT_PREFIX}{}{UNIT_SUFFIX}", escape_path(text));
        ensure!(
            unit.len() <= MAX_UNIT_NAME_BYTES,
            "coordinator home is too long to name a systemd unit"
        );
        Ok(Self {
            uid,
            home: home.to_path_buf(),
            unit,
        })
    }

    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

/// `systemd-escape --path` for an already-canonical absolute path, so `%f` in
/// the unit expands back to exactly the home this was derived from.
fn escape_path(path: &str) -> String {
    let relative = path.trim_start_matches('/');
    if relative.is_empty() {
        return "-".to_string();
    }
    let mut escaped = String::with_capacity(relative.len());
    for (index, byte) in relative.bytes().enumerate() {
        match byte {
            b'/' => escaped.push('-'),
            b'.' if index == 0 => escaped.push_str("\\x2e"),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' | b'.' => {
                escaped.push(char::from(byte));
            }
            other => {
                let _ = write!(escaped, "\\x{other:02x}");
            }
        }
    }
    escaped
}

/// How the answering process was started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lifetime {
    /// Spawned by a launcher and left running; nothing owns or reaps it.
    Detached,
    /// One invocation of the named unit under a systemd user manager.
    Managed { unit: String, invocation: String },
}

/// What a coordinator says about itself, not verified provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorStatus {
    pub protocol: u32,
    pub pid: u32,
    pub uid: u32,
    pub home: PathBuf,
    pub lifetime: Lifetime,
}

impl CoordinatorStatus {
    #[cfg(unix)]
    pub(crate) fn of_this_process(home: &Path, lifetime: Lifetime) -> Self {
        Self {
            protocol: STATUS_PROTOCOL,
            pid: std::process::id(),
            uid: rustix::process::geteuid().as_raw(),
            home: home.to_path_buf(),
            lifetime,
        }
    }
}

/// A systemd invocation ID: 128 bits as lowercase hex.
#[cfg(any(test, target_os = "linux"))]
fn is_invocation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `/proc/self/cgroup` places the process in a control group whose
/// leaf is `unit`. The manager puts a service's main process there.
#[cfg(any(test, target_os = "linux"))]
fn cgroup_names_unit(cgroup: &str, unit: &str) -> bool {
    cgroup.lines().any(|line| {
        line.splitn(3, ':')
            .nth(2)
            .and_then(|path| path.rsplit('/').next())
            == Some(unit)
    })
}

/// Establish that this process is the unit that owns `home`, started by a
/// service manager, and return the lifetime it will report.
///
/// The invocation ID is the manager's; the control group is read from the
/// kernel. Neither stops another process of the same user imitating a
/// service. Direct observation refuses this lifetime rather than treating
/// this process's self-claim as verified service provenance.
///
/// # Errors
///
/// The host is not Linux, `home` does not name a unit, or this process was
/// not started as that unit.
pub(crate) fn bind_managed(home: &Path) -> Result<Lifetime> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read as _;

        ensure!(
            Path::new(&mvm_core::config::mvm_home()) == home,
            "the unit must set MVM_HOME to the home it is an instance of"
        );
        let identity = ManagedIdentity::for_home(rustix::process::geteuid().as_raw(), home)?;
        let invocation = std::env::var("INVOCATION_ID")
            .context("no INVOCATION_ID: this process was not started by a service manager")?;
        ensure!(
            is_invocation_id(&invocation),
            "INVOCATION_ID is not a systemd invocation ID"
        );
        let mut cgroup = String::new();
        std::fs::File::open("/proc/self/cgroup")
            .context("opening /proc/self/cgroup")?
            .take(64 * 1024)
            .read_to_string(&mut cgroup)
            .context("reading /proc/self/cgroup")?;
        ensure!(
            cgroup_names_unit(&cgroup, identity.unit()),
            "this process is not in the control group of {}",
            identity.unit()
        );
        Ok(Lifetime::Managed {
            unit: identity.unit,
            invocation,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = home;
        anyhow::bail!("{}", ManagedRefusal::Unsupported)
    }
}

/// The kernel's record of who is on the other end of a connected socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerProcess {
    pub pid: u32,
    pub uid: u32,
}

/// Read `SO_PEERCRED` from a connected socket. For a client this is the
/// process that called `listen`, which is why the coordinator binds its own
/// socket instead of inheriting one from the manager.
///
/// A peer in another PID namespace is reported with PID 0; that is refused,
/// because no process can be matched to it.
#[cfg(target_os = "linux")]
pub(crate) fn peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> std::io::Result<PeerProcess> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a correctly sized `ucred` and `len` holds its size; the
    // kernel writes at most that many bytes.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(std::io::Error::other(
            "kernel returned short peer credentials",
        ));
    }
    peer_from_raw(cred.pid, cred.uid)
}

/// Accept a kernel-reported peer only if it names a real process.
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn peer_from_raw(pid: i32, uid: u32) -> std::io::Result<PeerProcess> {
    let pid = u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| {
            std::io::Error::other("kernel supplied no usable peer PID (another PID namespace?)")
        })?;
    Ok(PeerProcess { pid, uid })
}

#[cfg(target_os = "macos")]
pub(crate) fn peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> std::io::Result<PeerProcess> {
    use mvm_vmm::host::uds_peer::{connected_peer_pid, connected_peer_uid};
    peer_from_raw(connected_peer_pid(stream)?, connected_peer_uid(stream)?)
}

/// Why no authenticated managed coordinator could be reported. None of these
/// is evidence about what the coordinator has or has not committed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagedRefusal {
    #[error("manager-owned coordinator observation is unsupported")]
    Unsupported,
    #[error("{0}")]
    InvalidHome(String),
    #[error("the systemd user manager could not be asked about {unit}: {reason}")]
    ManagerUnavailable { unit: String, reason: &'static str },
    #[error(
        "{unit} is not provisioned for this user (load state {load_state:?}); mvmctl does not install it"
    )]
    NotProvisioned { unit: String, load_state: String },
    #[error(
        "{unit} is provisioned but not running (active state {active_state:?}); mvmctl does not start it"
    )]
    NotRunning { unit: String, active_state: String },
    #[error("the state of {unit} is unknown: {detail}")]
    Unknown { unit: String, detail: String },
    #[error("the process answering for {unit} is not the service its manager reports: {detail}")]
    IdentityMismatch { unit: String, detail: String },
}

/// Legacy manager observation shape; direct observation never returns this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCoordinator {
    pub unit: String,
    pub invocation: String,
    pub pid: u32,
    pub uid: u32,
    pub home: PathBuf,
}

/// Connect without waiting: a listener whose backlog is full answers
/// `EAGAIN` at once instead of blocking the caller.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connect_without_waiting(socket: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};

    #[cfg(target_os = "linux")]
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    #[cfg(target_os = "macos")]
    let fd = {
        // Darwin has no atomic SOCK_NONBLOCK/SOCK_CLOEXEC socket flags.
        let fd = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
        rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::NONBLOCK)?;
        fd
    };
    rustix::net::connect(&fd, &SocketAddrUnix::new(socket)?)?;
    rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::empty())?;
    Ok(fd.into())
}

/// Legacy manager observation is no longer supported.
/// Use [`process_status`] for direct detached-process observation.
///
/// # Errors
///
/// Always returns [`ManagedRefusal::Unsupported`].
pub fn managed_status(home: &Path) -> Result<ManagedCoordinator, ManagedRefusal> {
    let _ = home;
    Err(ManagedRefusal::Unsupported)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

    fn identity() -> ManagedIdentity {
        ManagedIdentity {
            uid: 1000,
            home: PathBuf::from("/home/op/.state"),
            unit: "mvm-policy-coordinator@home-op-.state.service".into(),
        }
    }

    fn status() -> CoordinatorStatus {
        CoordinatorStatus {
            protocol: STATUS_PROTOCOL,
            pid: 4242,
            uid: 1000,
            home: PathBuf::from("/home/op/.state"),
            lifetime: Lifetime::Managed {
                unit: identity().unit,
                invocation: INVOCATION.into(),
            },
        }
    }

    #[test]
    fn paths_escape_the_way_systemd_unescapes_them() {
        for (path, escaped) in [
            ("/home/op/.state", "home-op-.state"),
            ("/.hidden", "\\x2ehidden"),
            ("/srv/my-home/a b", "srv-my\\x2dhome-a\\x20b"),
            ("/var/lib/mvm_1:2", "var-lib-mvm_1:2"),
            ("/h\u{e9}", "h\\xc3\\xa9"),
            ("/", "-"),
        ] {
            assert_eq!(escape_path(path), escaped, "{path}");
        }
    }

    #[test]
    fn a_home_names_exactly_one_unit_and_must_be_canonical() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        std::fs::create_dir(&home).unwrap();
        let identity = ManagedIdentity::for_home(7, &home).unwrap();
        assert_eq!(identity.uid(), 7);
        assert_eq!(identity.home(), home);
        assert_eq!(
            identity.unit(),
            format!(
                "{UNIT_PREFIX}{}{UNIT_SUFFIX}",
                escape_path(home.to_str().unwrap())
            )
        );

        assert!(ManagedIdentity::for_home(7, Path::new("relative")).is_err());
        assert!(ManagedIdentity::for_home(7, &home.join("missing")).is_err());
        let link = home.with_file_name("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        let error = ManagedIdentity::for_home(7, &link).unwrap_err();
        assert!(error.to_string().contains("not canonical"), "{error:#}");
        let long = home.join("x".repeat(250));
        std::fs::create_dir(&long).unwrap();
        assert!(ManagedIdentity::for_home(7, &long).is_err());
    }

    #[test]
    fn status_round_trips_and_refuses_unknown_fields() {
        for status in [
            status(),
            CoordinatorStatus {
                lifetime: Lifetime::Detached,
                ..status()
            },
        ] {
            let bytes = serde_json::to_vec(&status).unwrap();
            assert_eq!(
                serde_json::from_slice::<CoordinatorStatus>(&bytes).unwrap(),
                status
            );
        }
        assert!(
            serde_json::from_str::<CoordinatorStatus>(
                r#"{"protocol":1,"pid":2,"uid":3,"home":"/h","lifetime":{"kind":"detached"},"ready":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn only_the_units_own_control_group_counts() {
        let unit = "mvm-policy-coordinator@home-op-.state.service";
        let inside = format!("0::/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}\n");
        assert!(cgroup_names_unit(&inside, unit));
        assert!(cgroup_names_unit(
            &format!("12:pids:/elsewhere\n1:name=systemd:/user.slice/{unit}\n"),
            unit
        ));
        for outside in [
            "0::/user.slice/user-1000.slice/session-3.scope\n".to_string(),
            format!("0::/user.slice/{unit}/child\n"),
            format!("0::/user.slice/x{unit}\n"),
            format!("{unit}\n"),
            String::new(),
        ] {
            assert!(!cgroup_names_unit(&outside, unit), "{outside:?}");
        }
    }

    #[test]
    fn a_peer_without_a_usable_pid_is_refused() {
        for pid in [0, -1] {
            assert!(peer_from_raw(pid, 1000).is_err(), "{pid}");
        }
        assert_eq!(
            peer_from_raw(42, 1000).unwrap(),
            PeerProcess { pid: 42, uid: 1000 }
        );
    }

    #[test]
    fn invocation_ids_are_exactly_128_bits_of_lowercase_hex() {
        assert!(is_invocation_id(INVOCATION));
        for bad in [
            "",
            "0123",
            &INVOCATION.to_uppercase(),
            &format!("{INVOCATION}0"),
            "g123456789abcdef0123456789abcdef",
        ] {
            assert!(!is_invocation_id(bad), "{bad:?}");
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn hosts_without_a_systemd_user_manager_refuse_both_sides() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            managed_status(home.path()),
            Err(ManagedRefusal::Unsupported)
        );
        assert!(bind_managed(home.path()).is_err());
    }
}
