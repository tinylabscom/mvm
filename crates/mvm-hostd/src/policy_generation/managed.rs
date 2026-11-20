//! The coordinator as a fixed systemd user service, and the checks that bind
//! one connection to it.
//!
//! There is one template unit per OS user and canonical MVM home; the home is
//! the unit's instance, so the name alone says which state root it owns. The
//! manager creates and reaps the process. Nothing here installs, enables or
//! starts a unit: one that is absent or stopped is reported, never replaced by
//! a process this code spawns.
//!
//! A verified connection says who answered. It is not readiness, current
//! authority, or permission to commit, and it does not confine anything from
//! another process of the same user.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "linux", all(test, unix)))]
mod native_bus;

/// The template every managed coordinator is an instance of.
pub const UNIT_PREFIX: &str = "mvm-policy-coordinator@";
const UNIT_SUFFIX: &str = ".service";
/// systemd's limit on a unit name.
const MAX_UNIT_NAME_BYTES: usize = 255;
/// The argument a unit's `ExecStart=` passes ahead of its home.
pub const MANAGED_HOME_FLAG: &str = "--managed-home";
/// Version of the [`CoordinatorStatus`] reply.
pub const STATUS_PROTOCOL: u32 = 1;

#[cfg(any(target_os = "linux", all(test, unix)))]
mod manager;

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

/// What a coordinator says about itself. Every field is a claim the caller
/// checks against the kernel and the manager before believing it.
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
/// service, which is why a client asks the manager who the service is rather
/// than taking this process's word.
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
#[cfg(any(test, target_os = "linux"))]
fn peer_from_raw(pid: i32, uid: u32) -> std::io::Result<PeerProcess> {
    let pid = u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| {
            std::io::Error::other("kernel supplied no usable peer PID (another PID namespace?)")
        })?;
    Ok(PeerProcess { pid, uid })
}

/// Why no authenticated managed coordinator could be reported. None of these
/// is evidence about what the coordinator has or has not committed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagedRefusal {
    #[error(
        "a manager-owned policy coordinator is supported only under a Linux systemd user manager"
    )]
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

/// One manager answer about the unit while it was running.
#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnitObservation {
    main_pid: u32,
    invocation: String,
}

/// The managed coordinator one authenticated connection reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCoordinator {
    pub unit: String,
    pub invocation: String,
    pub pid: u32,
    pub uid: u32,
    pub home: PathBuf,
}

/// The connection's kernel peer must be the manager's main process for the
/// unit, running as this user. Checked before anything is sent to it.
#[cfg(any(test, target_os = "linux"))]
fn verify_peer(
    expected: &ManagedIdentity,
    manager: &UnitObservation,
    peer: PeerProcess,
) -> Result<(), ManagedRefusal> {
    let mismatch = |detail: String| ManagedRefusal::IdentityMismatch {
        unit: expected.unit.clone(),
        detail,
    };
    if peer.uid != expected.uid {
        return Err(mismatch(format!(
            "the socket is served by uid {}, not {}",
            peer.uid, expected.uid
        )));
    }
    if peer.pid != manager.main_pid {
        return Err(mismatch(format!(
            "the socket is served by pid {}, the unit's main process is {}",
            peer.pid, manager.main_pid
        )));
    }
    Ok(())
}

/// The reply must restate the binding the caller derived independently, and
/// the manager must report the same invocation after the exchange as before
/// it, so a restart or a reused PID in between cannot pass.
#[cfg(any(test, target_os = "linux"))]
fn verify_status(
    expected: &ManagedIdentity,
    before: &UnitObservation,
    peer: PeerProcess,
    status: &CoordinatorStatus,
    after: &UnitObservation,
) -> Result<ManagedCoordinator, ManagedRefusal> {
    let claimed = CoordinatorStatus {
        protocol: STATUS_PROTOCOL,
        pid: peer.pid,
        uid: expected.uid,
        home: expected.home.clone(),
        lifetime: Lifetime::Managed {
            unit: expected.unit.clone(),
            invocation: before.invocation.clone(),
        },
    };
    if *status != claimed {
        return Err(ManagedRefusal::IdentityMismatch {
            unit: expected.unit.clone(),
            detail: format!("it reports {status:?}, the manager and kernel establish {claimed:?}"),
        });
    }
    if after != before {
        return Err(ManagedRefusal::Unknown {
            unit: expected.unit.clone(),
            detail: "the unit was restarted while its status was being read".into(),
        });
    }
    Ok(ManagedCoordinator {
        unit: expected.unit.clone(),
        invocation: before.invocation.clone(),
        pid: peer.pid,
        uid: expected.uid,
        home: expected.home.clone(),
    })
}

/// Connect without waiting: a listener whose backlog is full answers
/// `EAGAIN` at once instead of blocking the caller.
#[cfg(target_os = "linux")]
fn connect_without_waiting(socket: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::net::connect(&fd, &SocketAddrUnix::new(socket)?)?;
    rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::empty())?;
    Ok(fd.into())
}

#[cfg(target_os = "linux")]
async fn status_with_observer<F>(
    expected: &ManagedIdentity,
    deadline: std::time::Instant,
    mut observe: impl FnMut() -> F,
) -> Result<ManagedCoordinator, ManagedRefusal>
where
    F: std::future::Future<Output = Result<UnitObservation, ManagedRefusal>>,
{
    let unit = expected.unit();
    let unknown = |detail: String| ManagedRefusal::Unknown {
        unit: unit.to_string(),
        detail,
    };
    let require_budget = || {
        if std::time::Instant::now() >= deadline {
            Err(unknown(
                "managed coordinator observation deadline expired".into(),
            ))
        } else {
            Ok(())
        }
    };
    require_budget()?;
    let before = observe().await?;
    require_budget()?;
    let stream = connect_without_waiting(&super::coordinator::socket_path(expected.home()))
        .map_err(|error| unknown(format!("connecting to its socket: {error}")))?;
    let peer = peer_credentials(&stream)
        .map_err(|error| unknown(format!("reading its kernel credentials: {error}")))?;
    verify_peer(expected, &before, peer)?;
    // Keep the native manager's reader running while waiting on the coordinator.
    // Await the owned task rather than timing out and detaching its JoinHandle;
    // the stream itself enforces this same absolute deadline.
    let status =
        tokio::task::spawn_blocking(move || super::coordinator::exchange_status(stream, deadline))
            .await
            .map_err(|error| unknown(format!("joining the status exchange: {error}")))?
            .map_err(|error| unknown(format!("{error:#}")))?;
    require_budget()?;
    let after = observe().await?;
    require_budget()?;
    verify_status(expected, &before, peer, &status, &after)
}

/// Report the manager-owned coordinator for `home`, over one connection
/// authenticated against the kernel and the user manager.
///
/// Native manager queries bracket a non-waiting connect and a small status
/// exchange. All IPC shares one five-second deadline. It never launches a
/// subprocess, loads a dormant unit, or installs or starts a coordinator.
///
/// # Errors
///
/// A [`ManagedRefusal`] naming what is missing or does not match.
pub fn managed_status(home: &Path) -> Result<ManagedCoordinator, ManagedRefusal> {
    #[cfg(target_os = "linux")]
    {
        let expected = ManagedIdentity::for_home(rustix::process::geteuid().as_raw(), home)
            .map_err(|error| ManagedRefusal::InvalidHome(format!("{error:#}")))?;
        let deadline = std::time::Instant::now() + super::coordinator::STATUS_TIMEOUT;
        crate::blocking::block_on_anywhere(async {
            // One kernel-authenticated manager stream spans both observations.
            // A replacement manager cannot be accepted by reconnecting midway.
            let bus = manager::connect(&expected, deadline.into()).await?;
            status_with_observer(&expected, deadline, || {
                manager::observe(&bus, &expected, deadline.into())
            })
            .await
        })
        .map_err(|error| ManagedRefusal::Unknown {
            unit: expected.unit().to_string(),
            detail: format!("running native coordinator observation: {error}"),
        })?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = home;
        Err(ManagedRefusal::Unsupported)
    }
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

    fn observation() -> UnitObservation {
        UnitObservation {
            main_pid: 4242,
            invocation: INVOCATION.into(),
        }
    }

    fn peer() -> PeerProcess {
        PeerProcess {
            pid: 4242,
            uid: 1000,
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

    #[test]
    fn the_kernel_peer_must_be_the_managers_main_process_for_this_user() {
        verify_peer(&identity(), &observation(), peer()).unwrap();
        for wrong in [
            PeerProcess {
                pid: 4243,
                ..peer()
            },
            PeerProcess {
                uid: 1001,
                ..peer()
            },
        ] {
            assert!(matches!(
                verify_peer(&identity(), &observation(), wrong),
                Err(ManagedRefusal::IdentityMismatch { .. })
            ));
        }
    }

    #[test]
    fn a_reply_must_restate_the_binding_the_manager_and_kernel_establish() {
        let verified = verify_status(
            &identity(),
            &observation(),
            peer(),
            &status(),
            &observation(),
        )
        .unwrap();
        assert_eq!(
            verified,
            ManagedCoordinator {
                unit: identity().unit,
                invocation: INVOCATION.into(),
                pid: 4242,
                uid: 1000,
                home: PathBuf::from("/home/op/.state"),
            }
        );
        let other_invocation = "f".repeat(32);
        for wrong in [
            CoordinatorStatus {
                protocol: 2,
                ..status()
            },
            CoordinatorStatus {
                pid: 4243,
                ..status()
            },
            CoordinatorStatus { uid: 0, ..status() },
            CoordinatorStatus {
                home: PathBuf::from("/home/op/other"),
                ..status()
            },
            CoordinatorStatus {
                lifetime: Lifetime::Detached,
                ..status()
            },
            CoordinatorStatus {
                lifetime: Lifetime::Managed {
                    unit: "mvm-policy-coordinator@other.service".into(),
                    invocation: INVOCATION.into(),
                },
                ..status()
            },
            CoordinatorStatus {
                lifetime: Lifetime::Managed {
                    unit: identity().unit,
                    invocation: other_invocation.clone(),
                },
                ..status()
            },
        ] {
            assert!(
                matches!(
                    verify_status(&identity(), &observation(), peer(), &wrong, &observation()),
                    Err(ManagedRefusal::IdentityMismatch { .. })
                ),
                "{wrong:?}"
            );
        }
        for restarted in [
            UnitObservation {
                main_pid: 4243,
                ..observation()
            },
            UnitObservation {
                invocation: other_invocation,
                ..observation()
            },
        ] {
            assert!(matches!(
                verify_status(&identity(), &observation(), peer(), &status(), &restarted),
                Err(ManagedRefusal::Unknown { .. })
            ));
        }
    }

    /// A real listener in this process stands in for the service, so the
    /// kernel's peer PID is this test's own. The manager's answers are
    /// supplied; nothing here shows a unit was installed or started.
    #[cfg(target_os = "linux")]
    mod over_a_real_socket {
        use std::cell::Cell;
        use std::sync::Arc;

        use mvm_core::util::test_env::TestEnv;

        use super::super::super::coordinator::{bind, serve_on, socket_path};
        use super::*;

        fn status_with(
            home: &Path,
            observe: &dyn Fn(&str) -> Result<UnitObservation, ManagedRefusal>,
        ) -> Result<ManagedCoordinator, ManagedRefusal> {
            let expected = ManagedIdentity::for_home(rustix::process::geteuid().as_raw(), home)
                .map_err(|error| ManagedRefusal::InvalidHome(format!("{error:#}")))?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(status_with_observer(
                    &expected,
                    std::time::Instant::now() + super::super::super::coordinator::STATUS_TIMEOUT,
                    || std::future::ready(observe(expected.unit())),
                ))
        }

        struct Service {
            _environment: TestEnv,
            _root: tempfile::TempDir,
            home: PathBuf,
            unit: String,
        }

        fn canonical_home() -> (TestEnv, tempfile::TempDir, PathBuf) {
            let mut environment = TestEnv::new();
            let root = tempfile::tempdir().unwrap();
            let home = root.path().canonicalize().unwrap().join("home");
            std::fs::create_dir(&home).unwrap();
            environment.isolate_mvm_home(&home);
            (environment, root, home)
        }

        fn serving(lifetime: impl FnOnce(&ManagedIdentity) -> Lifetime) -> Service {
            let (environment, root, home) = canonical_home();
            let identity =
                ManagedIdentity::for_home(rustix::process::geteuid().as_raw(), &home).unwrap();
            let status = CoordinatorStatus::of_this_process(&home, lifetime(&identity));
            let (listener, store, owner) = bind(&home).unwrap();
            std::thread::spawn(move || {
                let _owner = owner;
                serve_on(&listener, &Arc::clone(&store), &status)
            });
            Service {
                _environment: environment,
                _root: root,
                home,
                unit: identity.unit,
            }
        }

        fn managed(identity: &ManagedIdentity) -> Lifetime {
            Lifetime::Managed {
                unit: identity.unit.clone(),
                invocation: INVOCATION.into(),
            }
        }

        fn running_as(pid: u32, invocation: &str) -> UnitObservation {
            UnitObservation {
                main_pid: pid,
                invocation: invocation.to_string(),
            }
        }

        #[test]
        fn the_managers_main_process_is_authenticated_and_reported() {
            let service = serving(managed);
            let asked = Cell::new(0);
            let reported = status_with(&service.home, &|unit| {
                assert_eq!(unit, service.unit);
                asked.set(asked.get() + 1);
                Ok(running_as(std::process::id(), INVOCATION))
            })
            .unwrap();
            assert_eq!(asked.get(), 2, "the manager is asked before and after");
            assert_eq!(
                reported,
                ManagedCoordinator {
                    unit: service.unit.clone(),
                    invocation: INVOCATION.into(),
                    pid: std::process::id(),
                    uid: rustix::process::geteuid().as_raw(),
                    home: service.home.clone(),
                }
            );
        }

        #[test]
        fn a_listener_that_is_not_the_units_main_process_is_refused() {
            let service = serving(managed);
            let refusal = status_with(&service.home, &|_| {
                Ok(running_as(std::process::id() + 1, INVOCATION))
            })
            .unwrap_err();
            assert!(
                matches!(&refusal, ManagedRefusal::IdentityMismatch { detail, .. } if detail.contains("main process")),
                "{refusal}"
            );
        }

        #[test]
        fn a_detached_coordinator_never_passes_for_the_service() {
            let service = serving(|_| Lifetime::Detached);
            let refusal = status_with(&service.home, &|_| {
                Ok(running_as(std::process::id(), INVOCATION))
            })
            .unwrap_err();
            assert!(
                matches!(refusal, ManagedRefusal::IdentityMismatch { .. }),
                "{refusal}"
            );
        }

        #[test]
        fn another_invocations_identity_is_refused() {
            let service = serving(managed);
            let refusal = status_with(&service.home, &|_| {
                Ok(running_as(std::process::id(), &"f".repeat(32)))
            })
            .unwrap_err();
            assert!(
                matches!(refusal, ManagedRefusal::IdentityMismatch { .. }),
                "{refusal}"
            );
        }

        #[test]
        fn a_unit_that_stops_or_restarts_during_the_exchange_is_not_verified() {
            let service = serving(managed);
            for (second, expected) in [
                (
                    Err(ManagedRefusal::NotRunning {
                        unit: service.unit.clone(),
                        active_state: "activating".into(),
                    }),
                    "not running",
                ),
                (
                    Ok(running_as(std::process::id(), &"f".repeat(32))),
                    "restarted while its status was being read",
                ),
            ] {
                let asked = Cell::new(0);
                let refusal = status_with(&service.home, &|_| {
                    asked.set(asked.get() + 1);
                    if asked.get() == 1 {
                        Ok(running_as(std::process::id(), INVOCATION))
                    } else {
                        second.clone()
                    }
                })
                .unwrap_err();
                assert!(refusal.to_string().contains(expected), "{refusal}");
            }
        }

        #[test]
        fn absent_stopped_or_unreachable_is_reported_and_nothing_is_started() {
            let (_environment, _root, home) = canonical_home();
            let socket = socket_path(&home);
            let identity =
                ManagedIdentity::for_home(rustix::process::geteuid().as_raw(), &home).unwrap();
            for (answer, expected) in [
                (
                    Err(ManagedRefusal::NotProvisioned {
                        unit: identity.unit.clone(),
                        load_state: "not-found".into(),
                    }),
                    "is not provisioned",
                ),
                (
                    Err(ManagedRefusal::NotRunning {
                        unit: identity.unit.clone(),
                        active_state: "failed".into(),
                    }),
                    "provisioned but not running",
                ),
                (
                    Err(ManagedRefusal::ManagerUnavailable {
                        unit: identity.unit.clone(),
                        reason: "its fixed native socket is unavailable",
                    }),
                    "native socket is unavailable",
                ),
                (
                    Ok(running_as(std::process::id(), INVOCATION)),
                    "connecting to its socket",
                ),
            ] {
                let refusal = status_with(&home, &|_| answer.clone()).unwrap_err();
                assert!(refusal.to_string().contains(expected), "{refusal}");
                assert!(!socket.exists(), "a refusal must not start a coordinator");
            }
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
