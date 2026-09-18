//! The helper process: how it is started, how it confines itself, and the
//! kernel interface it serves.
//!
//! Before it reads a single request the helper makes itself non-dumpable,
//! closes every descriptor it did not expect to inherit, opens `/dev/urandom`,
//! and installs a seccomp allowlist that permits little beyond reading and
//! writing its socket and the two `random` ioctls. Anything it has not needed
//! by then it cannot do afterwards.

use super::LISTEN_ARG;

/// How a helper reaches the agent.
#[derive(Debug, PartialEq, Eq)]
pub enum HelperTransport {
    /// A socket pair end inherited on [`super::HELPER_FD`].
    InheritedFd,
    /// A listening socket at [`super::HELPER_SOCKET`].
    Listen,
}

/// Parse the arguments that follow [`super::HELPER_ARG`]. Anything unexpected
/// is refused: the helper holds `CAP_SYS_ADMIN` and takes no configuration.
pub fn helper_transport<I>(args: I) -> Result<HelperTransport, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let rest: Vec<_> = args.into_iter().collect();
    match rest.as_slice() {
        [] => Ok(HelperTransport::InheritedFd),
        [flag] if flag == LISTEN_ARG => Ok(HelperTransport::Listen),
        _ => Err(format!("unexpected helper arguments {rest:?}")),
    }
}

/// Entry point for the agent binary run with [`super::HELPER_ARG`]; `args` are
/// the arguments after it. Returns the process exit code.
pub fn run_helper<I>(args: I) -> i32
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::make_not_dumpable() {
        eprintln!("mvm-guest-agent: CRNG reseed helper cannot disable dumping: {error}");
        return 1;
    }
    let transport = match helper_transport(args) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("mvm-guest-agent: CRNG reseed helper: {error}");
            return 2;
        }
    };
    #[cfg(target_os = "linux")]
    {
        match linux::serve_confined(transport) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("mvm-guest-agent: CRNG reseed helper stopped: {error}");
                1
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = transport;
        eprintln!("mvm-guest-agent: the CRNG reseed helper runs inside Linux guests only");
        1
    }
}

#[cfg(target_os = "linux")]
pub use linux::{HelperSpawn, start_helper};

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    use super::super::protocol::{KernelEntropy, serve, serve_connections};
    use super::super::{HELPER_ARG, HELPER_FD, HELPER_SOCKET, install_helper};
    use super::HelperTransport;

    /// `_IOW('R', 0x03, int[2])` from `linux/random.h`.
    pub(crate) const RNDADDENTROPY: u32 = 0x4008_5203;
    /// `_IO('R', 0x07)` from `linux/random.h`.
    pub(crate) const RNDRESEEDCRNG: u32 = 0x5207;

    #[cfg(target_arch = "aarch64")]
    const TARGET_ARCH: TargetArch = TargetArch::aarch64;
    #[cfg(target_arch = "x86_64")]
    const TARGET_ARCH: TargetArch = TargetArch::x86_64;

    /// The kernel's `struct rand_pool_info` with room for one token. The header
    /// declares `buf` as a flexible `__u32` array; the kernel reads `buf_size`
    /// bytes starting at its offset, so a byte array in the same place is the
    /// same request.
    #[repr(C)]
    struct RandPoolInfo {
        entropy_count: libc::c_int,
        buf_size: libc::c_int,
        buf: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    }

    // Layout contract with linux/random.h `struct rand_pool_info`, whose fixed
    // part is 8 bytes aligned to 4 with `entropy_count` at 0, `buf_size` at 4
    // and `buf` at 8. Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof
    // against the header, not read off this definition. The token array adds 16
    // bytes after the fixed part without changing its offsets or alignment.
    const _: () = {
        use core::mem::{align_of, offset_of, size_of};

        assert!(offset_of!(RandPoolInfo, entropy_count) == 0);
        assert!(offset_of!(RandPoolInfo, buf_size) == 4);
        assert!(offset_of!(RandPoolInfo, buf) == 8);
        assert!(align_of::<RandPoolInfo>() == 4);
        assert!(size_of::<RandPoolInfo>() == 8 + mvm_core::crypto::vmgenid::GENID_BYTES);
    };

    /// `/dev/urandom`, opened once before the seccomp filter forbids opening
    /// anything.
    pub(crate) struct DevRandom {
        file: File,
    }

    impl DevRandom {
        pub(crate) fn open() -> io::Result<Self> {
            Ok(Self {
                file: std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/urandom")?,
            })
        }

        fn ioctl(&self, request: u32, arg: *const libc::c_void) -> io::Result<()> {
            // SAFETY: `request` is one of the two `random` ioctls, each given
            // the argument its definition takes, and `file` stays open.
            let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), request as _, arg) };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    impl KernelEntropy for DevRandom {
        fn add_entropy(&mut self, bytes: &[u8], credited_bits: u32) -> io::Result<()> {
            let mut info = RandPoolInfo {
                entropy_count: credited_bits as libc::c_int,
                buf_size: bytes.len() as libc::c_int,
                buf: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            };
            if bytes.len() != info.buf.len() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            info.buf.copy_from_slice(bytes);
            self.ioctl(RNDADDENTROPY, (&info as *const RandPoolInfo).cast())
        }

        fn force_reseed(&mut self) -> io::Result<()> {
            self.ioctl(RNDRESEEDCRNG, std::ptr::null())
        }
    }

    pub(super) fn make_not_dumpable() -> io::Result<()> {
        // SAFETY: plain prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Confine the process and serve until the agent goes away.
    pub(super) fn serve_confined(transport: HelperTransport) -> io::Result<()> {
        match transport {
            HelperTransport::InheritedFd => {
                crate::fd_hygiene::close_descriptors_from(HELPER_FD as u32 + 1, None)?;
                let mut entropy = DevRandom::open()?;
                // SAFETY: PID 1 placed this process's end of the socket pair on
                // `HELPER_FD`, and nothing else in this process owns it.
                let mut stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(HELPER_FD) });
                install_filter()?;
                serve(&mut stream, &mut entropy)
            }
            HelperTransport::Listen => {
                crate::fd_hygiene::close_descriptors_from(3, None)?;
                let mut entropy = DevRandom::open()?;
                let listener = bind_private_listener(Path::new(HELPER_SOCKET))?;
                install_filter()?;
                serve_connections(listener.incoming(), &mut entropy);
                Err(io::Error::other("the listener stopped accepting"))
            }
        }
    }

    /// Bind at `path` with a socket file only its owner and group can connect
    /// to. A file left in the tmpfs by an earlier boot of this memory image
    /// would make the bind fail, so it is removed first.
    fn bind_private_listener(path: &Path) -> io::Result<UnixListener> {
        match std::fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        // SAFETY: umask takes and returns a mode and cannot fail. The socket
        // file is created 0660 and the previous mask is restored.
        let previous = unsafe { libc::umask(0o117) };
        let listener = UnixListener::bind(path);
        unsafe { libc::umask(previous) };
        listener
    }

    /// The allowlist. Everything else kills the process, and a dead helper
    /// reports every later restore as not reseeded, so a missing entry fails
    /// closed rather than open.
    ///
    /// Every name here is a syscall on both x86_64 and aarch64, and the list is
    /// written for what the C library and std actually issue on each, not for
    /// the libc function names. The places the two differ — `dup2`, `poll`,
    /// `open`, `stat` exist only on x86_64, where aarch64 has `dup3`, `ppoll`,
    /// `openat`, `newfstatat` — are all calls the helper makes only before the
    /// filter goes on (opening `/dev/urandom`, binding its socket, closing
    /// stray descriptors) or never, so none of them is needed here. The
    /// unprivileged helper test runs this filter on every CI architecture.
    pub(crate) fn helper_filter() -> Result<BpfProgram, seccompiler::BackendError> {
        let plain = [
            // Reading a request. std reads a socket with `recv`, which both C
            // libraries issue as `recvfrom`; `read`, `readv` and `recvmsg`
            // cover a library that routes it another way.
            libc::SYS_read,
            libc::SYS_readv,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            // Writing a reply. std writes a socket with `send` and
            // `MSG_NOSIGNAL`, issued as `sendto`; `eprintln!` writes stderr
            // with `write`. `writev` and `sendmsg` as above.
            libc::SYS_write,
            libc::SYS_writev,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            // The listening helper accepts each connection. std calls
            // `accept4` with close-on-exec on both architectures.
            libc::SYS_accept4,
            // Closing a finished connection.
            libc::SYS_close,
            // The allocator. Formatting an error allocates; glibc grows the
            // heap with `brk` and falls back to `mmap`, musl's allocator uses
            // `brk`, `mmap`, `munmap`, `mremap` and `madvise`.
            libc::SYS_brk,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            // The stderr lock and the allocator's own locks.
            libc::SYS_futex,
            libc::SYS_sched_yield,
            // Normally served by the vDSO; the syscall is the fallback when the
            // vDSO cannot answer.
            libc::SYS_clock_gettime,
            // Returning from the stack-overflow handler std installs, and the
            // mask changes around it.
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigprocmask,
            libc::SYS_sigaltstack,
            // Exiting: `exit_group` from `std::process::exit` and a return from
            // `main`, `exit` from a thread.
            libc::SYS_exit,
            libc::SYS_exit_group,
        ];
        let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
            plain.into_iter().map(|nr| (nr, Vec::new())).collect();
        let arg_equals = |index: u8, value: u64| {
            SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
                .and_then(|condition| SeccompRule::new(vec![condition]))
        };
        // The reseed itself, and nothing else `ioctl` can do.
        rules.insert(
            libc::SYS_ioctl,
            vec![
                arg_equals(1, RNDADDENTROPY.into())?,
                arg_equals(1, RNDRESEEDCRNG.into())?,
            ],
        );
        // std checks a descriptor is still open before closing one it owns.
        // On aarch64 glibc's `fcntl64` is the `fcntl` syscall, as it is on
        // x86_64. Only the flag read is allowed.
        rules.insert(libc::SYS_fcntl, vec![arg_equals(1, libc::F_GETFD as u64)?]);
        // musl's allocator makes pages of a new metadata area writable with
        // `mprotect`. Allowed only without `PROT_EXEC`, so the helper can never
        // make memory executable.
        rules.insert(
            libc::SYS_mprotect,
            vec![SeccompRule::new(vec![SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                0,
            )?])?],
        );
        BpfProgram::try_from(SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TARGET_ARCH,
        )?)
    }

    fn install_filter() -> io::Result<()> {
        // SAFETY: plain prctl with integer arguments. Required before an
        // unprivileged process may install a filter, and already set by the
        // launcher; repeated so the helper never depends on that.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let program = helper_filter().map_err(io::Error::other)?;
        seccompiler::apply_filter(&program).map_err(io::Error::other)
    }

    /// Starts a helper over a socket pair.
    pub struct HelperSpawn {
        executable: PathBuf,
        identity: Option<(u32, u32)>,
    }

    impl Default for HelperSpawn {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HelperSpawn {
        /// The agent's own binary, keeping the caller's identity.
        pub fn new() -> Self {
            Self {
                executable: PathBuf::from("/proc/self/exe"),
                identity: None,
            }
        }

        /// Run `executable` instead of this process's own binary.
        pub fn executable(mut self, executable: impl Into<PathBuf>) -> Self {
            self.executable = executable.into();
            self
        }

        /// Drop from root to `uid`/`gid` holding only `CAP_SYS_ADMIN`.
        pub fn identity(mut self, uid: u32, gid: u32) -> Self {
            self.identity = Some((uid, gid));
            self
        }

        /// Start the helper and return the agent's end of the socket pair.
        ///
        /// In the child, before exec: the helper's end is placed on
        /// [`HELPER_FD`], every descriptor above it is closed — the agent's
        /// listener and its open control connection included — and then the
        /// identity is dropped.
        pub fn spawn(&self) -> io::Result<(UnixStream, Child)> {
            use std::os::unix::process::CommandExt;

            let (agent_end, helper_end) = UnixStream::pair()?;
            let helper_fd = helper_end.as_raw_fd();
            let identity = self.identity;
            let mut cmd = Command::new(&self.executable);
            cmd.arg(HELPER_ARG)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            // SAFETY: runs in the forked child before exec, and calls only
            // async-signal-safe syscalls without allocating.
            unsafe {
                cmd.pre_exec(move || {
                    expose_helper_fd(helper_fd)?;
                    crate::fd_hygiene::mark_descriptors_close_on_exec_from(
                        HELPER_FD as u32 + 1,
                        None,
                    )?;
                    match identity {
                        Some((uid, gid)) => crate::guest_mount::assume_identity_retaining(
                            uid,
                            gid,
                            crate::guest_mount::CRNG_RESEED_HELPER_CAPABILITIES,
                        ),
                        None => Ok(()),
                    }
                });
            }
            let child = cmd.spawn()?;
            drop(helper_end);
            Ok((agent_end, child))
        }
    }

    /// Put the helper's end on [`HELPER_FD`] without close-on-exec.
    fn expose_helper_fd(fd: i32) -> io::Result<()> {
        // `dup2` onto itself is a no-op that leaves close-on-exec set, so the
        // already-in-place case has to clear the flag directly.
        let rc = if fd == HELPER_FD {
            // SAFETY: plain descriptor flag update.
            unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }
        } else {
            // SAFETY: both are plain descriptor numbers; `dup2` clears
            // close-on-exec on the new descriptor.
            unsafe { libc::dup2(fd, HELPER_FD) }
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Start this guest's helper under its own uid and keep the socket pair to
    /// it. Called by the PID-1 agent while it is still root, just before it
    /// drops privilege.
    ///
    /// A failure is logged and not fatal: the guest still boots, and a later
    /// restore reports that it has no helper, which the host refuses.
    pub fn start_helper() {
        let spawn = HelperSpawn::new().identity(
            crate::guest_mount::CRNG_RESEED_HELPER_UID,
            crate::guest_mount::CRNG_RESEED_HELPER_GID,
        );
        match spawn
            .spawn()
            .and_then(|(stream, child)| install_helper(stream).map(|()| child))
        {
            Ok(child) => eprintln!(
                "mvm-guest-agent: CRNG reseed helper pid={} uid={}",
                child.id(),
                crate::guest_mount::CRNG_RESEED_HELPER_UID
            ),
            Err(error) => eprintln!(
                "mvm-guest-agent: no CRNG reseed helper ({error}); restores of this guest will be refused"
            ),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_ioctl_numbers_match_the_kernel_header() {
            // _IOW('R', 0x03, int[2]): write direction, eight bytes of argument.
            assert_eq!(RNDADDENTROPY, (1 << 30) | (8 << 16) | (0x52 << 8) | 0x03);
            // _IO('R', 0x07): no direction, no argument.
            assert_eq!(RNDRESEEDCRNG, (0x52 << 8) | 0x07);
            assert_eq!(std::mem::size_of::<RandPoolInfo>(), 8 + 16);
        }

        #[test]
        fn the_helper_filter_compiles() {
            let program = helper_filter().expect("the allowlist is a valid filter");
            assert!(!program.is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn the_helper_accepts_only_its_two_invocations() {
        assert_eq!(
            helper_transport(Vec::<OsString>::new()),
            Ok(HelperTransport::InheritedFd)
        );
        assert_eq!(
            helper_transport([OsString::from(LISTEN_ARG)]),
            Ok(HelperTransport::Listen)
        );
        for args in [
            vec!["--listen=/tmp/elsewhere.sock"],
            vec![LISTEN_ARG, "/tmp/elsewhere.sock"],
            vec!["--config"],
        ] {
            assert!(
                helper_transport(args.into_iter().map(OsString::from)).is_err(),
                "a helper holding CAP_SYS_ADMIN must take no other arguments"
            );
        }
    }
}
