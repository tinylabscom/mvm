//! The declared-command tool helper: the one guest process that can run a
//! substituted tool's bytes.
//!
//! The guest init stashes every declared tool's original executable in a
//! directory only this helper's identity can read and mounts the
//! `mvm-tool-shim` client over every runnable path to those bytes. A workload
//! process that execs a declared command therefore reaches only the shim; the
//! shim relays the exact invocation here over a guest-local socket, and this
//! helper:
//!
//! 1. maps the shim's own executable path (the path the kernel used to reach
//!    it) to the one tool the signed plan bound to it — the workload cannot
//!    choose a tool identity, and an `argv[0]` that claims the declared tool's
//!    name fails closed into mediation;
//! 2. asks the host to decide the exact argv over `host.tool.v1` before any
//!    spawn, unless the agent already recorded a host decision for this relay
//!    (the host-initiated `MediatedExec` path decides exactly once, on the
//!    authenticated control session);
//! 3. verifies the stash bytes still hash to the digest pinned at activation,
//!    sanitizes the environment, and execs the tool as
//!    [`crate::guest_mount::TOOL_UID`] with all three gids at
//!    [`crate::guest_mount::TOOL_GID`] in a fresh session;
//! 4. records that session under the host-minted binding with the agent, so
//!    the tool's loopback egress is attributed and its routes and secrets are
//!    enforced at the endpoint — and retires the binding when the tool exits.
//!
//! Every failure before the spawn is a refusal, never an approval: an unknown
//! path, a malformed request, a denied decision, an unreachable host or agent,
//! a digest mismatch or a failed exec all end with the shim exiting nonzero
//! and the tool never running.

use std::io;
use std::path::Path;

use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;
use mvm_contract::protocol::network_flow::tool::{ToolCheckRequest, ToolDecisionReply};

use crate::tool_map::{
    Dispatch, EXIT_SPAWN, HelperReply, ShimRequest, ToolEntry, ToolMap, sha256_hex,
};

/// Largest tool binary the helper will hash and exec.
pub const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;

/// Failure modes that map to the reply the shim gets.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Mediation itself is broken (transport down, stash unreadable or
    /// tampered). The tool never runs.
    #[error("{0}")]
    Unavailable(String),
    /// The shim's request or the tool state was malformed.
    #[error("{0}")]
    BadRequest(String),
}

/// How the helper learns prior decisions and records sessions.
pub trait AgentDecisions {
    /// Consume the host decision recorded for a `MediatedExec` relay pid.
    /// `Ok(Some(binding))` is a decided relay (`None` binding when the tool
    /// scopes nothing); `Ok(None)` is an undecided caller.
    fn decided(&self, pid: u32) -> Result<Option<Option<ToolInvocationBinding>>, HelperError>;
    /// Record a tool session under its binding for egress attribution.
    fn record(&self, session: u32, binding: ToolInvocationBinding);
    /// Retire a recorded session after the tool exited.
    fn retire(&self, session: u32);
}

/// How the helper asks the host to decide an invocation.
pub trait HostDecisions {
    /// One exact invocation decision, fail closed.
    fn decide(&self, request: &ToolCheckRequest) -> Result<ToolDecisionReply, HelperError>;
    /// Release a binding the helper minted and now retires.
    fn release(&self, binding: ToolInvocationBinding);
}

/// The identity a request's tool runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunIdentity {
    /// The mediated tool: the distinct tool uid and group, fresh session.
    Tool,
    /// A shared binary under a non-tool name: the caller's own uid/gid, so
    /// applet behaviour is unchanged from the unsubstituted image.
    Caller { uid: u32, gid: u32 },
}

/// One validated, decided run the helper is about to spawn.
#[derive(Debug)]
pub struct ApprovedRun<'a> {
    /// The tool whose bytes run.
    pub entry: &'a ToolEntry,
    /// Exact argv the tool is spawned with (`argv[0]` is the declared path
    /// for a mediated run, the caller's own for a direct one).
    pub argv: Vec<String>,
    /// The caller's working directory.
    pub cwd: String,
    /// Environment for the tool (already sanitized when mediated).
    pub env: Vec<(String, String)>,
    /// What the spawned process becomes.
    pub identity: RunIdentity,
    /// The host-minted binding for a scoped tool, if any.
    pub binding: Option<ToolInvocationBinding>,
    /// Whether the helper minted the binding (undecided path) and so must
    /// release it at retirement; a consumed relay decision is released
    /// host-side by the `MediatedExec` caller.
    pub helper_minted_binding: bool,
}

/// Validate one shim request and take every decision the run needs. Pure
/// policy: socket plumbing and spawning stay outside so the rules are
/// testable without a guest.
pub fn approve<'a>(
    map: &'a ToolMap,
    request: &ShimRequest,
    peer_pid: u32,
    peer_uid: u32,
    peer_gid: u32,
    agent: &dyn AgentDecisions,
    host: &dyn HostDecisions,
) -> Result<ApprovedRun<'a>, HelperReply> {
    let (entry, mediate) =
        match map.dispatch(&request.exe, request.argv.first().map(String::as_str)) {
            Dispatch::Mediate(entry) => (entry, true),
            Dispatch::Direct(entry) => (entry, false),
            Dispatch::Unknown => {
                return Err(HelperReply::Denied {
                    reason: "the executed path is not a declared tool".into(),
                });
            }
        };
    let Some(argv) = non_empty_argv(&request.argv) else {
        return Err(HelperReply::Denied {
            reason: "empty declared command argv".into(),
        });
    };
    if !mediate {
        return Ok(ApprovedRun {
            entry,
            argv,
            cwd: request.cwd.clone(),
            env: request.env.clone(),
            identity: RunIdentity::Caller {
                uid: peer_uid,
                gid: peer_gid,
            },
            binding: None,
            helper_minted_binding: false,
        });
    }

    // The relayed argv is reported to the host with the declared executable
    // as argv[0]: the path that reached the shim is already verified to be
    // the signed one, so the policy match stays canonical no matter which
    // alias spelling the workload used.
    let mut canonical = argv;
    canonical[0] = entry.executable.clone();
    let (binding, helper_minted_binding) = match agent.decided(peer_pid) {
        Ok(Some(binding)) => (binding, false),
        Ok(None) => match decide_at_host(entry, &canonical, host)? {
            ToolDecisionReply::Allow => (None, false),
            ToolDecisionReply::AllowBound { binding } => (Some(binding), true),
            ToolDecisionReply::Deny => {
                return Err(HelperReply::Denied {
                    reason: "the declared tool invocation was denied by host policy".into(),
                });
            }
        },
        Err(error) => {
            return Err(HelperReply::Unavailable {
                reason: format!("tool decision state unavailable: {error}"),
            });
        }
    };

    Ok(ApprovedRun {
        entry,
        argv: canonical,
        cwd: request.cwd.clone(),
        env: crate::tool_map::sanitized_tool_env(&request.env),
        identity: RunIdentity::Tool,
        binding,
        helper_minted_binding,
    })
}

fn non_empty_argv(argv: &[String]) -> Option<Vec<String>> {
    let argv: Vec<String> = argv.to_vec();
    if argv.first().is_some_and(|first| !first.is_empty()) {
        Some(argv)
    } else {
        None
    }
}

fn decide_at_host(
    entry: &ToolEntry,
    canonical_argv: &[String],
    host: &dyn HostDecisions,
) -> Result<ToolDecisionReply, HelperReply> {
    let Some(request) = ToolCheckRequest::from_argv(entry.tool.clone(), canonical_argv) else {
        return Err(HelperReply::Unavailable {
            reason: "the declared tool invocation is malformed".into(),
        });
    };
    host.decide(&request)
        .map_err(|error| HelperReply::Unavailable {
            reason: format!("tool decision transport failed: {error}"),
        })
}

/// Verify the stash still holds the bytes pinned at activation.
pub fn verify_stash(entry: &ToolEntry, stash: &Path) -> Result<(), HelperError> {
    let bytes = std::fs::read(stash).map_err(|error| {
        HelperError::Unavailable(format!(
            "tool stash {} unreadable: {error}",
            stash.display()
        ))
    })?;
    if bytes.len() as u64 > MAX_TOOL_BYTES {
        return Err(HelperError::Unavailable(format!(
            "tool stash {} exceeds the {MAX_TOOL_BYTES}-byte bound",
            stash.display()
        )));
    }
    let actual = sha256_hex(&bytes);
    if actual != entry.digest {
        return Err(HelperError::Unavailable(format!(
            "tool stash {} does not match the digest pinned at activation",
            stash.display()
        )));
    }
    Ok(())
}

/// Finish a run the policy approved: verify the bytes, spawn the tool, wait
/// for it, and retire what it recorded. Returns the exit code for the shim.
pub fn run_approved(
    run: &ApprovedRun<'_>,
    stdio: [std::os::unix::io::RawFd; 3],
    events: &mut dyn FnMut() -> ToolEvent,
    agent: &dyn AgentDecisions,
    host: &dyn HostDecisions,
) -> i32 {
    if let Err(error) = verify_stash(run.entry, Path::new(&run.entry.stash)) {
        eprintln!("mvm-tool-helper: {error}");
        return crate::tool_map::EXIT_UNAVAILABLE;
    }
    let child = match spawn_tool(run, stdio) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("mvm-tool-helper: spawn {}: {error}", run.entry.tool);
            return EXIT_SPAWN;
        }
    };
    let child = u32::try_from(child).unwrap_or(u32::MAX);
    if let Some(binding) = run.binding.clone() {
        agent.record(child, binding);
    }
    let code = wait_or_kill(i32::try_from(child).unwrap_or(i32::MAX), events);
    if let Some(binding) = run.binding.clone() {
        agent.retire(child);
        if run.helper_minted_binding {
            host.release(binding);
        }
    }
    code
}

/// What the shim's control socket reported while the tool runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolEvent {
    /// The shim is alive; `Some` carries a signal the shim asked to be
    /// forwarded to the tool's process group.
    Running(Option<u8>),
    /// The shim is gone: kill the tool and stop waiting.
    Gone,
}

#[cfg(target_os = "linux")]
fn child_code(status: i32) -> i32 {
    // Reads the raw `waitpid` status directly: `ExitStatus::from_raw` is
    // unsafe on some toolchains and not on others, which makes it a
    // portability trap.
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    }
}

/// Wait for `child`, forwarding the shim's signals to the tool's process
/// group and killing the group the moment the shim goes away.
#[cfg(target_os = "linux")]
fn wait_or_kill(child: i32, events: &mut dyn FnMut() -> ToolEvent) -> i32 {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a writable int the kernel fills in.
        let rc = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if rc == child {
            return child_code(status);
        }
        if rc < 0 {
            // ECHILD and friends: the child is unwaitable, so report the
            // mediation as broken rather than spinning.
            return crate::tool_map::EXIT_UNAVAILABLE;
        }
        match events() {
            ToolEvent::Running(Some(signal)) => {
                // SAFETY: a positive signal number and the child's process
                // group id, both plain integers.
                unsafe { libc::kill(-child, signal as libc::c_int) };
            }
            ToolEvent::Running(None) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            ToolEvent::Gone => {
                // SAFETY: negative pid kills the child's process group, which
                // `setsid` in the child made its own.
                unsafe { libc::kill(-child, libc::SIGKILL) };
                let mut status = 0;
                // SAFETY: as above.
                unsafe { libc::waitpid(child, &mut status, 0) };
                return child_code(status);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_or_kill(_child: i32, _events: &mut dyn FnMut() -> ToolEvent) -> i32 {
    crate::tool_map::EXIT_UNAVAILABLE
}

/// Spawn the verified stash with the approved identity and descriptors.
/// Returns the child's pid.
#[cfg(target_os = "linux")]
fn spawn_tool(run: &ApprovedRun<'_>, stdio: [std::os::unix::io::RawFd; 3]) -> io::Result<i32> {
    use std::os::unix::io::AsRawFd;
    let stash = std::fs::File::open(&run.entry.stash)?;
    // Rust opens with O_CLOEXEC: the descriptor survives until the execveat
    // below consumes it and is then closed by the exec itself.
    let stash_fd = stash.as_raw_fd();
    let (uid, gid) = match run.identity {
        RunIdentity::Tool => (crate::guest_mount::TOOL_UID, crate::guest_mount::TOOL_GID),
        RunIdentity::Caller { uid, gid } => (uid, gid),
    };
    let argv: Vec<std::ffi::CString> = run
        .argv
        .iter()
        .map(|arg| std::ffi::CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let env: Vec<std::ffi::CString> = run
        .env
        .iter()
        .map(|(key, value)| std::ffi::CString::new(format!("{key}={value}").into_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|var| var.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let cwd = std::ffi::CString::new(run.cwd.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    // SAFETY: fork in a threaded helper; the child path calls only
    // async-signal-safe syscalls with plain integer arguments and pointers to
    // buffers that outlive the fork (they are not mutated afterwards). The
    // parent closes only its own copy of the stash descriptor.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: become the tool. Every step is async-signal-safe; any
        // failure ends in _exit, never a return into the forked address
        // space with two threads' locks held.
        unsafe {
            if libc::setsid() < 0 {
                libc::_exit(EXIT_SPAWN);
            }
            for (target, fd) in [(0, stdio[0]), (1, stdio[1]), (2, stdio[2])] {
                if fd != target && libc::dup2(fd, target) < 0 {
                    libc::_exit(EXIT_SPAWN);
                }
            }
            if libc::chdir(cwd.as_ptr()) != 0 && libc::chdir(cstr_root().as_ptr()) != 0 {
                libc::_exit(EXIT_SPAWN);
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                libc::_exit(EXIT_SPAWN);
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                libc::_exit(EXIT_SPAWN);
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                libc::_exit(EXIT_SPAWN);
            }
            // AT_EMPTY_PATH execs the open descriptor: no path walk through
            // the helper-only stash directory after the uid drop, and the
            // bytes were digest-verified before the fork.
            if execveat_raw(
                stash_fd,
                cstr_empty().as_ptr(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
                AT_EMPTY_PATH_RAW,
            ) != 0
            {
                libc::_exit(EXIT_SPAWN);
            }
            libc::_exit(EXIT_SPAWN);
        }
    }
    drop(stash);
    Ok(pid)
}

#[cfg(not(target_os = "linux"))]
fn spawn_tool(_run: &ApprovedRun<'_>, _stdio: [std::os::unix::io::RawFd; 3]) -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tools spawn only in a Linux guest",
    ))
}

/// `execveat(2)` via the raw syscall. The libC route is unusable in the
/// guest: `libc` gates the symbol away on linux-musl, and the pinned static
/// musl in the toolchain does not export `execveat` at all. The syscall
/// number is arch-fixed and `syscall(2)` is async-signal-safe.
#[cfg(target_os = "linux")]
fn execveat_raw(
    fd: libc::c_int,
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    // SAFETY: the caller passes a live descriptor and NUL-terminated vectors
    // that outlive the call, per the execveat(2) contract; every argument is
    // a plain integer or pointer to live memory.
    unsafe { libc::syscall(libc::SYS_execveat, fd, path, argv, envp, flags) as libc::c_int }
}

/// `AT_EMPTY_PATH` from `linux/fcntl.h`.
#[cfg(target_os = "linux")]
const AT_EMPTY_PATH_RAW: libc::c_int = 0x1000;

/// `msghdr::msg_controllen` and `cmsghdr::cmsg_len` are `usize` on some
/// libC/target combinations and `socklen_t` on others, and the set differs
/// between the pinned embed toolchains and the host toolchain. This trait
/// converts from `usize` for whichever field type the target libc declares.
#[cfg(target_os = "linux")]
trait MsgLen {
    fn of_len(len: usize) -> Self;
}

#[cfg(target_os = "linux")]
impl MsgLen for usize {
    fn of_len(len: usize) -> Self {
        len
    }
}

#[cfg(target_os = "linux")]
impl MsgLen for u32 {
    fn of_len(len: usize) -> Self {
        u32::try_from(len).expect("a control buffer always fits msg_controllen")
    }
}

#[cfg(target_os = "linux")]
fn cstr_empty() -> std::ffi::CString {
    std::ffi::CString::new("").expect("empty string has no NUL")
}

#[cfg(target_os = "linux")]
fn cstr_root() -> std::ffi::CString {
    std::ffi::CString::new("/").expect("root has no NUL")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoAgent;
    impl AgentDecisions for NoAgent {
        fn decided(&self, _pid: u32) -> Result<Option<Option<ToolInvocationBinding>>, HelperError> {
            Ok(None)
        }
        fn record(&self, _session: u32, _binding: ToolInvocationBinding) {}
        fn retire(&self, _session: u32) {}
    }

    struct NoHost;
    impl HostDecisions for NoHost {
        fn decide(&self, _request: &ToolCheckRequest) -> Result<ToolDecisionReply, HelperError> {
            Err(HelperError::Unavailable("no host".into()))
        }
        fn release(&self, _binding: ToolInvocationBinding) {}
    }

    fn entry(tool: &str, executable: &str) -> ToolEntry {
        ToolEntry {
            tool: tool.into(),
            executable: executable.into(),
            aliases: Vec::new(),
            stash: format!("/run/mvm/toolstash/{}", "a".repeat(64)),
            digest: "b".repeat(64),
        }
    }

    fn map(entries: Vec<ToolEntry>) -> ToolMap {
        ToolMap { tools: entries }
    }

    fn request(exe: &str, argv: &[&str]) -> ShimRequest {
        ShimRequest {
            exe: exe.into(),
            argv: argv.iter().map(ToString::to_string).collect(),
            cwd: "/work".into(),
            env: vec![
                ("LD_PRELOAD".into(), "/tmp/x".into()),
                ("PATH".into(), "/bin".into()),
            ],
        }
    }

    #[test]
    fn unknown_path_is_denied() {
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let reply = approve(
            &tools,
            &request("/tmp/sh", &["sh", "-c", "echo hi"]),
            10,
            901,
            901,
            &NoAgent,
            &NoHost,
        )
        .expect_err("unknown path refuses");
        assert!(matches!(reply, HelperReply::Denied { .. }));
    }

    #[test]
    fn empty_argv_is_denied() {
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let reply = approve(
            &tools,
            &request("/bin/sh", &[""]),
            10,
            901,
            901,
            &NoAgent,
            &NoHost,
        )
        .expect_err("empty argv refuses");
        assert!(matches!(reply, HelperReply::Denied { .. }));
    }

    #[test]
    fn direct_runs_use_the_caller_identity_and_untouched_env() {
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let run = approve(
            &tools,
            &request("/bin/sh", &["ls", "-l"]),
            10,
            901,
            901,
            &NoAgent,
            &NoHost,
        )
        .expect("direct run approves without any decision");
        assert_eq!(run.identity, RunIdentity::Caller { uid: 901, gid: 901 });
        assert_eq!(run.argv, vec!["ls", "-l"]);
        assert!(run.env.iter().any(|(key, _)| key == "LD_PRELOAD"));
        assert!(run.binding.is_none());
    }

    #[test]
    fn mediated_runs_canonicalize_argv_and_sanitize_env() {
        struct AllowHost;
        impl HostDecisions for AllowHost {
            fn decide(&self, request: &ToolCheckRequest) -> Result<ToolDecisionReply, HelperError> {
                assert_eq!(request.tool, "shell");
                assert_eq!(request.executable.as_deref(), Some("/bin/sh"));
                assert_eq!(request.argv, "/bin/sh -c 'echo hi'");
                Ok(ToolDecisionReply::Allow)
            }
            fn release(&self, _binding: ToolInvocationBinding) {}
        }
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let run = approve(
            &tools,
            &request("/bin/sh", &["sh", "-c", "echo hi"]),
            10,
            901,
            901,
            &NoAgent,
            &AllowHost,
        )
        .expect("mediated run approves");
        assert_eq!(run.identity, RunIdentity::Tool);
        assert_eq!(run.argv, vec!["/bin/sh", "-c", "echo hi"]);
        assert!(!run.env.iter().any(|(key, _)| key == "LD_PRELOAD"));
        assert!(run.env.iter().any(|(key, _)| key == "PATH"));
        assert!(!run.helper_minted_binding);
    }

    #[test]
    fn a_decided_relay_skips_the_host_and_is_not_released_here() {
        struct PanicHost;
        impl HostDecisions for PanicHost {
            fn decide(
                &self,
                _request: &ToolCheckRequest,
            ) -> Result<ToolDecisionReply, HelperError> {
                panic!("a decided relay must not re-ask the host");
            }
            fn release(&self, _binding: ToolInvocationBinding) {}
        }
        struct DecidedAgent;
        impl AgentDecisions for DecidedAgent {
            fn decided(
                &self,
                pid: u32,
            ) -> Result<Option<Option<ToolInvocationBinding>>, HelperError> {
                assert_eq!(pid, 77);
                Ok(Some(None))
            }
            fn record(&self, _session: u32, _binding: ToolInvocationBinding) {}
            fn retire(&self, _session: u32) {}
        }
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let run = approve(
            &tools,
            &request("/bin/sh", &["sh", "-c", "echo hi"]),
            77,
            901,
            901,
            &DecidedAgent,
            &PanicHost,
        )
        .expect("decided relay approves");
        assert!(!run.helper_minted_binding);
    }

    #[test]
    fn a_bound_allow_is_minted_by_the_helper_and_marked_for_release() {
        struct BoundHost;
        impl HostDecisions for BoundHost {
            fn decide(
                &self,
                _request: &ToolCheckRequest,
            ) -> Result<ToolDecisionReply, HelperError> {
                Ok(ToolDecisionReply::AllowBound {
                    binding: ToolInvocationBinding::from_random([3; 16]),
                })
            }
            fn release(&self, _binding: ToolInvocationBinding) {}
        }
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let run = approve(
            &tools,
            &request("/bin/sh", &["sh", "-c", "echo hi"]),
            10,
            901,
            901,
            &NoAgent,
            &BoundHost,
        )
        .expect("bound allow approves");
        assert!(run.binding.is_some());
        assert!(run.helper_minted_binding);
    }

    #[test]
    fn a_host_deny_is_a_denial_not_an_unavailability() {
        struct DenyHost;
        impl HostDecisions for DenyHost {
            fn decide(
                &self,
                _request: &ToolCheckRequest,
            ) -> Result<ToolDecisionReply, HelperError> {
                Ok(ToolDecisionReply::Deny)
            }
            fn release(&self, _binding: ToolInvocationBinding) {}
        }
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let reply = approve(
            &tools,
            &request("/bin/sh", &["sh", "-c", "echo hi"]),
            10,
            901,
            901,
            &NoAgent,
            &DenyHost,
        )
        .expect_err("deny refuses");
        assert!(matches!(reply, HelperReply::Denied { .. }));
    }

    #[test]
    fn a_host_transport_failure_is_unavailable_not_denied() {
        let tools = map(vec![entry("shell", "/bin/sh")]);
        let reply = approve(
            &tools,
            &request("/bin/sh", &["sh", "-c", "echo hi"]),
            10,
            901,
            901,
            &NoAgent,
            &NoHost,
        )
        .expect_err("transport failure refuses");
        assert!(matches!(reply, HelperReply::Unavailable { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_stash_detects_tampering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stash = dir.path().join("stash");
        std::fs::write(&stash, b"tool bytes").expect("write stash");
        let mut tool = entry("shell", "/bin/sh");
        tool.stash = stash.to_string_lossy().into_owned();
        tool.digest = sha256_hex(b"tool bytes");
        assert!(verify_stash(&tool, &stash).is_ok());
        std::fs::write(&stash, b"other bytes").expect("tamper");
        assert!(verify_stash(&tool, &stash).is_err());
    }
}

// ---------------------------------------------------------------------------
// Socket server: how the shim reaches the helper.
// ---------------------------------------------------------------------------

/// Bind the helper's guest-local socket and serve it for the life of the
/// helper. The socket lives in a root-owned directory the workload cannot
/// write, so the name cannot be unlinked and rebound by anything but root;
/// the shim additionally verifies the listener's identity after connecting.
#[cfg(target_os = "linux")]
pub fn bind_and_serve(map: ToolMap) -> io::Result<()> {
    let socket = std::path::Path::new(crate::tool_map::HELPER_SOCKET);
    let _ = std::fs::remove_file(socket);
    let listener = std::os::unix::net::UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o666)
    })?;
    eprintln!(
        "mvm-tool-helper: serving {} for {} declared tool(s)",
        socket.display(),
        map.tools.len()
    );
    serve(map, listener)
}

#[cfg(target_os = "linux")]
pub fn serve(map: ToolMap, listener: std::os::unix::net::UnixListener) -> io::Result<()> {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let map = map.clone();
        std::thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &map) {
                eprintln!("mvm-tool-helper: connection failed: {error}");
            }
        });
    }
    Ok(())
}

/// Read the shim's request line plus its attached descriptors 0, 1 and 2.
#[cfg(target_os = "linux")]
fn recv_request(
    stream: &std::os::unix::net::UnixStream,
) -> io::Result<(ShimRequest, [Option<std::os::unix::io::RawFd>; 3])> {
    use std::os::unix::io::AsRawFd;

    let mut buffer = vec![0u8; (crate::tool_map::MAX_SHIM_FRAME_BYTES + 1) as usize];
    let mut control = vec![0u8; 128];
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // Zero-initialized rather than a struct literal: `msghdr` carries private
    // padding fields on some libC targets (linux-musl), which makes literal
    // construction unconstructable there.
    let mut header = unsafe { std::mem::zeroed::<libc::msghdr>() };
    header.msg_name = std::ptr::null_mut();
    header.msg_namelen = 0;
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = MsgLen::of_len(control.len());
    header.msg_flags = 0;
    // SAFETY: `header` points at the live buffer and control vectors; the
    // kernel writes at most their lengths into them.
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut header, 0) };
    if received <= 0 {
        return Err(io::Error::last_os_error());
    }
    let line = std::str::from_utf8(&buffer[..received as usize])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let request: ShimRequest = serde_json::from_str(line.trim_end())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    let mut fds: [Option<std::os::unix::io::RawFd>; 3] = [None; 3];
    // SAFETY: `header` was filled by the successful recvmsg above; walking
    // its control messages reads only kernel-written memory within the
    // control buffer.
    unsafe {
        let mut control_header = libc::CMSG_FIRSTHDR(&header);
        while !control_header.is_null() {
            if (*control_header).cmsg_level == libc::SOL_SOCKET
                && (*control_header).cmsg_type == libc::SCM_RIGHTS
            {
                let count = ((*control_header).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<std::os::unix::io::RawFd>();
                let data = libc::CMSG_DATA(control_header) as *const std::os::unix::io::RawFd;
                for index in 0..count.min(3) {
                    fds[index] = Some(*data.add(index));
                }
            }
            control_header = libc::CMSG_NXTHDR(&header, control_header);
        }
    }
    Ok((request, fds))
}

/// The peer's kernel-authenticated pid and identity.
#[cfg(target_os = "linux")]
fn peer_process(stream: &std::os::unix::net::UnixStream) -> io::Result<(u32, u32, u32)> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a correctly sized `ucred` and `len` holds its size.
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
        return Err(io::Error::last_os_error());
    }
    Ok((cred.pid as u32, cred.uid, cred.gid))
}

/// An event source over the shim's control socket. After its one request the
/// shim sends nothing but forwarded signals (one byte each) and eventually
/// closes; readable data is drained as signals, and a hangup kills the tool.
#[cfg(target_os = "linux")]
fn peer_events(stream: std::os::unix::net::UnixStream) -> impl FnMut() -> ToolEvent {
    use std::collections::VecDeque;
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut pending: VecDeque<u8> = VecDeque::new();
    move || loop {
        if let Some(signal) = pending.pop_front() {
            return ToolEvent::Running(Some(signal));
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: `pollfd` is one live entry for the duration of the poll.
        let rc = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if rc <= 0 {
            return ToolEvent::Running(None);
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut buffer = [0u8; 64];
            // SAFETY: `buffer` is writable for the length handed to recv.
            let count = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if count <= 0 {
                return ToolEvent::Gone;
            }
            pending.extend(buffer[..count as usize].iter().copied());
            if pollfd.revents & libc::POLLHUP != 0 && pending.is_empty() {
                return ToolEvent::Gone;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn send_reply(stream: &mut std::os::unix::net::UnixStream, reply: &HelperReply) -> io::Result<()> {
    use std::io::Write;
    let mut line = serde_json::to_vec(reply).map_err(io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)
}

/// Serve one shim connection end to end.
#[cfg(target_os = "linux")]
fn handle_connection(mut stream: std::os::unix::net::UnixStream, map: &ToolMap) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(
        crate::vsock::TOOL_REQUEST_TIMEOUT_SECS,
    )));
    let (request, stdio) = recv_request(&stream)?;
    let (peer_pid, peer_uid, peer_gid) = peer_process(&stream)?;
    let stdio: [std::os::unix::io::RawFd; 3] = stdio.map(|fd| fd.unwrap_or(-1));

    let outcome = match approve(map, &request, peer_pid, peer_uid, peer_gid, agent(), host()) {
        Ok(run) => {
            let mut events = peer_events(stream.try_clone()?);
            HelperReply::Exited {
                code: run_approved(&run, stdio, &mut events, agent(), host()),
            }
        }
        Err(reply) => reply,
    };
    send_reply(&mut stream, &outcome)
}

/// The production agent-transport singleton.
#[cfg(target_os = "linux")]
fn agent() -> &'static dyn AgentDecisions {
    &SocketAgent
}

/// The production host-transport singleton.
#[cfg(target_os = "linux")]
fn host() -> &'static dyn HostDecisions {
    &BrokerHost
}

#[cfg(target_os = "linux")]
struct SocketAgent;

#[cfg(target_os = "linux")]
impl SocketAgent {
    fn call(
        request: &crate::tool_map::DecisionRequest,
    ) -> Result<crate::tool_map::DecisionReply, HelperError> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr as UnixAddr, UnixStream};

        let address =
            UnixAddr::from_abstract_name(crate::tool_decision_socket::DECISION_SOCKET_NAME)
                .map_err(|error| HelperError::Unavailable(format!("decision address: {error}")))?;
        let mut stream = UnixStream::connect_addr(&address)
            .map_err(|error| HelperError::Unavailable(format!("decision socket: {error}")))?;
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        let mut line = serde_json::to_vec(request).map_err(|error| {
            HelperError::Unavailable(format!("encode decision request: {error}"))
        })?;
        line.push(b'\n');
        stream
            .write_all(&line)
            .map_err(|error| HelperError::Unavailable(format!("send decision request: {error}")))?;
        let mut reply = String::new();
        BufReader::new(std::io::Read::take(
            &mut stream,
            crate::tool_map::MAX_DECISION_FRAME_BYTES,
        ))
        .read_line(&mut reply)
        .map_err(|error| HelperError::Unavailable(format!("read decision reply: {error}")))?;
        serde_json::from_str(reply.trim_end())
            .map_err(|error| HelperError::Unavailable(format!("decode decision reply: {error}")))
    }
}

#[cfg(target_os = "linux")]
impl AgentDecisions for SocketAgent {
    fn decided(&self, pid: u32) -> Result<Option<Option<ToolInvocationBinding>>, HelperError> {
        match Self::call(&crate::tool_map::DecisionRequest::Decided { pid })? {
            crate::tool_map::DecisionReply::Decided { binding } => Ok(Some(binding)),
            crate::tool_map::DecisionReply::NotDecided => Ok(None),
            other => Err(HelperError::Unavailable(format!(
                "unexpected decision reply {other:?}"
            ))),
        }
    }

    fn record(&self, session: u32, binding: ToolInvocationBinding) {
        let _ = Self::call(&crate::tool_map::DecisionRequest::Record {
            session,
            binding: Some(binding),
        });
    }

    fn retire(&self, session: u32) {
        let _ = Self::call(&crate::tool_map::DecisionRequest::Retire { session });
    }
}

#[cfg(target_os = "linux")]
struct BrokerHost;

#[cfg(target_os = "linux")]
impl BrokerHost {
    /// One framed `host.tool.v1` call. Mirrors the host-local connector
    /// client's deadlines: the endpoint can hold an `ask` for its full
    /// approval timeout, so the read waits just past it.
    fn call(verb: &str, payload: serde_json::Value) -> Result<serde_json::Value, HelperError> {
        use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId};

        let service = ServiceId::parse(mvm_core::protocol::host_tool::HOST_TOOL_SERVICE)
            .map_err(|error| HelperError::Unavailable(format!("tool service id: {error}")))?;
        let mut stream = crate::vsock::connect_host_vsock(
            crate::vsock::BROKER_PORT,
            crate::vsock::TOOL_REQUEST_TIMEOUT_SECS,
        )
        .map_err(|error| HelperError::Unavailable(format!("broker: {error}")))?;
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(
            crate::vsock::TOOL_DECISION_TIMEOUT_SECS,
        )));
        let request = ServiceCall {
            service,
            verb: verb.into(),
            correlation_id: CorrelationId::new(format!("tool-helper-{}", std::process::id())),
            payload,
            capability: None,
        };
        crate::broker_client::call(&mut stream, &request).map_err(|error| match error {
            crate::broker_client::BrokerError::Service { message, .. } => {
                HelperError::Unavailable(format!("host tool decision: {message}"))
            }
            crate::broker_client::BrokerError::Transport(error) => {
                HelperError::Unavailable(format!("host tool transport: {error}"))
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl HostDecisions for BrokerHost {
    fn decide(&self, request: &ToolCheckRequest) -> Result<ToolDecisionReply, HelperError> {
        let payload = serde_json::to_value(request)
            .map_err(|error| HelperError::Unavailable(format!("encode tool question: {error}")))?;
        let reply = Self::call(mvm_core::protocol::host_tool::DECIDE_VERB, payload)?;
        serde_json::from_value(reply)
            .map_err(|error| HelperError::Unavailable(format!("decode tool decision: {error}")))
    }

    fn release(&self, binding: ToolInvocationBinding) {
        let payload = serde_json::to_value(
            mvm_contract::protocol::network_flow::attribution::ToolInvocationRelease {
                release: binding,
            },
        );
        if let Ok(payload) = payload {
            let _ = Self::call(mvm_core::protocol::host_tool::RELEASE_VERB, payload);
        }
    }
}
