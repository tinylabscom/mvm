//! Attribute loopback egress connections to a host-admitted tool invocation.
//!
//! When the host admits a declared command whose tool owns routes or secrets,
//! its decision carries a binding. The agent starts that command as the leader
//! of a new session, in [`crate::guest_mount::TOOL_GID`], and records the
//! session under the binding for as long as the leader runs. A process outside
//! the session cannot join it — `setsid` only ever creates a session, and
//! `setpgid` cannot cross one — and the session id cannot be reused while any
//! member is alive.
//!
//! The egress client asks, for each loopback connection it accepts, which
//! binding the connection belongs to. The agent finds the client socket in
//! `/proc/net/tcp{,6}`, every process holding it through `/proc/<pid>/fd`, and
//! answers with the binding only when every holder is in one recorded session
//! whose leader is still the process that was recorded. Anything else — a
//! socket nobody is found holding, holders in different sessions, a leader
//! that has exited — answers no binding, and the endpoint treats the flow as
//! belonging to no tool.
//!
//! What this holds against a workload process outside the session, which
//! runs as the same uid:
//!
//! - It cannot open a connection that is attributed: the holders of its
//!   socket are not in the session.
//! - It cannot take over a session member. The tool group differs from the
//!   workload's, and the kernel's ptrace access check compares gids, so
//!   `ptrace`, `process_vm_readv`/`process_vm_writev`, `/proc/<pid>/mem` and
//!   `pidfd_getfd` against a member are refused. Seccomp is not what refuses
//!   them: the agent applies no filter to the processes it spawns, and
//!   `/proc/<pid>/mem` is not a syscall a filter could name. Yama is not in
//!   the guest kernel.
//!
//! What it does not hold, because the tool still shares the workload's uid:
//!
//! - Files. The tool reads the workload's home, working directory and any
//!   workload-writable path, so a tool whose binary, libraries or
//!   configuration live somewhere the workload can write runs what the
//!   workload put there, with the tool's routes and secrets. A tool must be a
//!   program from the read-only image whose behaviour such files cannot
//!   redirect.
//! - Signals. The workload can stop or kill a tool invocation.
//!
//! A separate tool uid would close both, and is not done.
//!
//! The question travels over an abstract-namespace socket the agent binds as
//! PID 1 before any workload runs. The egress client accepts an answer only
//! from a listener PID 1 created, and the agent answers only the dedicated
//! egress service identity (`EGRESS_CLIENT_IDENTITY`, uid/gid 989). Root, the
//! workload and unrelated identities are refused. A guest booted by another
//! init has no such listener, so its flows are never attributed and tool routes
//! and secrets stay refused. The agent answers one question at a time, with a
//! two-second deadline on each side, so a flood of proxy connections can delay
//! attribution; a delayed answer is no answer, which refuses.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard};

use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;
use serde::{Deserialize, Serialize};

/// Abstract-namespace name of the agent's attribution listener.
pub const ATTRIBUTION_SOCKET_NAME: &[u8] = b"mvm-tool-attribution";
/// Largest request or answer line either side reads.
const MAX_LINE_BYTES: u64 = 512;

/// One admitted invocation whose session's flows carry its binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveInvocation {
    /// The session the command leads; equal to the leader's pid.
    session: u32,
    /// The leader's start time in clock ticks since boot, so a reused pid is
    /// never mistaken for the leader.
    start_ticks: u64,
    binding: ToolInvocationBinding,
}

static LIVE: Mutex<Vec<LiveInvocation>> = Mutex::new(Vec::new());

fn live() -> MutexGuard<'static, Vec<LiveInvocation>> {
    LIVE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Keeps one invocation's session attributed. Dropped when its command has
/// been waited for, which ends the attribution.
#[derive(Debug)]
pub struct Registration {
    session: u32,
}

impl Drop for Registration {
    fn drop(&mut self) {
        live().retain(|entry| entry.session != self.session);
    }
}

/// Spawn `command` as the leader of a new session and record that session
/// under `binding`.
///
/// The registry stays locked across the spawn, so a question about a
/// connection the new command makes waits until its session is recorded
/// rather than racing it.
///
/// The command runs in [`crate::guest_mount::TOOL_GID`], which the agent holds
/// as its saved gid. An agent that does not hold it cannot start the command,
/// so a bound invocation never runs where the workload could reach into it.
pub fn spawn_attributed(
    command: &mut Command,
    binding: &ToolInvocationBinding,
) -> io::Result<(Child, Registration)> {
    spawn_attributed_in_group(command, binding, crate::guest_mount::TOOL_GID)
}

fn spawn_attributed_in_group(
    command: &mut Command,
    binding: &ToolInvocationBinding,
    gid: u32,
) -> io::Result<(Child, Registration)> {
    use std::os::unix::process::CommandExt;
    // SAFETY: the hook runs in the forked child before exec and calls only
    // `setsid` and a gid change, which are async-signal-safe and allocate
    // nothing.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            assume_group(gid)
        });
    }
    let mut live = live();
    let child = command.spawn()?;
    let session = child.id();
    // A leader whose start time cannot be read has already exited and been
    // reaped; it is left unrecorded, so nothing it left behind is attributed.
    match process_start_ticks(session) {
        Ok(start_ticks) => live.push(LiveInvocation {
            session,
            start_ticks,
            binding: binding.clone(),
        }),
        Err(error) => {
            eprintln!("mvm-guest-agent: tool invocation left unattributed: {error}");
        }
    }
    Ok((child, Registration { session }))
}

/// Make `gid` the real, effective and saved group id. Unprivileged, this
/// succeeds only for a gid the process already holds in one of the three.
#[cfg(target_os = "linux")]
fn assume_group(gid: u32) -> io::Result<()> {
    // SAFETY: plain id values; no pointer contract.
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Host test builds have no `setresgid`; `setgid` is the same check for a
/// process that is not root.
#[cfg(not(target_os = "linux"))]
fn assume_group(gid: u32) -> io::Result<()> {
    // SAFETY: a plain id value; no pointer contract.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The leader's start time, read from `/proc`. A host test build has no
/// `/proc`; there the value is never compared.
fn process_start_ticks(pid: u32) -> io::Result<u64> {
    if !cfg!(target_os = "linux") {
        return Ok(0);
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat(&stat)
        .map(|fields| fields.start_ticks)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable /proc stat"))
}

/// The fields of `/proc/<pid>/stat` attribution needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatFields {
    session: u32,
    start_ticks: u64,
}

/// Parse `/proc/<pid>/stat`. The command name is parenthesised and may hold
/// spaces or parentheses, so fields are counted from the last `)`.
fn parse_stat(text: &str) -> Option<StatFields> {
    let after_name = &text[text.rfind(')')? + 1..];
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // After the name: state(3) ppid(4) pgrp(5) session(6) ... starttime(22).
    Some(StatFields {
        session: fields.get(3)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
    })
}

/// Parse a `/proc/net/tcp{,6}` address: hex words in host byte order, then a
/// big-endian hex port.
fn parse_proc_addr(text: &str) -> Option<SocketAddr> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(addr, 16).ok()?.to_le_bytes(),
        )),
        32 => {
            let octets: Vec<u8> = (0..4)
                .map(|word| {
                    let hex = addr.get(word * 8..word * 8 + 8)?;
                    u32::from_str_radix(hex, 16).ok()
                })
                .collect::<Option<Vec<u32>>>()?
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).ok()?))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Whether `found` is `wanted`, counting an IPv4-mapped IPv6 address as the
/// IPv4 address it maps.
fn same_endpoint(found: SocketAddr, wanted: SocketAddr) -> bool {
    let canonical = |addr: SocketAddr| match addr.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), addr.port())),
        IpAddr::V4(_) => addr,
    };
    canonical(found) == canonical(wanted)
}

/// Find the inode of the socket whose local end is `client` and whose remote
/// end is `server`, in one `/proc/net/tcp{,6}` table.
fn find_socket_inode(table: &str, client: SocketAddr, server: SocketAddr) -> Option<u64> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let local = parse_proc_addr(fields.get(1)?)?;
        let remote = parse_proc_addr(fields.get(2)?)?;
        (same_endpoint(local, client) && same_endpoint(remote, server))
            .then(|| fields.get(9)?.parse().ok())
            .flatten()
            .filter(|inode| *inode != 0)
    })
}

/// What attribution reads from the process table. A trait so the decision is
/// testable without a guest.
trait ProcSource {
    /// `/proc/net/tcp` or `/proc/net/tcp6`.
    fn tcp_table(&self, v6: bool) -> Option<String>;
    /// Every pid in the process table.
    fn pids(&self) -> Vec<u32>;
    /// Every `/proc/<pid>/fd/*` link target the reader may see.
    fn fd_targets(&self, pid: u32) -> Vec<String>;
    /// `/proc/<pid>/stat`.
    fn stat(&self, pid: u32) -> Option<String>;
}

/// The binding a connection from `client` to `server` belongs to, if any.
fn attribute_with(
    source: &dyn ProcSource,
    live: &[LiveInvocation],
    client: SocketAddr,
    server: SocketAddr,
) -> Option<ToolInvocationBinding> {
    if live.is_empty() {
        return None;
    }
    let inode = [false, true].into_iter().find_map(|v6| {
        source
            .tcp_table(v6)
            .and_then(|table| find_socket_inode(&table, client, server))
    })?;
    let target = format!("socket:[{inode}]");
    let holders: Vec<u32> = source
        .pids()
        .into_iter()
        .filter(|pid| source.fd_targets(*pid).contains(&target))
        .collect();
    let mut sessions = holders.iter().map(|pid| {
        source
            .stat(*pid)
            .as_deref()
            .and_then(parse_stat)
            .map(|fields| fields.session)
    });
    let session = sessions.next()??;
    if !sessions.all(|other| other == Some(session)) {
        return None;
    }
    let invocation = live.iter().find(|entry| entry.session == session)?;
    let leader = source.stat(session).as_deref().and_then(parse_stat)?;
    (leader.session == session && leader.start_ticks == invocation.start_ticks)
        .then(|| invocation.binding.clone())
}

/// The real process table.
#[cfg(target_os = "linux")]
struct Procfs;

#[cfg(target_os = "linux")]
impl ProcSource for Procfs {
    fn tcp_table(&self, v6: bool) -> Option<String> {
        std::fs::read_to_string(if v6 {
            "/proc/net/tcp6"
        } else {
            "/proc/net/tcp"
        })
        .ok()
    }

    fn pids(&self) -> Vec<u32> {
        std::fs::read_dir("/proc")
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn fd_targets(&self, pid: u32) -> Vec<String> {
        // A tool invocation's descriptors are readable only with the tool
        // group's credentials; a workload process's only without them. The
        // agent holds the tool group as its saved gid, so this thread takes it
        // as its filesystem gid for the second look and gives it back.
        let found = read_fd_targets(pid);
        if !found.is_empty() {
            return found;
        }
        with_filesystem_gid(crate::guest_mount::TOOL_GID, || read_fd_targets(pid))
    }

    fn stat(&self, pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
    }
}

/// Every `/proc/<pid>/fd/*` link target this thread may read.
#[cfg(target_os = "linux")]
fn read_fd_targets(pid: u32) -> Vec<String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .filter_map(|target| target.to_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Run `read` with `gid` as this thread's filesystem gid, then restore it.
/// The filesystem gid is per thread, and the attribution listener answers on
/// a thread of its own.
#[cfg(target_os = "linux")]
fn with_filesystem_gid<T>(gid: u32, read: impl FnOnce() -> T) -> T {
    // SAFETY: plain id values; `setfsgid` returns the previous value.
    let previous = unsafe { libc::setfsgid(gid) };
    let result = read();
    // SAFETY: as above, restoring the value just returned.
    unsafe { libc::setfsgid(previous as libc::gid_t) };
    result
}

/// One question from the egress client: the accepted connection's ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttributionQuery {
    /// The connecting client's address — the proxy's peer.
    client: SocketAddr,
    /// The proxy's own listening address.
    server: SocketAddr,
}

/// The agent's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttributionAnswer {
    binding: Option<ToolInvocationBinding>,
}

/// Read one bounded JSON line.
fn read_line<T: for<'de> Deserialize<'de>>(stream: &mut impl io::Read) -> io::Result<T> {
    let mut line = String::new();
    BufReader::new(io::Read::take(stream, MAX_LINE_BYTES)).read_line(&mut line)?;
    serde_json::from_str(line.trim_end()).map_err(io::Error::other)
}

/// Write one JSON line.
fn write_line<T: Serialize>(stream: &mut impl Write, value: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)
}

/// Answer one question on an accepted connection.
fn answer(stream: &mut (impl io::Read + Write), source: &dyn ProcSource) -> io::Result<()> {
    let query: AttributionQuery = read_line(stream)?;
    let binding = attribute_with(source, &live(), query.client, query.server);
    write_line(stream, &AttributionAnswer { binding })
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener, UnixStream};

    use std::time::Duration;

    use super::*;
    use crate::guest_mount::EGRESS_CLIENT_IDENTITY;

    /// How long either side waits on the other before answering "no binding".
    const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
    /// The process that must have created the listener the egress client asks.
    const ANSWER_PID: i32 = 1;

    fn peer_credentials(stream: &UnixStream) -> io::Result<libc::ucred> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a correctly sized `ucred` and `len` holds its
        // size; the kernel writes at most that many bytes.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc == 0 {
            Ok(cred)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn address() -> io::Result<UnixAddr> {
        UnixAddr::from_abstract_name(ATTRIBUTION_SOCKET_NAME)
    }

    /// Bind the attribution listener. Called by PID 1 before any workload
    /// runs, so no workload can hold the name first.
    pub fn bind_listener() -> io::Result<UnixListener> {
        UnixListener::bind_addr(&address()?)
    }

    pub(super) fn serve_connection(mut stream: UnixStream, source: &dyn ProcSource) {
        if !peer_credentials(&stream).is_ok_and(|cred| {
            cred.uid == EGRESS_CLIENT_IDENTITY.uid() && cred.gid == EGRESS_CLIENT_IDENTITY.gid()
        }) {
            return;
        }
        let _ = stream.set_read_timeout(Some(QUERY_TIMEOUT));
        let _ = stream.set_write_timeout(Some(QUERY_TIMEOUT));
        if let Err(error) = answer(&mut stream, source) {
            eprintln!("mvm-guest-agent: tool attribution question failed: {error}");
        }
    }

    /// Answer questions for the life of the agent. Only the dedicated egress
    /// client identity is answered.
    pub fn serve(listener: UnixListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            serve_connection(stream, &Procfs);
        }
    }

    pub(super) fn query_from(
        client: SocketAddr,
        server: SocketAddr,
        answer_pid: i32,
    ) -> Option<ToolInvocationBinding> {
        let mut stream = UnixStream::connect_addr(&address().ok()?).ok()?;
        if peer_credentials(&stream).ok()?.pid != answer_pid {
            return None;
        }
        stream.set_read_timeout(Some(QUERY_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(QUERY_TIMEOUT)).ok()?;
        write_line(&mut stream, &AttributionQuery { client, server }).ok()?;
        read_line::<AttributionAnswer>(&mut stream).ok()?.binding
    }

    /// Ask the agent which binding a connection belongs to. Any failure,
    /// and any listener PID 1 did not create, answers none.
    pub fn query(client: SocketAddr, server: SocketAddr) -> Option<ToolInvocationBinding> {
        query_from(client, server, ANSWER_PID)
    }
}

#[cfg(target_os = "linux")]
pub use linux::{bind_listener, query, serve};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const CLIENT: &str = "127.0.0.1:40000";
    const SERVER: &str = "127.0.0.1:1080";

    fn binding() -> ToolInvocationBinding {
        ToolInvocationBinding::from_random([0x5a; 16])
    }

    fn stat(pid: u32, session: u32, start: u64) -> String {
        format!(
            "{pid} (tool (x) y) S 1 {pid} {session} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0"
        )
    }

    /// `127.0.0.1:40000 -> 127.0.0.1:1080`, inode 777.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:9C40 0100007F:0438 01 00000000:00000000 00:00000000 00000000   901        0 777 1 0000000000000000 20 4 30 10 -1\n";

    #[derive(Default)]
    struct FakeProc {
        tcp: Option<String>,
        tcp6: Option<String>,
        fds: BTreeMap<u32, Vec<String>>,
        stats: BTreeMap<u32, String>,
    }

    impl ProcSource for FakeProc {
        fn tcp_table(&self, v6: bool) -> Option<String> {
            if v6 {
                self.tcp6.clone()
            } else {
                self.tcp.clone()
            }
        }
        fn pids(&self) -> Vec<u32> {
            self.stats.keys().copied().collect()
        }
        fn fd_targets(&self, pid: u32) -> Vec<String> {
            self.fds.get(&pid).cloned().unwrap_or_default()
        }
        fn stat(&self, pid: u32) -> Option<String> {
            self.stats.get(&pid).cloned()
        }
    }

    /// Leader 100 (session 100, started at tick 5000) and its child 101 hold
    /// the client socket; 200 is an unrelated workload process.
    fn proc_with_holders(holders: &[u32]) -> FakeProc {
        let mut proc = FakeProc {
            tcp: Some(TCP.to_string()),
            ..FakeProc::default()
        };
        proc.stats.insert(100, stat(100, 100, 5000));
        proc.stats.insert(101, stat(101, 100, 5001));
        proc.stats.insert(200, stat(200, 7, 4000));
        for pid in holders {
            proc.fds
                .insert(*pid, vec!["pipe:[1]".into(), "socket:[777]".into()]);
        }
        proc
    }

    fn live_session(start_ticks: u64) -> Vec<LiveInvocation> {
        vec![LiveInvocation {
            session: 100,
            start_ticks,
            binding: binding(),
        }]
    }

    fn ask(proc: &FakeProc, live: &[LiveInvocation]) -> Option<ToolInvocationBinding> {
        attribute_with(
            proc,
            live,
            CLIENT.parse().expect("client"),
            SERVER.parse().expect("server"),
        )
    }

    #[test]
    fn stat_fields_are_counted_from_the_last_parenthesis() {
        assert_eq!(
            parse_stat(&stat(42, 40, 123456)),
            Some(StatFields {
                session: 40,
                start_ticks: 123456
            })
        );
        assert_eq!(parse_stat("42 (truncated"), None);
    }

    #[test]
    fn proc_addresses_decode_both_families() {
        assert_eq!(
            parse_proc_addr("0100007F:0438"),
            Some("127.0.0.1:1080".parse().expect("v4"))
        );
        assert_eq!(
            parse_proc_addr("0000000000000000FFFF00000100007F:0438"),
            Some("[::ffff:127.0.0.1]:1080".parse().expect("mapped"))
        );
        assert_eq!(parse_proc_addr("zz:0438"), None);
        assert!(same_endpoint(
            "[::ffff:127.0.0.1]:1080".parse().expect("mapped"),
            SERVER.parse().expect("server")
        ));
    }

    #[test]
    fn a_connection_held_only_by_the_session_carries_its_binding() {
        assert_eq!(
            ask(&proc_with_holders(&[100, 101]), &live_session(5000)),
            Some(binding())
        );
        assert_eq!(
            ask(&proc_with_holders(&[101]), &live_session(5000)),
            Some(binding())
        );
    }

    #[test]
    fn a_connection_from_outside_the_session_carries_none() {
        assert_eq!(ask(&proc_with_holders(&[200]), &live_session(5000)), None);
    }

    #[test]
    fn a_socket_shared_with_a_process_outside_the_session_carries_none() {
        assert_eq!(
            ask(&proc_with_holders(&[101, 200]), &live_session(5000)),
            None
        );
    }

    #[test]
    fn a_reused_leader_pid_carries_none() {
        assert_eq!(ask(&proc_with_holders(&[100]), &live_session(4999)), None);
    }

    #[test]
    fn nothing_is_attributed_without_a_live_invocation_or_a_holder() {
        assert_eq!(ask(&proc_with_holders(&[100]), &[]), None);
        assert_eq!(ask(&proc_with_holders(&[]), &live_session(5000)), None);
        let mut unknown_socket = proc_with_holders(&[100]);
        unknown_socket.tcp = Some(TCP.replace("9C40", "9C41"));
        assert_eq!(ask(&unknown_socket, &live_session(5000)), None);
    }

    #[test]
    fn a_dual_stack_client_is_found_in_the_ipv6_table() {
        let mut proc = proc_with_holders(&[101]);
        proc.tcp = None;
        proc.tcp6 = Some(TCP.replace(
            "0100007F:9C40 0100007F:0438",
            "0000000000000000FFFF00000100007F:9C40 0000000000000000FFFF00000100007F:0438",
        ));
        assert_eq!(ask(&proc, &live_session(5000)), Some(binding()));
    }

    #[test]
    fn the_wire_answers_one_question_per_connection() {
        let (mut agent, mut client) = std::os::unix::net::UnixStream::pair().expect("pair");
        write_line(
            &mut client,
            &AttributionQuery {
                client: CLIENT.parse().expect("client"),
                server: SERVER.parse().expect("server"),
            },
        )
        .expect("ask");
        answer(&mut agent, &FakeProc::default()).expect("answer");
        let reply: AttributionAnswer = read_line(&mut client).expect("reply");
        assert_eq!(reply, AttributionAnswer { binding: None });
        assert!(
            serde_json::from_str::<AttributionQuery>(
                r#"{"client":"127.0.0.1:1","server":"127.0.0.1:2","extra":1}"#
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_the_egress_service_identity_is_authorized_to_query() {
        assert_ne!(crate::guest_mount::EGRESS_CLIENT_IDENTITY.uid(), 0);
        assert_ne!(
            crate::guest_mount::EGRESS_CLIENT_IDENTITY.uid(),
            crate::guest_mount::WORKLOAD_UID
        );
    }

    /// Real `SO_PEERCRED` witness for the production listener and query paths.
    ///
    /// The parent owns a live TCP connection attributed to an admitted
    /// invocation. Each child runs the actual query client with a different
    /// kernel identity. Only the dedicated egress service uid receives the
    /// binding; root, the workload, and an unrelated guest uid are disconnected.
    #[cfg(target_os = "linux")]
    #[test]
    fn egress_identity_alone_receives_live_attribution_over_unix_credentials() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;

        const ROLE: &str = "MVM_ATTRIBUTION_CREDENTIAL_WITNESS";
        if let Ok(expected) = std::env::var(ROLE) {
            let client: SocketAddr = std::env::var("MVM_ATTRIBUTION_CLIENT")
                .expect("client address")
                .parse()
                .expect("valid client address");
            let server: SocketAddr = std::env::var("MVM_ATTRIBUTION_SERVER")
                .expect("server address")
                .parse()
                .expect("valid server address");
            let answer_pid = std::env::var("MVM_ATTRIBUTION_ANSWER_PID")
                .expect("answer pid")
                .parse()
                .expect("valid answer pid");
            let got = linux::query_from(client, server, answer_pid);
            let wanted = (expected == "allowed").then(binding);
            assert_eq!(got, wanted);
            return;
        }

        let requested = std::env::var("MVM_GUEST_PRIVILEGED_TESTS").ok();
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        match (requested.as_deref(), euid) {
            (Some("1"), 0) => {}
            (Some("1"), uid) => {
                panic!("MVM_GUEST_PRIVILEGED_TESTS=1 is set but this test runs as euid {uid}")
            }
            _ => return,
        }

        let listener = linux::bind_listener().expect("bind attribution listener");
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TCP server");
        let server = tcp_listener.local_addr().expect("server address");
        let tcp_client = std::net::TcpStream::connect(server).expect("connect TCP client");
        let client = tcp_client.local_addr().expect("client address");
        let (_accepted, _) = tcp_listener.accept().expect("accept TCP client");

        let admitted = binding();
        let stat = fs::read_to_string("/proc/self/stat").expect("read parent stat");
        let fields = parse_stat(&stat).expect("parse parent stat");
        let session_start_ticks =
            process_start_ticks(fields.session).expect("read session leader start ticks");
        let _registration = {
            let mut entries = live();
            entries.push(LiveInvocation {
                session: fields.session,
                start_ticks: session_start_ticks,
                binding: admitted.clone(),
            });
            Registration {
                session: fields.session,
            }
        };

        let fixture = tempfile::Builder::new()
            .prefix("mvm-attribution-witness-")
            .tempdir_in("/tmp")
            .expect("create executable fixture directory");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o755))
            .expect("make fixture directory traversable");
        let executable = fixture.path().join("witness");
        fs::copy(
            std::env::current_exe().expect("current test binary"),
            &executable,
        )
        .expect("copy test binary");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("make test binary executable");

        let egress = crate::guest_mount::EGRESS_CLIENT_IDENTITY;
        let cases = [
            ("allowed", egress.uid(), egress.gid()),
            ("refused-root", 0, 0),
            (
                "refused-workload",
                crate::guest_mount::WORKLOAD_UID,
                crate::guest_mount::WORKLOAD_GID,
            ),
            ("refused-wrong-group", egress.uid(), 990),
            ("refused-unrelated", 990, 990),
        ];
        for (expected, uid, gid) in cases {
            let mut command = Command::new(&executable);
            command
                .args([
                    "--exact",
                    "tool_attribution::tests::egress_identity_alone_receives_live_attribution_over_unix_credentials",
                    "--nocapture",
                ])
                .env(ROLE, expected)
                .env("MVM_ATTRIBUTION_CLIENT", client.to_string())
                .env("MVM_ATTRIBUTION_SERVER", server.to_string())
                .env(
                    "MVM_ATTRIBUTION_ANSWER_PID",
                    std::process::id().to_string(),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if uid != 0 {
                // SAFETY: this hook runs after fork and before exec. The libc
                // calls are async-signal-safe and use plain integer arguments.
                unsafe {
                    command.pre_exec(move || {
                        if libc::setgroups(0, std::ptr::null()) != 0
                            || libc::setresgid(gid, gid, gid) != 0
                            || libc::setresuid(uid, uid, uid) != 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            let child = command.spawn().expect("spawn credential witness");
            let (stream, _) = listener.accept().expect("accept attribution query");
            linux::serve_connection(stream, &Procfs);
            let output = child
                .wait_with_output()
                .expect("wait for credential witness");
            assert!(
                output.status.success(),
                "{expected} child failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_agent_without_the_tool_group_cannot_start_a_bound_command() {
        // SAFETY: getuid and getegid have no precondition.
        let (uid, egid) = unsafe { (libc::getuid(), libc::getegid()) };
        if uid == 0 || egid == crate::guest_mount::TOOL_GID {
            return;
        }
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let refused = ToolInvocationBinding::from_random([0x77; 16]);
        assert!(spawn_attributed(&mut command, &refused).is_err());
        assert!(live().iter().all(|entry| entry.binding != refused));
    }

    #[cfg(unix)]
    #[test]
    fn an_attributed_command_leads_its_own_session_until_it_is_waited_for() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        // SAFETY: getegid has no precondition.
        let own_group = unsafe { libc::getegid() };
        let (mut child, registration) =
            spawn_attributed_in_group(&mut command, &binding(), own_group)
                .expect("spawn attributed");
        let pid = child.id();
        assert!(
            live()
                .iter()
                .any(|entry| entry.session == pid && entry.binding == binding())
        );
        crate::child_wait::wait(&mut child).expect("wait");
        drop(registration);
        assert!(!live().iter().any(|entry| entry.session == pid));
    }
}
