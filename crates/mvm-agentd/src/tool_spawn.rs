//! Workload-origin declared-tool mediation: shim, helper, and their protocol.
//!
//! A declared tool's executable paths are shadowed at activation by the
//! `mvm-tool-shim` binary (see `guest_bootstrap::substitute_declared_tools`).
//! When any process — the workload's own spawn or an agent exec — runs a
//! declared path, the shim reports the exact invocation to the privileged
//! `mvm-tool-spawn` helper over an abstract socket and waits. The helper
//!
//! 1. proves *byte provenance*: the peer's `/proc/<pid>/exe` must be one of
//!    the signed, shim-installed declared paths, so a workload's own client
//!    code cannot talk the protocol into running a tool;
//! 2. asks the host through the authorized broker service `host.tool.v1`,
//!    which the admitted plan binds exactly when tools are declared. The
//!    per-VM decision gate applies the signed tool rules and records the
//!    outcome in the chain-signed audit log before answering;
//! 3. on an allow, moves the original aside: it executes the store copy (the
//!    only readable copy, in a directory only the helper can traverse) as the
//!    workload uid in the tool group, leading its own session, with the
//!    requester's stdio and working directory; a bound allow's session is
//!    registered with the agent's attribution table so its egress carries
//!    the invocation's binding;
//! 4. refuses everything else — deny, transport failure, timeout, malformed
//!    request — and the shim exits nonzero without ever running the tool.
//!
//! The shim is a PATH shadow, not the enforcement: the enforcement is that
//! the original binary lives only in the helper-readable store and the
//! helper spawns it only after a host decision. A workload that skips the
//! shim and execs the store path directly gets `EACCES`; one that speaks the
//! socket protocol without the shim's `/proc/<pid>/exe` is refused.

use std::io::{self, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use mvm_contract::protocol::host_tool::{DECIDE_VERB, HOST_TOOL_SERVICE, RELEASE_VERB};
use mvm_contract::protocol::network_flow::tool::{
    MAX_TOOL_ARGV_BYTES, ToolCheckRequest, ToolDecisionReply,
};
use serde::{Deserialize, Serialize};

use crate::guest_mount::{TOOL_GID, WORKLOAD_UID};
use crate::tool_attribution;

/// Everything the helper needs lives under this tmpfs directory, created by
/// root at activation. The directory is owned by the helper identity, mode
/// 0700, so only the helper can traverse into the store.
pub const SPAWN_DIR: &str = "/run/mvm/tool-spawn";
/// Root-written mapping from each signed declared path to its store copy.
pub const MANIFEST_PATH: &str = "/run/mvm/tool-spawn/manifest.json";
/// Directory holding the original tool binaries, moved aside at activation.
pub const STORE_DIR: &str = "/run/mvm/tool-spawn/store";
/// Abstract-namespace name of the helper's request socket.
pub const HELPER_SOCKET_NAME: &[u8] = b"mvm-tool-spawn";

/// Total environment bytes a request may carry.
pub const MAX_ENV_BYTES: usize = 256 * 1024;
/// stdin, stdout, stderr, and the working-directory fd.
pub const SPAWN_FDS: usize = 4;
/// The shim's exit code when the invocation is refused or mediation fails.
/// Distinct from 127 (not-found) and from a tool's own codes.
pub const MEDIATION_REFUSED_EXIT: i32 = 126;
/// How long the helper waits for the host's decision. The endpoint holds an
/// operator approval for at most 120 s; beyond this the helper denies.
pub const DECIDE_TIMEOUT: Duration = Duration::from_secs(130);

// ============================================================================
// Manifest
// ============================================================================

/// One declared tool's installed shadow: the signed path the shim was
/// installed at and the store file holding the original bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpawnEntry {
    /// Tool name the admitted plan binds the path to.
    pub tool: String,
    /// The declared executable path (where the shim is installed).
    pub path: String,
    /// File name of the original binary inside [`STORE_DIR`].
    pub store: String,
}

/// The root-written manifest the helper serves from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpawnManifest {
    pub tools: Vec<ToolSpawnEntry>,
}

impl ToolSpawnManifest {
    /// Load and validate the manifest. A missing or malformed manifest is a
    /// hard error: activation must have refused to run without a valid one,
    /// so a helper that sees anything else must not guess.
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let manifest: Self =
            serde_json::from_slice(&bytes).map_err(|error| invalid_data(error.to_string()))?;
        for entry in &manifest.tools {
            if entry.tool.is_empty()
                || entry.tool.contains('\0')
                || !mvm_contract::policy::tool_rules::normalized_executable_path(&entry.path)
                || entry.store.contains('/')
                || entry.store.is_empty()
                || entry.store.contains('\0')
            {
                return Err(invalid_data(format!(
                    "manifest entry for {} is not a normalized declared path",
                    entry.path
                )));
            }
        }
        Ok(manifest)
    }

    /// The entry whose signed path matches `path`, if any.
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<&ToolSpawnEntry> {
        self.tools.iter().find(|entry| entry.path == path)
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

// ============================================================================
// Shim <-> helper wire protocol
// ============================================================================

/// What the shim sends for one invocation. Carries four file descriptors
/// out-of-band (stdin, stdout, stderr, working directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnRequest {
    /// The shim's resolved executable path (one of the signed declared
    /// paths); the helper re-derives it from the peer's `/proc/<pid>/exe`
    /// and treats this field as advisory only.
    pub executable: String,
    /// The exact argv the requester executed with.
    pub argv: Vec<String>,
    /// The requester's full environment.
    pub env: Vec<String>,
}

impl SpawnRequest {
    /// Structural bounds before the helper acts on a request.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let argv_bytes = self.argv.iter().try_fold(0usize, |len, arg| {
            len.checked_add(arg.len())?.checked_add(1)
        });
        let env_bytes = self.env.iter().try_fold(0usize, |len, var| {
            len.checked_add(var.len())?.checked_add(1)
        });
        let Some(argv_bytes) = argv_bytes else {
            return false;
        };
        let Some(env_bytes) = env_bytes else {
            return false;
        };
        !self.argv.is_empty()
            && argv_bytes <= MAX_TOOL_ARGV_BYTES
            && env_bytes <= MAX_ENV_BYTES
            && self
                .argv
                .iter()
                .chain(self.env.iter())
                .all(|field| !field.contains('\0'))
    }
}

/// Messages the helper sends back, in order: exactly one of `denied` or
/// `running`, then `exit` once the tool has finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SpawnMessage {
    /// The host refused, or mediation itself failed. `reason` is a fixed
    /// safe string; it never contains command text.
    Denied { reason: String },
    /// The tool runs as `pid`; signals are forwarded to it.
    Running { pid: u32 },
    /// The tool finished with `code` (a wait status collapsed to 8 bits or
    /// 128 + signal).
    Exit { code: i32 },
}

// ============================================================================
// Framing + descriptor passing
// ============================================================================

fn write_frame(stream: &mut UnixStream, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|error| invalid_data(error.to_string()))?;
    if bytes.len() > MAX_TOOL_ARGV_BYTES + MAX_ENV_BYTES {
        return Err(invalid_data("frame exceeds the mediation size cap"));
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_TOOL_ARGV_BYTES + MAX_ENV_BYTES {
        return Err(invalid_data("frame exceeds the mediation size cap"));
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| invalid_data(error.to_string()))
}

/// Send the request with the four carry fds attached. One `sendmsg` with a
/// header carrying `SCM_CREDENTIALS` is unnecessary — the kernel fills
/// `SO_PEERCRED` on the receiving side — but the rights must travel with the
/// first byte of the frame.
fn send_request(stream: &UnixStream, request: &SpawnRequest, fds: &[OwnedFd]) -> io::Result<()> {
    let bytes = serde_json::to_vec(request).map_err(|error| invalid_data(error.to_string()))?;
    if bytes.len() > MAX_TOOL_ARGV_BYTES + MAX_ENV_BYTES {
        return Err(invalid_data("request exceeds the mediation size cap"));
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0u8; 128];
    // One cmsghdr carrying `fds.len()` raw fds. The length is computed by
    // hand (not libc::CMSG_LEN) because the cmsghdr layout differs between
    // glibc and musl targets; the wire shape is identical.
    let payload_len = fds.len() * std::mem::size_of::<i32>();
    let cmsg_len = std::mem::size_of::<libc::cmsghdr>() + payload_len;
    if cmsg_len > control.len() {
        return Err(invalid_data("fd payload too large for the control buffer"));
    }
    // SAFETY: an all-zero msghdr is a valid initial value; every pointer
    // field is assigned from live buffers below before the syscall.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = cmsg_len as _;
    // SAFETY: `header` points at `iov`/`control`, which outlive the call;
    // the control length was checked against the buffer; `fds` outlives the
    // call.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&header);
        if cmsg.is_null() {
            return Err(invalid_data("control buffer too small for a header"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len as _;
        let target = libc::CMSG_DATA(cmsg).cast::<i32>();
        for (index, fd) in fds.iter().enumerate() {
            std::ptr::write_unaligned(target.add(index), fd.as_raw_fd());
        }
        let sent = libc::sendmsg(stream.as_raw_fd(), &header, 0);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != bytes.len() {
            return Err(invalid_data("short send of the mediation request"));
        }
    }
    Ok(())
}

/// Receive the request frame and its attached fds, validating the count.
fn recv_request(stream: &UnixStream) -> io::Result<(SpawnRequest, Vec<OwnedFd>)> {
    let mut len = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: len.as_mut_ptr().cast(),
        iov_len: len.len(),
    };
    let mut control = [0u8; 128];
    // SAFETY: an all-zero msghdr is a valid initial value; the buffers
    // assigned here outlive the call. Received fds are owned into
    // `received` below, and the count is validated before use.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len() as _;
    // SAFETY: buffers outlive the call; the kernel writes at most
    // `control.len()` control bytes and one iov entry.
    let received = unsafe {
        let got = libc::recvmsg(stream.as_raw_fd(), &mut header, 0);
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        if got as usize != len.len() {
            return Err(invalid_data("short receive of the mediation request"));
        }
        let mut received = Vec::new();
        let mut cmsg = libc::CMSG_FIRSTHDR(&header);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let count = ((*cmsg).cmsg_len as usize - std::mem::size_of::<libc::cmsghdr>())
                    / std::mem::size_of::<i32>();
                let base = libc::CMSG_DATA(cmsg).cast::<i32>();
                for index in 0..count {
                    received.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                        base.add(index),
                    )));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&header, cmsg);
        }
        received
    };
    if received.len() != SPAWN_FDS {
        return Err(invalid_data(format!(
            "expected {SPAWN_FDS} carried fds, got {}",
            received.len()
        )));
    }
    // The frame body follows its 4-byte length prefix, which recvmsg
    // consumed as the iov. Read the rest of the frame from a clone so the
    // accepted socket keeps its original position state.
    let body_len = u32::from_le_bytes(len) as usize;
    if body_len > MAX_TOOL_ARGV_BYTES + MAX_ENV_BYTES {
        return Err(invalid_data("frame exceeds the mediation size cap"));
    }
    let mut body = vec![0u8; body_len];
    let mut reader = stream.try_clone()?;
    reader.read_exact(&mut body)?;
    let request: SpawnRequest =
        serde_json::from_slice(&body).map_err(|error| invalid_data(error.to_string()))?;
    Ok((request, received))
}

/// The peer's process credentials: the byte-provenance and identity check
/// the helper builds its decision on.
// allow(secret-debug): pid/uid/gid are kernel-attested identity facts, not
// secret material; logging them is the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a plain struct and `len` its size; getsockopt fills
    // both. SO_PEERCRED cannot be spoofed by the peer.
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
    Ok(PeerCredentials {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Resolve `/proc/<pid>/exe`, stripping the kernel's " (deleted)" suffix a
/// shadowed executable carries. Returns `None` when the link cannot be read
/// (the peer vanished) — the caller treats that as a refusal.
pub fn proc_exe(pid: i32) -> Option<String> {
    let link = format!("/proc/{pid}/exe");
    let target = std::fs::read_link(link).ok()?;
    let text = target.to_string_lossy();
    Some(
        text.strip_suffix(" (deleted)")
            .unwrap_or(text.as_ref())
            .to_string(),
    )
}

// ============================================================================
// Host decision through the authorized broker service
// ============================================================================

/// Ask the host to decide and audit this invocation. Every failure —
/// connect, framing, typed service error, malformed reply — is a denial,
/// so a caller can never mistake a transport failure for an approval.
pub fn decide(tool: &str, executable: &str, argv: &[String]) -> ToolDecisionReply {
    decide_inner(tool, executable, argv).unwrap_or(ToolDecisionReply::Deny)
}

fn decide_inner(tool: &str, executable: &str, argv: &[String]) -> Option<ToolDecisionReply> {
    let mut question = ToolCheckRequest::from_argv(tool.to_string(), argv)?;
    // The signed binding names the path the shim was installed at; the
    // argv[0] a requester chose cannot widen it.
    question.executable = Some(executable.to_string());
    if !question.is_valid() {
        return None;
    }
    let reply = broker_call(DECIDE_VERB, serde_json::to_value(&question).ok()?)?;
    serde_json::from_value(reply).ok()
}

/// Retire an invocation's binding after its command finished.
pub fn release(binding: &mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding) {
    if let Ok(payload) = serde_json::to_value(
        mvm_contract::protocol::network_flow::attribution::ToolInvocationRelease {
            release: binding.clone(),
        },
    ) {
        let _ = broker_call(RELEASE_VERB, payload);
    }
}

/// One `host.tool.v1` call with the decision deadline. Connect gets its own
/// short budget; the read may wait out the endpoint's operator-approval
/// window.
fn broker_call(verb: &str, payload: serde_json::Value) -> Option<serde_json::Value> {
    use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let call = ServiceCall {
        service: ServiceId::parse(HOST_TOOL_SERVICE).ok()?,
        verb: verb.to_string(),
        correlation_id: CorrelationId::new(format!(
            "tool-spawn-{}",
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )),
        payload,
        capability: None,
    };
    crate::broker_client::broker_call_bounded(&call, Duration::from_secs(10), DECIDE_TIMEOUT)
        .ok()
}

// ============================================================================
// Shim side (`mvm-tool-shim`)
// ============================================================================

/// Collect the requester's argv, refusing non-UTF-8 arguments: the host gate
/// decides on text, so a byte it cannot read is an invocation it cannot
/// vouch for.
fn collect_argv() -> io::Result<Vec<String>> {
    std::env::args_os()
        .map(|arg| {
            let bytes = arg.as_os_str().as_bytes();
            String::from_utf8(bytes.to_vec()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "argv is not valid UTF-8; the invocation cannot be mediated",
                )
            })
        })
        .collect()
}

fn collect_env() -> Vec<String> {
    std::env::vars_os()
        .map(|(key, value)| {
            let mut var = key.as_os_str().as_bytes().to_vec();
            var.push(b'=');
            var.extend_from_slice(value.as_os_str().as_bytes());
            String::from_utf8_lossy(&var).into_owned()
        })
        .collect()
}

/// Duplicate the stdio fds and open the working directory for the helper to
/// inherit into the tool.
fn carry_fds() -> io::Result<Vec<OwnedFd>> {
    let mut fds = Vec::with_capacity(SPAWN_FDS);
    for fd in [0, 1, 2] {
        // SAFETY: dup returns a new fd referring to the same open file
        // description; it is owned from here on.
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `dup` is a freshly owned fd.
        fds.push(unsafe { OwnedFd::from_raw_fd(dup) });
    }
    // SAFETY: open(".") on a directory returns an owned fd or -1.
    let cwd = unsafe { libc::open(c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if cwd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `cwd` is a freshly owned fd.
    fds.push(unsafe { OwnedFd::from_raw_fd(cwd) });
    Ok(fds)
}

fn helper_address() -> io::Result<SocketAddr> {
    SocketAddr::from_abstract_name(HELPER_SOCKET_NAME)
}

/// Entry point of `mvm-tool-shim`.
pub fn run_shim() -> i32 {
    match shim_inner() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("mvm-tool-shim: {error}");
            MEDIATION_REFUSED_EXIT
        }
    }
}

fn shim_inner() -> io::Result<i32> {
    let executable = proc_exe(std::process::id() as i32)
        .ok_or_else(|| invalid_data("cannot resolve the shim's own executable"))?;
    let argv = collect_argv()?;
    let env = collect_env();
    let request = SpawnRequest {
        executable,
        argv,
        env,
    };
    if !request.is_valid() {
        return Err(invalid_data("the invocation exceeds mediation bounds"));
    }
    let fds = carry_fds()?;
    let mut stream = UnixStream::connect_addr(&helper_address()?).map_err(|error| {
        io::Error::new(error.kind(), format!("tool mediation unavailable: {error}"))
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    send_request(&stream, &request, &fds)?;
    drop(fds);

    let reply: SpawnMessage = read_frame(&mut stream)?;
    let pid = match reply {
        SpawnMessage::Denied { reason } => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("declared tool invocation denied: {reason}"),
            ));
        }
        SpawnMessage::Running { pid } => pid,
        SpawnMessage::Exit { .. } => {
            return Err(invalid_data("helper sent an exit before a decision"));
        }
    };
    forward_signals(pid);
    let final_message: SpawnMessage = read_frame(&mut stream)?;
    match final_message {
        SpawnMessage::Exit { code } => Ok(code),
        _ => Err(invalid_data("helper sent an unexpected second message")),
    }
}

/// Signals a shell would forward to a foreground job. Each handler relays
/// to the tool (same uid, so the kernel allows it); signals the workload
/// sends the shim reach the tool. `KILL`/`STOP` cannot be caught and are
/// not relayed — the workload can always `kill -KILL` the shim itself,
/// after which the tool keeps running in its own session, same as any
/// orphaned process group.
fn forward_signals(pid: u32) {
    // Signals that arrive between handler installation and the pid publish
    // are recorded in a mask and drained below, so an early SIGTERM is not
    // silently lost.
    PENDING_SIGNALS.store(0, std::sync::atomic::Ordering::SeqCst);
    const FORWARDED: &[i32] = &[
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ];
    for signal in FORWARDED {
        // SAFETY: sigaction with a plain fn pointer; the handler only
        // records into `PENDING_SIGNALS` until the pid is published.
        unsafe {
            let action = libc::sigaction {
                sa_sigaction: record_pending as usize,
                sa_mask: std::mem::zeroed(),
                sa_flags: 0,
                sa_restorer: None,
            };
            libc::sigaction(*signal, &action, std::ptr::null_mut());
        }
    }
    TOOL_PID.store(pid as i32, std::sync::atomic::Ordering::SeqCst);
    let pending = PENDING_SIGNALS.swap(0, std::sync::atomic::Ordering::SeqCst);
    for (index, signal) in FORWARDED.iter().enumerate() {
        if pending & (1 << index) != 0 {
            relay(*signal);
        }
    }
}

static TOOL_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static PENDING_SIGNALS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn record_pending(signal: i32) {
    const FORWARDED: &[i32] = &[
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ];
    if let Some(index) = FORWARDED.iter().position(|forwarded| *forwarded == signal) {
        PENDING_SIGNALS.fetch_or(1 << index, std::sync::atomic::Ordering::SeqCst);
    }
    relay(signal);
}

fn relay(signal: i32) {
    let pid = TOOL_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: plain kill of a same-uid pid; nothing depends on the
        // result.
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

// ============================================================================
// Helper side (`mvm-tool-spawn`)
// ============================================================================

/// Entry point of `mvm-tool-spawn`. Loads the manifest, binds the abstract
/// socket, and mediates one invocation at a time forever. Any accept or
/// per-connection failure is logged and the loop continues; a missing or
/// invalid manifest is fatal because activation should have refused it.
pub fn run_helper() -> i32 {
    let manifest = match ToolSpawnManifest::load(Path::new(MANIFEST_PATH)) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("mvm-tool-spawn: no valid mediation manifest at {MANIFEST_PATH}: {error}");
            return 1;
        }
    };
    let listener = match bind_helper() {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("mvm-tool-spawn: cannot bind the mediation socket: {error}");
            return 1;
        }
    };
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_invocation(&stream, &manifest) {
                    eprintln!("mvm-tool-spawn: invocation failed closed: {error}");
                }
            }
            Err(error) => eprintln!("mvm-tool-spawn: accept failed: {error}"),
        }
    }
    0
}

fn bind_helper() -> io::Result<UnixListener> {
    UnixListener::bind_addr(&helper_address()?)
}

/// Mediate one accepted connection: prove provenance, ask the host, spawn
/// or deny, then report the outcome. Fails closed at every step.
pub fn handle_invocation(accepted: &UnixStream, manifest: &ToolSpawnManifest) -> io::Result<()> {
    let mut stream = accepted.try_clone()?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let (request, fds) = recv_request(accepted)?;
    if !request.is_valid() {
        return reply(
            &mut stream,
            SpawnMessage::Denied {
                reason: "invalid tool invocation".into(),
            },
        );
    }

    // Byte provenance: the peer must BE the shim installed at a signed
    // declared path. A workload client that connects with its own binary
    // fails this check no matter what it claims.
    let peer = peer_credentials(&stream)?;
    let Some(real_exe) = proc_exe(peer.pid) else {
        return reply(
            &mut stream,
            SpawnMessage::Denied {
                reason: "tool provenance unavailable".into(),
            },
        );
    };
    let Some(entry) = manifest.lookup(&real_exe) else {
        return reply(
            &mut stream,
            SpawnMessage::Denied {
                reason: "the executable is not a declared tool".into(),
            },
        );
    };

    let decision = decide(&entry.tool, &entry.path, &request.argv);
    let binding = match decision {
        ToolDecisionReply::Allow => None,
        ToolDecisionReply::AllowBound { binding } => Some(binding),
        ToolDecisionReply::Deny => {
            return reply(
                &mut stream,
                SpawnMessage::Denied {
                    reason: "declared tool invocation denied".into(),
                },
            );
        }
    };

    let child = spawn_store(entry, &request, fds)?;
    let pid = child.id();
    let start_ticks = tool_attribution::process_start_ticks_for(pid);
    if let (Some(binding), Some(start_ticks)) = (&binding, start_ticks) {
        tool_attribution::register_invocation(pid, start_ticks, binding);
    }
    reply(&mut stream, SpawnMessage::Running { pid })?;

    let status = wait_child(child);
    if let Some(binding) = &binding {
        tool_attribution::unregister_invocation(pid);
        release(binding);
    }
    reply(&mut stream, SpawnMessage::Exit { code: status })
}

fn reply(stream: &mut UnixStream, message: SpawnMessage) -> io::Result<()> {
    write_frame(stream, &message)
}

/// Spawn the store copy as the workload uid in the tool group, leading a
/// new session, with the requester's stdio, working directory, and
/// environment. Runs from the helper's identity: it holds exactly the
/// capabilities this transition needs (`CAP_SETGID`, `CAP_SETUID`,
/// `CAP_SETPCAP` for the bounding-set drop) and nothing else.
fn spawn_store(
    entry: &ToolSpawnEntry,
    request: &SpawnRequest,
    fds: Vec<OwnedFd>,
) -> io::Result<std::process::Child> {
    let store_path = Path::new(STORE_DIR).join(&entry.store);
    let mut fds = fds.into_iter();
    let stdin = fds.next().expect("validated fd count");
    let stdout = fds.next().expect("validated fd count");
    let stderr = fds.next().expect("validated fd count");
    let cwd = fds.next().expect("validated fd count");

    let mut command = Command::new(&store_path);
    if let Some(arg0) = request.argv.first() {
        // Keep the exact argv the host decided on.
        use std::os::unix::process::CommandExt;
        command.arg0(arg0);
    }
    command.args(request.argv.iter().skip(1));
    // The tool gets exactly the requester's environment — not the helper's.
    command.env_clear();
    for var in &request.env {
        let Some((key, value)) = var.split_once('=') else {
            continue;
        };
        command.env(key, value);
    }
    command
        .stdin(std::process::Stdio::from(stdin))
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr));

    // SAFETY: the hook runs between fork and exec and calls only
    // async-signal-safe id/mask transitions, ordered so the drop of the
    // bounding set precedes the uid change that would lose the privilege
    // to perform it.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            if libc::fchdir(cwd.as_raw_fd()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            drop_bounding_set()?;
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setresgid(TOOL_GID, TOOL_GID, TOOL_GID) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setresuid(WORKLOAD_UID, WORKLOAD_UID, WORKLOAD_UID) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// Drop every capability from the bounding set. The helper keeps
/// `CAP_SETPCAP` precisely so this succeeds; the later `setresuid` clears
/// the permitted/effective/inheritable sets, and the ambient set was never
/// populated for this identity.
fn drop_bounding_set() -> io::Result<()> {
    for capability in 0..=40 {
        // SAFETY: plain prctl with scalar args.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            // EINVAL means the kernel does not know this capability number;
            // every other errno is a real failure to narrow the set.
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Wait for the tool and collapse the wait status the way shells report
/// it: exit code as-is, signal death as 128 + signal.
fn wait_child(mut child: std::process::Child) -> i32 {
    match child.wait() {
        Ok(status) => {
            if let Some(code) = status.code() {
                code
            } else {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::process::ExitStatusExt;
                    128 + status.signal().unwrap_or(0)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    128
                }
            }
        }
        Err(_) => 1,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_load_validates_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "tools": [
                    {"tool": "python", "path": "/usr/local/bin/python3", "store": "python3"},
                ],
            })
            .to_string(),
        )
        .expect("write manifest");
        let manifest = ToolSpawnManifest::load(&path).expect("manifest loads");
        let entry = manifest.lookup("/usr/local/bin/python3").expect("lookup");
        assert_eq!(entry.tool, "python");
        assert_eq!(entry.store, "python3");
        assert!(manifest.lookup("/usr/local/bin/python3.12").is_none());

        std::fs::write(
            &path,
            serde_json::json!({
                "tools": [
                    {"tool": "python", "path": "relative/path", "store": "python3"},
                ],
            })
            .to_string(),
        )
        .expect("write bad manifest");
        assert!(ToolSpawnManifest::load(&path).is_err());
    }

    #[test]
    fn spawn_request_bounds_argv_and_env() {
        let valid = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec!["/bin/tool".into(), "-c".into()],
            env: vec!["A=1".into()],
        };
        assert!(valid.is_valid());

        let oversized = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec!["x".repeat(MAX_TOOL_ARGV_BYTES + 1)],
            env: vec![],
        };
        assert!(!oversized.is_valid());

        let nul = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec!["/bin/tool\0junk".into()],
            env: vec![],
        };
        assert!(!nul.is_valid());

        let no_argv = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec![],
            env: vec![],
        };
        assert!(!no_argv.is_valid());
    }

    #[test]
    fn spawn_message_roundtrips_with_a_status_tag() {
        for message in [
            SpawnMessage::Denied {
                reason: "declared tool invocation denied".into(),
            },
            SpawnMessage::Running { pid: 42 },
            SpawnMessage::Exit { code: 3 },
        ] {
            let json = serde_json::to_vec(&message).expect("serialize");
            let round: SpawnMessage = serde_json::from_slice(&json).expect("deserialize");
            assert_eq!(round, message);
        }
        assert!(serde_json::from_slice::<SpawnMessage>(b"{\"status\":\"mint\"}").is_err());
    }

    #[test]
    fn request_frames_survive_a_socket_pair() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let request = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec!["/bin/tool".into(), "arg with spaces".into()],
            env: vec!["KEY=value".into()],
        };
        write_frame(&mut client, &request).expect("write frame");
        let round: SpawnRequest = read_frame(&mut server).expect("read frame");
        assert_eq!(round, request);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn requests_carry_the_stdio_and_cwd_fds() {
        let (client, server) = UnixStream::pair().expect("socket pair");
        let request = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec!["/bin/tool".into()],
            env: vec![],
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let cwd = std::fs::File::open(dir.path()).expect("open cwd");
        let fds: Vec<OwnedFd> = vec![
            // SAFETY: dup of a live fd; each dup is owned.
            unsafe { OwnedFd::from_raw_fd(libc::dup(0)) },
            unsafe { OwnedFd::from_raw_fd(libc::dup(1)) },
            unsafe { OwnedFd::from_raw_fd(libc::dup(2)) },
            cwd.into(),
        ];
        send_request(&client, &request, &fds).expect("send request");
        drop(client);
        let (round, received) = recv_request(&server).expect("receive request");
        assert_eq!(round, request);
        assert_eq!(received.len(), SPAWN_FDS);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wrong_fd_count_is_refused() {
        let (client, server) = UnixStream::pair().expect("socket pair");
        let request = SpawnRequest {
            executable: "/bin/tool".into(),
            argv: vec!["/bin/tool".into()],
            env: vec![],
        };
        let fds: Vec<OwnedFd> = vec![
            // SAFETY: dup of a live fd; each dup is owned.
            unsafe { OwnedFd::from_raw_fd(libc::dup(0)) },
        ];
        send_request(&client, &request, &fds).expect("send request");
        drop(client);
        assert!(recv_request(&server).is_err());
    }

    #[test]
    fn peer_credentials_report_the_socket_pair() {
        let (client, server) = UnixStream::pair().expect("socket pair");
        let _ = client;
        let creds = peer_credentials(&server).expect("peer credentials");
        assert!(creds.pid > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_exe_resolves_this_test_binary() {
        let path = proc_exe(std::process::id() as i32).expect("own exe");
        assert!(path.starts_with('/'), "absolute path: {path}");
        assert!(!path.contains(" (deleted)"), "suffix stripped: {path}");
    }

    #[test]
    fn wait_status_collapses_to_shell_codes() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 7")
            .spawn()
            .expect("spawn sh");
        assert_eq!(wait_child(child), 7);

        child = Command::new("/bin/sh")
            .arg("-c")
            .arg("kill -TERM $$")
            .spawn()
            .expect("spawn sh");
        #[cfg(target_os = "linux")]
        assert_eq!(wait_child(child), 128 + libc::SIGTERM);
    }

    #[test]
    fn collect_env_keeps_key_value_shape() {
        // SAFETY: setenv with static strings.
        unsafe {
            libc::setenv(c"MVM_TOOL_SPAWN_TEST".as_ptr(), c"present".as_ptr(), 1);
        }
        let env = collect_env();
        assert!(env.contains(&"MVM_TOOL_SPAWN_TEST=present".to_string()));
    }
}
