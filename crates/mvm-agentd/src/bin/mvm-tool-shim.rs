//! In-guest client mounted over every declared tool's executable path.
//!
//! The workload never reaches the tool's bytes: any runnable path to them was
//! substituted with this client at activation. It reports its own executable
//! path (the one the kernel used), the exact argv, the working directory and
//! the environment to the tool helper over a guest-local socket, hands over
//! its stdio descriptors, forwards the signals it receives so interactive
//! tools keep their semantics, and exits with the tool's status. It holds no
//! privilege and makes no policy decision: every refusal comes from the
//! helper, which asks the host before any mediated spawn.

use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
use mvm_agentd::tool_map::HELPER_SOCKET;
#[cfg(target_os = "linux")]
use mvm_agentd::tool_map::ShimRequest;
use mvm_agentd::tool_map::{EXIT_DENIED, EXIT_UNAVAILABLE, HelperReply, MAX_SHIM_FRAME_BYTES};

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("mvm-tool-shim: {message}");
            EXIT_UNAVAILABLE
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    let request = shim_request()?;
    let mut stream = connect()?;
    #[cfg(target_os = "linux")]
    send_request(&mut stream, &request)?;
    forward_signals(&stream);
    wait_reply(&mut stream)
}

/// Build the request from what the kernel gave this process: its own
/// executable path is the substituted path the workload actually reached, and
/// argv is the invocation exactly as made.
#[cfg(target_os = "linux")]
fn shim_request() -> Result<ShimRequest, String> {
    let exe = own_exe()?;
    let argv: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".into());
    let env: Vec<(String, String)> = std::env::vars().collect();
    Ok(ShimRequest {
        exe,
        argv,
        cwd,
        env,
    })
}

/// This process's executable path, used to look the tool up in the map.
#[cfg(target_os = "linux")]
fn own_exe() -> Result<String, String> {
    mvm_agentd::tool_map::process_executable(std::process::id())
        .map_err(|error| format!("read /proc/self/exe: {error}"))
}

/// Connect to the helper, proving the listener is the helper identity: the
/// socket directory is root-owned and writable only by the helper group;
/// the peer credentials confirm who actually accepted the connection.
#[cfg(target_os = "linux")]
fn connect() -> Result<std::os::unix::net::UnixStream, String> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(HELPER_SOCKET)
        .map_err(|error| format!("tool helper unavailable at {HELPER_SOCKET}: {error}"))?;
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(
        mvm_agentd::vsock::TOOL_REQUEST_TIMEOUT_SECS,
    )));
    let helper = mvm_agentd::guest_mount::TOOL_HELPER_IDENTITY;
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
        return Err(format!(
            "helper credentials: {}",
            std::io::Error::last_os_error()
        ));
    }
    if cred.uid != helper.uid() || cred.gid != helper.gid() {
        return Err("the tool helper listener has the wrong identity".into());
    }
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect() -> Result<std::os::unix::net::UnixStream, String> {
    Err("tools mediate only in a Linux guest".into())
}

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

/// `CMSG_LEN` speaks `socklen_t` on both Linux and BSD-ish targets while the
/// `msghdr` fields want `usize` on Linux; this normalizes to `usize`.
#[cfg(target_os = "linux")]
fn cmsg_len(bytes: usize) -> usize {
    u32::try_from(bytes)
        .map(|bytes| {
            // SAFETY: CMSG_LEN only computes a length from its argument.
            unsafe { libc::CMSG_LEN(bytes) as usize }
        })
        .unwrap_or(usize::MAX)
}

/// Send the request with descriptors 0, 1 and 2 attached out of band.
#[cfg(target_os = "linux")]
fn send_request(
    stream: &mut std::os::unix::net::UnixStream,
    request: &ShimRequest,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::io::RawFd;

    let mut line = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    line.push(b'\n');
    if line.len() > MAX_SHIM_FRAME_BYTES as usize {
        return Err("tool request exceeds its frame bound".into());
    }
    let mut fds: Vec<RawFd> = Vec::new();
    for fd in [0, 1, 2] {
        // SAFETY: `fd` is one of the three well-known descriptors; fcntl
        // reports its flags or EINVAL when it is closed.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err("the tool invocation has a closed standard descriptor".into());
        }
    }
    for fd in [0, 1, 2] {
        // SAFETY: the preflight above proved all three descriptors are open.
        let owned = unsafe { libc::dup(fd) };
        if owned < 0 {
            for received in fds {
                // SAFETY: each descriptor came from a successful dup above.
                unsafe { libc::close(received) };
            }
            return Err(format!(
                "duplicate tool descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        fds.push(owned);
    }
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(24) } as usize];
    let mut iov = libc::iovec {
        iov_base: line.as_mut_ptr().cast(),
        iov_len: line.len(),
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
    // SAFETY: with at least one descriptor attached, `header` describes a
    // control buffer large enough for `fds`; the CMSG writes stay within it.
    unsafe {
        if !fds.is_empty() {
            let capacity = ((control.len() - libc::CMSG_LEN(0) as usize)
                / std::mem::size_of::<RawFd>())
            .min(fds.len());
            header.msg_controllen =
                MsgLen::of_len(cmsg_len(capacity * std::mem::size_of::<RawFd>()));
            let control_header = libc::CMSG_FIRSTHDR(&header);
            (*control_header).cmsg_level = libc::SOL_SOCKET;
            (*control_header).cmsg_type = libc::SCM_RIGHTS;
            (*control_header).cmsg_len =
                MsgLen::of_len(cmsg_len(capacity * std::mem::size_of::<RawFd>()));
            let data = libc::CMSG_DATA(control_header) as *mut RawFd;
            for (index, fd) in fds.iter().take(capacity).enumerate() {
                *data.add(index) = *fd;
            }
        }
        let sent = libc::sendmsg(stream.as_raw_fd(), &header, 0);
        for fd in fds {
            // The helper received its own copies with the message.
            let _ = libc::close(fd);
        }
        if sent < 0 {
            return Err(format!(
                "send tool request: {}",
                std::io::Error::last_os_error()
            ));
        }
        if sent == 0 {
            return Err("send tool request: no bytes were written".into());
        }
        let sent = usize::try_from(sent).map_err(|error| error.to_string())?;
        stream
            .write_all(&line[sent..])
            .map_err(|error| format!("finish tool request: {error}"))?;
    }
    Ok(())
}

/// Arm signal forwarding: each caught signal's number is written to the
/// helper as one byte, and the helper forwards it to the tool's process
/// group. `write` is async-signal-safe, so the handler itself stays safe.
#[cfg(target_os = "linux")]
fn forward_signals(stream: &std::os::unix::net::UnixStream) {
    FORWARD_FD.store(stream.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
    for signal in [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
        libc::SIGCONT,
    ] {
        // SAFETY: `action` is a fully initialized sigaction for one signal;
        // the handler uses only async-signal-safe calls on plain values.
        unsafe {
            let action = libc::sigaction {
                sa_sigaction: forward_handler as *const () as usize,
                sa_mask: std::mem::zeroed(),
                sa_flags: 0,
                sa_restorer: None,
            };
            let _ = libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

#[cfg(target_os = "linux")]
extern "C" fn forward_handler(signal: libc::c_int) {
    let byte = [signal as u8];
    // SAFETY: `byte` is one writable byte; write is async-signal-safe. The
    // destination is the helper socket installed by forward_signals (the
    // value travels in a static because a handler cannot close over one).
    unsafe {
        if FORWARD_FD.load(std::sync::atomic::Ordering::Relaxed) >= 0 {
            libc::write(
                FORWARD_FD.load(std::sync::atomic::Ordering::Relaxed),
                byte.as_ptr().cast(),
                1,
            );
        }
    }
}

#[cfg(target_os = "linux")]
static FORWARD_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(not(target_os = "linux"))]
fn forward_signals(_stream: &std::os::unix::net::UnixStream) {}

/// Block until the helper's final reply and map it to an exit code.
fn wait_reply(stream: &mut std::os::unix::net::UnixStream) -> Result<i32, String> {
    let mut line = String::new();
    stream
        .take(MAX_SHIM_FRAME_BYTES)
        .read_to_string(&mut line)
        .map_err(|error| format!("tool helper reply failed: {error}"))?;
    let reply: HelperReply = serde_json::from_str(line.trim_end())
        .map_err(|error| format!("tool helper reply: {error}"))?;
    match reply {
        HelperReply::Exited { code } => Ok(code),
        HelperReply::Denied { reason } => {
            eprintln!("mvm-tool-shim: {reason}");
            Ok(EXIT_DENIED)
        }
        HelperReply::Unavailable { reason } => {
            eprintln!("mvm-tool-shim: {reason}");
            Ok(EXIT_UNAVAILABLE)
        }
    }
}
