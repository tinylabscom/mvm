//! Event-driven capture follows the direct child, not slave EOF. After exit,
//! drain until WouldBlock/EOF. Continuously readable output hits the deadline,
//! never truncates into success. Later writes after a drained boundary are not
//! CLI output.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

pub fn output(command: Command, timeout: Duration) -> io::Result<Output> {
    capture_using_reader(command, timeout, |mut file, buf| file.read(buf))
}

// The read seam exercises failures through real child cleanup, not just parsing.
pub(super) fn capture_using_reader(
    command: Command,
    timeout: Duration,
    read: impl FnMut(&File, &mut [u8]) -> io::Result<usize> + Send + 'static,
) -> io::Result<Output> {
    // BDD may already run inside Tokio. This thread owns its runtime and all
    // resources; joining leaves no background reader or borrowed FD behind.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(capture(command, timeout, read))
    })
    .join()
    .map_err(|_| io::Error::other("terminal capture worker panicked"))?
}

fn terminal_pair() -> io::Result<(File, File)> {
    // openpty then fcntl races unrelated spawns. Open both FDs atomically
    // CLOEXEC instead; standard File::try_clone also uses atomic duplication.
    let master = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
        .open("/dev/ptmx")?;
    // SAFETY: master owns a live PTY descriptor throughout both libc calls.
    if unsafe { nix::libc::grantpt(master.as_raw_fd()) } < 0
        || unsafe { nix::libc::unlockpt(master.as_raw_fd()) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let slave = open_slave(&master)?;
    Ok((master, slave))
}

#[cfg(target_os = "linux")]
fn open_slave(master: &File) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    // SAFETY: this opens our live master's peer with the supplied atomic flags.
    let fd = unsafe {
        nix::libc::ioctl(
            master.as_raw_fd(),
            nix::libc::TIOCGPTPEER,
            nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        // Unsupported kernels fail closed, not back to inheritable openpty.
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful ioctl returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "macos")]
fn open_slave(master: &File) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let mut name = [0u8; 128];
    // SAFETY: macOS TIOCPTYGNAME writes exactly its fixed 128-byte buffer.
    if unsafe {
        nix::libc::ioctl(
            master.as_raw_fd(),
            nix::libc::TIOCPTYGNAME.into(),
            name.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let name = std::ffi::CStr::from_bytes_until_nul(&name)
        .map_err(|_| io::Error::other("PTY peer path has no terminator"))?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOCTTY)
        .open(std::ffi::OsStr::from_bytes(name.to_bytes()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_slave(_master: &File) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic PTY allocation requires Linux or macOS",
    ))
}

async fn capture(
    command: Command,
    timeout: Duration,
    mut read: impl FnMut(&File, &mut [u8]) -> io::Result<usize>,
) -> io::Result<Output> {
    let (master, slave) = terminal_pair()?;
    // SAFETY: `master` is a live PTY descriptor the AsyncFd now owns and never swaps.
    let master = unsafe { AsyncFd::register(master) }?;
    let mut command = tokio::process::Command::from(command);
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .kill_on_drop(true);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut child = command.spawn()?;
    drop(command);
    let mut bytes = Vec::new();
    let mut status = None;
    let mut closed = false;
    let mut buf = [0; 8192];
    let result: io::Result<std::process::ExitStatus> = async {
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "terminal capture timed out"));
            }
            if let Some(status) = status {
                if closed {
                    return Ok(status);
                }
                match read(master.get_ref(), &mut buf) {
                    Ok(0) => return Ok(status),
                    Ok(n) => bytes.extend_from_slice(&buf[..n]),
                    Err(e) if terminal_end(&e) => return Ok(status),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
                // Continuous output must not starve the deadline.
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "terminal capture timed out"));
                }
                exited = child.wait() => { status = Some(exited?); }
                ready = master.readable(), if !closed => {
                    let mut ready = ready?;
                    match ready.try_io(|fd| read(fd.get_ref(), &mut buf)) {
                        Ok(Ok(0)) => closed = true,
                        Ok(Ok(n)) => bytes.extend_from_slice(&buf[..n]),
                        Ok(Err(e)) if terminal_end(&e) => closed = true,
                        Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                        Ok(Err(e)) => return Err(e),
                        Err(_would_block) => {}
                    }
                }
            }
        }
    }.await;
    match result {
        Ok(status) => Ok(Output {
            status,
            stdout: bytes,
            stderr: Vec::new(),
        }),
        Err(error) => {
            if let Err(cleanup) = child.kill().await
                && child.try_wait()?.is_none()
            {
                return Err(io::Error::other(format!(
                    "{error}; failed to kill and reap terminal child: {cleanup}"
                )));
            }
            Err(io::Error::new(
                error.kind(),
                format!(
                    "{error}; captured terminal output:\n{}",
                    String::from_utf8_lossy(&bytes)
                ),
            ))
        }
    }
}

fn terminal_end(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || (cfg!(target_os = "linux") && error.raw_os_error() == Some(nix::libc::EIO))
}
