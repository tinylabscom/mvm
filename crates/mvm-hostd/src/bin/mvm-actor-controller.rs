//! Independently owned actor root; no public lifecycle listener.

use std::os::fd::FromRawFd as _;
use std::os::unix::net::UnixStream;

fn main() -> anyhow::Result<()> {
    mvm_core::helper_contract::exit_with_probe_answer_if_requested("mvm-actor-controller");
    mvm_hostd::panic_hook::install("actor-controller");
    anyhow::ensure!(
        // SAFETY: fcntl inspects the inherited descriptor without taking ownership.
        unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0,
        "missing private bootstrap socket"
    );
    // SAFETY: this role owns fd 0 exactly once. The spawn path supplies a socket;
    // peer_addr below rejects ordinary terminal/file stdin before reading input.
    let bootstrap = unsafe { UnixStream::from_raw_fd(0) };
    bootstrap.peer_addr()?;
    anyhow::ensure!(
        // SAFETY: fd 0 is owned above; fcntl only sets its close-on-exec flag.
        unsafe { libc::fcntl(0, libc::F_SETFD, libc::FD_CLOEXEC) } >= 0,
        "cannot isolate bootstrap socket"
    );
    mvm_hostd::actor_controller::run(bootstrap)
}
