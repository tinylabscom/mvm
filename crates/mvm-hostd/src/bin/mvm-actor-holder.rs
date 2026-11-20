//! Dedicated VM-scoped actor session holder.

use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;

fn main() -> anyhow::Result<()> {
    mvm_vmm::host::helper_contract::exit_with_probe_answer_if_requested("mvm-actor-holder");
    mvm_hostd::panic_hook::install("actor-holder");
    mvm_hostd::parent_death::exit_when_orphaned();
    for fd in [0, mvm_hostd::actor_holder::CONTROLLER_FD] {
        // SAFETY: fcntl only inspects the descriptor and reports invalid handles.
        let valid = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        anyhow::ensure!(valid, "missing inherited actor socket");
    }
    // SAFETY: the trusted spawn path exclusively transfers socket endpoints as
    // stdin and fd 3. Each descriptor is adopted exactly once by this process.
    let (bootstrap, controller) = unsafe {
        (
            UnixStream::from_raw_fd(0),
            UnixStream::from_raw_fd(mvm_hostd::actor_holder::CONTROLLER_FD),
        )
    };
    mvm_hostd::actor_holder::run(bootstrap, controller)
}
