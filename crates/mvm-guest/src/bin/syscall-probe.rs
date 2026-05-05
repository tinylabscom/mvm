//! `syscall-probe` — exits with the errno of an attempted `socket(2)` call.
//!
//! Test-only binary. Spawned by `tests/seccomp_apply.rs` under
//! `mvm-seccomp-apply <tier> --` to verify that tier allowlists
//! actually deny what they claim. Exit-code contract:
//!
//! - 0 → `socket(AF_INET, SOCK_STREAM, 0)` succeeded.
//! - 1 → call failed with `EPERM` (the seccomp-shaped denial).
//! - other → call failed with a different errno (raw value, capped at 254).
//!
//! Not shipped in production: `nix/packages/mvm-guest-agent.nix`
//! explicitly selects `mvm-guest-agent` and `mvm-seccomp-apply` as
//! the bins to build, so this binary stays in `target/` only.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("syscall-probe runs inside Linux microVM guests only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(255);
        eprintln!("syscall-probe: socket(AF_INET, SOCK_STREAM) failed: errno={errno} ({err})");
        // Exit codes are u8; cap below 255 so the kernel's "killed by
        // signal" channel stays distinct.
        std::process::exit(errno.min(254));
    }
    unsafe {
        libc::close(fd);
    }
    std::process::exit(0);
}
