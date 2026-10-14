//! `syscall-probe` — exits with the errno of an attempted syscall.
//!
//! Test-only binary. Spawned by `tests/seccomp_apply.rs` under
//! `mvm-seccomp-apply <tier> --` to verify that tier allowlists
//! actually deny what they claim. The optional first argument names the
//! probe: `inet` (the default), `vsock`, or `groups`. Exit-code contract:
//!
//! - 0 → the socket opened or `getgroups(0, NULL)` returned a group count.
//! - 1 → call failed with `EPERM` (the seccomp-shaped denial).
//! - other → call failed with a different errno (raw value, capped at 254).
//! - 64 → the argument is not one this probe knows.
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
    let family_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "inet".to_string());
    if family_name == "groups" {
        // A zero-sized query reads only the count; it cannot change groups.
        if unsafe { libc::getgroups(0, std::ptr::null_mut()) } < 0 {
            exit_errno("getgroups(0, NULL)");
        }
        return;
    }
    let family = match family_name.as_str() {
        "inet" => libc::AF_INET,
        "vsock" => libc::AF_VSOCK,
        other => {
            eprintln!("syscall-probe: unknown probe {other:?} (expected inet, vsock or groups)");
            std::process::exit(64);
        }
    };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        exit_errno("socket");
    }
    unsafe {
        libc::close(fd);
    }
    std::process::exit(0);
}

#[cfg(target_os = "linux")]
fn exit_errno(call: &str) -> ! {
    let err = std::io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(255);
    eprintln!("syscall-probe: {call} failed: errno={errno} ({err})");
    // Exit codes are u8; cap below 255 so signal termination stays distinct.
    std::process::exit(errno.min(254));
}
