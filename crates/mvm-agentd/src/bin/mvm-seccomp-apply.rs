//! `mvm-seccomp-apply` — install a seccomp BPF filter, then run a wrapped command.
//!
//! Usage:
//!     `mvm-seccomp-apply <tier> -- <cmd> [args...]`
//!
//! `<tier>` is one of `essential` / `minimal` / `standard` / `network`
//! / `unrestricted` (matching `mvm_core::crypto::seccomp::SeccompTier`).
//! On `unrestricted`, the shim is a no-op handoff — useful so the
//! launcher line stays uniform regardless of tier.
//!
//! Why a shim instead of `setpriv --seccomp-filter`:
//!
//! - `setpriv --seccomp-filter` consumes a binary BPF dump; producing
//!   the dump at Nix-evaluation time would require pinning a libseccomp
//!   build inside the rootfs's closure. Compiling in-process via
//!   `seccompiler` keeps the dependency on a small Rust crate and
//!   compiles consistently across tier definitions.
//!
//! - The shim is short, zero external runtime dependencies beyond
//!   what `mvm-guest-agent` already drags in. It piggybacks on the
//!   guest agent's store path so it ships in the same closure.
//!
//! Linux-only: seccomp is a Linux kernel feature, and the seccompiler
//! crate doesn't even build on Darwin. The binary's `main` is gated
//! on `target_os = "linux"`; on other targets it errors with a clear
//! message so `cargo check --workspace` still passes for CLI dev on a
//! Mac.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "mvm-seccomp-apply runs inside Linux microVM guests only — \
         the host shouldn't be invoking it directly."
    );
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use mvm_core::crypto::seccomp::SeccompTier;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
compile_error!("mvm-seccomp-apply only supports aarch64 and x86_64 on Linux");

#[cfg(target_os = "linux")]
fn main() {
    let mut args = env::args();
    let _argv0 = args.next();

    let tier_str = args.next().unwrap_or_else(|| die("missing <tier>"));
    let separator = args.next().unwrap_or_else(|| die("missing `--` separator"));
    if separator != "--" {
        die("expected `--` between tier and command");
    }
    let cmd = args
        .next()
        .unwrap_or_else(|| die("missing command after `--`"));
    let cmd_args: Vec<String> = args.collect();

    let tier: SeccompTier = tier_str
        .parse()
        .unwrap_or_else(|e| die(&format!("invalid tier {tier_str:?}: {e}")));

    #[cfg(target_os = "linux")]
    mvm_agentd::fd_hygiene::close_descriptors_from(3, None)
        .unwrap_or_else(|e| die(&format!("close inherited descriptors: {e}")));

    if !tier.is_unrestricted() {
        apply_filter(tier).unwrap_or_else(|e| die(&format!("seccomp install failed: {e}")));
    }

    // Hand off to the wrapped command via a single Unix syscall (no
    // intermediate sh, no PATH lookup beyond what the kernel does).
    // The seccomp filter is inherited by the new process image because
    // PR_SET_SECCOMP is sticky.
    let err = Command::new(&cmd).args(&cmd_args).exec();
    die(&format!("execve {cmd}: {err}"));
}

/// Compile the tier's allowlist to BPF and install it, through the same
/// builder the guest agent uses for the workloads it starts. Any syscall
/// outside the list returns SECCOMP_RET_ERRNO with EPERM, keeping the process
/// alive so the user sees a clean failure rather than a SIGSYS coredump.
#[cfg(target_os = "linux")]
fn apply_filter(tier: SeccompTier) -> anyhow::Result<()> {
    set_no_new_privs()?;
    if let Some(program) = mvm_agentd::workload_seccomp::compile(tier)? {
        mvm_agentd::workload_seccomp::install(&program)?;
    }
    Ok(())
}

/// Set PR_SET_NO_NEW_PRIVS on the current process. Defense-in-depth:
/// the kernel requires NNP for an unprivileged process to install a
/// seccomp filter, and the launch wrapper already passes
/// `setpriv --no-new-privs`. Owning the call here means a future
/// caller that forgets the setpriv flag still gets the filter
/// installed instead of a late EACCES from `seccomp(2)`. The bit is
/// idempotent — setting it when already set is a no-op.
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> anyhow::Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) takes only scalar
    // args and has no preconditions on process state. The kernel
    // returns 0 on success and -1 with errno on failure; we surface
    // the errno via std::io::Error::last_os_error.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "linux")]
fn die(msg: &str) -> ! {
    eprintln!("mvm-seccomp-apply: {msg}");
    std::process::exit(2);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// `set_no_new_privs` is a named `fn:` witness for the claim that no
    /// guest binary can elevate to uid 0, and it had no test: the catalog
    /// gate proves the symbol exists, not that anything asserts what it
    /// does. Replacing the whole body with `Ok(())` therefore survived,
    /// leaving `PR_SET_NO_NEW_PRIVS` unset while the claim read as
    /// witnessed — and an unset bit is exactly how a setuid binary regains
    /// privilege across `execve`.
    ///
    /// Reading the bit back with `PR_GET_NO_NEW_PRIVS` is what makes this
    /// discriminate: asserting only that the call returns `Ok` is what a
    /// constant `Ok(())` passes.
    ///
    /// The bit is one-way for the calling process, which is safe here
    /// because nextest gives every test its own process, and it is
    /// idempotent, so ordering against anything else does not matter.
    #[test]
    fn set_no_new_privs_actually_sets_the_kernel_bit() {
        // SAFETY: prctl(PR_GET_NO_NEW_PRIVS, ...) takes only scalar args,
        // reads process state and has no preconditions.
        let before = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        assert_eq!(
            before, 0,
            "a fresh test process must start without no_new_privs, or this test proves nothing"
        );

        set_no_new_privs().expect("prctl(PR_SET_NO_NEW_PRIVS) must succeed");

        // SAFETY: as above.
        let after = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        assert_eq!(after, 1, "no_new_privs must be set after the call returns");

        // Idempotent, as the doc comment claims.
        set_no_new_privs().expect("setting an already-set bit is a no-op");
        // SAFETY: as above.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
            1
        );
    }
}
