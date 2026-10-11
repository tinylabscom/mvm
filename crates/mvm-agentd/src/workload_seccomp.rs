//! The seccomp filter every workload process the agent starts runs under.
//!
//! The host admits a tier into the signed plan and names it on the guest
//! kernel command line as `mvm.seccomp=<tier>`. Activation reads it once,
//! compiles the tier's allowlist and holds the program for the life of the
//! agent ([`admit_from_cmdline`]). Every site that starts workload code then
//! installs that program in the child, after the child's other pre-exec setup
//! and immediately before `execve` ([`confine`] for a `Command`,
//! [`install_admitted`] after a raw `fork`). `no_new_privs` is set as part of
//! the install, so the filter cannot be shed by exec'ing a setuid binary.
//!
//! The agent itself is never filtered: it needs mounts, vsock and process
//! control the workload tiers deny. The filter is per child, and the kernel
//! carries it across every later `fork` and `execve`, so a workload's own
//! descendants inherit it.
//!
//! A syscall outside the tier fails with `EPERM` rather than killing the
//! process, the same action `mvm-seccomp-apply` has always used: a workload
//! sees a failed call it can report, not a SIGSYS core.
//!
//! A boot whose cmdline names no tier — a standby parent booted before any
//! workload was admitted, or a host that predates the token — admits nothing,
//! and its workloads run unfiltered, exactly as before the tier was enforced.

use mvm_core::crypto::seccomp::SeccompTier;
use std::sync::OnceLock;

/// The kernel cmdline key the host names the admitted tier under. Matches
/// `mvm_vmm::host::cmdline::SECCOMP_CMDLINE_KEY`, which the agent cannot
/// depend on.
pub const CMDLINE_KEY: &str = "mvm.seccomp";

/// The tier `cmdline` names, `None` when it names none.
///
/// # Errors
///
/// A value that is not a tier, or the key given twice. Either means the host
/// and guest disagree about the boot contract, and guessing would run the
/// workload under a filter nobody admitted.
pub fn tier_from_cmdline(cmdline: &str) -> Result<Option<SeccompTier>, String> {
    let prefix = format!("{CMDLINE_KEY}=");
    let mut values = cmdline
        .split_whitespace()
        .filter_map(|token| token.strip_prefix(prefix.as_str()));
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(format!("{CMDLINE_KEY} is named more than once"));
    }
    value
        .parse::<SeccompTier>()
        .map(Some)
        .map_err(|error| format!("{CMDLINE_KEY}: {error}"))
}

/// What activation admitted: the tier, and its compiled program. `program` is
/// `None` for `unrestricted`, which installs nothing.
struct Admitted {
    tier: SeccompTier,
    #[cfg(target_os = "linux")]
    program: Option<seccompiler::BpfProgram>,
}

static ADMITTED: OnceLock<Admitted> = OnceLock::new();

/// Admit `tier` for every workload process started from now on.
///
/// The program is compiled here, at activation, so a tier that cannot be
/// compiled fails the boot instead of every later spawn, and so a post-fork
/// child only has to hand finished bytes to the kernel.
///
/// # Errors
///
/// The tier fails to compile, or a different tier was already admitted. The
/// filter is fixed for the life of the guest; a second activation may repeat
/// the tier but not change it.
pub fn admit(tier: SeccompTier) -> Result<(), String> {
    if let Some(admitted) = ADMITTED.get() {
        return if admitted.tier == tier {
            Ok(())
        } else {
            Err(format!(
                "workload seccomp tier is already {}; refusing {tier}",
                admitted.tier
            ))
        };
    }
    let admitted = Admitted {
        tier,
        #[cfg(target_os = "linux")]
        program: compile(tier).map_err(|error| format!("compile seccomp tier {tier}: {error}"))?,
    };
    // Activation is single-threaded; losing a race here would mean two
    // activations at once, which the boot state already refuses.
    let _ = ADMITTED.set(admitted);
    match ADMITTED.get() {
        Some(admitted) if admitted.tier == tier => Ok(()),
        _ => Err(format!(
            "workload seccomp tier changed while admitting {tier}"
        )),
    }
}

/// Admit the tier `cmdline` names, if it names one. Returns what was admitted.
///
/// # Errors
///
/// See [`tier_from_cmdline`] and [`admit`].
pub fn admit_from_cmdline(cmdline: &str) -> Result<Option<SeccompTier>, String> {
    let Some(tier) = tier_from_cmdline(cmdline)? else {
        return Ok(None);
    };
    admit(tier)?;
    Ok(Some(tier))
}

/// The tier workload processes start under, `None` before activation admitted
/// one.
#[must_use]
pub fn admitted_tier() -> Option<SeccompTier> {
    ADMITTED.get().map(|admitted| admitted.tier)
}

/// Install the admitted filter in the calling process.
///
/// For a post-fork child: it reads a value fixed before the fork, allocates
/// nothing and makes only `prctl` and `seccomp` calls. A no-op when nothing
/// was admitted or the tier is `unrestricted`.
///
/// # Errors
///
/// The kernel refused `no_new_privs` or the filter. The caller must not exec.
pub fn install_admitted() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(program) = ADMITTED
        .get()
        .and_then(|admitted| admitted.program.as_deref())
    {
        return install(program);
    }
    Ok(())
}

/// Arrange for `command`'s child to install the admitted filter immediately
/// before it execs.
///
/// Pre-exec hooks run in the order they were registered, and the tiers deny
/// calls other hooks make (`setgid`, for one), so call this after every other
/// `pre_exec` on `command` — in practice, immediately before `spawn`.
pub fn confine(command: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs in the forked child before exec. It reads a
        // value fixed before the fork and makes only async-signal-safe calls,
        // allocating nothing.
        unsafe {
            command.pre_exec(install_admitted);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

/// Compile `tier` to a BPF program: listed syscalls are allowed, anything else
/// fails with `EPERM`. `None` for `unrestricted`.
///
/// A name that has no number on this architecture is skipped — tiers list
/// legacy x86_64 names beside their `*at` replacements so a capability holds
/// on both — which is why the syscall table only has to know the names that
/// exist here.
///
/// # Errors
///
/// The program fails to compile.
#[cfg(target_os = "linux")]
pub fn compile(tier: SeccompTier) -> Result<Option<seccompiler::BpfProgram>, seccompiler::Error> {
    use mvm_core::crypto::seccomp::syscall_table::syscall_number;
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};

    if tier.is_unrestricted() {
        return Ok(None);
    }
    let rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> = tier
        .syscalls()
        .into_iter()
        .filter_map(syscall_number)
        .map(|nr| (nr, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TARGET_ARCH,
    )?;
    Ok(Some(filter.try_into()?))
}

/// Set `no_new_privs` and install `program` on the calling thread.
///
/// Allocation-free, so it is safe in a post-fork child.
///
/// # Errors
///
/// The `prctl` or `seccomp` call failed, carrying its errno.
#[cfg(target_os = "linux")]
pub fn install(program: seccompiler::BpfProgramRef) -> std::io::Result<()> {
    match seccompiler::apply_filter(program) {
        Ok(()) => Ok(()),
        Err(seccompiler::Error::Prctl(error) | seccompiler::Error::Seccomp(error)) => Err(error),
        Err(_) => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const TARGET_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TARGET_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cmdline_without_the_key_names_no_tier() {
        assert_eq!(tier_from_cmdline("console=hvc0 mvm.hostname=web"), Ok(None));
        assert_eq!(tier_from_cmdline(""), Ok(None));
    }

    /// Every tier the host can emit parses back to itself, so the guest
    /// enforces what the plan admitted rather than a default.
    #[test]
    fn every_tier_round_trips_through_the_cmdline() {
        for tier in SeccompTier::ALL {
            let cmdline = format!("console=hvc0 {CMDLINE_KEY}={tier} mvm.hostname=web");
            assert_eq!(tier_from_cmdline(&cmdline), Ok(Some(*tier)));
        }
    }

    #[test]
    fn an_unknown_tier_is_refused_rather_than_defaulted() {
        let error = tier_from_cmdline("mvm.seccomp=lenient").unwrap_err();
        assert!(error.contains("lenient"), "{error}");
    }

    #[test]
    fn a_tier_named_twice_is_refused() {
        let error = tier_from_cmdline("mvm.seccomp=standard mvm.seccomp=unrestricted").unwrap_err();
        assert!(error.contains("more than once"), "{error}");
    }

    /// A key that merely starts with ours is a different key.
    #[test]
    fn a_longer_key_is_not_this_one() {
        assert_eq!(tier_from_cmdline("mvm.seccomp_debug=1"), Ok(None));
    }

    /// The tier activation admits is the tier every later spawn reads, and a
    /// later activation cannot swap it. One test, because the admitted tier is
    /// process state. It admits `unrestricted`, which installs nothing, so a
    /// threaded runner's other tests that spawn children are not filtered by
    /// it; `tests/seccomp_apply.rs` admits an enforcing tier in a process of
    /// its own and proves the filter lands in the child.
    #[test]
    fn the_admitted_tier_reaches_the_launch_path_and_cannot_be_replaced() {
        assert_eq!(
            admitted_tier(),
            None,
            "nothing is admitted before activation"
        );
        install_admitted().expect("installing nothing succeeds");

        let cmdline = format!("console=hvc0 {CMDLINE_KEY}=unrestricted");
        assert_eq!(
            admit_from_cmdline(&cmdline),
            Ok(Some(SeccompTier::Unrestricted))
        );
        assert_eq!(admitted_tier(), Some(SeccompTier::Unrestricted));

        // Repeating the same tier is accepted; changing it is not.
        assert_eq!(admit(SeccompTier::Unrestricted), Ok(()));
        let error = admit(SeccompTier::Standard).unwrap_err();
        assert!(error.contains("refusing standard"), "{error}");
        assert_eq!(admitted_tier(), Some(SeccompTier::Unrestricted));
        install_admitted().expect("unrestricted installs no filter");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unrestricted_compiles_to_no_program() {
        assert!(compile(SeccompTier::Unrestricted).unwrap().is_none());
    }

    /// Each enforcing tier compiles to a non-empty program on this
    /// architecture, and the cumulative tiers grow.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_enforcing_tier_compiles() {
        let mut previous = 0usize;
        for tier in [
            SeccompTier::Essential,
            SeccompTier::Minimal,
            SeccompTier::Standard,
            SeccompTier::Network,
        ] {
            let program = compile(tier)
                .unwrap()
                .expect("an enforcing tier has a program");
            assert!(program.len() > previous, "{tier} did not grow the program");
            previous = program.len();
        }
    }
}
