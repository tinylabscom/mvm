//! Restore-time wall-clock synchronization for the guest agent.
//!
//! The agent normally runs without broad privilege. The image launcher grants
//! it only `CAP_SYS_TIME` so this narrow operation can correct a restored
//! guest clock before the init restart hook runs; the capability is not
//! exposed to workload processes.

use std::io;

/// Failure while applying a host-provided restore epoch.
#[derive(Debug, thiserror::Error)]
pub enum RestoreClockError {
    /// The epoch is absent, malformed, ambiguous, zero, or cannot be
    /// represented by the platform's `timeval`.
    #[error("host epoch is missing, invalid, or outside the platform time range")]
    InvalidEpoch,
    /// This operation is only available in the Linux guest.
    #[error("restore clock synchronization is unavailable on this platform")]
    Unsupported,
    /// The kernel rejected the clock update.
    #[error("settimeofday failed: {0}")]
    SetTime(#[source] io::Error),
}

/// Set the guest wall clock to the supplied Unix epoch seconds.
pub fn resync(epoch_secs: u64) -> Result<(), RestoreClockError> {
    if epoch_secs == 0 {
        return Err(RestoreClockError::InvalidEpoch);
    }

    #[cfg(target_os = "linux")]
    {
        let tv = libc::timeval {
            tv_sec: epoch_secs
                .try_into()
                .map_err(|_| RestoreClockError::InvalidEpoch)?,
            tv_usec: 0,
        };
        // SAFETY: `tv` is fully initialized and the timezone pointer is null,
        // which Linux ignores. The caller is the dedicated guest agent, whose
        // image launcher grants only CAP_SYS_TIME for this operation.
        let rc = unsafe { libc::settimeofday(&tv, std::ptr::null()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(RestoreClockError::SetTime(io::Error::last_os_error()))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = epoch_secs;
        Err(RestoreClockError::Unsupported)
    }
}

/// Seed a cold guest's wall clock from its authenticated launch cmdline.
///
/// Returns the applied epoch for an audit-friendly success log. Missing,
/// malformed, or duplicated tokens fail before the clock syscall.
pub fn resync_from_cmdline(cmdline: &str) -> Result<u64, RestoreClockError> {
    resync_from_cmdline_with(cmdline, resync)
}

fn resync_from_cmdline_with(
    cmdline: &str,
    apply: impl FnOnce(u64) -> Result<(), RestoreClockError>,
) -> Result<u64, RestoreClockError> {
    let epoch = mvm_core::vm_backend::decode_host_epoch_cmdline(cmdline)
        .ok_or(RestoreClockError::InvalidEpoch)?;
    apply(epoch)?;
    Ok(epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_boot_cmdline_applies_the_host_epoch() {
        let applied = std::cell::Cell::new(None);
        let epoch = resync_from_cmdline_with(
            "console=hvc0 mvm.hostepoch=1786425335 root=/dev/vda",
            |value| {
                applied.set(Some(value));
                Ok(())
            },
        )
        .expect("valid host epoch must be applied");

        assert_eq!(epoch, 1_786_425_335);
        assert_eq!(applied.get(), Some(epoch));
    }

    #[test]
    fn cold_boot_cmdline_refuses_invalid_or_ambiguous_epochs_before_apply() {
        for cmdline in [
            "console=hvc0",
            "mvm.hostepoch=0",
            "mvm.hostepoch=bad",
            "mvm.hostepoch=1 mvm.hostepoch=2",
        ] {
            let applied = std::cell::Cell::new(false);
            let result = resync_from_cmdline_with(cmdline, |_| {
                applied.set(true);
                Ok(())
            });
            assert!(matches!(result, Err(RestoreClockError::InvalidEpoch)));
            assert!(
                !applied.get(),
                "invalid cmdline reached clock syscall: {cmdline}"
            );
        }
    }

    #[test]
    fn cold_boot_clock_propagates_kernel_refusal() {
        let result =
            resync_from_cmdline_with("mvm.hostepoch=42", |_| Err(RestoreClockError::Unsupported));
        assert!(matches!(result, Err(RestoreClockError::Unsupported)));
    }

    #[test]
    fn pid1_seeds_the_clock_before_time_sensitive_trust_setup() {
        let source = include_str!("bin/mvm-guest-agent/init.rs");
        let body = source
            .split("pub(crate) fn early_setup")
            .nth(1)
            .expect("early_setup must exist")
            .split("\nfn ")
            .next()
            .expect("function body is delimited by the next item");

        let mounted = body
            .find("mount_early_filesystems")
            .expect("PID 1 must mount /proc before reading its cmdline");
        let synchronized = body
            .find("seed_wall_clock_from_host_epoch")
            .expect("PID 1 must synchronize the cold-boot wall clock");
        let anchor = body
            .find("provision_host_signer_anchor")
            .expect("PID 1 must provision its host trust anchor");
        let grant = body
            .find("provision_verb_grant")
            .expect("PID 1 must provision its signed verb grant");

        assert!(mounted < synchronized);
        assert!(synchronized < anchor);
        assert!(synchronized < grant);
    }

    #[test]
    fn zero_epoch_is_rejected() {
        // A zero epoch is the protocol's no-clock-sync sentinel and must not
        // move a guest clock back to the Unix epoch.
        assert!(matches!(resync(0), Err(RestoreClockError::InvalidEpoch)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn max_epoch_is_rejected_before_linux_syscall() {
        assert!(matches!(
            resync(u64::MAX),
            Err(RestoreClockError::InvalidEpoch)
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn max_epoch_is_unsupported_outside_linux() {
        assert!(matches!(
            resync(u64::MAX),
            Err(RestoreClockError::Unsupported)
        ));
    }
}
