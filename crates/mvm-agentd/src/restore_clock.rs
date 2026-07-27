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
    /// The epoch cannot be represented by the platform's `timeval`.
    #[error("restore epoch is outside the platform time range")]
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

#[cfg(test)]
mod tests {
    use super::*;

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
