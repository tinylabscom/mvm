//! Dropping the privileges the tunnel needed to exist.
//!
//! Creating `mvm0` and installing its routes needs `CAP_NET_ADMIN`. Moving
//! packets across an already-open fd needs nothing. So the agent drops
//! every capability — effective, permitted, inheritable, ambient, and the
//! bounding set — as soon as setup completes, and sets `PR_SET_NO_NEW_PRIVS`
//! so nothing it execs can regain them.
//!
//! The consequence that matters: a workload sharing the guest cannot
//! reconfigure `mvm0`, create another interface, or alter routes, because
//! by the time it runs, nothing in the guest holds `CAP_NET_ADMIN`.

/// What a privilege drop accomplished. Returned rather than logged so the
/// caller can refuse to continue on a partial drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropReport {
    pub no_new_privs: bool,
    pub capabilities_cleared: bool,
    pub bounding_set_cleared: bool,
}

impl DropReport {
    /// Whether every step succeeded.
    pub fn is_complete(&self) -> bool {
        self.no_new_privs && self.capabilities_cleared && self.bounding_set_cleared
    }

    /// The steps that did not complete, for an error message.
    pub fn shortfall(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.no_new_privs {
            out.push("no_new_privs");
        }
        if !self.capabilities_cleared {
            out.push("capabilities");
        }
        if !self.bounding_set_cleared {
            out.push("bounding_set");
        }
        out
    }
}

/// Drop every privilege the agent no longer needs.
///
/// Fail-closed is the caller's job: this reports what happened, and the
/// agent refuses to proceed on an incomplete drop rather than running the
/// packet pump with `CAP_NET_ADMIN` still held.
#[cfg(target_os = "linux")]
pub fn drop_privileges() -> DropReport {
    DropReport {
        no_new_privs: linux::set_no_new_privs(),
        capabilities_cleared: linux::clear_all_capabilities(),
        bounding_set_cleared: linux::clear_bounding_set(),
    }
}

/// Non-Linux builds have no tunnel to secure, so there is nothing to drop.
/// Reported as complete so the shared caller has one code path.
#[cfg(not(target_os = "linux"))]
pub fn drop_privileges() -> DropReport {
    DropReport {
        no_new_privs: true,
        capabilities_cleared: true,
        bounding_set_cleared: true,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    // linux/capability.h
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // The highest capability number Linux 6.12 defines. Dropping past the
    // end of the range is harmless (EINVAL), so overshooting is safe; the
    // constant is here so the loop bound is explicit rather than magic.
    const CAP_LAST_CAP: libc::c_ulong = 40;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_CAPBSET_DROP: libc::c_int = 24;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::pid_t,
    }

    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    /// Layout contract with `linux/capability.h`. `capset` reads each word
    /// by offset, so a mismatch clears the wrong set rather than failing —
    /// and the failure direction is not symmetric: a shifted write can
    /// leave a capability set that should have been dropped.
    const _: () = {
        use core::mem::{align_of, offset_of, size_of};
        assert!(size_of::<CapHeader>() == 8);
        assert!(align_of::<CapHeader>() == 4);
        assert!(offset_of!(CapHeader, version) == 0);
        assert!(offset_of!(CapHeader, pid) == 4);
        assert!(size_of::<CapData>() == 12);
        assert!(align_of::<CapData>() == 4);
        assert!(offset_of!(CapData, effective) == 0);
        assert!(offset_of!(CapData, permitted) == 4);
        assert!(offset_of!(CapData, inheritable) == 8);
    };

    pub(super) fn set_no_new_privs() -> bool {
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar arguments and
        // touches no memory we own.
        unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
    }

    pub(super) fn clear_all_capabilities() -> bool {
        let header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [CapData::default(); 2];
        // SAFETY: both pointers reference stack values that outlive the
        // call and match the kernel's expected layout (asserted above).
        let rc =
            unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
        rc == 0
    }

    pub(super) fn clear_bounding_set() -> bool {
        let mut ok = true;
        for cap in 0..=CAP_LAST_CAP {
            // SAFETY: scalar-argument prctl.
            let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
            // EINVAL means the capability number does not exist on this
            // kernel, which is not a failure to drop it.
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINVAL) {
                    ok = false;
                }
            }
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_report_has_no_shortfall() {
        let report = DropReport {
            no_new_privs: true,
            capabilities_cleared: true,
            bounding_set_cleared: true,
        };
        assert!(report.is_complete());
        assert!(report.shortfall().is_empty());
    }

    #[test]
    fn each_missing_step_is_named_in_the_shortfall() {
        let report = DropReport {
            no_new_privs: false,
            capabilities_cleared: true,
            bounding_set_cleared: false,
        };
        assert!(!report.is_complete());
        assert_eq!(report.shortfall(), vec!["no_new_privs", "bounding_set"]);
    }

    /// Running the real drop inside the test process would disarm the test
    /// runner, so this only asserts the non-Linux shape. The Linux path is
    /// covered by the privileged integration lane, which runs it in a child
    /// process and then checks `/proc/self/status`.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_builds_report_a_complete_drop() {
        assert!(drop_privileges().is_complete());
    }
}
