//! The capability-set syscalls behind every guest privilege drop: `capset` for
//! the effective, permitted and inheritable sets, and `PR_CAP_AMBIENT` for the
//! ambient set that lets a non-root process keep a capability across exec.

#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT: libc::c_int = 47;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

/// Linux v3 stores each set as two 32-bit words, low word first.
fn capability_data(capabilities: u64) -> [CapData; 2] {
    [capabilities as u32, (capabilities >> 32) as u32].map(|word| CapData {
        effective: word,
        permitted: word,
        inheritable: word,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn set_capabilities(capabilities: u64) -> std::io::Result<()> {
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = capability_data(capabilities);
    // SAFETY: the v3 header and both data words have the Linux ABI layout.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn raise_ambient_capabilities(capabilities: u64) -> std::io::Result<()> {
    for capability in 0..u64::BITS {
        if !super::bounding_set_retains(capabilities, capability) {
            continue;
        }
        let rc = unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                capability as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

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

// Layout contract with linux/capability.h `__user_cap_header_struct` and
// `__user_cap_data_struct`. Both are passed to capset(2) by pointer; the
// kernel reads each capability word by offset, so a Rust layout drift would
// silently request the wrong privilege set.
//
// Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof, not read from these
// Rust definitions. `pid_t` is i32 on every Linux target mvm builds for.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_data_preserves_both_words_in_every_set() {
        for mask in [
            0,
            1u64 << 10,
            (1u64 << 10) | (1u64 << 38) | (1u64 << 39),
            u64::MAX,
        ] {
            let data = capability_data(mask);
            for (low, high) in [
                (data[0].effective, data[1].effective),
                (data[0].permitted, data[1].permitted),
                (data[0].inheritable, data[1].inheritable),
            ] {
                assert_eq!(u64::from(low) | (u64::from(high) << 32), mask);
            }
        }
    }
}
