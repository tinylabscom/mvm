//! The capability-set syscalls behind every guest privilege drop: `capset` for
//! the effective, permitted and inheritable sets, and `PR_CAP_AMBIENT` for the
//! ambient set that lets a non-root process keep a capability across exec.

use super::{CAP_KILL, CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN, CAP_SYS_TIME};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

pub(super) fn set_capabilities(capabilities: u32) -> std::io::Result<()> {
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: capabilities,
            permitted: capabilities,
            inheritable: capabilities,
        },
        CapData::default(),
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn raise_ambient_capabilities(capabilities: u32) -> std::io::Result<()> {
    for capability in [CAP_KILL, CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN, CAP_SYS_TIME] {
        if capabilities & (1u32 << capability) == 0 {
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
