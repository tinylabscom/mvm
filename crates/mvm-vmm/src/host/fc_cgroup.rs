//! Read-only Linux cgroup-v2 observations for FC containment qualification.
//!
//! These values are not placement authority or stable enforcement evidence.
//! Configuration can change between reads and after this call. A future birth
//! boundary must control/recheck the original cgroup and own the actual child.
//! This module creates no cgroup, changes no limit and spawns no process.
//! The byte cap is not an elapsed-time deadline for kernel file reads.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};

/// A kernel control value, including an explicitly unbounded setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The kernel reported `max`, not an enforced finite ceiling.
    Unbounded,
    /// The exact configured ceiling; zero is not interpreted as unlimited.
    Value(u64),
}

/// `cpu.max` bandwidth values, not CPU-time or scheduling-weight evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    /// Quota in microseconds, or `max`.
    pub quota_micros: Limit,
    /// Nonzero period in microseconds.
    pub period_micros: u64,
}

/// Non-atomic observations from control files under one borrowed directory FD.
///
/// This is deliberately ordinary diagnostic data, not a verified/prepared token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// `memory.max` in bytes.
    pub memory_max: Limit,
    /// `memory.swap.max` in bytes.
    pub swap_max: Limit,
    /// `pids.max`, counting processes and threads.
    pub tasks_max: Limit,
    /// CPU bandwidth quota and period.
    pub cpu_max: CpuMax,
}

/// Read required controllers from an already-open cgroup-v2 directory.
///
/// No pathname is reopened. Missing controllers, non-cgroup filesystems,
/// symlinks, mount crossings, nonregular control files and malformed/oversized
/// values refuse. Kernels without the required openat2 resolution flags refuse;
/// there is no openat fallback.
/// Successful observation does not establish delegation, clone permissions,
/// born-placement, race-free limits or owner-death containment.
pub fn observe(directory: &File) -> io::Result<Observation> {
    if !directory.metadata()?.is_dir() {
        return Err(invalid(
            "cgroup observation requires a directory descriptor",
        ));
    }
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: the borrowed descriptor stays open and stat is a valid out-buffer.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the statfs buffer.
    let stat = unsafe { stat.assume_init() };
    if i128::from(stat.f_type) != i128::from(libc::CGROUP2_SUPER_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroup observation requires the kernel cgroup-v2 filesystem",
        ));
    }
    Ok(Observation {
        memory_max: parse_limit(&read_control(directory, c"memory.max")?)?,
        swap_max: parse_limit(&read_control(directory, c"memory.swap.max")?)?,
        tasks_max: parse_limit(&read_control(directory, c"pids.max")?)?,
        cpu_max: parse_cpu_max(&read_control(directory, c"cpu.max")?)?,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Linux UAPI openat2.h: three __u64 fields, including on 32-bit Linux.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// UAPI __u64 uses natural integer alignment: 8 on x86_64/aarch64, 4 on i386.
// The C header fixes the size and offsets independently of that alignment.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<OpenHow>() == 24);
    assert!(align_of::<OpenHow>() == align_of::<u64>());
    assert!(offset_of!(OpenHow, flags) == 0);
    assert!(offset_of!(OpenHow, mode) == 8);
    assert!(offset_of!(OpenHow, resolve) == 16);
};

fn control_open_how() -> io::Result<OpenHow> {
    // Linux UAPI: NO_XDEV also rejects bind mounts of another cgroup's files.
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    Ok(OpenHow {
        flags: u64::try_from(
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
        .map_err(|_| invalid("invalid cgroup control open flags"))?,
        mode: 0,
        resolve: RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    })
}

fn open_control(directory: &File, name: &CStr, how: &OpenHow) -> io::Result<File> {
    // SAFETY: the borrowed directory/name and initialized fixed-size UAPI struct
    // remain valid for this syscall. Only fixed single control names are supplied.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            name.as_ptr(),
            how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // A successful descriptor-returning syscall returns a nonnegative C int.
    let fd = i32::try_from(raw).map_err(|_| invalid("invalid cgroup control descriptor"))?;
    // SAFETY: openat2 returned a fresh descriptor, transferred exactly once.
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(invalid("cgroup control must be a regular file"));
    }
    Ok(file)
}

fn read_control(directory: &File, name: &CStr) -> io::Result<String> {
    let file = open_control(directory, name, &control_open_how()?)?;
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes)?;
    if bytes.len() > 128 || !bytes.is_ascii() || bytes.contains(&0) {
        return Err(invalid("invalid or oversized cgroup control value"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("invalid cgroup control encoding"))
}

fn parse_number(text: &str) -> io::Result<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("invalid cgroup unsigned value"));
    }
    text.parse()
        .map_err(|_| invalid("cgroup unsigned value overflow"))
}

fn parse_limit(text: &str) -> io::Result<Limit> {
    match text.trim_ascii() {
        "max" => Ok(Limit::Unbounded),
        number => parse_number(number).map(Limit::Value),
    }
}

fn parse_cpu_max(text: &str) -> io::Result<CpuMax> {
    let mut fields = text.split_ascii_whitespace();
    let quota = fields.next().ok_or_else(|| invalid("missing CPU quota"))?;
    let period = fields.next().ok_or_else(|| invalid("missing CPU period"))?;
    if fields.next().is_some() {
        return Err(invalid("unexpected CPU control field"));
    }
    let quota_micros = parse_limit(quota)?;
    let period_micros = parse_number(period)?;
    if quota_micros == Limit::Value(0) || period_micros == 0 {
        return Err(invalid("CPU quota and period must be nonzero"));
    }
    Ok(CpuMax {
        quota_micros,
        period_micros,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_zero_and_unbounded_limits_are_distinct() {
        assert_eq!(parse_limit("0\n").unwrap(), Limit::Value(0));
        assert_eq!(parse_limit("128\n").unwrap(), Limit::Value(128));
        assert_eq!(parse_limit("max\n").unwrap(), Limit::Unbounded);
        for value in ["", "+1", "-1", "true", "max 1", "18446744073709551616"] {
            assert!(parse_limit(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn cpu_bandwidth_requires_exactly_two_nonzero_fields() {
        assert_eq!(
            parse_cpu_max("200000 100000\n").unwrap(),
            CpuMax {
                quota_micros: Limit::Value(200000),
                period_micros: 100000,
            }
        );
        assert_eq!(
            parse_cpu_max("max 100000\n").unwrap().quota_micros,
            Limit::Unbounded
        );
        for value in ["max", "1 2 3", "0 100000", "max 0", "+1 100000"] {
            assert!(parse_cpu_max(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn ordinary_directories_cannot_impersonate_cgroup_filesystems() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        assert_eq!(
            observe(&directory).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let file = tempfile::tempfile().unwrap();
        assert!(observe(&file).is_err());
    }

    #[test]
    fn descriptor_relative_reads_do_not_follow_links_or_accept_directories() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        std::fs::write(root.path().join("target"), b"128\n").unwrap();
        std::os::unix::fs::symlink("target", root.path().join("memory.max")).unwrap();
        assert_eq!(
            read_control(&directory, c"memory.max")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ELOOP)
        );
        std::fs::create_dir(root.path().join("pids.max")).unwrap();
        assert!(read_control(&directory, c"pids.max").is_err());
        assert!(read_control(&directory, c"memory.swap.max").is_err());
    }

    #[test]
    fn oversized_binary_and_nul_control_bodies_refuse() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        for bytes in [vec![b'1'; 129], vec![255], b"1\0\n".to_vec()] {
            std::fs::write(root.path().join("memory.max"), bytes).unwrap();
            assert_eq!(
                read_control(&directory, c"memory.max").unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn reads_remain_on_the_original_directory_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("original");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("memory.max"), b"128\n").unwrap();
        let directory = File::open(&path).unwrap();
        std::fs::rename(&path, root.path().join("held")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("memory.max"), b"999\n").unwrap();
        assert_eq!(read_control(&directory, c"memory.max").unwrap(), "128\n");
    }

    #[test]
    fn changed_limits_are_new_observations_not_a_stable_bounds_token() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let path = root.path().join("memory.max");
        std::fs::write(&path, b"128\n").unwrap();
        assert_eq!(
            parse_limit(&read_control(&directory, c"memory.max").unwrap()).unwrap(),
            Limit::Value(128)
        );
        std::fs::write(&path, b"max\n").unwrap();
        assert_eq!(
            parse_limit(&read_control(&directory, c"memory.max").unwrap()).unwrap(),
            Limit::Unbounded
        );
    }

    #[test]
    fn unsupported_resolution_flags_refuse_without_an_openat_fallback() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        std::fs::write(root.path().join("memory.max"), b"128\n").unwrap();
        let mut how = control_open_how().unwrap();
        how.resolve |= 1 << 63;
        assert_eq!(
            open_control(&directory, c"memory.max", &how)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    #[ignore = "requires the existing Linux /proc mount boundary; creates no mounts"]
    fn existing_mount_crossing_is_refused_before_reading() {
        let root = File::open("/").unwrap();
        assert_eq!(
            open_control(&root, c"proc", &control_open_how().unwrap())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EXDEV)
        );
    }

    #[test]
    #[ignore = "requires an operator-selected real Linux cgroup-v2 directory"]
    fn observe_real_kernel_controllers_without_modification() {
        let path = std::env::var_os("MVM_TEST_CGROUP_DIR").expect("selected cgroup directory");
        let directory = File::open(path).unwrap();
        let observation = observe(&directory).unwrap();
        assert!(observation.cpu_max.period_micros > 0);
        // Neither finite values nor `max` establish birth placement or containment.
    }
}
