//! Probe the host's capacity, or load it from an inventory file.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::mvmd_iface::host_inventory::HostCapacity;

/// Capacity of this host: logical cores, physical memory, and the size of the
/// filesystem holding the mvm home.
///
/// # Errors
/// When the OS refuses to report a figure.
pub fn probe_host_capacity() -> Result<HostCapacity> {
    let cores = std::thread::available_parallelism().context("reading the core count")?;
    Ok(HostCapacity {
        total_vcpus: u32::try_from(cores.get()).unwrap_or(u32::MAX),
        total_mem_mib: total_memory_bytes()? / (1024 * 1024),
        total_disk_gib: filesystem_bytes(&mvm_core::config::mvm_home())? / (1024 * 1024 * 1024),
    })
}

/// Read a [`HostCapacity`] from a JSON inventory override.
///
/// # Errors
/// An unreadable file, malformed JSON, or an unknown field.
pub fn load_inventory(path: &Path) -> Result<HostCapacity> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading inventory {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing inventory {}", path.display()))
}

#[cfg(target_os = "macos")]
fn total_memory_bytes() -> Result<u64> {
    let mut mem: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: the name is NUL-terminated; `mem` and `len` are valid for the
    // write sysctl performs, and `len` holds the size of `mem`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&raw mut mem).cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || mem == 0 {
        bail!("sysctl hw.memsize: {}", std::io::Error::last_os_error());
    }
    Ok(mem)
}

#[cfg(not(target_os = "macos"))]
fn total_memory_bytes() -> Result<u64> {
    // SAFETY: sysconf takes an integer name and has no memory preconditions.
    let (pages, page) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    match (u64::try_from(pages), u64::try_from(page)) {
        (Ok(p), Ok(s)) if p > 0 && s > 0 => Ok(p.saturating_mul(s)),
        _ => bail!("sysconf could not report physical memory"),
    }
}

/// Size of the filesystem holding `path`, or its nearest existing ancestor
/// (the mvm home need not exist yet).
fn filesystem_bytes(path: &str) -> Result<u64> {
    let mut dir = PathBuf::from(path);
    while !dir.exists() {
        if !dir.pop() {
            bail!("no existing ancestor of {path}");
        }
    }
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
        .context("path holds a NUL byte")?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `c` is a valid NUL-terminated path and `st` is writable storage
    // of the right type; it is read only after statvfs reports success.
    let rc = unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) };
    if rc != 0 {
        bail!(
            "statvfs {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: statvfs returned 0, so it initialised the struct.
    let st = unsafe { st.assume_init() };
    #[allow(clippy::unnecessary_cast)] // field widths differ per platform
    Ok((st.f_blocks as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("inv.json");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn probe_reports_nonzero_figures() {
        let c = probe_host_capacity().unwrap();
        assert!(c.total_vcpus > 0);
        assert!(c.total_mem_mib > 0);
        assert!(c.total_disk_gib > 0);
    }

    #[test]
    fn filesystem_probe_walks_up_to_an_existing_ancestor() {
        assert!(filesystem_bytes("/definitely/not/here/at/all").unwrap() > 0);
    }

    #[test]
    fn inventory_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let want = HostCapacity {
            total_vcpus: 8,
            total_mem_mib: 16384,
            total_disk_gib: 500,
        };
        let p = write(dir.path(), &serde_json::to_string(&want).unwrap());
        assert_eq!(load_inventory(&p).unwrap(), want);
    }

    #[test]
    fn inventory_rejects_unknown_fields_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let extra = r#"{"total_vcpus":1,"total_mem_mib":1,"total_disk_gib":1,"gpus":2}"#;
        assert!(load_inventory(&write(dir.path(), extra)).is_err());
        assert!(load_inventory(&write(dir.path(), "{not json")).is_err());
        assert!(load_inventory(&dir.path().join("missing.json")).is_err());
    }
}
