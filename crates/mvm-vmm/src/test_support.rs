#[cfg(test)]
use std::error::Error;
#[cfg(test)]
use std::os::unix::net::UnixListener;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
fn is_permission_denied_io(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(test)]
pub(crate) fn error_chain_has_permission_denied(err: &(dyn Error + 'static)) -> bool {
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        return is_permission_denied_io(io_err);
    }
    let mut source = err.source();
    while let Some(next) = source {
        if let Some(io_err) = next.downcast_ref::<std::io::Error>()
            && is_permission_denied_io(io_err)
        {
            return true;
        }
        source = next.source();
    }
    false
}

#[cfg(test)]
pub(crate) fn bind_unix_listener(path: &Path) -> Option<UnixListener> {
    if let Some(parent) = path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        if is_permission_denied_io(&err) {
            eprintln!(
                "skipping test: sandbox denied creating Unix socket parent {}: {err}",
                parent.display()
            );
            return None;
        }
        panic!(
            "creating Unix socket parent {} failed: {err}",
            parent.display()
        );
    }
    let _ = std::fs::remove_file(path);
    match UnixListener::bind(path) {
        Ok(listener) => Some(listener),
        Err(err) if is_permission_denied_io(&err) => {
            eprintln!(
                "skipping test: sandbox denied binding Unix socket {}: {err}",
                path.display()
            );
            None
        }
        Err(err) => panic!("binding Unix socket {} failed: {err}", path.display()),
    }
}

/// Allocate `size` bytes of zeroed, **page-aligned** scratch RAM for the VMM
/// device tests and leak it for the process lifetime.
#[cfg(test)]
pub(crate) fn page_aligned_ram(size: usize) -> &'static mut [u8] {
    use std::alloc::{Layout, alloc_zeroed};
    assert!(size > 0, "scratch RAM size must be non-zero");
    // SAFETY: `sysconf(_SC_PAGESIZE)` returns the process page size, a valid
    // power-of-two alignment for `Layout`.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let layout = Layout::from_size_align(size, page).expect("page-aligned layout");
    // SAFETY: `layout` has non-zero size.
    let ptr = unsafe { alloc_zeroed(layout) };
    assert!(!ptr.is_null(), "page-aligned RAM allocation failed");
    // SAFETY: `ptr` is a fresh, uniquely-owned `size`-byte zeroed allocation,
    // intentionally leaked so it stays valid for the whole test process.
    unsafe { std::slice::from_raw_parts_mut(ptr, size) }
}
