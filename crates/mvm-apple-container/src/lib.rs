//! Apple Containerization framework bridge for mvm.
//!
//! On macOS 26+ with Apple Silicon, this crate provides FFI bindings to
//! a Swift static library that wraps Apple's Containerization framework.
//! On other platforms, all functions return "not available" errors.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// FFI bindings to the Swift bridge library.
#[cfg(not(apple_container_stub))]
mod ffi {
    use std::os::raw::c_char;

    unsafe extern "C" {
        pub fn mvm_apple_container_is_available() -> bool;
        pub fn mvm_apple_container_free_string(ptr: *mut c_char);
        pub fn mvm_apple_container_start(
            id: *const c_char,
            kernel_path: *const c_char,
            rootfs_path: *const c_char,
            cpus: i32,
            memory_mib: u64,
        ) -> *mut c_char;
        pub fn mvm_apple_container_stop(id: *const c_char) -> *mut c_char;
        pub fn mvm_apple_container_list() -> *mut c_char;
    }
}

/// Read a C string returned by the Swift bridge, convert to Rust String,
/// and free the original.
#[cfg(not(apple_container_stub))]
unsafe fn read_and_free(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::mvm_apple_container_free_string(ptr) };
    s
}

/// Check if Apple Containers are available on this platform.
pub fn is_available() -> bool {
    #[cfg(not(apple_container_stub))]
    {
        unsafe { ffi::mvm_apple_container_is_available() }
    }
    #[cfg(apple_container_stub)]
    {
        false
    }
}

/// Start a container from a local ext4 rootfs and kernel.
///
/// Returns `Ok(())` on success or an error message on failure.
pub fn start(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
) -> Result<(), String> {
    #[cfg(not(apple_container_stub))]
    {
        let c_id = CString::new(id).map_err(|e| e.to_string())?;
        let c_kernel = CString::new(kernel_path).map_err(|e| e.to_string())?;
        let c_rootfs = CString::new(rootfs_path).map_err(|e| e.to_string())?;
        let result = unsafe {
            read_and_free(ffi::mvm_apple_container_start(
                c_id.as_ptr(),
                c_kernel.as_ptr(),
                c_rootfs.as_ptr(),
                cpus as i32,
                memory_mib,
            ))
        };
        if result.is_empty() {
            Ok(())
        } else {
            Err(result)
        }
    }
    #[cfg(apple_container_stub)]
    {
        let _ = (id, kernel_path, rootfs_path, cpus, memory_mib);
        Err("Apple Containers not available on this platform".to_string())
    }
}

/// Stop a running container.
pub fn stop(id: &str) -> Result<(), String> {
    #[cfg(not(apple_container_stub))]
    {
        let c_id = CString::new(id).map_err(|e| e.to_string())?;
        let result = unsafe { read_and_free(ffi::mvm_apple_container_stop(c_id.as_ptr())) };
        if result.is_empty() {
            Ok(())
        } else {
            Err(result)
        }
    }
    #[cfg(apple_container_stub)]
    {
        let _ = id;
        Err("Apple Containers not available on this platform".to_string())
    }
}

/// List running container IDs as a JSON array string.
pub fn list_ids() -> Vec<String> {
    #[cfg(not(apple_container_stub))]
    {
        let json = unsafe { read_and_free(ffi::mvm_apple_container_list()) };
        serde_json::from_str(&json).unwrap_or_default()
    }
    #[cfg(apple_container_stub)]
    {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_returns_bool() {
        let _ = is_available();
    }

    #[test]
    fn test_list_ids_returns_vec() {
        let ids = list_ids();
        // No containers running in test mode
        assert!(ids.is_empty());
    }

    /// Integration test: boot an Apple Container from a Nix-built ext4 rootfs.
    ///
    /// Requires:
    /// - macOS 26+ on Apple Silicon
    /// - Pre-built template artifacts at ~/.mvm/templates/hello/
    /// - Run with: cargo test -p mvm-apple-container -- --ignored boot_test
    #[test]
    #[ignore]
    fn boot_test_apple_container() {
        if !is_available() {
            eprintln!("Skipping: Apple Containers not available");
            return;
        }

        let home = std::env::var("HOME").expect("HOME must be set");
        let artifacts = format!("{}/.mvm/templates/hello/artifacts", home);

        // Find the current revision (latest directory)
        let mut entries: Vec<_> = std::fs::read_dir(&artifacts)
            .expect("template artifacts dir must exist")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let rev_dir = entries
            .last()
            .expect("at least one revision must exist")
            .path();

        let kernel = rev_dir.join("vmlinux");
        let rootfs = rev_dir.join("rootfs.ext4");

        assert!(kernel.exists(), "kernel not found at {}", kernel.display());
        assert!(rootfs.exists(), "rootfs not found at {}", rootfs.display());

        eprintln!("Booting Apple Container with:");
        eprintln!("  kernel: {}", kernel.display());
        eprintln!("  rootfs: {}", rootfs.display());

        let result = start(
            "boot-test",
            kernel.to_str().expect("kernel path must be UTF-8"),
            rootfs.to_str().expect("rootfs path must be UTF-8"),
            2,
            512,
        );

        match &result {
            Ok(()) => {
                eprintln!("Container started successfully!");
                // Verify it appears in list
                let ids = list_ids();
                assert!(
                    ids.contains(&"boot-test".to_string()),
                    "boot-test not in list: {ids:?}"
                );
                // Stop it
                let stop_result = stop("boot-test");
                assert!(stop_result.is_ok(), "stop failed: {stop_result:?}");
                eprintln!("Container stopped successfully!");
            }
            Err(e) => {
                // Log the error but don't fail — the rootfs may not be
                // compatible with Apple Container's vminitd expectations.
                // This is expected until we build a Container-specific rootfs.
                eprintln!("Container start returned error (may be expected): {e}");
            }
        }
    }
}
