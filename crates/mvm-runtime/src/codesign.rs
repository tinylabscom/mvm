//! macOS codesigning of mvm's VMM binaries with their required entitlements.
//!
//! The signing itself is [`mvm_vmm::host::codesign`]; this module adds the one
//! piece that needs the concrete backends — finding which supervisors this host
//! has, so `mvmctl env sign` and the self-update path can sign them all.

pub use mvm_vmm::host::codesign::{
    RequiredEntitlement, SignReport, SignTarget, entitlement_present, entitlements_present,
    sign_binaries, sign_targets, try_ensure_signed as ensure_signed,
};

/// An installed release keeps its executables behind symlinks into a versioned
/// directory. The signer refuses to write through a link, so it is handed the
/// real file; a path that cannot be resolved is left as it was.
fn resolve_link(path: std::path::PathBuf) -> std::path::PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// The binaries that need macOS entitlements to launch a VM: the running CLI
/// plus whichever supervisors resolve on this host.
/// Unresolved supervisors are silently skipped (a host may have only
/// one backend installed).
pub fn collect_sign_targets() -> Vec<SignTarget> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        out.push(SignTarget {
            path: resolve_link(exe),
            required: RequiredEntitlement::Virtualization,
        });
    }
    if let Ok(p) = mvm_backends::driver::libkrun_process::resolve_supervisor_path() {
        out.push(SignTarget {
            path: resolve_link(p),
            required: RequiredEntitlement::Hypervisor,
        });
    }
    if let Ok(p) = mvm_backends::driver::hvf_process::resolve_supervisor_path() {
        out.push(SignTarget {
            path: resolve_link(p),
            required: RequiredEntitlement::Hypervisor,
        });
    }
    out.dedup_by(|a, b| a.path == b.path);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_link_returns_the_real_file_behind_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(resolve_link(link), std::fs::canonicalize(&real).unwrap());
        let missing = dir.path().join("missing");
        assert_eq!(resolve_link(missing.clone()), missing);
    }

    #[test]
    fn collect_sign_targets_includes_current_exe() {
        let targets = collect_sign_targets();
        let exe = std::env::current_exe().unwrap();
        assert!(targets.iter().any(|target| target.path == exe));
    }
}
