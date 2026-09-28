//! macOS codesigning of mvm's VMM binaries with their required entitlements.
//!
//! The signing itself is [`mvm_vmm::host::codesign`]; this module adds the one
//! piece that needs the concrete backends — finding which supervisors this host
//! has, so `mvmctl env sign` and the self-update path can sign them all.

pub use mvm_vmm::host::codesign::{
    RequiredEntitlement, SignReport, SignTarget, ensure_signed, entitlement_present,
    entitlements_present, sign_binaries, sign_targets,
};

/// The binaries that need macOS entitlements to launch a VM: the running CLI
/// plus whichever supervisors resolve on this host.
/// Unresolved supervisors are silently skipped (a host may have only
/// one backend installed).
pub fn collect_sign_targets() -> Vec<SignTarget> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        out.push(SignTarget {
            path: exe,
            required: RequiredEntitlement::Virtualization,
        });
    }
    if let Ok(p) = mvm_backends::driver::libkrun_process::resolve_supervisor_path() {
        out.push(SignTarget {
            path: p,
            required: RequiredEntitlement::Hypervisor,
        });
    }
    if let Ok(p) = mvm_backends::driver::hvf_process::resolve_supervisor_path() {
        out.push(SignTarget {
            path: p,
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
    fn collect_sign_targets_includes_current_exe() {
        let targets = collect_sign_targets();
        let exe = std::env::current_exe().unwrap();
        assert!(targets.iter().any(|target| target.path == exe));
    }
}
