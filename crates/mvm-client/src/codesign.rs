//! macOS entitlement repair for mvmctl's VM launch targets.

pub use mvm_runtime::codesign::SignReport;

/// Sign every launch target this host has and report each one. Entitlements
/// exist only on macOS, so elsewhere there is nothing to sign.
pub fn sign_launch_targets() -> Vec<SignReport> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    mvm_runtime::codesign::sign_targets(&mvm_runtime::codesign::collect_sign_targets())
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    #[test]
    fn nothing_to_sign_off_macos() {
        assert!(super::sign_launch_targets().is_empty());
    }
}
