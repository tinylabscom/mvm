//! In-process preparation and native validation of macOS VM executables.
//!
//! Prepare executables before launch with [`sign_targets`]. Signing an on-disk
//! replacement cannot grant entitlements to an already running process.

use std::path::{Path, PathBuf};

pub use mvm_core::native_signature::RequiredEntitlement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignTarget {
    pub path: PathBuf,
    pub required: RequiredEntitlement,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignReport {
    pub path: PathBuf,
    /// True only after a validated staged signature has been installed.
    pub applied: bool,
    pub entitlements_present: bool,
    /// Preparation failures are never represented as successful application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Validate the native signature and typed entitlements in every Mach-O slice.
pub fn entitlement_present(path: &Path, required: RequiredEntitlement) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::verify(path, required).is_ok())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, required);
        None
    }
}

pub fn entitlements_present(path: &Path) -> Option<bool> {
    entitlement_present(path, RequiredEntitlement::VirtualizationAndHypervisor)
}

pub fn sign_binaries(targets: &[PathBuf]) -> Vec<SignReport> {
    sign_targets(
        &targets
            .iter()
            .cloned()
            .map(|path| SignTarget {
                path,
                required: RequiredEntitlement::VirtualizationAndHypervisor,
            })
            .collect::<Vec<_>>(),
    )
}

/// Prepare role-specific executables before launch, without subprocesses.
/// No-op (empty) off macOS.
pub fn sign_targets(targets: &[SignTarget]) -> Vec<SignReport> {
    #[cfg(target_os = "macos")]
    {
        targets.iter().map(macos::sign_path).collect()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = targets;
        Vec::new()
    }
}

/// Fallibly check the loaded supervisor identity, not just its current on-disk path.
///
/// The installer/preparer must sign before launch; this never mutates or
/// re-executes the running helper. No-op off macOS.
pub fn try_ensure_signed() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::ensure_signed()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

/// Preserve the historical non-fallible entry point.
///
/// Startup paths that must reject an unready supervisor use
/// [`try_ensure_signed`] and propagate its error.
pub fn ensure_signed() {
    let _ = try_ensure_signed();
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn a_distribution_signature_is_never_replaced_to_repair_an_entitlement() {
        let error = macos::require_repair_allowed(true).unwrap_err();
        assert!(error.contains("valid Developer ID signature"), "{error}");
        assert!(error.contains("reinstall"), "{error}");
        macos::require_repair_allowed(false).unwrap();
    }

    #[test]
    fn sign_report_is_serializable() {
        let report = SignReport {
            path: PathBuf::from("/tmp/mvmctl"),
            applied: false,
            entitlements_present: false,
            error: Some("invalid Mach-O".into()),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"applied\":false"));
        assert!(json.contains("invalid Mach-O"));
    }

    #[test]
    fn signer_entrypoints_keep_compatibility_and_fallibility_distinct() {
        let _: fn() = ensure_signed;
        let _: fn() -> std::result::Result<(), String> = try_ensure_signed;
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn signing_is_noop_off_macos() {
        let path = PathBuf::from("/not/an/executable");
        assert_eq!(entitlements_present(&path), None);
        assert!(sign_binaries(&[path]).is_empty());
        assert!(try_ensure_signed().is_ok());
    }
}
