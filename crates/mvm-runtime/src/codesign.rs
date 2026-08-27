//! macOS codesigning of mvm's VMM binaries with their required entitlements.
//!
//! Apple requires the binary that launches a Virtualization.framework VM to
//! carry `com.apple.security.virtualization` and the binary that enters
//! Hypervisor.framework to carry `com.apple.security.hypervisor`. The CLI
//! and per-VM supervisors are signed separately because they have different
//! roles. Everything here is a no-op off macOS.

use std::path::{Path, PathBuf};

/// The macOS entitlement required by a signed mvm executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredEntitlement {
    /// Required by the CLI's Virtualization.framework path.
    Virtualization,
    /// Required by the per-VM Hypervisor.framework supervisor.
    Hypervisor,
    /// The combined profile retained for callers of the legacy bulk API.
    VirtualizationAndHypervisor,
}

#[cfg(target_os = "macos")]
impl RequiredEntitlement {
    fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Virtualization => &["com.apple.security.virtualization"],
            Self::Hypervisor => &["com.apple.security.hypervisor"],
            Self::VirtualizationAndHypervisor => &[
                "com.apple.security.virtualization",
                "com.apple.security.hypervisor",
            ],
        }
    }
}

/// An executable and the entitlement required by its runtime role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignTarget {
    /// Path to the executable to inspect or sign.
    pub path: PathBuf,
    /// Entitlement the executable must carry.
    pub required: RequiredEntitlement,
}

/// Outcome of attempting to sign one binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignReport {
    pub path: PathBuf,
    /// Whether codesign was (re)applied during this call.
    pub applied: bool,
    /// Whether the target's required entitlement is present after signing.
    pub entitlements_present: bool,
}

/// Check whether an executable carries a specific required entitlement.
pub fn entitlement_present(path: &Path, required: RequiredEntitlement) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::entitlement_present(path, required))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, required);
        None
    }
}

/// Check whether an executable carries both historical VM entitlements.
///
/// New callers should use [`entitlement_present`] with the target's specific
/// runtime role. This compatibility wrapper remains for existing consumers of
/// the original bulk signing API.
pub fn entitlements_present(path: &Path) -> Option<bool> {
    entitlement_present(path, RequiredEntitlement::VirtualizationAndHypervisor)
}

/// Ad-hoc re-sign a list of executables with the historical combined profile.
///
/// New callers should use [`sign_targets`] so each executable receives only
/// the entitlement required by its runtime role.
pub fn sign_binaries(targets: &[PathBuf]) -> Vec<SignReport> {
    let targets: Vec<SignTarget> = targets
        .iter()
        .cloned()
        .map(|path| SignTarget {
            path,
            required: RequiredEntitlement::VirtualizationAndHypervisor,
        })
        .collect();
    sign_targets(&targets)
}

/// Ad-hoc re-sign each role-specific target and report the post-sign state.
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

/// Auto-sign the running supervisor on first launch if it lacks the
/// Hypervisor.framework entitlement, then re-exec the signed binary
/// (`MVM_SIGNED=1` guards against a recursion loop). No-op off macOS / when
/// already signed.
pub fn ensure_signed() {
    #[cfg(target_os = "macos")]
    {
        macos::ensure_signed();
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{RequiredEntitlement, SignReport, SignTarget};
    use std::path::Path;

    const VIRTUALIZATION_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\"><dict>\n\
        <key>com.apple.security.virtualization</key><true/>\n\
        </dict></plist>";

    const HYPERVISOR_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\"><dict>\n\
        <key>com.apple.security.hypervisor</key><true/>\n\
        </dict></plist>";

    const COMBINED_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\"><dict>\n\
        <key>com.apple.security.virtualization</key><true/>\n\
        <key>com.apple.security.hypervisor</key><true/>\n\
        </dict></plist>";

    pub(super) fn sign_path(target: &SignTarget) -> SignReport {
        let already = entitlement_present(&target.path, target.required);
        if !already {
            sign_binary(&target.path.to_string_lossy(), target.required);
        }
        SignReport {
            path: target.path.clone(),
            applied: !already,
            entitlements_present: entitlement_present(&target.path, target.required),
        }
    }

    /// Sign the binary ad-hoc with the entitlement required by its role.
    fn sign_binary(exe_str: &str, required: RequiredEntitlement) {
        let ent_path = std::env::temp_dir().join("mvm-entitlements.plist");
        let entitlements = match required {
            RequiredEntitlement::Virtualization => VIRTUALIZATION_ENTITLEMENTS_PLIST,
            RequiredEntitlement::Hypervisor => HYPERVISOR_ENTITLEMENTS_PLIST,
            RequiredEntitlement::VirtualizationAndHypervisor => COMBINED_ENTITLEMENTS_PLIST,
        };
        if std::fs::write(&ent_path, entitlements).is_err() {
            return;
        }
        let _ = std::process::Command::new("codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&ent_path)
            .arg(exe_str)
            .output();
        let _ = std::fs::remove_file(&ent_path);
    }

    /// Read the binary's entitlements XML via codesign.
    fn read_entitlements_xml(path: &Path) -> Option<String> {
        let out = std::process::Command::new("codesign")
            .args(["-d", "--entitlements", "-", "--xml"])
            .arg(path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// True when the executable carries the entitlement required by its role.
    pub(super) fn entitlement_present(path: &Path, required: RequiredEntitlement) -> bool {
        match read_entitlements_xml(path) {
            Some(xml) => required.keys().iter().all(|key| xml.contains(key)),
            None => false,
        }
    }

    pub(super) fn ensure_signed() {
        // Already re-exec'd or launched by launchd with a signed binary.
        if std::env::var("MVM_SIGNED").as_deref() == Ok("1") {
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(_) => return,
        };
        let exe_str = exe.to_str().unwrap_or("");

        // Binaries signed before the hypervisor entitlement was added have
        // only `virtualization`; the missing `hypervisor` key forces a
        // one-time re-sign on first run after upgrade.
        if entitlement_present(&exe, RequiredEntitlement::Hypervisor) {
            return;
        }
        let _ = exe_str;

        tracing::info!("Signing binary with the Hypervisor.framework entitlement...");
        sign_binary(&exe.to_string_lossy(), RequiredEntitlement::Hypervisor);

        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&exe)
            .args(std::env::args_os().skip(1))
            .env("MVM_SIGNED", "1")
            .exec();
        tracing::error!("Re-exec after signing failed: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_report_is_serializable() {
        let r = SignReport {
            path: std::path::PathBuf::from("/tmp/mvmctl"),
            applied: true,
            entitlements_present: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"applied\":true"));
        assert!(json.contains("\"entitlements_present\":true"));
    }

    #[test]
    fn collect_sign_targets_includes_current_exe() {
        let targets = collect_sign_targets();
        let exe = std::env::current_exe().unwrap();
        assert!(targets.iter().any(|target| target.path == exe));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn entitlements_present_is_none_off_macos() {
        assert!(
            entitlement_present(
                std::path::Path::new("/bin/sh"),
                RequiredEntitlement::Virtualization
            )
            .is_none()
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn sign_targets_is_noop_off_macos() {
        let target = SignTarget {
            path: std::path::PathBuf::from("/bin/sh"),
            required: RequiredEntitlement::Virtualization,
        };
        assert!(sign_targets(&[target]).is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn legacy_sign_binaries_is_noop_off_macos() {
        assert!(sign_binaries(&[std::path::PathBuf::from("/bin/sh")]).is_empty());
    }
}
