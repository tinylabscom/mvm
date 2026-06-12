//! macOS codesigning of mvm's VMM binaries with the Virtualization +
//! Hypervisor entitlements.
//!
//! Apple Virtualization.framework refuses to launch a VM unless the
//! launching binary carries both `com.apple.security.virtualization` and
//! `com.apple.security.hypervisor`. The CLI (`mvmctl`) and whichever
//! per-VM supervisor a backend resolves (vz / libkrun) must both be
//! signed. Everything here is a no-op off macOS.

use std::path::{Path, PathBuf};

/// Outcome of attempting to sign one binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignReport {
    pub path: PathBuf,
    /// Whether codesign was (re)applied during this call.
    pub applied: bool,
    /// Whether both VZ + Hypervisor entitlements are present after.
    pub entitlements_present: bool,
}

/// `Some(true/false)` on macOS (both required entitlements present?),
/// `None` on platforms where the question is meaningless.
pub fn entitlements_present(path: &Path) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::entitlements_present(path))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        None
    }
}

/// Ad-hoc re-sign each target with the VZ + Hypervisor entitlements and
/// report the post-sign state. No-op (empty) off macOS.
pub fn sign_binaries(targets: &[PathBuf]) -> Vec<SignReport> {
    #[cfg(target_os = "macos")]
    {
        targets.iter().map(|p| macos::sign_path(p)).collect()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = targets;
        Vec::new()
    }
}

/// The binaries that need VZ/Hypervisor entitlements to launch a VM:
/// the running CLI plus whichever supervisors resolve on this host.
/// Unresolved supervisors are silently skipped (a host may have only
/// one backend installed).
pub fn collect_sign_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        out.push(exe);
    }
    if let Ok(p) = crate::vz::resolve_supervisor_path() {
        out.push(p);
    }
    if let Ok(p) = crate::libkrun::resolve_supervisor_path() {
        out.push(p);
    }
    out.dedup();
    out
}

/// Auto-sign the running CLI on first launch if it lacks the
/// entitlements, then re-exec the signed binary (`MVM_SIGNED=1` guards
/// against a recursion loop). No-op off macOS / when already signed.
pub fn ensure_signed() {
    #[cfg(target_os = "macos")]
    {
        macos::ensure_signed();
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::SignReport;
    use std::path::Path;

    /// Ad-hoc entitlements plist applied by [`sign_binary`]. Lifted to a
    /// const so the entitlement set is testable — inlining the XML would
    /// make the "did we keep both keys" invariant invisible to CI.
    const ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\"><dict>\n\
        <key>com.apple.security.virtualization</key><true/>\n\
        <key>com.apple.security.hypervisor</key><true/>\n\
        </dict></plist>";

    pub(super) fn sign_path(path: &Path) -> SignReport {
        let already = entitlements_present(path);
        if !already {
            sign_binary(&path.to_string_lossy());
        }
        SignReport {
            path: path.to_path_buf(),
            applied: !already,
            entitlements_present: entitlements_present(path),
        }
    }

    /// Sign the binary ad-hoc with both VZ and Hypervisor.framework
    /// entitlements (no self-restart).
    fn sign_binary(exe_str: &str) {
        let ent_path = std::env::temp_dir().join("mvm-entitlements.plist");
        if std::fs::write(&ent_path, ENTITLEMENTS_PLIST).is_err() {
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

    /// True only when BOTH the virtualization and hypervisor entitlements
    /// are present (the launch path requires both).
    pub(super) fn entitlements_present(path: &Path) -> bool {
        match read_entitlements_xml(path) {
            Some(xml) => {
                xml.contains("com.apple.security.virtualization")
                    && xml.contains("com.apple.security.hypervisor")
            }
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
        if entitlements_present(&exe) {
            return;
        }
        let _ = exe_str;

        tracing::info!("Signing binary with virtualization + hypervisor entitlements...");
        sign_binary(&exe.to_string_lossy());

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
        assert!(targets.contains(&exe));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn entitlements_present_is_none_off_macos() {
        assert!(entitlements_present(std::path::Path::new("/bin/sh")).is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn sign_binaries_is_noop_off_macos() {
        assert!(sign_binaries(&[std::path::PathBuf::from("/bin/sh")]).is_empty());
    }
}
