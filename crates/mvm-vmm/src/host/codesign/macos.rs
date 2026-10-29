use super::{RequiredEntitlement, SignReport, SignTarget};
use core_foundation::url::CFURL;
use mvm_core::native_signature::requirement;
pub(super) use mvm_core::native_signature::verify;
#[cfg(test)]
use mvm_core::native_signature::verify_slices;
use security_framework::os::macos::code_signing::SecStaticCode;
use security_framework::os::macos::code_signing::{Flags, SecCode};
use std::{io::Write, path::Path};

type Result<T> = std::result::Result<T, String>;

mod loaded;

fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn signed_bytes(data: &[u8], required: RequiredEntitlement) -> Result<Vec<u8>> {
    let mut entitlements = plist::Dictionary::new();
    for key in required.keys() {
        entitlements.insert((*key).into(), plist::Value::Boolean(true));
    }
    // Import only compatibility metadata, never previous entitlement authority.
    mvm_macho_sign::sign(data, &plist::Value::Dictionary(entitlements)).map_err(error)
}

fn prepare(target: &SignTarget) -> Result<bool> {
    let metadata = std::fs::symlink_metadata(&target.path).map_err(error)?;
    if !metadata.file_type().is_file() {
        return Err("signing requires a regular file, not a symlink or directory".into());
    }
    if verify(&target.path, target.required).is_ok() {
        return Ok(false);
    }
    require_repair_allowed(distribution_signature_valid(&target.path)?)?;
    let original = std::fs::read(&target.path).map_err(error)?;
    let output = signed_bytes(&original, target.required)?;
    install(target, &original, &output, metadata.permissions())?;
    Ok(true)
}

fn distribution_signature_valid(path: &Path) -> Result<bool> {
    let url = CFURL::from_path(path, false).ok_or("invalid executable path")?;
    let Ok(code) = SecStaticCode::from_path(&url, Flags::NONE) else {
        return Ok(false);
    };
    let requirement =
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            .parse()
            .map_err(error)?;
    Ok(code
        .check_validity(Flags::CHECK_ALL_ARCHITECTURES, &requirement)
        .is_ok())
}

pub(super) fn require_repair_allowed(distribution_signature_valid: bool) -> Result<()> {
    if distribution_signature_valid {
        return Err(
            "a valid Developer ID signature lacks the required entitlement; reinstall a correctly entitled distribution rather than replace its signature"
                .into(),
        );
    }
    Ok(())
}

fn install(
    target: &SignTarget,
    original: &[u8],
    output: &[u8],
    permissions: std::fs::Permissions,
) -> Result<()> {
    let parent = target
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(error)?;
    staged.write_all(output).map_err(error)?;
    staged
        .as_file()
        .set_permissions(permissions)
        .map_err(error)?;
    staged.as_file().sync_all().map_err(error)?;
    verify(staged.path(), target.required)?;
    // Refuse an observed concurrent replacement rather than overwrite new content.
    // Destinations must be trusted and exclusively owned or use cooperating
    // writers: this is not a filesystem compare-and-swap against a malicious
    // replacement after the guard.
    if !std::fs::symlink_metadata(&target.path)
        .map_err(error)?
        .file_type()
        .is_file()
    {
        return Err("target is no longer a regular file".into());
    }
    if std::fs::read(&target.path).map_err(error)? != original {
        return Err("target changed during signing; retry preparation".into());
    }
    staged.persist(&target.path).map_err(error)?;
    Ok(())
}

pub(super) fn sign_path(target: &SignTarget) -> SignReport {
    match prepare(target) {
        Ok(applied) => SignReport {
            path: target.path.clone(),
            applied,
            entitlements_present: true,
            error: None,
        },
        Err(error) => SignReport {
            path: target.path.clone(),
            applied: false,
            entitlements_present: false,
            error: Some(error),
        },
    }
}

pub(super) fn ensure_signed() -> Result<()> {
    let required = RequiredEntitlement::Hypervisor;
    let check = || {
        loaded::require_true(required.keys())?;
        let code = SecCode::for_self(Flags::NONE).map_err(error)?;
        code.check_validity(Flags::NONE, &requirement(required)?)
            .map_err(error)?;
        let path = code
            .path(Flags::NONE)
            .map_err(error)?
            .to_path()
            .ok_or("loaded code has no path")?;
        verify(&path, required)
    };
    check().map_err(|e: String| format!(
        "supervisor is not ready: {e}; prepare this executable with sign_targets before launch, then restart it (signing cannot grant entitlements to a running process)"
    ))
}

#[cfg(test)]
mod tests;
