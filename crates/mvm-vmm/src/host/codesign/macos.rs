use super::{RequiredEntitlement, SignReport, SignTarget};
use apple_codesign::{MachFile, MachOSigner, SettingsScope, SigningSettings};
use core_foundation::url::CFURL;
use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement, SecStaticCode};
use std::{io::Write, path::Path};

type Result<T> = std::result::Result<T, String>;

mod loaded;

fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn requirement(required: RequiredEntitlement) -> Result<SecRequirement> {
    required
        .keys()
        .iter()
        // The requirement language has no boolean equality literal. `exists`
        // rejects absence/false, but typed checks are still mandatory: use
        // verify_values for disk slices and SecTask values for loaded code.
        .map(|key| format!("entitlement[\"{key}\"] exists"))
        .collect::<Vec<_>>()
        .join(" and ")
        .parse()
        .map_err(error)
}

fn verify_values(value: &plist::Value, required: RequiredEntitlement) -> Result<()> {
    let dict = value
        .as_dictionary()
        .ok_or("entitlements are not a dictionary")?;
    for key in required.keys() {
        if dict.get(key) != Some(&plist::Value::Boolean(true)) {
            return Err(format!("required entitlement {key} is not boolean true"));
        }
    }
    Ok(())
}

fn verify_slices(data: &[u8], required: RequiredEntitlement) -> Result<()> {
    let file = MachFile::parse(data).map_err(error)?;
    let mut count = 0;
    for macho in file.iter_macho() {
        count += 1;
        let signature = macho
            .code_signature()
            .map_err(error)?
            .ok_or("unsigned Mach-O slice")?;
        let xml = signature
            .entitlements()
            .map_err(error)?
            .ok_or("missing entitlements")?;
        let value = plist::Value::from_reader_xml(xml.as_str().as_bytes()).map_err(error)?;
        verify_values(&value, required)?;
        // Modern kernels consume DER; do not accept contradictory XML and DER.
        if let Some(der) = signature.entitlements_der().map_err(error)? {
            verify_values(&der.parse_der().map_err(error)?, required)?;
        }
    }
    if count == 0 {
        return Err("Mach-O has no executable slices".into());
    }
    Ok(())
}

pub(super) fn verify(path: &Path, required: RequiredEntitlement) -> Result<()> {
    let data = std::fs::read(path).map_err(error)?;
    verify_slices(&data, required)?;
    let url = CFURL::from_path(path, false).ok_or("invalid executable path")?;
    let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(error)?;
    code.check_validity(Flags::CHECK_ALL_ARCHITECTURES, &requirement(required)?)
        .map_err(error)
}

fn signed_bytes(data: &[u8], required: RequiredEntitlement) -> Result<Vec<u8>> {
    let mut entitlements = plist::Dictionary::new();
    for key in required.keys() {
        entitlements.insert((*key).into(), plist::Value::Boolean(true));
    }
    let mut xml = Vec::new();
    plist::Value::Dictionary(entitlements)
        .to_writer_xml(&mut xml)
        .map_err(error)?;
    let xml = String::from_utf8(xml).map_err(error)?;
    let file = MachFile::parse(data).map_err(error)?;
    if file.iter_macho().next().is_none() {
        return Err("Mach-O has no executable slices".into());
    }
    // Set the role first, so importing compatibility settings cannot inherit
    // unrelated entitlements. Preserve identifiers, hardening, launch constraints,
    // embedded Info.plist and old-platform digest requirements, but no signing key.
    let mut settings = SigningSettings::default();
    settings
        .set_entitlements_xml(SettingsScope::Main, &xml)
        .map_err(error)?;
    settings.import_settings_from_macho(data).map_err(error)?;
    let identifier = settings
        .binary_identifier(SettingsScope::MultiArchIndex(0))
        .unwrap_or("com.mvm.prepared")
        .to_owned();
    for (index, _) in file.iter_macho().enumerate() {
        let scope = SettingsScope::MultiArchIndex(index);
        settings
            .set_entitlements_xml(scope.clone(), &xml)
            .map_err(error)?;
        if settings.binary_identifier(&scope).is_none() {
            settings.set_binary_identifier(scope, &identifier);
        }
    }
    let mut output = Vec::new();
    MachOSigner::new(data)
        .map_err(error)?
        .write_signed_binary(&settings, &mut output)
        .map_err(error)?;
    Ok(output)
}

fn prepare(target: &SignTarget) -> Result<bool> {
    let metadata = std::fs::symlink_metadata(&target.path).map_err(error)?;
    if !metadata.file_type().is_file() {
        return Err("signing requires a regular file, not a symlink or directory".into());
    }
    if verify(&target.path, target.required).is_ok() {
        return Ok(false);
    }
    let original = std::fs::read(&target.path).map_err(error)?;
    let output = signed_bytes(&original, target.required)?;
    install(target, &original, &output, metadata.permissions())?;
    Ok(true)
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
