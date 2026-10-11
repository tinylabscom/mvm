use super::*;
use apple_codesign::{UniversalBinaryBuilder, macho_builder::MachOBuilder};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn fixture(arm: bool) -> Vec<u8> {
    // MH_EXECUTE; these fixtures are parsed and validated, never executed.
    let builder = if arm {
        MachOBuilder::new_aarch64(2)
    } else {
        MachOBuilder::new_x86_64(2)
    };
    builder.write_macho().unwrap()
}

fn target(dir: &Path, bytes: &[u8], required: RequiredEntitlement) -> SignTarget {
    let path = dir.join("fixture");
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
    SignTarget { path, required }
}

#[test]
fn native_signing_is_atomic_role_specific_and_idempotent() {
    for required in [
        RequiredEntitlement::Hypervisor,
        RequiredEntitlement::Virtualization,
        RequiredEntitlement::VirtualizationAndHypervisor,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let target = target(dir.path(), &fixture(true), required);
        let old_inode = std::fs::metadata(&target.path).unwrap().ino();
        let report = sign_path(&target);
        assert!(report.applied, "{report:?}");
        assert!(report.entitlements_present, "{report:?}");
        assert!(report.error.is_none());
        verify(&target.path, required).unwrap();
        assert_ne!(old_inode, std::fs::metadata(&target.path).unwrap().ino());
        assert_eq!(
            std::fs::metadata(&target.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        if required != RequiredEntitlement::VirtualizationAndHypervisor {
            let other = if required == RequiredEntitlement::Hypervisor {
                RequiredEntitlement::Virtualization
            } else {
                RequiredEntitlement::Hypervisor
            };
            assert!(verify(&target.path, other).is_err());
        }
        let bytes = std::fs::read(&target.path).unwrap();
        let inode = std::fs::metadata(&target.path).unwrap().ino();
        let report = sign_path(&target);
        assert!(!report.applied, "{report:?}");
        assert!(report.entitlements_present);
        assert_eq!(bytes, std::fs::read(&target.path).unwrap());
        assert_eq!(inode, std::fs::metadata(&target.path).unwrap().ino());
    }
}

#[test]
fn native_validity_rejects_tampered_code_even_with_entitlements() {
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &fixture(true), RequiredEntitlement::Hypervisor);
    assert!(sign_path(&target).applied);
    let mut bytes = std::fs::read(&target.path).unwrap();
    // Padding in the signed __TEXT page; leaves the Mach-O and plist parseable.
    bytes[2048] ^= 1;
    verify_slices(&bytes, target.required).unwrap();
    std::fs::write(&target.path, bytes).unwrap();
    assert!(verify(&target.path, target.required).is_err());
}

#[test]
fn changing_role_does_not_inherit_previous_entitlements() {
    let dir = tempfile::tempdir().unwrap();
    let mut target = target(
        dir.path(),
        &fixture(true),
        RequiredEntitlement::Virtualization,
    );
    assert!(sign_path(&target).applied);
    target.required = RequiredEntitlement::Hypervisor;
    let report = sign_path(&target);
    assert!(report.applied, "{report:?}");
    verify(&target.path, target.required).unwrap();
    assert!(verify(&target.path, RequiredEntitlement::Virtualization).is_err());
}

#[test]
fn false_and_string_entitlements_are_not_authority() {
    for value in ["<false/>", "<string>true</string>"] {
        let mut settings = SigningSettings::default();
        settings.set_binary_identifier(SettingsScope::Main, "com.mvm.invalid-entitlement");
        settings.set_entitlements_xml(SettingsScope::Main, format!(
            "<plist version=\"1.0\"><dict><key>com.apple.security.hypervisor</key>{value}</dict></plist>"
        )).unwrap();
        let mut bytes = Vec::new();
        MachOSigner::new(&fixture(true))
            .unwrap()
            .write_signed_binary(&settings, &mut bytes)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = target(dir.path(), &bytes, RequiredEntitlement::Hypervisor);
        // The OS accepts the signature itself, but our typed policy refuses it.
        let url = CFURL::from_path(&target.path, false).unwrap();
        let code = SecStaticCode::from_path(&url, Flags::NONE).unwrap();
        code.check_validity(Flags::CHECK_ALL_ARCHITECTURES, &"true".parse().unwrap())
            .unwrap();
        assert!(verify(&target.path, target.required).is_err());
    }
}

#[test]
fn failed_preparation_keeps_original_and_reports_failure() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"not a Mach-O";
    let target = target(dir.path(), bytes, RequiredEntitlement::Hypervisor);
    let inode = std::fs::metadata(&target.path).unwrap().ino();
    let report = sign_path(&target);
    assert!(!report.applied);
    assert!(!report.entitlements_present);
    assert!(report.error.is_some());
    assert_eq!(std::fs::read(&target.path).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&target.path).unwrap().ino(), inode);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn universal_requires_every_slice_and_signs_both() {
    let required = RequiredEntitlement::Hypervisor;
    let mut fat = UniversalBinaryBuilder::default();
    fat.add_binary(signed_bytes(&fixture(true), required).unwrap())
        .unwrap();
    fat.add_binary(signed_bytes(&fixture(false), RequiredEntitlement::Virtualization).unwrap())
        .unwrap();
    let mut bytes = Vec::new();
    fat.write(&mut bytes).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &bytes, required);
    assert!(verify(&target.path, required).is_err());
    let report = sign_path(&target);
    assert!(report.applied, "{report:?}");
    verify(&target.path, required).unwrap();
    let bytes = std::fs::read(&target.path).unwrap();
    assert_eq!(MachFile::parse(&bytes).unwrap().iter_macho().count(), 2);
}

#[test]
fn failed_native_staging_validation_preserves_original_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let original = fixture(true);
    let target = target(dir.path(), &original, RequiredEntitlement::Hypervisor);
    let mut corrupted = signed_bytes(&original, target.required).unwrap();
    corrupted[2048] ^= 1;
    verify_slices(&corrupted, target.required).unwrap();
    let metadata = std::fs::metadata(&target.path).unwrap();
    assert!(install(&target, &original, &corrupted, metadata.permissions()).is_err());
    assert_eq!(std::fs::read(&target.path).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&target.path).unwrap().ino(),
        metadata.ino()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn symlink_is_not_a_signing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &fixture(true), RequiredEntitlement::Hypervisor);
    let bytes = std::fs::read(&target.path).unwrap();
    let link = dir.path().join("symlink");
    std::os::unix::fs::symlink(&target.path, &link).unwrap();
    let report = sign_path(&SignTarget {
        path: link,
        required: target.required,
    });
    assert!(!report.applied);
    assert!(report.error.is_some());
    assert_eq!(std::fs::read(&target.path).unwrap(), bytes);
}
