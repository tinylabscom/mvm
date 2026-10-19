//! Fixed macOS VM entitlement policy and in-process native signature validation.
//! Verification does not sign, mutate, authenticate a publisher, or execute code.

/// The macOS entitlement required by a signed mvm executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredEntitlement {
    Virtualization,
    Hypervisor,
    VirtualizationAndHypervisor,
}

impl RequiredEntitlement {
    pub fn keys(self) -> &'static [&'static str] {
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

#[cfg(target_os = "macos")]
pub use macos::{requirement, verify, verify_slices, verify_values};

#[cfg(target_os = "macos")]
mod macos {
    use super::RequiredEntitlement;
    use core_foundation::url::CFURL;
    use security_framework::os::macos::code_signing::SecRequirement;
    use security_framework::os::macos::code_signing::{Flags, SecStaticCode};
    use std::path::Path;

    type Result<T> = std::result::Result<T, String>;

    pub fn requirement(required: RequiredEntitlement) -> Result<SecRequirement> {
        required
            .keys()
            .iter()
            .map(|key| format!("entitlement[\"{key}\"] exists"))
            .collect::<Vec<_>>()
            .join(" and ")
            .parse()
            .map_err(|error: security_framework::base::Error| error.to_string())
    }

    pub fn verify_values(value: &plist::Value, required: RequiredEntitlement) -> Result<()> {
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

    pub fn verify_slices(data: &[u8], required: RequiredEntitlement) -> Result<()> {
        for macho in mvm_macho_sign::slices(data).map_err(|error| error.to_string())? {
            let signature = macho.signature_blobs().map_err(|error| error.to_string())?;
            let xml = signature.get(&5).ok_or("missing entitlements")?;
            if xml.get(..4) != Some(&0xfade_7171u32.to_be_bytes()) {
                return Err("invalid XML entitlement blob".into());
            }
            let value =
                plist::Value::from_reader_xml(&xml[8..]).map_err(|error| error.to_string())?;
            verify_values(&value, required)?;
            if let Some(der) = signature.get(&7) {
                if der.get(..4) != Some(&0xfade_7172u32.to_be_bytes()) {
                    return Err("invalid DER entitlement blob".into());
                }
                let der = mvm_macho_sign::decode_entitlements_der(&der[8..])
                    .map_err(|error| error.to_string())?;
                verify_values(&der, required)?;
                if der != value {
                    return Err("XML and DER entitlements disagree".into());
                }
            }
        }
        Ok(())
    }

    pub fn verify(path: &Path, required: RequiredEntitlement) -> Result<()> {
        let data = std::fs::read(path).map_err(|error| error.to_string())?;
        verify_slices(&data, required)?;
        let url = CFURL::from_path(path, false).ok_or("invalid executable path")?;
        let code =
            SecStaticCode::from_path(&url, Flags::NONE).map_err(|error| error.to_string())?;
        code.check_validity(Flags::CHECK_ALL_ARCHITECTURES, &requirement(required)?)
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn native_parser_refuses_empty_malformed_and_truncated_data_without_feature_gate() {
            for bytes in [b"".as_slice(), b"not a Mach-O", &[0xcf, 0xfa, 0xed, 0xfe]] {
                assert!(verify_slices(bytes, RequiredEntitlement::Hypervisor).is_err());
            }
        }

        #[test]
        fn fixed_role_entitlements_require_boolean_true() {
            for value in [
                plist::Value::Boolean(false),
                plist::Value::String("true".into()),
            ] {
                let mut dict = plist::Dictionary::new();
                dict.insert("com.apple.security.hypervisor".into(), value);
                assert!(
                    verify_values(
                        &plist::Value::Dictionary(dict),
                        RequiredEntitlement::Hypervisor
                    )
                    .is_err()
                );
            }
            let mut dict = plist::Dictionary::new();
            dict.insert(
                "com.apple.security.hypervisor".into(),
                plist::Value::Boolean(true),
            );
            let value = plist::Value::Dictionary(dict);
            assert!(verify_values(&value, RequiredEntitlement::Hypervisor).is_ok());
            assert!(
                verify_values(&value, RequiredEntitlement::VirtualizationAndHypervisor).is_err()
            );
        }
    }
}
