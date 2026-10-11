//! Preview and repair role-specific macOS signing without exposing backend types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Signing is opt-in. Preview only inspects the currently resolved targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    #[serde(default)]
    pub apply: bool,
}

/// The established command JSON row; no private signer implementation crosses
/// the client boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SignTargetReport {
    pub path: PathBuf,
    /// True only when signing succeeded, not merely when it was attempted.
    pub applied: bool,
    pub entitlements_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SignReport {
    pub supported: bool,
    pub targets: Vec<SignTargetReport>,
}

impl SignReport {
    pub fn is_complete(&self) -> bool {
        self.supported
            && self
                .targets
                .iter()
                .all(|target| target.entitlements_present && target.error.is_none())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing target configuration: {0}")]
    Configuration(String),
    #[error("cannot inspect signing target {path:?}: {kind}")]
    Metadata {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    #[error("signing target must be an absolute regular file without parent traversal: {0:?}")]
    InvalidTarget(PathBuf),
}

trait Signer {
    fn supported(&self) -> bool;
    fn targets(&self) -> Result<Vec<mvm_vmm::host::codesign::SignTarget>, SignError>;
    fn inspect(&self, target: &mvm_vmm::host::codesign::SignTarget) -> bool;
    fn apply(&self, target: &mvm_vmm::host::codesign::SignTarget) -> Result<bool, String>;
}

struct HostSigner {
    targets: Vec<mvm_vmm::host::codesign::SignTarget>,
}

impl Signer for HostSigner {
    fn supported(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn targets(&self) -> Result<Vec<mvm_vmm::host::codesign::SignTarget>, SignError> {
        Ok(self.targets.clone())
    }

    fn inspect(&self, target: &mvm_vmm::host::codesign::SignTarget) -> bool {
        mvm_vmm::host::codesign::entitlement_present(&target.path, target.required).unwrap_or(false)
    }

    fn apply(&self, target: &mvm_vmm::host::codesign::SignTarget) -> Result<bool, String> {
        let report = mvm_vmm::host::codesign::sign_targets(std::slice::from_ref(target))
            .into_iter()
            .next()
            .ok_or_else(|| "signing provider returned no result".to_owned())?;
        if let Some(error) = report.error {
            return Err(error);
        }
        if report.entitlements_present {
            Ok(report.applied)
        } else {
            Err("signing did not establish the required signature and entitlements".to_owned())
        }
    }
}

/// Re-resolve and inspect targets on every call. Preview reports are deliberately
/// not accepted as authority to sign paths later. Failed signing is represented
/// by an error and `applied: false`, including in JSON output.
pub fn sign(request: &SignRequest) -> Result<SignReport, SignError> {
    if !cfg!(target_os = "macos") {
        return Ok(SignReport {
            supported: false,
            targets: Vec::new(),
        });
    }
    let (targets, _guard) =
        crate::builder_images::host_helpers::registered_sign_targets(request.apply)
            .map_err(|error| SignError::Configuration(format!("{error:#}")))?;
    sign_with(request, &HostSigner { targets })
}

fn sign_with(request: &SignRequest, signer: &impl Signer) -> Result<SignReport, SignError> {
    if !signer.supported() {
        return Ok(SignReport {
            supported: false,
            targets: Vec::new(),
        });
    }
    let targets = signer.targets()?;
    if targets.is_empty() {
        return Err(SignError::Configuration(
            "no explicit signing targets were registered".into(),
        ));
    }
    // Validate the entire set before changing any executable.
    for target in &targets {
        if !target.path.is_absolute()
            || target
                .path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(SignError::InvalidTarget(target.path.clone()));
        }
        let metadata =
            std::fs::symlink_metadata(&target.path).map_err(|error| SignError::Metadata {
                path: target.path.clone(),
                kind: error.kind(),
            })?;
        if !metadata.is_file() {
            return Err(SignError::InvalidTarget(target.path.clone()));
        }
    }
    let mut reports = Vec::new();
    for target in targets {
        let already = signer.inspect(&target);
        let attempted = request.apply && !already;
        let (mut applied, mut error) = if attempted {
            match signer.apply(&target) {
                Ok(applied) => (applied, None),
                Err(error) => (false, Some(error)),
            }
        } else {
            (false, None)
        };
        let entitlements_present = if attempted {
            signer.inspect(&target)
        } else {
            already
        };
        if attempted && !entitlements_present {
            applied = false;
            error.get_or_insert_with(|| {
                "required signature and entitlements are absent after signing".into()
            });
        }
        reports.push(SignTargetReport {
            path: target.path.clone(),
            applied,
            entitlements_present,
            error,
        });
    }
    Ok(SignReport {
        supported: true,
        targets: reports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Fake {
        path: PathBuf,
        supported: bool,
        signed: Cell<bool>,
        attempts: Cell<usize>,
        fail: bool,
        unverified_success: bool,
    }

    impl Signer for Fake {
        fn supported(&self) -> bool {
            self.supported
        }
        fn targets(&self) -> Result<Vec<mvm_vmm::host::codesign::SignTarget>, SignError> {
            Ok(vec![mvm_vmm::host::codesign::SignTarget {
                path: self.path.clone(),
                required: mvm_vmm::host::codesign::RequiredEntitlement::Hypervisor,
            }])
        }
        fn inspect(&self, _: &mvm_vmm::host::codesign::SignTarget) -> bool {
            self.signed.get()
        }
        fn apply(&self, _: &mvm_vmm::host::codesign::SignTarget) -> Result<bool, String> {
            self.attempts.set(self.attempts.get() + 1);
            if self.unverified_success {
                return Ok(true);
            }
            self.signed.set(!self.fail);
            if self.fail {
                Err("fixture signing failure".into())
            } else {
                Ok(true)
            }
        }
    }

    fn fake(path: PathBuf) -> Fake {
        Fake {
            path,
            supported: true,
            signed: Cell::new(false),
            attempts: Cell::new(0),
            fail: false,
            unverified_success: false,
        }
    }

    #[test]
    fn target_configuration_failure_never_inspects_or_signs() {
        struct Unregistered;
        impl Signer for Unregistered {
            fn supported(&self) -> bool {
                true
            }
            fn targets(&self) -> Result<Vec<mvm_vmm::host::codesign::SignTarget>, SignError> {
                Err(SignError::Configuration(
                    "register an explicit install target".into(),
                ))
            }
            fn inspect(&self, _: &mvm_vmm::host::codesign::SignTarget) -> bool {
                panic!("configuration failure must stop before inspection")
            }
            fn apply(&self, _: &mvm_vmm::host::codesign::SignTarget) -> Result<bool, String> {
                panic!("configuration failure must stop before signing")
            }
        }
        for apply in [false, true] {
            assert!(matches!(
                sign_with(&SignRequest { apply }, &Unregistered),
                Err(SignError::Configuration(_))
            ));
        }
    }

    #[test]
    fn preview_apply_and_reclassification_use_current_state() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let signer = fake(file.path().to_owned());
        let request: SignRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.apply);
        assert!(!sign_with(&request, &signer).unwrap().is_complete());
        assert_eq!(signer.attempts.get(), 0);
        assert!(
            sign_with(&SignRequest { apply: true }, &signer)
                .unwrap()
                .is_complete()
        );
        assert!(
            sign_with(&SignRequest { apply: true }, &signer)
                .unwrap()
                .is_complete()
        );
        assert_eq!(signer.attempts.get(), 1);
        signer.signed.set(false);
        sign_with(&SignRequest { apply: true }, &signer).unwrap();
        assert_eq!(signer.attempts.get(), 2);
    }

    #[test]
    fn signing_failure_remains_visible_and_wire_rows_are_compatible() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut signer = fake(file.path().to_owned());
        signer.fail = true;
        let report = sign_with(&SignRequest { apply: true }, &signer).unwrap();
        assert!(!report.is_complete());
        assert!(!report.targets[0].applied);
        assert_eq!(
            serde_json::to_value(&report.targets[0]).unwrap(),
            serde_json::json!({
                "path": file.path(), "applied": false, "entitlements_present": false,
                "error": "fixture signing failure"
            })
        );
        let roundtrip: SignReport =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(roundtrip, report);
    }

    #[test]
    fn legacy_rows_without_error_remain_readable() {
        let row: SignTargetReport = serde_json::from_value(serde_json::json!({
            "path": "/fixture", "applied": false, "entitlements_present": true
        }))
        .unwrap();
        assert!(row.error.is_none());
        assert!(
            SignReport {
                supported: true,
                targets: vec![row]
            }
            .is_complete()
        );
    }

    #[test]
    fn claimed_signing_success_requires_post_sign_verification() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut signer = fake(file.path().to_owned());
        signer.unverified_success = true;
        let report = sign_with(&SignRequest { apply: true }, &signer).unwrap();
        assert_eq!(signer.attempts.get(), 1);
        assert!(!report.is_complete());
        assert!(!report.targets[0].applied);
        assert!(!report.targets[0].entitlements_present);
        assert!(
            report.targets[0]
                .error
                .as_deref()
                .unwrap()
                .contains("after signing")
        );
    }

    #[test]
    fn unsupported_and_bad_paths_never_sign() {
        let mut signer = fake(PathBuf::from("/missing-sign-target"));
        signer.supported = false;
        assert!(
            !sign_with(&SignRequest { apply: true }, &signer)
                .unwrap()
                .supported
        );
        signer.supported = true;
        assert!(matches!(
            sign_with(&SignRequest { apply: true }, &signer),
            Err(SignError::Metadata { .. })
        ));
        signer.path = PathBuf::from("/tmp/../sign-target");
        assert!(matches!(
            sign_with(&SignRequest { apply: true }, &signer),
            Err(SignError::InvalidTarget(_))
        ));
        signer.path = PathBuf::from("relative");
        assert!(sign_with(&SignRequest { apply: true }, &signer).is_err());
        assert_eq!(signer.attempts.get(), 0);
        assert!(serde_json::from_str::<SignRequest>(r#"{"force":true}"#).is_err());
    }
}
