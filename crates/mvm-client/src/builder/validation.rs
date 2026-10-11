use mvm_build::builder_route::{FlakeCheckDispatch, FlakeCheckVerdict};
use mvm_core::build_env::ShellEnvironment;

/// A resolved flake reference, as visible inside the builder execution boundary.
#[derive(Debug, Clone)]
pub struct FlakeValidationRequest {
    pub flake_ref: String,
    /// Stream progress through the build environment rather than capture it.
    pub visible: bool,
}

/// The result of checking a flake. Diagnostics deliberately contain no raw
/// subprocess output: a flake can print credentials from its environment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlakeValidationReport {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum FlakeValidationError {
    #[error("invalid flake reference")]
    InvalidReference,
    #[error("running 'nix flake check' requires an available Linux builder")]
    GuestExecutionUnavailable,
    #[error("typed flake check failed")]
    Transport,
}

/// Validate a resolved flake using the typed builder daemon when available.
/// A failed daemon exchange never falls back to another execution boundary.
pub fn validate_flake(
    request: &FlakeValidationRequest,
) -> Result<FlakeValidationReport, FlakeValidationError> {
    validate_reference(&request.flake_ref)?;
    let vms_root = mvm_build::builder_vm::builder_vm_cache_dir().join("vms");
    match mvm_build::builder_route::try_typed_flake_check(&vms_root, &request.flake_ref) {
        FlakeCheckDispatch::Took(Ok(FlakeCheckVerdict::Valid)) => Ok(verdict(true)),
        FlakeCheckDispatch::Took(Ok(FlakeCheckVerdict::Invalid { .. })) => Ok(verdict(false)),
        FlakeCheckDispatch::Took(Err(_)) => Err(FlakeValidationError::Transport),
        FlakeCheckDispatch::Fellback => validate_fallback(
            request,
            &mvm_runtime::build_env::RuntimeBuildEnv,
            mvm_runtime::linux_env::guest_exec_via_vm_available(),
        ),
    }
}

fn validate_fallback(
    request: &FlakeValidationRequest,
    environment: &dyn ShellEnvironment,
    guest_exec_available: bool,
) -> Result<FlakeValidationReport, FlakeValidationError> {
    if !guest_exec_available {
        return Err(FlakeValidationError::GuestExecutionUnavailable);
    }
    validate_flake_on(request, environment)
}

/// Check on an explicitly supplied builder environment. Embedders and tests use
/// the core shell contract, never a callback containing frontend build policy.
pub fn validate_flake_on(
    request: &FlakeValidationRequest,
    environment: &dyn ShellEnvironment,
) -> Result<FlakeValidationReport, FlakeValidationError> {
    validate_reference(&request.flake_ref)?;
    let quoted = request.flake_ref.replace('\'', "'\\''");
    let script = format!("nix flake check '{quoted}'");
    let valid = if request.visible {
        environment.shell_exec_visible(&script).is_ok()
    } else {
        environment.shell_exec_capture(&script).is_ok()
    };
    Ok(verdict(valid))
}

fn validate_reference(reference: &str) -> Result<(), FlakeValidationError> {
    if reference.trim().is_empty()
        || reference.starts_with('-')
        || reference.contains('\0')
        || mvm_core::naming::validate_flake_ref(reference).is_err()
    {
        return Err(FlakeValidationError::InvalidReference);
    }
    Ok(())
}

fn verdict(valid: bool) -> FlakeValidationReport {
    FlakeValidationReport {
        valid,
        error: (!valid).then(|| "Flake check failed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Environment {
        calls: Mutex<Vec<String>>,
        refuse: bool,
    }

    impl ShellEnvironment for Environment {
        fn shell_exec(&self, script: &str) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push(script.to_string());
            anyhow::ensure!(!self.refuse, "untrusted output containing a credential");
            Ok(())
        }
        fn shell_exec_stdout(&self, script: &str) -> anyhow::Result<String> {
            self.shell_exec(script)?;
            Ok(String::new())
        }
        fn shell_exec_visible(&self, script: &str) -> anyhow::Result<()> {
            self.shell_exec(script)
        }
        fn log_info(&self, _: &str) {}
        fn log_success(&self, _: &str) {}
    }

    fn request(reference: &str) -> FlakeValidationRequest {
        FlakeValidationRequest {
            flake_ref: reference.to_string(),
            visible: false,
        }
    }

    #[test]
    fn valid_reference_is_one_quoted_argument() {
        let environment = Environment::default();
        assert!(
            validate_flake_on(&request("/work/it's a flake"), &environment)
                .unwrap()
                .valid
        );
        assert_eq!(
            *environment.calls.lock().unwrap(),
            ["nix flake check '/work/it'\\''s a flake'"]
        );
    }

    #[test]
    fn invalid_references_never_execute() {
        let environment = Environment::default();
        for reference in ["", " ", "-L", ".;id", "$(id)", "x\0y"] {
            assert!(validate_flake_on(&request(reference), &environment).is_err());
        }
        assert!(environment.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn unavailable_guest_execution_refuses_before_the_flake_check() {
        let environment = Environment::default();
        assert!(matches!(
            validate_fallback(&request("/work"), &environment, false),
            Err(FlakeValidationError::GuestExecutionUnavailable)
        ));
        assert!(environment.calls.lock().unwrap().is_empty());
        assert!(
            validate_fallback(&request("/work"), &environment, true)
                .unwrap()
                .valid
        );
    }

    #[test]
    fn refusal_report_does_not_expose_subprocess_output() {
        let environment = Environment {
            refuse: true,
            ..Environment::default()
        };
        let report = validate_flake_on(&request("/work"), &environment).unwrap();
        assert!(!report.valid);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("credential"));
        assert_eq!(
            serde_json::from_str::<FlakeValidationReport>(&json).unwrap(),
            report
        );
    }

    #[test]
    fn visible_mode_uses_the_same_validation() {
        let environment = Environment::default();
        let mut request = request("github:org/repo");
        request.visible = true;
        assert!(validate_flake_on(&request, &environment).unwrap().valid);
        assert_eq!(environment.calls.lock().unwrap().len(), 1);
    }
}
