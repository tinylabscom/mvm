//! Opening the terminal a machine's signed plan admits for its application.
//!
//! A plan carrying an application-terminal grant names one exact argv. The
//! terminal runs that argv as the workload user, with the host-provisioned
//! environment the machine was started with: the egress proxy, the CA bundle
//! and secret placeholders, never a raw secret. A caller cannot choose the
//! program or add its own environment, and the guest agent checks the argv a
//! second time against the host-signed grant. Terminals stay development-only:
//! a sealed production image refuses every console request whatever its plan
//! carries.

use mvm_contract::grants::ApplicationTerminalGrant;

/// What a console request asked for, before the plan is consulted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminalRequest {
    /// The argv the caller named. Empty asks for the default.
    pub argv: Vec<String>,
    /// Variables the caller added.
    pub env: Vec<(String, String)>,
}

/// Why a terminal request was refused before anything reached the guest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TerminalRequestError {
    #[error(
        "machine {machine:?} admits an application terminal for {program:?}, and its \
         environment comes from the host; drop --env and declare the variables in the image \
         or the plan instead"
    )]
    CallerEnvironment { machine: String, program: String },
    #[error(
        "machine {machine:?} admits an application terminal for {program:?} only; drop the \
         argv to open it, or start a machine whose plan admits the program you named"
    )]
    OtherProgram { machine: String, program: String },
}

/// The argv and environment a console on `machine` opens with.
///
/// Without an application-terminal grant the request passes through
/// unchanged. With one, the granted argv and the machine's host-provisioned
/// environment replace the defaults, and a request naming another program or
/// its own variables is refused.
pub fn resolve_terminal_request(
    machine: &str,
    request: TerminalRequest,
) -> Result<TerminalRequest, TerminalRequestError> {
    let granted = mvm_hostd::audit::plan_persist::read_plan(machine)
        .ok()
        .and_then(|plan| plan.grants)
        .and_then(|grants| grants.application_terminal);
    resolve_with(machine, granted.as_ref(), request, || {
        crate::entrypoint::dispatch::workload_egress_env(machine)
    })
}

fn resolve_with(
    machine: &str,
    granted: Option<&ApplicationTerminalGrant>,
    request: TerminalRequest,
    host_env: impl FnOnce() -> Vec<(String, String)>,
) -> Result<TerminalRequest, TerminalRequestError> {
    let Some(granted) = granted else {
        return Ok(request);
    };
    let program = granted.argv[0].clone();
    if !request.env.is_empty() {
        return Err(TerminalRequestError::CallerEnvironment {
            machine: machine.to_string(),
            program,
        });
    }
    if !request.argv.is_empty() && request.argv != granted.argv {
        return Err(TerminalRequestError::OtherProgram {
            machine: machine.to_string(),
            program,
        });
    }
    Ok(TerminalRequest {
        argv: granted.argv.clone(),
        env: host_env(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> ApplicationTerminalGrant {
        ApplicationTerminalGrant::new(vec!["/usr/bin/claude".into()]).unwrap()
    }

    fn host_env() -> Vec<(String, String)> {
        vec![
            ("HTTPS_PROXY".into(), "http://127.0.0.1:3128".into()),
            ("ANTHROPIC_API_KEY".into(), "mvm-placeholder".into()),
        ]
    }

    #[test]
    fn without_a_grant_the_request_is_unchanged() {
        let request = TerminalRequest {
            argv: vec!["/bin/sh".into()],
            env: vec![("A".into(), "b".into())],
        };
        assert_eq!(
            resolve_with("vm", None, request.clone(), || unreachable!()),
            Ok(request)
        );
    }

    #[test]
    fn a_grant_supplies_its_argv_and_the_host_environment() {
        let resolved =
            resolve_with("vm", Some(&grant()), TerminalRequest::default(), host_env).unwrap();
        assert_eq!(resolved.argv, vec!["/usr/bin/claude".to_string()]);
        assert_eq!(resolved.env, host_env());
        let same = TerminalRequest {
            argv: vec!["/usr/bin/claude".into()],
            env: Vec::new(),
        };
        assert_eq!(
            resolve_with("vm", Some(&grant()), same, host_env).unwrap(),
            resolved
        );
    }

    #[test]
    fn a_grant_refuses_another_program_or_caller_variables() {
        let shell = TerminalRequest {
            argv: vec!["/bin/sh".into()],
            env: Vec::new(),
        };
        let error = resolve_with("vm", Some(&grant()), shell, host_env).unwrap_err();
        assert!(matches!(error, TerminalRequestError::OtherProgram { .. }));
        assert!(error.to_string().contains("/usr/bin/claude"), "{error}");
        let env = TerminalRequest {
            argv: Vec::new(),
            env: vec![("LD_PRELOAD".into(), "/tmp/x.so".into())],
        };
        let error = resolve_with("vm", Some(&grant()), env, host_env).unwrap_err();
        assert!(matches!(
            error,
            TerminalRequestError::CallerEnvironment { .. }
        ));
    }
}
