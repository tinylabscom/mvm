//! The authority to attach a terminal to one declared application.
//!
//! An application terminal is not the administrative console. The console
//! defaults to an interactive shell and runs whatever argv the caller names;
//! an application terminal runs exactly the argv the signed plan admitted, as
//! the workload user, with the host-provisioned environment and no
//! dynamic-loader variables, and never falls back to a shell. The grant does not open the console on a sealed image: the
//! console verbs stay development-only, so a sealed production guest refuses
//! every terminal whatever its plan carries.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::assurance::Sha256Digest;

/// Most arguments an application terminal's argv may carry.
pub const MAX_APPLICATION_TERMINAL_ARGS: usize = 64;
/// Longest single argument, in bytes.
pub const MAX_APPLICATION_TERMINAL_ARG_BYTES: usize = 4096;

/// Domain separator for [`ApplicationTerminalGrant::digest_argv`].
const ARGV_DIGEST_DOMAIN: &[u8] = b"mvm-application-terminal-argv-v1\0";

/// The one program a terminal may run, admitted by the signed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ApplicationTerminalGrant {
    /// The exact argv. `argv[0]` is an absolute path, so the guest resolves
    /// nothing on the caller's behalf.
    pub argv: Vec<String>,
}

impl ApplicationTerminalGrant {
    /// Validate `argv` into a grant.
    pub fn new(argv: Vec<String>) -> Result<Self, ApplicationTerminalGrantError> {
        validate_argv(&argv)?;
        Ok(Self { argv })
    }

    /// The digest the host-signed verb grant carries in place of the argv,
    /// which would not fit the guest kernel command line.
    #[must_use]
    pub fn argv_digest(&self) -> Sha256Digest {
        Self::digest_argv(&self.argv)
    }

    /// Digest an argv the same way a grant is digested, so the guest can
    /// compare a request's argv against the pinned one without holding it.
    #[must_use]
    pub fn digest_argv(argv: &[String]) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(ARGV_DIGEST_DOMAIN);
        for arg in argv {
            hasher.update((arg.len() as u64).to_be_bytes());
            hasher.update(arg.as_bytes());
        }
        Sha256Digest::from_bytes(&hasher.finalize().into())
    }
}

impl<'de> Deserialize<'de> for ApplicationTerminalGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            argv: Vec<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.argv).map_err(serde::de::Error::custom)
    }
}

/// What the host-signed verb grant carries: the argv's digest, not the argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ApplicationTerminalBinding {
    pub argv_digest: Sha256Digest,
}

impl From<&ApplicationTerminalGrant> for ApplicationTerminalBinding {
    fn from(grant: &ApplicationTerminalGrant) -> Self {
        Self {
            argv_digest: grant.argv_digest(),
        }
    }
}

impl ApplicationTerminalBinding {
    /// Whether a terminal request may open: it must name exactly the admitted
    /// argv, and its environment may not set a dynamic-loader variable, which
    /// would run code other than the admitted program. The host supplies the
    /// rest of the environment: the egress proxy, the CA bundle and secret
    /// placeholders, never a raw secret.
    pub fn admit<'a>(
        &self,
        argv: &[String],
        env_names: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), ApplicationTerminalRefusal> {
        if argv.is_empty() {
            return Err(ApplicationTerminalRefusal::NoArgv);
        }
        if ApplicationTerminalGrant::digest_argv(argv) != self.argv_digest {
            return Err(ApplicationTerminalRefusal::ArgvMismatch);
        }
        if env_names.into_iter().any(is_loader_variable) {
            return Err(ApplicationTerminalRefusal::LoaderEnvironment);
        }
        Ok(())
    }
}

/// A variable the dynamic loader reads to load or locate code.
fn is_loader_variable(name: &str) -> bool {
    name.starts_with("LD_")
}

/// Why a terminal request under an application-terminal grant was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationTerminalRefusal {
    #[error(
        "this machine's plan admits an application terminal, not a shell; \
         open the terminal with the exact argv its grant names"
    )]
    NoArgv,
    #[error(
        "the requested argv is not the one this machine's plan admitted as its \
         application terminal; use the argv from its application_terminal grant"
    )]
    ArgvMismatch,
    #[error(
        "an application terminal's environment may not set a dynamic-loader \
         variable (LD_*); it would run code other than the admitted program"
    )]
    LoaderEnvironment,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationTerminalGrantError {
    #[error("application terminal argv must not be empty")]
    Empty,
    #[error("application terminal argv has more than {MAX_APPLICATION_TERMINAL_ARGS} arguments")]
    TooManyArgs,
    #[error(
        "application terminal argument {0} is longer than {MAX_APPLICATION_TERMINAL_ARG_BYTES} bytes"
    )]
    ArgTooLong(usize),
    #[error("application terminal argument {0} contains a NUL byte")]
    Nul(usize),
    #[error("application terminal argv[0] {0:?} is not a normalized absolute path")]
    ProgramNotAbsolute(String),
}

fn validate_argv(argv: &[String]) -> Result<(), ApplicationTerminalGrantError> {
    let Some(program) = argv.first() else {
        return Err(ApplicationTerminalGrantError::Empty);
    };
    if argv.len() > MAX_APPLICATION_TERMINAL_ARGS {
        return Err(ApplicationTerminalGrantError::TooManyArgs);
    }
    for (index, arg) in argv.iter().enumerate() {
        if arg.len() > MAX_APPLICATION_TERMINAL_ARG_BYTES {
            return Err(ApplicationTerminalGrantError::ArgTooLong(index));
        }
        if arg.contains('\0') {
            return Err(ApplicationTerminalGrantError::Nul(index));
        }
    }
    if !normalized_absolute(program) {
        return Err(ApplicationTerminalGrantError::ProgramNotAbsolute(
            program.clone(),
        ));
    }
    Ok(())
}

fn normalized_absolute(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn argv(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn binding() -> ApplicationTerminalBinding {
        let grant = ApplicationTerminalGrant::new(argv(&["/usr/bin/claude"])).unwrap();
        ApplicationTerminalBinding::from(&grant)
    }

    #[test]
    fn a_grant_needs_an_absolute_normalized_program() {
        for bad in [
            vec![],
            argv(&["claude"]),
            argv(&["./claude"]),
            argv(&["/usr/../bin/sh"]),
            argv(&["/"]),
            argv(&["/usr//bin/claude"]),
        ] {
            assert!(
                ApplicationTerminalGrant::new(bad.clone()).is_err(),
                "{bad:?}"
            );
        }
        assert!(ApplicationTerminalGrant::new(argv(&["/usr/bin/claude", "--resume"])).is_ok());
    }

    #[test]
    fn a_grant_bounds_its_argv() {
        let many = vec!["/bin/app".to_string(); MAX_APPLICATION_TERMINAL_ARGS + 1];
        assert_eq!(
            ApplicationTerminalGrant::new(many),
            Err(ApplicationTerminalGrantError::TooManyArgs)
        );
        let long = vec![
            "/bin/app".to_string(),
            "x".repeat(MAX_APPLICATION_TERMINAL_ARG_BYTES + 1),
        ];
        assert_eq!(
            ApplicationTerminalGrant::new(long),
            Err(ApplicationTerminalGrantError::ArgTooLong(1))
        );
        assert_eq!(
            ApplicationTerminalGrant::new(argv(&["/bin/app", "a\0b"])),
            Err(ApplicationTerminalGrantError::Nul(1))
        );
    }

    #[test]
    fn deserializing_validates_like_the_constructor() {
        assert!(serde_json::from_str::<ApplicationTerminalGrant>(r#"{"argv":["sh"]}"#).is_err());
        assert!(
            serde_json::from_str::<ApplicationTerminalGrant>(r#"{"argv":["/bin/app"],"env":[]}"#)
                .is_err()
        );
        let grant: ApplicationTerminalGrant =
            serde_json::from_str(r#"{"argv":["/usr/bin/claude"]}"#).unwrap();
        assert_eq!(grant.argv, argv(&["/usr/bin/claude"]));
    }

    #[test]
    fn the_digest_separates_argument_boundaries() {
        assert_ne!(
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/a", "bc"])),
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/ab", "c"]))
        );
        assert_ne!(
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/a", ""])),
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/a"]))
        );
    }

    #[test]
    fn only_the_exact_argv_without_loader_variables_is_admitted() {
        let binding = binding();
        assert_eq!(binding.admit(&argv(&["/usr/bin/claude"]), []), Ok(()));
        assert_eq!(
            binding.admit(
                &argv(&["/usr/bin/claude"]),
                ["HTTPS_PROXY", "ANTHROPIC_API_KEY"]
            ),
            Ok(())
        );
        assert_eq!(
            binding.admit(&[], []),
            Err(ApplicationTerminalRefusal::NoArgv)
        );
        assert_eq!(
            binding.admit(&argv(&["/bin/sh"]), []),
            Err(ApplicationTerminalRefusal::ArgvMismatch)
        );
        assert_eq!(
            binding.admit(&argv(&["/usr/bin/claude", "--dangerously-skip"]), []),
            Err(ApplicationTerminalRefusal::ArgvMismatch)
        );
        assert_eq!(
            binding.admit(&argv(&["/usr/bin/claude"]), ["LD_PRELOAD"]),
            Err(ApplicationTerminalRefusal::LoaderEnvironment)
        );
    }
}
