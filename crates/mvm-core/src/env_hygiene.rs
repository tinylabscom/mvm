//! The one filter for environment variables that change what a process loads
//! or executes before its own code runs.
//!
//! Two seams apply it. Environment a caller hands to a guest workload
//! (`--env`, a launch plan's entrypoint env, a process started over the guest
//! API) is checked with [`EnvFilter::refuse_denied`]: the caller named the
//! variable, so it is refused with its name and family rather than dropped.
//! The host helper processes `mvmctl` starts — the per-VM supervisors, the
//! network and GPU endpoints, the broker and signers, the builder, the shells
//! that launch Firecracker — are built with [`helper_command`], which silently
//! removes the same variables from what the helper would otherwise inherit and
//! logs each removed name at debug level. Nobody asked for an inherited
//! variable, so nobody is refused over one.
//!
//! No value is ever logged or put in an error: a denied variable is reported
//! by name and family only, because a password-manager session token's value
//! is the credential.
//!
//! The families:
//!
//! - **loader**: `LD_*`, `DYLD_*` — inject a shared library or redirect symbol
//!   resolution in every dynamically linked program.
//! - **shell**: `BASH_ENV`, `ENV`, `BASH_FUNC_*`, `PROMPT_COMMAND`, `IFS`,
//!   `CDPATH`, `GLOBIGNORE`, `SHELLOPTS`, `PS4` — run code or change parsing in
//!   every shell the process starts.
//! - **interpreter**: `PYTHONSTARTUP`, `PYTHONPATH`, `PYTHONHOME`,
//!   `NODE_OPTIONS`, `NODE_PATH`, `PERL5LIB`, `PERL5OPT`, `PERLLIB`, `RUBYOPT`,
//!   `RUBYLIB`, `GEM_*`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
//!   `JDK_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`, `GOFLAGS` — load code into, or
//!   change the flags of, every interpreter or toolchain run.
//! - **password-manager session**: `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*`,
//!   `OP_SESSION_*`, `BW_SESSION` — a live credential for a whole vault, which
//!   has no business in a guest or in a helper.
//!
//! Matching is case-sensitive, because every consumer of these names is: the
//! dynamic loader reads `LD_PRELOAD`, not `ld_preload`, and a Unix environment
//! can hold both as distinct variables.
//!
//! A denied variable comes back only by its exact name through an explicit
//! [`EnvReadmit`]. A pattern (`LD_*`) or a bare family prefix (`LD_`) is
//! refused as a re-admission, so no single re-admission can reopen a family.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::process::Command;

/// Why a variable is on the denylist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvFamily {
    /// Dynamic-loader control (`LD_*`, `DYLD_*`).
    Loader,
    /// Shell startup and parsing control.
    Shell,
    /// Interpreter and toolchain startup control.
    Interpreter,
    /// A password-manager session or service-account token.
    SessionToken,
}

impl EnvFamily {
    /// Short human label, used in refusals and logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Shell => "shell",
            Self::Interpreter => "interpreter",
            Self::SessionToken => "password-manager session",
        }
    }
}

impl fmt::Display for EnvFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy)]
enum Matcher {
    Exact(&'static str),
    Prefix(&'static str),
}

impl Matcher {
    fn matches(self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix),
        }
    }
}

const DENYLIST: &[(Matcher, EnvFamily)] = &[
    (Matcher::Prefix("LD_"), EnvFamily::Loader),
    (Matcher::Prefix("DYLD_"), EnvFamily::Loader),
    (Matcher::Exact("BASH_ENV"), EnvFamily::Shell),
    (Matcher::Exact("ENV"), EnvFamily::Shell),
    (Matcher::Prefix("BASH_FUNC_"), EnvFamily::Shell),
    (Matcher::Exact("PROMPT_COMMAND"), EnvFamily::Shell),
    (Matcher::Exact("IFS"), EnvFamily::Shell),
    (Matcher::Exact("CDPATH"), EnvFamily::Shell),
    (Matcher::Exact("GLOBIGNORE"), EnvFamily::Shell),
    (Matcher::Exact("SHELLOPTS"), EnvFamily::Shell),
    (Matcher::Exact("PS4"), EnvFamily::Shell),
    (Matcher::Exact("PYTHONSTARTUP"), EnvFamily::Interpreter),
    (Matcher::Exact("PYTHONPATH"), EnvFamily::Interpreter),
    (Matcher::Exact("PYTHONHOME"), EnvFamily::Interpreter),
    (Matcher::Exact("NODE_OPTIONS"), EnvFamily::Interpreter),
    (Matcher::Exact("NODE_PATH"), EnvFamily::Interpreter),
    (Matcher::Exact("PERL5LIB"), EnvFamily::Interpreter),
    (Matcher::Exact("PERL5OPT"), EnvFamily::Interpreter),
    (Matcher::Exact("PERLLIB"), EnvFamily::Interpreter),
    (Matcher::Exact("RUBYOPT"), EnvFamily::Interpreter),
    (Matcher::Exact("RUBYLIB"), EnvFamily::Interpreter),
    (Matcher::Prefix("GEM_"), EnvFamily::Interpreter),
    (Matcher::Exact("JAVA_TOOL_OPTIONS"), EnvFamily::Interpreter),
    (Matcher::Exact("_JAVA_OPTIONS"), EnvFamily::Interpreter),
    (Matcher::Exact("JDK_JAVA_OPTIONS"), EnvFamily::Interpreter),
    (
        Matcher::Exact("DOTNET_STARTUP_HOOKS"),
        EnvFamily::Interpreter,
    ),
    (Matcher::Exact("GOFLAGS"), EnvFamily::Interpreter),
    (
        Matcher::Exact("OP_SERVICE_ACCOUNT_TOKEN"),
        EnvFamily::SessionToken,
    ),
    (Matcher::Prefix("OP_CONNECT_"), EnvFamily::SessionToken),
    (Matcher::Prefix("OP_SESSION_"), EnvFamily::SessionToken),
    (Matcher::Exact("BW_SESSION"), EnvFamily::SessionToken),
];

/// The family `name` is denied under, or `None` when it is not denied.
#[must_use]
pub fn classify(name: &str) -> Option<EnvFamily> {
    DENYLIST
        .iter()
        .find(|(matcher, _)| matcher.matches(name))
        .map(|(_, family)| *family)
}

fn is_family_prefix(name: &str) -> bool {
    DENYLIST
        .iter()
        .any(|(matcher, _)| matches!(matcher, Matcher::Prefix(prefix) if *prefix == name))
}

/// A re-admission that was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadmitError {
    /// The name carries a glob metacharacter.
    #[error(
        "re-admitting `{0}` refused: a re-admission names one variable exactly, never a pattern"
    )]
    Pattern(String),
    /// The name is a whole family's prefix rather than one variable.
    #[error(
        "re-admitting `{0}` refused: that is a family prefix; name the one variable to re-admit"
    )]
    FamilyPrefix(String),
    /// The name cannot be an environment variable name.
    #[error("re-admitting `{0}` refused: not a valid environment variable name")]
    InvalidName(String),
}

/// Denied names re-admitted by exact name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvReadmit {
    names: BTreeSet<String>,
}

impl EnvReadmit {
    /// Re-admit nothing.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Re-admit each of `names`, refusing the first pattern, family prefix, or
    /// invalid name.
    pub fn from_names<I, S>(names: I) -> Result<Self, ReadmitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut readmit = Self::none();
        for name in names {
            readmit.insert(name.as_ref())?;
        }
        Ok(readmit)
    }

    /// Re-admit one exact name.
    pub fn insert(&mut self, name: &str) -> Result<(), ReadmitError> {
        if name.is_empty() || name.contains(['=', '\0']) {
            return Err(ReadmitError::InvalidName(name.to_string()));
        }
        if name.contains(['*', '?', '[', ']', '{', '}']) {
            return Err(ReadmitError::Pattern(name.to_string()));
        }
        if is_family_prefix(name) {
            return Err(ReadmitError::FamilyPrefix(name.to_string()));
        }
        self.names.insert(name.to_string());
        Ok(())
    }

    /// Whether `name` is re-admitted.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Whether nothing is re-admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// What the filter decides for one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvVerdict {
    /// Not on the denylist.
    Allowed,
    /// On the denylist and re-admitted by exact name.
    Readmitted(EnvFamily),
    /// On the denylist and not re-admitted.
    Denied(EnvFamily),
}

/// A variable the filter kept out. Carries the name, never the value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeniedVar {
    /// The variable's name.
    pub name: String,
    /// Why it is denied.
    pub family: EnvFamily,
}

impl fmt::Display for DeniedVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.family)
    }
}

/// Explicitly supplied variables the filter refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedEnv {
    vars: Vec<DeniedVar>,
}

impl DeniedEnv {
    /// The refused variables, sorted by name.
    #[must_use]
    pub fn vars(&self) -> &[DeniedVar] {
        &self.vars
    }

    /// The refused names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.vars.iter().map(|var| var.name.as_str()).collect()
    }
}

impl fmt::Display for DeniedEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("refused environment variable")?;
        if self.vars.len() > 1 {
            f.write_str("s")?;
        }
        f.write_str(" ")?;
        for (index, var) in self.vars.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{var}")?;
        }
        f.write_str(
            ": these change what a process loads or runs before its own code starts; \
             re-admit one only by its exact name",
        )
    }
}

impl std::error::Error for DeniedEnv {}

/// The denylist plus the caller's exact-name re-admissions.
#[derive(Debug, Clone, Default)]
pub struct EnvFilter {
    readmit: EnvReadmit,
}

impl EnvFilter {
    /// A filter re-admitting exactly `readmit`.
    #[must_use]
    pub fn new(readmit: EnvReadmit) -> Self {
        Self { readmit }
    }

    /// A filter re-admitting nothing.
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// The decision for one name.
    #[must_use]
    pub fn verdict(&self, name: &str) -> EnvVerdict {
        match classify(name) {
            None => EnvVerdict::Allowed,
            Some(family) if self.readmit.contains(name) => EnvVerdict::Readmitted(family),
            Some(family) => EnvVerdict::Denied(family),
        }
    }

    /// Every denied name in `names`, sorted and deduplicated.
    #[must_use]
    pub fn denied<'a, I>(&self, names: I) -> Vec<DeniedVar>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut denied: Vec<DeniedVar> = names
            .into_iter()
            .filter_map(|name| match self.verdict(name) {
                EnvVerdict::Denied(family) => Some(DeniedVar {
                    name: name.to_string(),
                    family,
                }),
                EnvVerdict::Allowed | EnvVerdict::Readmitted(_) => None,
            })
            .collect();
        denied.sort();
        denied.dedup();
        denied
    }

    /// Refuse explicitly supplied names: the caller typed them, so they are
    /// told which ones and why rather than having them vanish.
    pub fn refuse_denied<'a, I>(&self, names: I) -> Result<(), DeniedEnv>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let vars = self.denied(names);
        if vars.is_empty() {
            Ok(())
        } else {
            Err(DeniedEnv { vars })
        }
    }
}

/// A [`Command`] for a host helper process, with every denied variable this
/// process would hand down removed from what the helper inherits.
///
/// A variable the call site then sets explicitly with `.env(...)` is that
/// site's own, named decision; this removes only what would otherwise have
/// arrived unasked.
#[must_use]
pub fn helper_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    scrub_command(&mut command, &EnvReadmit::none());
    command
}

/// Remove from `command` every denied variable it would inherit from this
/// process or has been given as an override, other than those in `readmit`.
/// Returns the removed names, sorted.
pub fn scrub_command(command: &mut Command, readmit: &EnvReadmit) -> Vec<String> {
    let inherited = std::env::vars_os().map(|(name, _)| name);
    strip_denied(command, inherited, readmit)
}

/// [`scrub_command`] over an explicit set of inherited names, so the removal
/// is testable without touching this process's environment.
pub fn strip_denied<I>(command: &mut Command, inherited: I, readmit: &EnvReadmit) -> Vec<String>
where
    I: IntoIterator<Item = OsString>,
{
    let overrides: Vec<OsString> = command
        .get_envs()
        .filter(|(_, value)| value.is_some())
        .map(|(name, _)| name.to_os_string())
        .collect();
    let filter = EnvFilter::new(readmit.clone());
    let mut removed: Vec<String> = inherited
        .into_iter()
        .chain(overrides)
        .filter_map(|name| {
            let name = name.to_string_lossy().into_owned();
            matches!(filter.verdict(&name), EnvVerdict::Denied(_)).then_some(name)
        })
        .collect();
    removed.sort();
    removed.dedup();
    for name in &removed {
        tracing::debug!(name = %name, "removed denied variable from a helper's environment");
        command.env_remove(name);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family(name: &str) -> Option<EnvFamily> {
        classify(name)
    }

    #[test]
    fn loader_family_is_denied() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
        ] {
            assert_eq!(family(name), Some(EnvFamily::Loader), "{name}");
        }
    }

    #[test]
    fn shell_family_is_denied() {
        for name in [
            "BASH_ENV",
            "ENV",
            "BASH_FUNC_foo%%",
            "BASH_FUNC_x()",
            "PROMPT_COMMAND",
            "IFS",
            "CDPATH",
            "GLOBIGNORE",
            "SHELLOPTS",
            "PS4",
        ] {
            assert_eq!(family(name), Some(EnvFamily::Shell), "{name}");
        }
    }

    #[test]
    fn interpreter_family_is_denied() {
        for name in [
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "PYTHONHOME",
            "NODE_OPTIONS",
            "NODE_PATH",
            "PERL5LIB",
            "PERL5OPT",
            "PERLLIB",
            "RUBYOPT",
            "RUBYLIB",
            "GEM_HOME",
            "GEM_PATH",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "DOTNET_STARTUP_HOOKS",
            "GOFLAGS",
        ] {
            assert_eq!(family(name), Some(EnvFamily::Interpreter), "{name}");
        }
    }

    #[test]
    fn password_manager_session_family_is_denied() {
        for name in [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_CONNECT_HOST",
            "OP_CONNECT_TOKEN",
            "OP_SESSION_my",
            "BW_SESSION",
        ] {
            assert_eq!(family(name), Some(EnvFamily::SessionToken), "{name}");
        }
    }

    #[test]
    fn ordinary_names_are_allowed_including_near_misses() {
        for name in [
            "PATH",
            "HOME",
            "LDFLAGS",
            "OLD_PWD",
            "ENVIRONMENT",
            "MY_ENV",
            "BASH",
            "PYTHONUNBUFFERED",
            "NODE_ENV",
            "RUBY_VERSION",
            "GEMFILE",
            "OP_ACCOUNT",
            "BW_CLIENTID",
            "RUST_LOG",
            "MVM_HOME",
        ] {
            assert_eq!(family(name), None, "{name}");
        }
    }

    #[test]
    fn matching_is_case_sensitive() {
        for name in ["ld_preload", "Ld_Preload", "bash_env", "pythonpath", "env"] {
            assert_eq!(family(name), None, "{name}");
        }
        let filter = EnvFilter::new(EnvReadmit::from_names(["ld_preload"]).expect("valid"));
        assert_eq!(
            filter.verdict("LD_PRELOAD"),
            EnvVerdict::Denied(EnvFamily::Loader),
            "re-admitting a differently cased name must not re-admit the real one"
        );
    }

    #[test]
    fn exact_name_readmission_admits_only_that_name() {
        let filter = EnvFilter::new(
            EnvReadmit::from_names(["LD_LIBRARY_PATH", "PYTHONPATH"]).expect("valid"),
        );
        assert_eq!(
            filter.verdict("LD_LIBRARY_PATH"),
            EnvVerdict::Readmitted(EnvFamily::Loader)
        );
        assert_eq!(
            filter.verdict("PYTHONPATH"),
            EnvVerdict::Readmitted(EnvFamily::Interpreter)
        );
        assert_eq!(
            filter.verdict("LD_PRELOAD"),
            EnvVerdict::Denied(EnvFamily::Loader)
        );
        assert_eq!(filter.verdict("PATH"), EnvVerdict::Allowed);
    }

    #[test]
    fn pattern_readmission_is_refused() {
        for name in [
            "LD_*",
            "DYLD_*",
            "*",
            "LD_PRE?OAD",
            "GEM_[A-Z]*",
            "OP_{A,B}",
        ] {
            assert_eq!(
                EnvReadmit::from_names([name]),
                Err(ReadmitError::Pattern(name.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn family_prefix_readmission_is_refused() {
        for name in [
            "LD_",
            "DYLD_",
            "BASH_FUNC_",
            "GEM_",
            "OP_CONNECT_",
            "OP_SESSION_",
        ] {
            assert_eq!(
                EnvReadmit::from_names([name]),
                Err(ReadmitError::FamilyPrefix(name.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn invalid_readmission_names_are_refused() {
        for name in ["", "A=B", "A\0B"] {
            assert_eq!(
                EnvReadmit::from_names([name]),
                Err(ReadmitError::InvalidName(name.to_string())),
                "{name:?}"
            );
        }
    }

    #[test]
    fn bash_function_export_can_be_readmitted_by_exact_name() {
        let filter = EnvFilter::new(EnvReadmit::from_names(["BASH_FUNC_foo%%"]).expect("valid"));
        assert_eq!(
            filter.verdict("BASH_FUNC_foo%%"),
            EnvVerdict::Readmitted(EnvFamily::Shell)
        );
        assert_eq!(
            filter.verdict("BASH_FUNC_bar%%"),
            EnvVerdict::Denied(EnvFamily::Shell)
        );
    }

    #[test]
    fn refusal_names_every_denied_variable_once_and_never_a_value() {
        let filter = EnvFilter::strict();
        let err = filter
            .refuse_denied(["PYTHONPATH", "APP_MODE", "LD_PRELOAD", "LD_PRELOAD"])
            .expect_err("denied names refuse");
        assert_eq!(err.names(), vec!["LD_PRELOAD", "PYTHONPATH"]);
        let message = err.to_string();
        assert!(message.contains("LD_PRELOAD (loader)"), "{message}");
        assert!(message.contains("PYTHONPATH (interpreter)"), "{message}");
        assert!(!message.contains("APP_MODE"), "{message}");
        assert!(filter.refuse_denied(["APP_MODE", "PATH"]).is_ok());
    }

    fn removals(command: &Command) -> Vec<String> {
        command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn strip_denied_removes_inherited_and_overridden_denied_names() {
        let mut command = Command::new("/bin/true");
        command.env("PYTHONPATH", "/evil").env("APP_MODE", "dev");
        let inherited = ["LD_PRELOAD", "PATH", "OP_SESSION_abc"].map(OsString::from);
        let removed = strip_denied(&mut command, inherited, &EnvReadmit::none());
        assert_eq!(removed, vec!["LD_PRELOAD", "OP_SESSION_abc", "PYTHONPATH"]);
        assert_eq!(removals(&command), removed);
        assert!(
            command
                .get_envs()
                .any(|(name, value)| name == "APP_MODE" && value.is_some()),
            "an ordinary override survives"
        );
    }

    #[test]
    fn strip_denied_keeps_a_readmitted_loader_variable() {
        let mut command = Command::new("/bin/true");
        command.env("DYLD_FALLBACK_LIBRARY_PATH", "/opt/homebrew/lib");
        let readmit = EnvReadmit::from_names(["DYLD_FALLBACK_LIBRARY_PATH"]).expect("valid");
        let inherited = ["DYLD_INSERT_LIBRARIES"].map(OsString::from);
        let removed = strip_denied(&mut command, inherited, &readmit);
        assert_eq!(removed, vec!["DYLD_INSERT_LIBRARIES"]);
        assert!(command.get_envs().any(|(name, value)| {
            name == "DYLD_FALLBACK_LIBRARY_PATH" && value == Some(OsStr::new("/opt/homebrew/lib"))
        }));
    }

    #[test]
    fn helper_command_strips_a_denied_override_through_scrub() {
        let mut command = helper_command("/bin/true");
        command.env("BASH_ENV", "/tmp/evil.sh");
        let removed = scrub_command(&mut command, &EnvReadmit::none());
        assert!(removed.contains(&"BASH_ENV".to_string()), "{removed:?}");
        assert!(removals(&command).contains(&"BASH_ENV".to_string()));
    }
}
