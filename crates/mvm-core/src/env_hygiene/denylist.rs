//! The denylist itself: which names are denied, and under which family.
//!
//! Standard library only, with no crate dependencies, because `mvm-cli`'s build
//! script includes this file by path: it starts the same toolchain processes
//! `mvmctl` does and cannot depend on a workspace crate.

use std::fmt;

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
    (Matcher::Prefix("PERL5"), EnvFamily::Interpreter),
    (Matcher::Exact("PERLLIB"), EnvFamily::Interpreter),
    (Matcher::Prefix("RUBY"), EnvFamily::Interpreter),
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

/// Whether `name` is one family's whole prefix rather than a variable.
pub fn is_family_prefix(name: &str) -> bool {
    DENYLIST
        .iter()
        .any(|(matcher, _)| matches!(matcher, Matcher::Prefix(prefix) if *prefix == name))
}
