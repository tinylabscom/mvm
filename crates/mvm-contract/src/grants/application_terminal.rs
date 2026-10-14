//! The authority to attach a terminal to one declared application.
//!
//! An application terminal is not the administrative console. The console
//! defaults to an interactive shell and runs whatever argv the caller names;
//! an application terminal runs exactly the argv the signed plan admitted, as
//! the workload user, and never falls back to a shell. The grant does not open
//! the console on a sealed image: the console verbs stay development-only, so a
//! sealed production guest refuses every terminal whatever its plan carries.
//!
//! Every check here is an allowlist over exact bytes, never a prefix,
//! substring or normalised comparison:
//!
//! - The argv is compared whole, by a length-framed digest, so the caller can
//!   neither add, drop, reorder nor split an argument.
//! - The program is an absolute, normalised path of printable ASCII, and may
//!   not be a shell, an interpreter, or a launcher that runs another program,
//!   so a grant cannot name a shell under another name. The guest additionally
//!   checks the path is the file it names (no symlink) and that the workload
//!   cannot rewrite it.
//! - The environment is the host-provisioned set and nothing else: the egress
//!   proxy variables pointing at the guest loopback, the fixed CA bundle paths,
//!   and secret placeholders whose value is a minted placeholder token. Any
//!   other name or value, including every variable a loader or interpreter
//!   reads to run code, is refused.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::assurance::Sha256Digest;
use crate::substitution::{SECRET_PLACEHOLDER_HEX_LEN, SECRET_PLACEHOLDER_PREFIX};

/// Most arguments an application terminal's argv may carry.
pub const MAX_APPLICATION_TERMINAL_ARGS: usize = 64;
/// Longest single argument, in bytes.
pub const MAX_APPLICATION_TERMINAL_ARG_BYTES: usize = 4096;
/// Most environment variables a terminal request may carry.
pub const MAX_APPLICATION_TERMINAL_ENV: usize = 64;

/// Domain separator for [`ApplicationTerminalGrant::digest_argv`].
const ARGV_DIGEST_DOMAIN: &[u8] = b"mvm-application-terminal-argv-v1\0";

/// Programs that run a caller-chosen program or script: shells, interpreters,
/// and launchers. A grant naming one would be a shell under another name.
/// Matched against the exact final path component; an interpreter family
/// also matches its versioned names (`python3.12`).
const COMMAND_RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ash",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "fish",
    "rbash",
    "busybox",
    "toybox",
    "env",
    "sudo",
    "su",
    "doas",
    "runuser",
    "setpriv",
    "mvm-setpriv",
    "nsenter",
    "unshare",
    "chroot",
    "nohup",
    "xargs",
    "timeout",
    "script",
    "expect",
    "watch",
    "strace",
    "ltrace",
    "gdb",
    "screen",
    "tmux",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "sed",
    "find",
    "vi",
    "vim",
    "nvim",
    "emacs",
    "nano",
    "less",
    "more",
    "man",
    "tclsh",
    "wish",
    "osascript",
    "dbus-launch",
    "systemd-run",
    "flock",
    "stdbuf",
    "nice",
    "ionice",
    "taskset",
    "time",
    "exec",
    "eval",
    "deno",
    "bun",
    "npx",
    "jshell",
];
const INTERPRETER_FAMILIES: &[&str] = &[
    "python",
    "pypy",
    "perl",
    "ruby",
    "irb",
    "node",
    "nodejs",
    "lua",
    "luajit",
    "php",
    "tclsh",
    "java",
    "jjs",
    "guile",
    "racket",
    "Rscript",
    "R",
    "julia",
    "pwsh",
    "powershell",
];

/// Proxy variables the host provisions. Their value must be a URL naming the
/// guest loopback.
const PROXY_VARIABLES: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
/// The loopback list the host provisions as `NO_PROXY`.
const NO_PROXY_VARIABLES: &[&str] = &["NO_PROXY", "no_proxy"];
const NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";
/// CA bundle variables and the one fixed path each may carry.
const CA_VARIABLES: &[(&str, &str)] = &[
    ("SSL_CERT_FILE", "/run/mvm/ca-bundle.crt"),
    ("CURL_CA_BUNDLE", "/run/mvm/ca-bundle.crt"),
    ("REQUESTS_CA_BUNDLE", "/run/mvm/ca-bundle.crt"),
    ("NODE_EXTRA_CA_CERTS", "/run/mvm/egress-ca.crt"),
];
/// Names a loader, shell or interpreter reads to run code. A placeholder
/// value is inert, but these are refused under any value so a secret bound
/// under one of these names cannot be used to reach them.
const CODE_LOADING_VARIABLES: &[&str] = &[
    "NODE_OPTIONS",
    "NODE_PATH",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "GCONV_PATH",
    "HOSTALIASES",
    "LOCPATH",
    "NLSPATH",
    "TMPDIR",
    "HOME",
    "PATH",
    "SHELL",
    "IFS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "EDITOR",
    "VISUAL",
    "PAGER",
];
const CODE_LOADING_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "PYTHON",
    "PERL",
    "RUBY",
    "GEM_",
    "BUNDLE_",
    "LUA_",
    "NPM_CONFIG_",
    "BUN_",
    "DENO_",
    "MALLOC_",
    "GLIBC_",
    "BASH_FUNC_",
];

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
    /// Each argument is length-framed, so moving a byte across an argument
    /// boundary changes the digest.
    #[must_use]
    pub fn digest_argv(argv: &[String]) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(ARGV_DIGEST_DOMAIN);
        hasher.update((argv.len() as u64).to_be_bytes());
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
    /// argv, and carry only the host-provisioned environment.
    pub fn admit(
        &self,
        argv: &[String],
        env: &[(String, String)],
    ) -> Result<(), ApplicationTerminalRefusal> {
        if argv.is_empty() {
            return Err(ApplicationTerminalRefusal::NoArgv);
        }
        if ApplicationTerminalGrant::digest_argv(argv) != self.argv_digest {
            return Err(ApplicationTerminalRefusal::ArgvMismatch);
        }
        if env.len() > MAX_APPLICATION_TERMINAL_ENV {
            return Err(ApplicationTerminalRefusal::Environment);
        }
        if !env
            .iter()
            .all(|(name, value)| host_provisioned_variable(name, value))
        {
            return Err(ApplicationTerminalRefusal::Environment);
        }
        Ok(())
    }
}

/// Whether `name=value` is one the host provisions for an application
/// terminal. Exact names and exact value shapes only.
#[must_use]
pub fn host_provisioned_variable(name: &str, value: &str) -> bool {
    if PROXY_VARIABLES.contains(&name) {
        return loopback_proxy_url(value);
    }
    if NO_PROXY_VARIABLES.contains(&name) {
        return value == NO_PROXY_VALUE;
    }
    if let Some((_, path)) = CA_VARIABLES.iter().find(|(ca, _)| *ca == name) {
        return value == *path;
    }
    placeholder_name(name) && placeholder_value(value)
}

/// `http://127.0.0.1:<port>` or `socks5h://127.0.0.1:<port>`, nothing more.
fn loopback_proxy_url(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| value.strip_prefix("socks5h://127.0.0.1:"))
    else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 5
        && rest.bytes().all(|byte| byte.is_ascii_digit())
        && rest.parse::<u16>().is_ok_and(|port| port != 0)
}

/// An upper-case shell identifier that no loader or interpreter reads.
fn placeholder_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && !CODE_LOADING_VARIABLES.contains(&name)
        && !CODE_LOADING_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        && !PROXY_VARIABLES.contains(&name)
        && !NO_PROXY_VARIABLES.contains(&name)
}

/// Exactly a minted secret placeholder: the prefix and lower-case hex of the
/// minted length.
fn placeholder_value(value: &str) -> bool {
    value
        .strip_prefix(SECRET_PLACEHOLDER_PREFIX)
        .is_some_and(|hex| {
            hex.len() == SECRET_PLACEHOLDER_HEX_LEN
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
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
        "an application terminal takes only the host-provisioned environment \
         (the egress proxy, the CA bundle and secret placeholders); declare any \
         other variable in the image instead"
    )]
    Environment,
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
    #[error("application terminal argument {0} contains a control character")]
    ControlCharacter(usize),
    #[error(
        "application terminal argv[0] {0:?} is not a normalized absolute path of printable ASCII"
    )]
    ProgramNotAbsolute(String),
    #[error(
        "application terminal argv[0] {0:?} runs other programs (a shell, interpreter or \
         launcher); name the application's own executable"
    )]
    CommandRunner(String),
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
        if arg.chars().any(char::is_control) {
            return Err(ApplicationTerminalGrantError::ControlCharacter(index));
        }
    }
    if !normalized_absolute(program) {
        return Err(ApplicationTerminalGrantError::ProgramNotAbsolute(
            program.clone(),
        ));
    }
    if runs_other_programs(program) {
        return Err(ApplicationTerminalGrantError::CommandRunner(
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
        && rest.bytes().all(|byte| byte.is_ascii_graphic())
        && rest
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

/// Whether the final path component names a shell, interpreter or launcher.
/// Compared exactly, so `/usr/bin/claude` is never matched by a substring; an
/// interpreter family also matches a version suffix of digits and dots.
fn runs_other_programs(program: &str) -> bool {
    let name = program.rsplit('/').next().unwrap_or(program);
    COMMAND_RUNNERS.contains(&name)
        || INTERPRETER_FAMILIES.iter().any(|family| {
            name.strip_prefix(family).is_some_and(|version| {
                version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn argv(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    fn placeholder() -> String {
        alloc::format!(
            "{SECRET_PLACEHOLDER_PREFIX}{}",
            "a1".repeat(SECRET_PLACEHOLDER_HEX_LEN / 2)
        )
    }

    fn binding() -> ApplicationTerminalBinding {
        let grant = ApplicationTerminalGrant::new(argv(&["/usr/bin/claude"])).unwrap();
        ApplicationTerminalBinding::from(&grant)
    }

    #[test]
    fn a_grant_needs_an_absolute_normalized_printable_program() {
        for bad in [
            vec![],
            argv(&["claude"]),
            argv(&["./claude"]),
            argv(&["/usr/../bin/sh"]),
            argv(&["/usr/bin/./claude"]),
            argv(&["/"]),
            argv(&["/usr//bin/claude"]),
            argv(&["/usr/bin/claude/"]),
            argv(&["/usr/bin/cl aude"]),
            argv(&["/usr/bin/clаude"]),
        ] {
            assert!(
                ApplicationTerminalGrant::new(bad.clone()).is_err(),
                "{bad:?}"
            );
        }
        assert!(ApplicationTerminalGrant::new(argv(&["/usr/bin/claude", "--resume"])).is_ok());
    }

    #[test]
    fn a_grant_cannot_name_a_shell_interpreter_or_launcher() {
        for runner in [
            "/bin/sh",
            "/usr/bin/bash",
            "/usr/bin/env",
            "/bin/busybox",
            "/usr/bin/python3",
            "/usr/bin/python3.12",
            "/usr/local/bin/node",
            "/usr/bin/perl",
            "/usr/bin/sudo",
            "/usr/bin/xargs",
            "/usr/bin/awk",
        ] {
            assert!(
                matches!(
                    ApplicationTerminalGrant::new(argv(&[runner, "-c", "id"])),
                    Err(ApplicationTerminalGrantError::CommandRunner(_))
                ),
                "{runner}"
            );
        }
        // Exact component match: a name containing a runner's name is not one.
        for application in [
            "/usr/bin/claude",
            "/opt/shell-tool/bin/sharp",
            "/usr/bin/nodemon-x",
        ] {
            assert!(
                ApplicationTerminalGrant::new(argv(&[application])).is_ok(),
                "{application}"
            );
        }
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
        for control in ["a\0b", "a\nb", "a\u{1b}[2Jb"] {
            assert_eq!(
                ApplicationTerminalGrant::new(argv(&["/bin/app", control])),
                Err(ApplicationTerminalGrantError::ControlCharacter(1))
            );
        }
    }

    #[test]
    fn deserializing_validates_like_the_constructor() {
        assert!(serde_json::from_str::<ApplicationTerminalGrant>(r#"{"argv":["sh"]}"#).is_err());
        assert!(
            serde_json::from_str::<ApplicationTerminalGrant>(r#"{"argv":["/bin/sh","-c","id"]}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ApplicationTerminalGrant>(r#"{"argv":["/bin/app"],"env":[]}"#)
                .is_err()
        );
        let grant: ApplicationTerminalGrant =
            serde_json::from_str(r#"{"argv":["/usr/bin/claude"]}"#).unwrap();
        assert_eq!(grant.argv, argv(&["/usr/bin/claude"]));
    }

    #[test]
    fn the_digest_separates_argument_boundaries_and_counts() {
        assert_ne!(
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/a", "bc"])),
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/ab", "c"]))
        );
        assert_ne!(
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/a", ""])),
            ApplicationTerminalGrant::digest_argv(&argv(&["/bin/a"]))
        );
        assert_ne!(
            ApplicationTerminalGrant::digest_argv(&argv(&["/usr/bin/Claude"])),
            ApplicationTerminalGrant::digest_argv(&argv(&["/usr/bin/claude"]))
        );
    }

    #[test]
    fn only_the_exact_argv_is_admitted() {
        let binding = binding();
        assert_eq!(binding.admit(&argv(&["/usr/bin/claude"]), &[]), Ok(()));
        assert_eq!(
            binding.admit(&[], &[]),
            Err(ApplicationTerminalRefusal::NoArgv)
        );
        for other in [
            argv(&["/bin/sh"]),
            argv(&["/usr/bin/claude", "--dangerously-skip-permissions"]),
            argv(&["/usr/bin/claude", ""]),
            argv(&["/usr/bin/claude2"]),
            argv(&["/usr/bin/Claude"]),
            argv(&["/usr/bin/../bin/claude"]),
            argv(&["/usr//bin/claude"]),
        ] {
            assert_eq!(
                binding.admit(&other, &[]),
                Err(ApplicationTerminalRefusal::ArgvMismatch),
                "{other:?}"
            );
        }
    }

    #[test]
    fn the_host_provisioned_environment_is_admitted() {
        let placeholder = placeholder();
        let host = env(&[
            ("HTTPS_PROXY", "http://127.0.0.1:1080"),
            ("https_proxy", "http://127.0.0.1:1080"),
            ("ALL_PROXY", "socks5h://127.0.0.1:1080"),
            ("NO_PROXY", "localhost,127.0.0.1,::1"),
            ("SSL_CERT_FILE", "/run/mvm/ca-bundle.crt"),
            ("NODE_EXTRA_CA_CERTS", "/run/mvm/egress-ca.crt"),
            ("ANTHROPIC_API_KEY", &placeholder),
        ]);
        assert_eq!(binding().admit(&argv(&["/usr/bin/claude"]), &host), Ok(()));
    }

    #[test]
    fn any_other_environment_is_refused() {
        let placeholder = placeholder();
        for (name, value) in [
            ("LD_PRELOAD", "/tmp/x.so"),
            ("LD_PRELOAD", placeholder.as_str()),
            ("NODE_OPTIONS", "--require /tmp/x.js"),
            ("NODE_OPTIONS", placeholder.as_str()),
            ("BASH_ENV", placeholder.as_str()),
            ("PYTHONSTARTUP", placeholder.as_str()),
            ("PATH", placeholder.as_str()),
            ("HTTPS_PROXY", "http://attacker.example:8080"),
            ("HTTPS_PROXY", "http://127.0.0.1:1080@evil"),
            ("HTTPS_PROXY", "http://127.0.0.1.evil:1080"),
            ("NO_PROXY", "*"),
            ("SSL_CERT_FILE", "/tmp/evil.crt"),
            ("ANTHROPIC_API_KEY", "sk-ant-raw-secret"),
            ("ANTHROPIC_API_KEY", "mvm-secret-short"),
            ("anthropic_api_key", placeholder.as_str()),
            ("ANTHROPIC_АPI_KEY", placeholder.as_str()),
            ("MY_VAR", "anything"),
        ] {
            assert_eq!(
                binding().admit(&argv(&["/usr/bin/claude"]), &env(&[(name, value)])),
                Err(ApplicationTerminalRefusal::Environment),
                "{name}={value}"
            );
        }
        let too_many: Vec<(String, String)> = (0..=MAX_APPLICATION_TERMINAL_ENV)
            .map(|index| (alloc::format!("SECRET_{index}"), placeholder.clone()))
            .collect();
        assert_eq!(
            binding().admit(&argv(&["/usr/bin/claude"]), &too_many),
            Err(ApplicationTerminalRefusal::Environment)
        );
    }
}
