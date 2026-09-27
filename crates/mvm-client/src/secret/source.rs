//! Where a secret's value comes from, when it does not come from a prompt.
//!
//! A source reference names a place on the host the value already lives, so
//! it never has to be typed, pasted, or passed on a command line:
//!
//! | Reference                          | Read from                                   |
//! | ---------------------------------- | ------------------------------------------- |
//! | `env://VAR`                        | this process's environment                  |
//! | `file:///abs/path`                 | a regular file, at most 64 KiB              |
//! | `keychain://service/account`       | the operator's OS keychain                  |
//! | `op://vault/item[/section]/field`  | 1Password, through `op read`                |
//! | `bw://item/field`                  | Bitwarden, through `bw get <field> <item>`  |
//!
//! Resolution happens on the host, once, when the value is accepted — the
//! value is then stored like any other and the guest still only ever sees a
//! placeholder. Re-run the command to pick up a rotated value.
//!
//! The password-manager CLIs are the part that needs care, because running
//! them means executing a binary found on `PATH` while a vault is unlocked:
//!
//! - every argument is checked against a narrow character set before anything
//!   runs, and the binary is given an argument vector, never a shell line;
//! - the binary is looked up only in directories that are absolute, owned by
//!   root or the current user, not world-writable, and not inside the current
//!   directory, its repository, or `MVM_HOME` — the places a checked-out
//!   project or a guest's output could have put an `op` of its own;
//! - the child's environment is scrubbed of loader and interpreter variables,
//!   keeping only the session variables of the one CLI being run;
//! - the call is killed after a timeout, and its output is bounded;
//! - no value is ever logged or put in an error. A failure reports the CLI's
//!   exit status and the first line of what it wrote to stderr, which is where
//!   these tools say "not signed in".

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use secrecy::ExposeSecret;

use super::SecretValueInput;

/// The most a source may yield. A credential is a few hundred bytes; a file or
/// CLI that produces more is not what the operator meant to point at.
const MAX_SOURCE_BYTES: usize = 64 * 1024;

/// How long a password-manager CLI may take. Long enough for a desktop-app
/// unlock prompt to be answered, short enough that a hung CLI does not hang
/// `mvmctl`.
const DEFAULT_CLI_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a source reference could not be used. Never carries a value.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error(
        "unrecognised secret source {0:?}; expected env://, file://, keychain://, op:// or bw://"
    )]
    UnknownScheme(String),
    #[error("malformed secret source {reference:?}: {reason}")]
    Malformed {
        reference: String,
        reason: &'static str,
    },
    #[error("{reference} is not set in this environment")]
    EnvUnset { reference: String },
    #[error("{reference} yielded an empty value")]
    Empty { reference: String },
    #[error("{reference} yielded more than {MAX_SOURCE_BYTES} bytes")]
    TooLarge { reference: String },
    #[error("{reference} is not valid UTF-8")]
    NotUtf8 { reference: String },
    #[error("reading {reference}: {detail}")]
    Read { reference: String, detail: String },
    #[error(
        "`{program}` was not found in a trusted directory on PATH (absolute, owned by root or \
         you, not world-writable, and outside the current project and MVM_HOME)"
    )]
    CliNotFound { program: &'static str },
    #[error("`{program}` did not finish within {secs}s and was stopped")]
    CliTimedOut { program: &'static str, secs: u64 },
    #[error("`{program}` failed ({status}){detail}")]
    CliFailed {
        program: &'static str,
        status: String,
        detail: String,
    },
}

/// The fields `bw get` answers by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitwardenField {
    Password,
    Username,
    Notes,
    Totp,
}

impl BitwardenField {
    fn parse(field: &str) -> Option<Self> {
        match field {
            "password" => Some(Self::Password),
            "username" => Some(Self::Username),
            "notes" => Some(Self::Notes),
            "totp" => Some(Self::Totp),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Username => "username",
            Self::Notes => "notes",
            Self::Totp => "totp",
        }
    }
}

/// A parsed, validated source reference. Holds only where the value lives,
/// never the value, so `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    Env { var: String },
    File { path: PathBuf },
    Keychain { service: String, account: String },
    OnePassword { reference: String },
    Bitwarden { item: String, field: BitwardenField },
}

impl std::fmt::Display for SecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env { var } => write!(f, "env://{var}"),
            Self::File { path } => write!(f, "file://{}", path.display()),
            Self::Keychain { service, account } => write!(f, "keychain://{service}/{account}"),
            Self::OnePassword { reference } => f.write_str(reference),
            Self::Bitwarden { item, field } => write!(f, "bw://{item}/{}", field.as_str()),
        }
    }
}

impl std::str::FromStr for SecretSource {
    type Err = SourceError;

    fn from_str(reference: &str) -> Result<Self, SourceError> {
        let malformed = |reason| SourceError::Malformed {
            reference: reference.to_string(),
            reason,
        };
        if let Some(var) = reference.strip_prefix("env://") {
            if !is_env_name(var) {
                return Err(malformed(
                    "the variable must be a shell name: [A-Za-z_][A-Za-z0-9_]*",
                ));
            }
            return Ok(Self::Env {
                var: var.to_string(),
            });
        }
        if let Some(path) = reference.strip_prefix("file://") {
            let path = Path::new(path);
            if !path.is_absolute() {
                return Err(malformed("the path must be absolute: file:///abs/path"));
            }
            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(malformed("the path must not contain `..`"));
            }
            return Ok(Self::File {
                path: path.to_path_buf(),
            });
        }
        if let Some(rest) = reference.strip_prefix("keychain://") {
            let (service, account) = rest
                .split_once('/')
                .ok_or_else(|| malformed("expected keychain://service/account"))?;
            if !is_keychain_part(service) || !is_keychain_part(account) {
                return Err(malformed(
                    "service and account must be non-empty and printable, without `/`",
                ));
            }
            return Ok(Self::Keychain {
                service: service.to_string(),
                account: account.to_string(),
            });
        }
        if let Some(rest) = reference.strip_prefix("op://") {
            let segments: Vec<&str> = rest.split('/').collect();
            if !(3..=4).contains(&segments.len()) {
                return Err(malformed(
                    "expected op://vault/item/field or op://vault/item/section/field",
                ));
            }
            if !segments.iter().all(|s| is_vault_name(s)) {
                return Err(malformed(
                    "each part may use letters, digits, space, `_`, `-` and `.`, and may not start with `-`",
                ));
            }
            return Ok(Self::OnePassword {
                reference: reference.to_string(),
            });
        }
        if let Some(rest) = reference.strip_prefix("bw://") {
            let (item, field) = rest
                .split_once('/')
                .ok_or_else(|| malformed("expected bw://item/field"))?;
            if !is_vault_name(item) {
                return Err(malformed(
                    "the item may use letters, digits, space, `_`, `-` and `.`, and may not start with `-`",
                ));
            }
            let field = BitwardenField::parse(field)
                .ok_or_else(|| malformed("the field must be password, username, notes or totp"))?;
            return Ok(Self::Bitwarden {
                item: item.to_string(),
                field,
            });
        }
        Err(SourceError::UnknownScheme(reference.to_string()))
    }
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_keychain_part(part: &str) -> bool {
    !part.is_empty() && !part.contains('/') && !part.chars().any(char::is_control)
}

/// A vault, item, section or field name as a password-manager CLI takes it.
///
/// Narrow on purpose: the value becomes an argument to a program that can read
/// a whole vault, so anything a CLI might read as syntax — `?` query
/// parameters, quoting, a leading `-` that parses as a flag — is refused
/// rather than escaped. An item with such a name can be named by its id.
fn is_vault_name(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('-')
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
}

/// How a resolver reads an environment variable.
type EnvReader = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Resolves source references. The fields are the seams a test replaces; the
/// host resolver reads the real environment and the real `PATH`.
pub struct SourceResolver {
    env: EnvReader,
    search_path: Vec<PathBuf>,
    untrusted_roots: Vec<PathBuf>,
    timeout: Duration,
}

impl SourceResolver {
    /// The resolver for this host: this process's environment and `PATH`,
    /// with the current directory, its repository and `MVM_HOME` untrusted.
    #[must_use]
    pub fn host() -> Self {
        let search_path = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        let mut untrusted_roots = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(repo) = cwd.ancestors().find(|dir| dir.join(".git").exists()) {
                untrusted_roots.push(repo.to_path_buf());
            }
            untrusted_roots.push(cwd);
        }
        if let Ok(home) = mvm_core::config::mvm_home_strict() {
            untrusted_roots.push(home);
        }
        Self {
            env: Box::new(|name| std::env::var(name).ok()),
            search_path,
            untrusted_roots,
            timeout: DEFAULT_CLI_TIMEOUT,
        }
    }

    /// Replace how environment variables are read.
    #[must_use]
    pub fn with_env(
        mut self,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.env = Box::new(env);
        self
    }

    /// Replace the directories searched for a password-manager CLI.
    #[must_use]
    pub fn with_search_path(mut self, dirs: Vec<PathBuf>) -> Self {
        self.search_path = dirs;
        self
    }

    /// Add a directory tree no CLI may be run from.
    #[must_use]
    pub fn with_untrusted_root(mut self, root: PathBuf) -> Self {
        self.untrusted_roots.push(root);
        self
    }

    /// Replace how long a CLI may run.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Read the value `source` names.
    ///
    /// # Errors
    ///
    /// Any [`SourceError`]; none of them carries the value.
    pub fn resolve(&self, source: &SecretSource) -> Result<SecretValueInput, SourceError> {
        let reference = source.to_string();
        let value = match source {
            SecretSource::Env { var } => (self.env)(var).ok_or_else(|| SourceError::EnvUnset {
                reference: reference.clone(),
            })?,
            SecretSource::File { path } => read_file(path, &reference)?,
            SecretSource::Keychain { service, account } => {
                mvm_core::crypto::secret_store::read_os_keychain_item(service, account)
                    .map_err(|e| SourceError::Read {
                        reference: reference.clone(),
                        detail: format!("{e:#}"),
                    })?
                    .expose_secret()
                    .clone()
            }
            SecretSource::OnePassword { reference: op_ref } => self.run_cli(
                Cli::OnePassword,
                &["read", "--no-newline", op_ref.as_str()],
                &reference,
            )?,
            SecretSource::Bitwarden { item, field } => self.run_cli(
                Cli::Bitwarden,
                &["get", field.as_str(), item.as_str()],
                &reference,
            )?,
        };
        finish_value(value, &reference).map(SecretValueInput::new)
    }

    /// Run a password-manager CLI and return what it printed.
    fn run_cli(&self, cli: Cli, args: &[&str], reference: &str) -> Result<String, SourceError> {
        let program = cli.program();
        let binary = self
            .find_trusted(program)
            .ok_or(SourceError::CliNotFound { program })?;
        let mut command = std::process::Command::new(&binary);
        let readmit = mvm_core::env_hygiene::EnvReadmit::from_names(
            std::env::vars_os()
                .map(|(name, _)| name.to_string_lossy().into_owned())
                .filter(|name| cli.owns_session_var(name)),
        )
        .map_err(|e| SourceError::Read {
            reference: reference.to_string(),
            detail: e.to_string(),
        })?;
        // Every denied variable is removed from what the CLI inherits except
        // this CLI's own session variables, re-admitted by exact name.
        mvm_core::env_hygiene::scrub_command(&mut command, &readmit);
        let trusted: Vec<&PathBuf> = self
            .search_path
            .iter()
            .filter(|dir| self.is_trusted_dir(dir))
            .collect();
        if let Ok(path) = std::env::join_paths(trusted) {
            command.env("PATH", path);
        }
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|e| SourceError::Read {
            reference: reference.to_string(),
            detail: format!("starting `{program}`: {e}"),
        })?;
        let stdout = child
            .stdout
            .take()
            .map(|pipe| spawn_bounded_reader(pipe, MAX_SOURCE_BYTES + 1));
        let stderr = child
            .stderr
            .take()
            .map(|pipe| spawn_bounded_reader(pipe, 4096));
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SourceError::CliTimedOut {
                        program,
                        secs: self.timeout.as_secs(),
                    });
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => {
                    return Err(SourceError::Read {
                        reference: reference.to_string(),
                        detail: format!("waiting for `{program}`: {e}"),
                    });
                }
            }
        };
        let out = stdout.map(join_reader).unwrap_or_default();
        let err = stderr.map(join_reader).unwrap_or_default();
        if !status.success() {
            let first_line = String::from_utf8_lossy(&err)
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(|line| format!(": {}", line.chars().take(200).collect::<String>()))
                .unwrap_or_default();
            return Err(SourceError::CliFailed {
                program,
                status: status.to_string(),
                detail: first_line,
            });
        }
        if out.len() > MAX_SOURCE_BYTES {
            return Err(SourceError::TooLarge {
                reference: reference.to_string(),
            });
        }
        String::from_utf8(out).map_err(|_| SourceError::NotUtf8 {
            reference: reference.to_string(),
        })
    }

    /// The first `program` in a trusted directory on the search path whose
    /// file is itself trustworthy.
    fn find_trusted(&self, program: &str) -> Option<PathBuf> {
        self.search_path
            .iter()
            .filter(|dir| self.is_trusted_dir(dir))
            .map(|dir| dir.join(program))
            .find(|candidate| is_trusted_file(candidate))
    }

    fn is_trusted_dir(&self, dir: &Path) -> bool {
        if !dir.is_absolute() {
            return false;
        }
        let Ok(canonical) = dir.canonicalize() else {
            return false;
        };
        let under_untrusted = self.untrusted_roots.iter().any(|root| {
            let root = root.canonicalize().unwrap_or_else(|_| root.clone());
            canonical.starts_with(&root)
        });
        !under_untrusted && owned_and_not_world_writable(&canonical, 0o002)
    }
}

/// A binary found on the path must be a regular file, owned by root or the
/// current user, and writable by neither its group nor the world — the same
/// shape a package manager leaves.
fn is_trusted_file(candidate: &Path) -> bool {
    let Ok(canonical) = candidate.canonicalize() else {
        return false;
    };
    canonical.is_file() && owned_and_not_world_writable(&canonical, 0o022)
}

#[cfg(unix)]
fn owned_and_not_world_writable(path: &Path, forbidden_mode: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let owner_ok = meta.uid() == 0 || Some(meta.uid()) == effective_uid();
    owner_ok && meta.mode() & forbidden_mode == 0
}

#[cfg(not(unix))]
fn owned_and_not_world_writable(_path: &Path, _forbidden_mode: u32) -> bool {
    false
}

/// This process's effective uid, read as the owner of a file it just created —
/// which avoids `unsafe` for one `geteuid` call.
#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    tempfile::tempfile()
        .and_then(|file| file.metadata())
        .ok()
        .map(|meta| meta.uid())
}

#[derive(Clone, Copy)]
enum Cli {
    OnePassword,
    Bitwarden,
}

impl Cli {
    fn program(self) -> &'static str {
        match self {
            Self::OnePassword => "op",
            Self::Bitwarden => "bw",
        }
    }

    /// Whether `name` is one of this CLI's own session variables, which the
    /// environment filter denies to every other helper.
    fn owns_session_var(self, name: &str) -> bool {
        match self {
            Self::OnePassword => {
                name == "OP_SERVICE_ACCOUNT_TOKEN"
                    || name.starts_with("OP_SESSION_")
                    || name.starts_with("OP_CONNECT_")
            }
            Self::Bitwarden => name == "BW_SESSION",
        }
    }
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    pipe: R,
    limit: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = pipe.take(limit as u64).read_to_end(&mut out);
        out
    })
}

fn join_reader(handle: std::thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

fn read_file(path: &Path, reference: &str) -> Result<String, SourceError> {
    let read_err = |detail: String| SourceError::Read {
        reference: reference.to_string(),
        detail,
    };
    let meta = std::fs::metadata(path).map_err(|e| read_err(e.to_string()))?;
    if !meta.is_file() {
        return Err(read_err("not a regular file".into()));
    }
    if meta.len() > MAX_SOURCE_BYTES as u64 {
        return Err(SourceError::TooLarge {
            reference: reference.to_string(),
        });
    }
    let bytes = std::fs::read(path).map_err(|e| read_err(e.to_string()))?;
    String::from_utf8(bytes).map_err(|_| SourceError::NotUtf8 {
        reference: reference.to_string(),
    })
}

/// Drop one trailing newline — a value written with `echo` or a heredoc — and
/// refuse an empty result, which is a misconfigured source rather than a
/// credential.
fn finish_value(mut value: String, reference: &str) -> Result<String, SourceError> {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.len() > MAX_SOURCE_BYTES {
        return Err(SourceError::TooLarge {
            reference: reference.to_string(),
        });
    }
    if value.is_empty() {
        return Err(SourceError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(value)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn parse(s: &str) -> Result<SecretSource, SourceError> {
        s.parse()
    }

    fn resolver_in(dir: &Path) -> SourceResolver {
        SourceResolver::host()
            .with_env(|_| None)
            .with_search_path(vec![dir.to_path_buf()])
            .with_timeout(Duration::from_secs(10))
    }

    /// Put an executable script named `name` in `dir`, printing `stdout`.
    fn fake_cli(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn value_of(input: SecretValueInput) -> String {
        input.storage_value().expose_secret().clone()
    }

    #[test]
    fn every_scheme_parses_and_prints_back_the_same_reference() {
        for reference in [
            "env://ANTHROPIC_API_KEY",
            "file:///run/secrets/api",
            "keychain://mvm-dev/anthropic",
            "op://Private/Anthropic/credential",
            "op://Private/Anthropic API/keys/credential",
            "bw://anthropic key/password",
        ] {
            let source = parse(reference).unwrap();
            assert_eq!(source.to_string(), reference);
        }
    }

    #[test]
    fn a_reference_that_could_be_read_as_syntax_is_refused() {
        for bad in [
            "env://1BAD",
            "env://A-B",
            "file://relative/path",
            "file:///etc/../etc/shadow",
            "keychain://service-only",
            "keychain:///account",
            "op://vault/item",
            "op://vault/item/field?attribute=otp",
            "op://vault/-item/field",
            "op://vault/item/$(id)",
            "op://vault/it\"em/field",
            "op://a/b/c/d/e",
            "bw://-x/password",
            "bw://item/uri",
            "bw://item;rm/password",
            "ftp://nope",
            "plain-value",
        ] {
            assert!(parse(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn env_source_reads_the_variable_and_refuses_an_unset_one() {
        let resolver = SourceResolver::host()
            .with_env(|name| (name == "MY_KEY").then(|| "sk-from-env".to_string()));
        let value = resolver.resolve(&parse("env://MY_KEY").unwrap()).unwrap();
        assert_eq!(value_of(value), "sk-from-env");
        let err = resolver
            .resolve(&parse("env://OTHER").unwrap())
            .unwrap_err();
        assert!(matches!(err, SourceError::EnvUnset { .. }), "{err}");
    }

    #[test]
    fn file_source_strips_one_newline_and_refuses_empty_and_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("key");
        std::fs::write(&file, "sk-from-file\n").unwrap();
        let resolver = SourceResolver::host();
        let reference = format!("file://{}", file.display());
        assert_eq!(
            value_of(resolver.resolve(&parse(&reference).unwrap()).unwrap()),
            "sk-from-file"
        );

        std::fs::write(&file, "\n").unwrap();
        let err = resolver.resolve(&parse(&reference).unwrap()).unwrap_err();
        assert!(matches!(err, SourceError::Empty { .. }), "{err}");

        std::fs::write(&file, vec![b'a'; MAX_SOURCE_BYTES + 1]).unwrap();
        let err = resolver.resolve(&parse(&reference).unwrap()).unwrap_err();
        assert!(matches!(err, SourceError::TooLarge { .. }), "{err}");

        let as_dir = format!("file://{}", dir.path().display());
        assert!(resolver.resolve(&parse(&as_dir).unwrap()).is_err());
    }

    #[test]
    fn op_is_run_with_its_reference_as_one_argument_and_its_output_is_the_value() {
        let dir = tempfile::tempdir().unwrap();
        // Answers only the exact argument vector expected, so a reference
        // split into several arguments, or passed through a shell, fails.
        fake_cli(
            dir.path(),
            "op",
            "[ \"$#\" = 3 ] && [ \"$1\" = read ] && [ \"$2\" = --no-newline ] \
             && [ \"$3\" = 'op://Private/Anthropic API/credential' ] && printf sk-from-op || exit 3",
        );
        let resolver = resolver_in(dir.path());
        let value = resolver
            .resolve(&parse("op://Private/Anthropic API/credential").unwrap())
            .unwrap();
        assert_eq!(value_of(value), "sk-from-op");
    }

    #[test]
    fn bw_is_asked_for_the_named_field_of_the_named_item() {
        let dir = tempfile::tempdir().unwrap();
        fake_cli(
            dir.path(),
            "bw",
            "[ \"$1\" = get ] && [ \"$2\" = password ] && [ \"$3\" = 'my item' ] && printf 'sk-from-bw\\n' || exit 3",
        );
        let value = resolver_in(dir.path())
            .resolve(&parse("bw://my item/password").unwrap())
            .unwrap();
        assert_eq!(value_of(value), "sk-from-bw");
    }

    #[test]
    fn a_failing_cli_reports_its_status_and_stderr_line_not_its_stdout() {
        let dir = tempfile::tempdir().unwrap();
        fake_cli(
            dir.path(),
            "op",
            "printf 'partial-secret-output'; echo '[ERROR] not currently signed in' >&2; exit 1",
        );
        let err = resolver_in(dir.path())
            .resolve(&parse("op://v/i/f").unwrap())
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("not currently signed in"), "{text}");
        assert!(!text.contains("partial-secret-output"), "{text}");
    }

    #[test]
    fn a_hung_cli_is_stopped_at_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        // By absolute path: the resolver runs the CLI with PATH narrowed to its
        // trusted directories, which here is only the fixture directory.
        fake_cli(dir.path(), "op", "exec /bin/sleep 30");
        let started = Instant::now();
        let err = resolver_in(dir.path())
            .with_timeout(Duration::from_millis(300))
            .resolve(&parse("op://v/i/f").unwrap())
            .unwrap_err();
        assert!(matches!(err, SourceError::CliTimedOut { .. }), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_cli_inside_an_untrusted_tree_is_never_run() {
        let project = tempfile::tempdir().unwrap();
        let bin = project.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bin).unwrap();
        let marker = project.path().join("ran");
        fake_cli(
            &bin,
            "op",
            &format!("touch '{}'; printf planted", marker.display()),
        );
        let err = resolver_in(&bin)
            .with_untrusted_root(project.path().to_path_buf())
            .resolve(&parse("op://v/i/f").unwrap())
            .unwrap_err();
        assert!(matches!(err, SourceError::CliNotFound { .. }), "{err}");
        assert!(!marker.exists(), "the planted binary must not run");
    }

    #[test]
    fn a_cli_in_a_world_writable_directory_or_writable_by_others_is_never_run() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        fake_cli(&open, "op", "printf planted");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = resolver_in(&open)
            .resolve(&parse("op://v/i/f").unwrap())
            .unwrap_err();
        assert!(matches!(err, SourceError::CliNotFound { .. }), "{err}");

        let group = dir.path().join("group");
        std::fs::create_dir(&group).unwrap();
        let binary = fake_cli(&group, "op", "printf planted");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = resolver_in(&group)
            .resolve(&parse("op://v/i/f").unwrap())
            .unwrap_err();
        assert!(matches!(err, SourceError::CliNotFound { .. }), "{err}");
    }

    #[test]
    fn a_relative_path_entry_is_never_searched() {
        let err = SourceResolver::host()
            .with_search_path(vec![PathBuf::from("bin")])
            .resolve(&parse("op://v/i/f").unwrap())
            .unwrap_err();
        assert!(matches!(err, SourceError::CliNotFound { .. }), "{err}");
    }

    #[test]
    fn the_cli_gets_its_own_session_variable_and_no_loader_variable() {
        let dir = tempfile::tempdir().unwrap();
        fake_cli(
            dir.path(),
            "bw",
            "[ -n \"$BW_SESSION\" ] && [ -z \"$DYLD_INSERT_LIBRARIES\" ] && [ -z \"$LD_PRELOAD\" ] && printf ok || printf leaked",
        );
        let resolver = resolver_in(dir.path());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("BW_SESSION", "session-token");
        env.set("LD_PRELOAD", "/tmp/evil.so");
        let value = resolver
            .resolve(&parse("bw://item/password").unwrap())
            .unwrap();
        assert_eq!(value_of(value), "ok");
    }
}
