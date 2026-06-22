//! Machine-oriented Rust SDK wrappers.
//!
//! This module deliberately shells to `mvmctl machine ...` instead of
//! reimplementing launch logic. Admission, policy, receipts, audit, OCI
//! verification, and persistent machine state stay owned by the CLI path.

use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

/// Environment variable used to override the `mvmctl` binary path.
pub const MVM_CLI_BIN_ENV: &str = "MVM_CLI_BIN";

/// Captured result from a successful `mvmctl machine` subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineResult {
    /// Process exit code.
    pub exit_code: i32,
    /// UTF-8 decoded stdout, using replacement characters for invalid bytes.
    pub stdout: String,
    /// UTF-8 decoded stderr, using replacement characters for invalid bytes.
    pub stderr: String,
}

/// Errors surfaced by machine SDK wrappers.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    /// The builder would produce an invalid `mvmctl machine` invocation.
    #[error("{0}")]
    InvalidInput(String),
    /// The `mvmctl` subprocess could not be spawned.
    #[error("failed to spawn `{program}`: {source}")]
    Spawn {
        /// Program path attempted.
        program: String,
        /// Full argv, including the program path.
        argv: Vec<String>,
        /// Underlying OS error.
        source: std::io::Error,
    },
    /// `mvmctl machine ...` exited non-zero.
    #[error("`mvmctl machine` failed with exit code {exit_code:?}")]
    Failed {
        /// Full argv, including the program path.
        argv: Vec<String>,
        /// Process exit code, or `None` if terminated by signal.
        exit_code: Option<i32>,
        /// UTF-8 decoded stderr, using replacement characters for invalid bytes.
        stderr: String,
    },
}

/// Subprocess client used by machine builders.
#[derive(Debug, Clone)]
pub struct MachineClient {
    cli_bin: PathBuf,
}

impl MachineClient {
    /// Create a client that invokes `cli_bin`.
    pub fn new(cli_bin: impl Into<PathBuf>) -> Self {
        Self {
            cli_bin: cli_bin.into(),
        }
    }

    /// Create a client from [`MVM_CLI_BIN_ENV`], falling back to `mvmctl`.
    pub fn from_env() -> Self {
        let cli_bin = env::var_os(MVM_CLI_BIN_ENV).unwrap_or_else(|| OsString::from("mvmctl"));
        Self::new(cli_bin)
    }

    /// Return the configured `mvmctl` binary path.
    pub fn cli_bin(&self) -> &Path {
        &self.cli_bin
    }

    fn run_machine<I, S>(&self, args: I) -> Result<MachineResult, MachineError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let machine_args: Vec<OsString> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        let mut argv = Vec::with_capacity(machine_args.len() + 2);
        argv.push(os_to_string(self.cli_bin.as_os_str()));
        argv.push("machine".to_string());
        argv.extend(machine_args.iter().map(|arg| os_to_string(arg.as_os_str())));

        let output = Command::new(&self.cli_bin)
            .arg("machine")
            .args(&machine_args)
            .output()
            .map_err(|source| MachineError::Spawn {
                program: os_to_string(self.cli_bin.as_os_str()),
                argv: argv.clone(),
                source,
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Err(MachineError::Failed {
                argv,
                exit_code: output.status.code(),
                stderr,
            });
        }

        Ok(MachineResult {
            exit_code: output.status.code().unwrap_or(0),
            stdout,
            stderr,
        })
    }
}

impl Default for MachineClient {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Persistent machine handle plus lifecycle builder entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    name: String,
}

impl Machine {
    /// Construct a handle for an existing named machine.
    pub fn named(name: impl Into<String>) -> Result<Self, MachineError> {
        let name = require_non_empty(name.into(), "name")?;
        Ok(Self { name })
    }

    /// Return this machine's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Build a `mvmctl machine start --name <name>` invocation.
    pub fn start(&self) -> MachineStartBuilder {
        MachineStartBuilder::new(self.name.clone())
    }

    /// Build a `mvmctl machine exec --name <name> -- <command...>` invocation.
    pub fn exec<I, S>(&self, command: I) -> MachineExecBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        MachineExecBuilder::new(self.name.clone(), collect_strings(command))
    }

    /// Build a `mvmctl machine shell --name <name>` invocation.
    pub fn shell(&self) -> MachineShellBuilder {
        MachineShellBuilder::new(self.name.clone())
    }

    /// Build a `mvmctl machine stop --name <name>` invocation.
    pub fn stop(&self) -> MachineStopBuilder {
        MachineStopBuilder::new(self.name.clone())
    }
}

/// Entry point for ephemeral `machine run` builders.
pub struct MachineRun;

impl MachineRun {
    /// Start building a `mvmctl machine run` invocation.
    pub fn builder() -> MachineRunBuilder {
        MachineRunBuilder::default()
    }
}

/// Builder for `mvmctl machine run`.
#[derive(Debug, Clone, Default)]
pub struct MachineRunBuilder {
    image: Option<String>,
    command: Vec<String>,
    net: bool,
    allow_hosts: Vec<String>,
    cpus: Option<u16>,
    memory: Option<String>,
    profile: Option<String>,
    volumes: Vec<String>,
    env: Vec<String>,
    timeout: Option<u64>,
    receipt: Option<String>,
    json: bool,
    dry_run: bool,
}

impl MachineRunBuilder {
    /// Set the OCI image reference.
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    /// Set the command argv executed in the ephemeral machine.
    pub fn command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = collect_strings(command);
        self
    }

    /// Enable or disable dev-tier networking.
    pub fn net(mut self, enabled: bool) -> Self {
        self.net = enabled;
        self
    }

    /// Add one allowed egress host.
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.allow_hosts.push(host.into());
        self
    }

    /// Add multiple allowed egress hosts.
    pub fn allow_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_hosts.extend(collect_strings(hosts));
        self
    }

    /// Set the CPU count.
    pub fn cpus(mut self, cpus: u16) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Set the memory cap, using the same string format as the CLI.
    pub fn memory(mut self, memory: impl Into<String>) -> Self {
        self.memory = Some(memory.into());
        self
    }

    /// Set the launch profile.
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Add one host directory share (`HOST:/GUEST[:MODE]`).
    pub fn volume(mut self, volume: impl Into<String>) -> Self {
        self.volumes.push(volume.into());
        self
    }

    /// Add multiple host directory shares.
    pub fn volumes<I, S>(mut self, volumes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.volumes.extend(collect_strings(volumes));
        self
    }

    /// Add one environment assignment.
    pub fn env(mut self, assignment: impl Into<String>) -> Self {
        self.env.push(assignment.into());
        self
    }

    /// Add multiple environment assignments.
    pub fn envs<I, S>(mut self, assignments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.env.extend(collect_strings(assignments));
        self
    }

    /// Set the CLI timeout in seconds.
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Write a machine receipt to `path`.
    pub fn receipt(mut self, path: impl Into<String>) -> Self {
        self.receipt = Some(path.into());
        self
    }

    /// Request JSON output from the CLI.
    pub fn json(mut self, enabled: bool) -> Self {
        self.json = enabled;
        self
    }

    /// Request a dry-run summary instead of launching.
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let image = require_option(&self.image, "image")?;
        require_non_empty_slice(&self.command, "command")?;
        validate_strings(&self.allow_hosts, "--allow-host")?;
        validate_strings(&self.volumes, "--volume")?;
        validate_strings(&self.env, "--env")?;

        let mut args = vec!["run".to_string(), "--image".to_string(), image.to_string()];
        if self.net {
            args.push("--net".to_string());
        }
        append_repeated(&mut args, "--allow-host", &self.allow_hosts);
        if let Some(cpus) = self.cpus {
            args.extend(["--cpus".to_string(), cpus.to_string()]);
        }
        append_optional(&mut args, "--memory", self.memory.as_deref())?;
        append_optional(&mut args, "--profile", self.profile.as_deref())?;
        append_repeated(&mut args, "--volume", &self.volumes);
        append_repeated(&mut args, "--env", &self.env);
        if let Some(timeout) = self.timeout {
            args.extend(["--timeout".to_string(), timeout.to_string()]);
        }
        append_optional(&mut args, "--receipt", self.receipt.as_deref())?;
        if self.json {
            args.push("--json".to_string());
        }
        if self.dry_run {
            args.push("--dry-run".to_string());
        }
        args.push("--".to_string());
        args.extend(self.command.iter().cloned());
        Ok(args)
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn run(&self) -> Result<MachineResult, MachineError> {
        self.run_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn run_with(&self, client: &MachineClient) -> Result<MachineResult, MachineError> {
        client.run_machine(self.machine_args()?)
    }
}

/// Entry point for persistent `machine create` builders.
pub struct MachineCreate;

impl MachineCreate {
    /// Start building a `mvmctl machine create --name <name>` invocation.
    pub fn builder(name: impl Into<String>) -> MachineCreateBuilder {
        MachineCreateBuilder::new(name.into())
    }
}

/// Entry point for portable artifact verification builders.
pub struct MachineCheckArtifact;

impl MachineCheckArtifact {
    /// Start building a `mvmctl machine check-artifact <path>` invocation.
    pub fn builder(path: impl Into<String>) -> MachineCheckArtifactBuilder {
        MachineCheckArtifactBuilder::new(path.into())
    }
}

/// Builder for `mvmctl machine check-artifact`.
#[derive(Debug, Clone)]
pub struct MachineCheckArtifactBuilder {
    path: String,
    key: Option<String>,
    json: bool,
}

impl MachineCheckArtifactBuilder {
    fn new(path: String) -> Self {
        Self {
            path,
            key: None,
            json: false,
        }
    }

    /// Set the verifying-key file path.
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Request JSON output from the CLI.
    pub fn json(mut self, enabled: bool) -> Self {
        self.json = enabled;
        self
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let path = require_non_empty(self.path.clone(), "path")?;
        let mut args = vec!["check-artifact".to_string(), path];
        append_optional(&mut args, "--key", self.key.as_deref())?;
        if self.json {
            args.push("--json".to_string());
        }
        Ok(args)
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn run(&self) -> Result<MachineResult, MachineError> {
        self.run_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn run_with(&self, client: &MachineClient) -> Result<MachineResult, MachineError> {
        client.run_machine(self.machine_args()?)
    }
}

/// Builder for `mvmctl machine create`.
#[derive(Debug, Clone)]
pub struct MachineCreateBuilder {
    name: String,
    image: Option<String>,
    manifest: Option<String>,
    net: bool,
    allow_hosts: Vec<String>,
    cpus: Option<u16>,
    memory: Option<String>,
    mem_initial: Option<String>,
    profile: Option<String>,
    force: bool,
    json: bool,
}

impl MachineCreateBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            image: None,
            manifest: None,
            net: false,
            allow_hosts: Vec::new(),
            cpus: None,
            memory: None,
            mem_initial: None,
            profile: None,
            force: false,
            json: false,
        }
    }

    /// Set the OCI image reference.
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    /// Set the `mvm.toml` / `Mvmfile.toml` manifest path.
    pub fn manifest(mut self, manifest: impl Into<String>) -> Self {
        self.manifest = Some(manifest.into());
        self
    }

    /// Enable or disable dev-tier networking.
    pub fn net(mut self, enabled: bool) -> Self {
        self.net = enabled;
        self
    }

    /// Add one allowed egress host.
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.allow_hosts.push(host.into());
        self
    }

    /// Add multiple allowed egress hosts.
    pub fn allow_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_hosts.extend(collect_strings(hosts));
        self
    }

    /// Set the CPU count.
    pub fn cpus(mut self, cpus: u16) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Set the memory cap, using the same string format as the CLI.
    pub fn memory(mut self, memory: impl Into<String>) -> Self {
        self.memory = Some(memory.into());
        self
    }

    /// Set the initial host memory commitment, using the same string format as the CLI.
    pub fn mem_initial(mut self, mem_initial: impl Into<String>) -> Self {
        self.mem_initial = Some(mem_initial.into());
        self
    }

    /// Set the launch profile.
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Allow replacing an existing machine spec.
    pub fn force(mut self, enabled: bool) -> Self {
        self.force = enabled;
        self
    }

    /// Request JSON output from the CLI.
    pub fn json(mut self, enabled: bool) -> Self {
        self.json = enabled;
        self
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let name = require_non_empty(self.name.clone(), "name")?;
        if self.image.is_some() && self.manifest.is_some() {
            return Err(MachineError::InvalidInput(
                "MachineCreate accepts image OR manifest, not both".to_string(),
            ));
        }
        validate_strings(&self.allow_hosts, "--allow-host")?;

        let mut args = vec!["create".to_string(), "--name".to_string(), name];
        append_optional(&mut args, "--image", self.image.as_deref())?;
        append_optional(&mut args, "--manifest", self.manifest.as_deref())?;
        if self.net {
            args.push("--net".to_string());
        }
        append_repeated(&mut args, "--allow-host", &self.allow_hosts);
        if let Some(cpus) = self.cpus {
            args.extend(["--cpus".to_string(), cpus.to_string()]);
        }
        append_optional(&mut args, "--memory", self.memory.as_deref())?;
        append_optional(&mut args, "--mem-initial", self.mem_initial.as_deref())?;
        append_optional(&mut args, "--profile", self.profile.as_deref())?;
        if self.force {
            args.push("--force".to_string());
        }
        if self.json {
            args.push("--json".to_string());
        }
        Ok(args)
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn create(&self) -> Result<Machine, MachineError> {
        self.create_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn create_with(&self, client: &MachineClient) -> Result<Machine, MachineError> {
        client.run_machine(self.machine_args()?)?;
        Machine::named(self.name.clone())
    }
}

/// Builder for `mvmctl machine start`.
#[derive(Debug, Clone)]
pub struct MachineStartBuilder {
    name: String,
    receipt: Option<String>,
    json: bool,
    dry_run: bool,
}

impl MachineStartBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            receipt: None,
            json: false,
            dry_run: false,
        }
    }

    /// Write a machine-start receipt to `path`.
    pub fn receipt(mut self, path: impl Into<String>) -> Self {
        self.receipt = Some(path.into());
        self
    }

    /// Request JSON output from the CLI.
    pub fn json(mut self, enabled: bool) -> Self {
        self.json = enabled;
        self
    }

    /// Request a dry-run summary instead of launching.
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let name = require_non_empty(self.name.clone(), "name")?;
        let mut args = vec!["start".to_string(), "--name".to_string(), name];
        append_optional(&mut args, "--receipt", self.receipt.as_deref())?;
        if self.json {
            args.push("--json".to_string());
        }
        if self.dry_run {
            args.push("--dry-run".to_string());
        }
        Ok(args)
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn run(&self) -> Result<MachineResult, MachineError> {
        self.run_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn run_with(&self, client: &MachineClient) -> Result<MachineResult, MachineError> {
        client.run_machine(self.machine_args()?)
    }
}

/// Builder for `mvmctl machine exec`.
#[derive(Debug, Clone)]
pub struct MachineExecBuilder {
    name: String,
    command: Vec<String>,
    force: bool,
}

impl MachineExecBuilder {
    fn new(name: String, command: Vec<String>) -> Self {
        Self {
            name,
            command,
            force: false,
        }
    }

    /// Force command execution when the CLI supports doing so.
    pub fn force(mut self, enabled: bool) -> Self {
        self.force = enabled;
        self
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let name = require_non_empty(self.name.clone(), "name")?;
        require_non_empty_slice(&self.command, "command")?;
        let mut args = vec!["exec".to_string(), "--name".to_string(), name];
        if self.force {
            args.push("--force".to_string());
        }
        args.push("--".to_string());
        args.extend(self.command.iter().cloned());
        Ok(args)
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn run(&self) -> Result<MachineResult, MachineError> {
        self.run_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn run_with(&self, client: &MachineClient) -> Result<MachineResult, MachineError> {
        client.run_machine(self.machine_args()?)
    }
}

/// Builder for `mvmctl machine shell`.
#[derive(Debug, Clone)]
pub struct MachineShellBuilder {
    name: String,
    force: bool,
}

impl MachineShellBuilder {
    fn new(name: String) -> Self {
        Self { name, force: false }
    }

    /// Force shell attachment when the CLI supports doing so.
    pub fn force(mut self, enabled: bool) -> Self {
        self.force = enabled;
        self
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let name = require_non_empty(self.name.clone(), "name")?;
        let mut args = vec!["shell".to_string(), "--name".to_string(), name];
        if self.force {
            args.push("--force".to_string());
        }
        Ok(args)
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn run(&self) -> Result<MachineResult, MachineError> {
        self.run_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn run_with(&self, client: &MachineClient) -> Result<MachineResult, MachineError> {
        client.run_machine(self.machine_args()?)
    }
}

/// Builder for `mvmctl machine stop`.
#[derive(Debug, Clone)]
pub struct MachineStopBuilder {
    name: String,
}

impl MachineStopBuilder {
    fn new(name: String) -> Self {
        Self { name }
    }

    /// Return the `machine` subcommand argv, excluding the `mvmctl` program.
    pub fn machine_args(&self) -> Result<Vec<String>, MachineError> {
        let name = require_non_empty(self.name.clone(), "name")?;
        Ok(vec!["stop".to_string(), "--name".to_string(), name])
    }

    /// Execute this builder with the default [`MachineClient`].
    pub fn run(&self) -> Result<MachineResult, MachineError> {
        self.run_with(&MachineClient::default())
    }

    /// Execute this builder with `client`.
    pub fn run_with(&self, client: &MachineClient) -> Result<MachineResult, MachineError> {
        client.run_machine(self.machine_args()?)
    }
}

fn append_optional(
    args: &mut Vec<String>,
    flag: &str,
    value: Option<&str>,
) -> Result<(), MachineError> {
    if let Some(value) = value {
        let value = require_non_empty(value.to_string(), flag)?;
        args.extend([flag.to_string(), value]);
    }
    Ok(())
}

fn append_repeated(args: &mut Vec<String>, flag: &str, values: &[String]) {
    for value in values {
        args.extend([flag.to_string(), value.clone()]);
    }
}

fn collect_strings<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    values.into_iter().map(Into::into).collect()
}

fn os_to_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn require_non_empty(value: String, label: &str) -> Result<String, MachineError> {
    if value.is_empty() {
        return Err(MachineError::InvalidInput(format!(
            "{label} must be non-empty"
        )));
    }
    Ok(value)
}

fn require_non_empty_slice(values: &[String], label: &str) -> Result<(), MachineError> {
    if values.is_empty() {
        return Err(MachineError::InvalidInput(format!(
            "{label} must be non-empty"
        )));
    }
    validate_strings(values, label)
}

fn require_option<'a>(value: &'a Option<String>, label: &str) -> Result<&'a str, MachineError> {
    value
        .as_deref()
        .ok_or_else(|| MachineError::InvalidInput(format!("{label} must be set")))
        .and_then(|value| {
            if value.is_empty() {
                Err(MachineError::InvalidInput(format!(
                    "{label} must be non-empty"
                )))
            } else {
                Ok(value)
            }
        })
}

fn validate_strings(values: &[String], label: &str) -> Result<(), MachineError> {
    if values.iter().any(String::is_empty) {
        return Err(MachineError::InvalidInput(format!(
            "{label} values must be non-empty"
        )));
    }
    Ok(())
}
