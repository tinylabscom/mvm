//! What the running process is, as far as finding and spawning host helpers
//! is concerned.
//!
//! `mvmctl` is the default. Its helper binaries sit beside its own executable,
//! and it may run itself again for a hidden internal subcommand. A library
//! loaded into some other program is neither: its executable's directory is
//! that program's (an interpreter's, typically), and running its executable
//! again runs the interpreter. Such a host says so once, before it resolves or
//! spawns anything, through [`declare_host_binary_dir`] and
//! [`declare_library_embedder`].
//!
//! Both declarations are set-once process globals held in [`OnceLock`]s, never
//! environment variables: mutating the environment of a multithreaded host
//! process is unsound. Resolution code does not read the globals directly. It
//! takes a [`HostProcess`] value, which only [`HostProcess::current`] builds
//! from the globals, so a test constructs exactly the process it wants to
//! describe and nothing it does is visible to another test.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{BuildProfile, build_profile_of_dir};

/// File name of the CLI binary. A library embedder never spawns it.
pub const CLI_BIN: &str = "mvmctl";

static DECLARED_HOST_BINARY_DIR: OnceLock<PathBuf> = OnceLock::new();
static DECLARED_LIBRARY_EMBEDDER: OnceLock<()> = OnceLock::new();

/// Declare the directory holding this process's host helper binaries.
///
/// Every sibling-binary lookup then searches `dir` in place of the running
/// executable's directory. Set-once: repeating the same directory is accepted,
/// so a library initialiser that runs twice is harmless, while a different
/// directory is refused. Silently keeping the first would leave the second
/// caller resolving helpers from a directory it never named; silently taking
/// the second would change, mid-process, which binaries already-resolved
/// neighbours were paired with.
pub fn declare_host_binary_dir(dir: impl Into<PathBuf>) -> Result<(), HostBinaryDirError> {
    declare_dir_in(&DECLARED_HOST_BINARY_DIR, dir.into())
}

/// Declare that this process is a library embedding the runtime rather than
/// `mvmctl`.
///
/// From then on every path that would run `mvmctl` — or build one — refuses
/// with [`CliSpawnRefused`]. There is no way to take the declaration back, and
/// declaring it again changes nothing.
pub fn declare_library_embedder() {
    DECLARED_LIBRARY_EMBEDDER.get_or_init(|| ());
}

fn declare_dir_in(slot: &OnceLock<PathBuf>, dir: PathBuf) -> Result<(), HostBinaryDirError> {
    if !dir.is_absolute() {
        return Err(HostBinaryDirError::NotAbsolute(dir));
    }
    let declared = slot.get_or_init(|| dir.clone());
    if *declared == dir {
        return Ok(());
    }
    Err(HostBinaryDirError::AlreadyDeclared {
        declared: declared.clone(),
        requested: dir,
    })
}

/// Why [`declare_host_binary_dir`] refused a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostBinaryDirError {
    /// A relative directory would resolve against a working directory the
    /// host process is free to change.
    NotAbsolute(PathBuf),
    /// A different directory was declared first.
    AlreadyDeclared {
        /// The directory already in force.
        declared: PathBuf,
        /// The directory this call asked for.
        requested: PathBuf,
    },
}

impl fmt::Display for HostBinaryDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute(dir) => write!(
                f,
                "host binary directory must be an absolute path, got {}",
                dir.display()
            ),
            Self::AlreadyDeclared {
                declared,
                requested,
            } => write!(
                f,
                "host binary directory is already declared as {}; refusing to redeclare it as {}",
                declared.display(),
                requested.display()
            ),
        }
    }
}

impl std::error::Error for HostBinaryDirError {}

/// The facts about the running process that helper resolution depends on.
///
/// [`HostProcess::current`] reads the process declarations; the other
/// constructors describe a process explicitly and touch no global state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostProcess {
    declared_binary_dir: Option<PathBuf>,
    library_embedder: bool,
}

impl HostProcess {
    /// This process, as declared. With nothing declared this is `mvmctl`.
    pub fn current() -> Self {
        Self::from_slots(&DECLARED_HOST_BINARY_DIR, &DECLARED_LIBRARY_EMBEDDER)
    }

    fn from_slots(dir: &OnceLock<PathBuf>, embedder: &OnceLock<()>) -> Self {
        Self {
            declared_binary_dir: dir.get().cloned(),
            library_embedder: embedder.get().is_some(),
        }
    }

    /// A process that declared nothing: `mvmctl` itself.
    pub fn undeclared() -> Self {
        Self::default()
    }

    /// This description with `dir` as the declared host binary directory.
    pub fn with_binary_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.declared_binary_dir = Some(dir.into());
        self
    }

    /// This description marked as a library embedder.
    pub fn as_library_embedder(mut self) -> Self {
        self.library_embedder = true;
        self
    }

    /// Whether this process is a library embedding the runtime.
    pub fn is_library_embedder(&self) -> bool {
        self.library_embedder
    }

    /// The directory host helper binaries are expected in: the declared one,
    /// or else the running executable's own directory.
    ///
    /// A declared directory replaces the executable's rather than preceding
    /// it. An embedder's executable directory is its interpreter's, and
    /// searching there is the lookup the declaration exists to stop.
    pub fn binary_dir(&self) -> Option<PathBuf> {
        self.declared_binary_dir.clone().or_else(current_exe_dir)
    }

    /// The cargo profile [`Self::binary_dir`] is, when its name reveals one.
    ///
    /// Read from the host binary directory rather than the executable, so an
    /// embedder that declared `target/release` rebuilds helpers in the release
    /// profile, not in whatever its interpreter's path happens to suggest.
    pub fn build_profile(&self) -> Option<BuildProfile> {
        self.binary_dir().as_deref().and_then(build_profile_of_dir)
    }

    /// `name` inside [`Self::binary_dir`], when that file exists.
    pub fn binary_named(&self, name: &str) -> Option<PathBuf> {
        self.binary_dir()
            .map(|dir| dir.join(name))
            .filter(|candidate| candidate.is_file())
    }

    /// Refuse `spawn` when this process is a library embedder.
    pub fn refuse_cli_spawn(&self, spawn: CliSpawn) -> Result<(), CliSpawnRefused> {
        if self.library_embedder {
            return Err(CliSpawnRefused { spawn });
        }
        Ok(())
    }
}

fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// A path that would run `mvmctl`, or build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliSpawn {
    /// Running an `mvmctl` to bootstrap the builder VM image or build the SDK
    /// sidecar.
    BuilderBootstrapHelper,
    /// `cargo build --bin mvmctl` to produce that helper.
    BuilderBootstrapHelperBuild,
    /// Running the current executable as the builder VM's egress supervisor.
    BuilderEgressSupervisor,
    /// Running `mvmctl machine restart` for a workload that failed its
    /// healthcheck.
    HealthRestart,
    /// Resolving `mvmctl` as a per-VM host helper, named by its path-override
    /// environment variable.
    HostHelper {
        /// The helper's path-override environment variable.
        env_var: String,
    },
}

impl CliSpawn {
    fn action(&self) -> String {
        match self {
            Self::BuilderBootstrapHelper => {
                "bootstrapping the builder VM image would run `mvmctl`".to_string()
            }
            Self::BuilderBootstrapHelperBuild => {
                "bootstrapping the builder VM image would run `cargo build --bin mvmctl`"
                    .to_string()
            }
            Self::BuilderEgressSupervisor => {
                "starting the builder VM's egress supervisor would run this process's executable \
                 as `mvmctl`"
                    .to_string()
            }
            Self::HealthRestart => {
                "restarting an unhealthy workload would run `mvmctl machine restart`".to_string()
            }
            Self::HostHelper { env_var } => {
                format!("the host helper overridden by {env_var} is `mvmctl` itself")
            }
        }
    }

    fn remedy(&self) -> &'static str {
        match self {
            Self::BuilderBootstrapHelper
            | Self::BuilderBootstrapHelperBuild
            | Self::BuilderEgressSupervisor => {
                "Bootstrap this host with `mvmctl bootstrap` first, then retry."
            }
            Self::HealthRestart => "Restart it with `mvmctl machine restart`.",
            Self::HostHelper { .. } => "Run this workload through `mvmctl` instead.",
        }
    }
}

/// A library embedder was asked to run `mvmctl` or build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliSpawnRefused {
    spawn: CliSpawn,
}

impl CliSpawnRefused {
    /// The path that was refused.
    pub fn spawn(&self) -> &CliSpawn {
        &self.spawn
    }
}

impl fmt::Display for CliSpawnRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, and this process is a library embedding the mvm runtime, which never runs or \
             builds `mvmctl`. {}",
            self.spawn.action(),
            self.spawn.remedy()
        )
    }
}

impl std::error::Error for CliSpawnRefused {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_declared_describes_mvmctl() {
        let dir = OnceLock::new();
        let embedder = OnceLock::new();

        let host = HostProcess::from_slots(&dir, &embedder);

        assert_eq!(host, HostProcess::undeclared());
        assert!(!host.is_library_embedder());
        assert!(
            host.refuse_cli_spawn(CliSpawn::BuilderBootstrapHelper)
                .is_ok()
        );
    }

    #[test]
    fn an_undeclared_process_looks_beside_its_own_executable() {
        let exe = std::env::current_exe().expect("test binary path");

        assert_eq!(
            HostProcess::undeclared().binary_dir().as_deref(),
            exe.parent()
        );
    }

    #[test]
    fn a_declared_directory_replaces_the_executable_directory() {
        let declared = tempfile::TempDir::new().expect("tempdir");
        let host = HostProcess::undeclared().with_binary_dir(declared.path());

        assert_eq!(host.binary_dir().as_deref(), Some(declared.path()));
    }

    #[test]
    fn binary_named_finds_only_files_in_the_declared_directory() {
        let declared = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(declared.path().join("mvm-helper"), b"").expect("write helper");
        let host = HostProcess::undeclared().with_binary_dir(declared.path());

        assert_eq!(
            host.binary_named("mvm-helper"),
            Some(declared.path().join("mvm-helper"))
        );
        assert_eq!(host.binary_named("mvm-absent"), None);
    }

    #[test]
    fn the_build_profile_is_read_from_the_declared_directory() {
        let host = HostProcess::undeclared().with_binary_dir("/repo/target/release");

        assert_eq!(host.build_profile(), Some(BuildProfile::Release));
    }

    #[test]
    fn declarations_are_read_back_from_their_slots() {
        let dir = OnceLock::new();
        let embedder = OnceLock::new();
        declare_dir_in(&dir, PathBuf::from("/opt/mvm/bin")).expect("first declaration");
        embedder.get_or_init(|| ());

        assert_eq!(
            HostProcess::from_slots(&dir, &embedder),
            HostProcess::undeclared()
                .with_binary_dir("/opt/mvm/bin")
                .as_library_embedder()
        );
    }

    #[test]
    fn redeclaring_the_same_directory_is_accepted() {
        let slot = OnceLock::new();

        declare_dir_in(&slot, PathBuf::from("/opt/mvm/bin")).expect("first declaration");
        declare_dir_in(&slot, PathBuf::from("/opt/mvm/bin")).expect("same directory again");

        assert_eq!(slot.get(), Some(&PathBuf::from("/opt/mvm/bin")));
    }

    #[test]
    fn declaring_a_different_directory_is_refused_and_keeps_the_first() {
        let slot = OnceLock::new();
        declare_dir_in(&slot, PathBuf::from("/opt/mvm/bin")).expect("first declaration");

        let err = declare_dir_in(&slot, PathBuf::from("/usr/local/bin"))
            .expect_err("a second directory must be refused");

        assert_eq!(
            err,
            HostBinaryDirError::AlreadyDeclared {
                declared: PathBuf::from("/opt/mvm/bin"),
                requested: PathBuf::from("/usr/local/bin"),
            }
        );
        assert_eq!(slot.get(), Some(&PathBuf::from("/opt/mvm/bin")));
    }

    #[test]
    fn a_relative_directory_is_refused_and_declares_nothing() {
        let slot = OnceLock::new();

        let err = declare_dir_in(&slot, PathBuf::from("bin")).expect_err("relative refused");

        assert_eq!(err, HostBinaryDirError::NotAbsolute(PathBuf::from("bin")));
        assert!(slot.get().is_none());
    }

    #[test]
    fn a_library_embedder_refuses_every_cli_spawn_and_says_how_to_proceed() {
        let host = HostProcess::undeclared().as_library_embedder();

        for spawn in [
            CliSpawn::BuilderBootstrapHelper,
            CliSpawn::BuilderBootstrapHelperBuild,
            CliSpawn::BuilderEgressSupervisor,
        ] {
            let err = host
                .refuse_cli_spawn(spawn.clone())
                .expect_err("embedder refuses");
            assert_eq!(err.spawn(), &spawn);
            assert!(err.to_string().contains("mvmctl bootstrap"), "{err}");
        }
        let helper = host
            .refuse_cli_spawn(CliSpawn::HostHelper {
                env_var: "MVM_QEMU_BRIDGE_PATH".to_string(),
            })
            .expect_err("embedder refuses");
        assert!(
            helper.to_string().contains("MVM_QEMU_BRIDGE_PATH"),
            "{helper}"
        );
    }
}
