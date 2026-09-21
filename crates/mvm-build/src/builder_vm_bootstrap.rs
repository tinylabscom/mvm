//! Acquiring and running the builder-VM bootstrap helper.
//!
//! On a source checkout with a cold `~/.mvm/cache/builder-vm/<arch>/`, the
//! image has to be built before anything can boot it — and building it needs an
//! `mvmctl` carrying the embedded Linux host binaries. That is the only thing a
//! helper is ever for, so the resolution ladder asks in order: an explicitly
//! named helper, the running executable when it has declared the payload, a
//! fresh one already on disk, then a build.
//!
//! The build is last on purpose. It costs minutes and needs the pinned
//! cross-compile toolchain, so it is preflighted and every refusal names all
//! three ways past it.
//!
//! None of that applies to a library embedding the runtime. It is not `mvmctl`
//! and must never run or build one, so once [`declare_library_embedder`] has
//! been called every rung of the ladder refuses with
//! [`BuilderVmError::CliSpawnRefused`] instead.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, io};

use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};

use crate::builder_vm::BuilderVmError;
use crate::builder_vm_image::builder_vm_source_checkout_root;

/// Declare that this process is a library embedding the runtime, not `mvmctl`.
///
/// Set-once and irreversible. Afterwards builder-VM bootstrap, the cargo build
/// of a bootstrap helper, and the builder egress supervisor all refuse rather
/// than run the current executable or an `mvmctl`; the host has to have been
/// bootstrapped with `mvmctl bootstrap` beforehand.
pub use mvm_vmm::host::aux_bin::declare_library_embedder;

pub(crate) const BUILDER_VM_BOOTSTRAP_BIN_ENV: &str = "MVM_BUILDER_VM_BOOTSTRAP_BIN";
const BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV: &str = "MVM_SKIP_BUILDER_VM_AUTO_BOOTSTRAP";
/// Set on every process this crate spawns to bootstrap the builder VM image.
///
/// A bootstrap that finishes without populating the cache must fail, not
/// delegate: without this marker the child re-enters auto-bootstrap on the same
/// cold cache and forks another child, forever. One level is all the delegation
/// that can ever help, because the second level has nothing new to try.
const BUILDER_VM_BOOTSTRAP_ACTIVE_ENV: &str = "MVM_BUILDER_VM_BOOTSTRAP_ACTIVE";

/// Whether the running executable carries the embedded Linux host binaries.
///
/// The whole point of the bootstrap helper is to obtain a binary that has
/// them, so when the running one already does it *is* the helper and there is
/// nothing to build. This crate sits below the one that owns the embed table
/// and cannot read it, so the binary that owns it says so once at startup.
/// Default `false`: an undeclared caller (a test binary, a library embedder)
/// gets the conservative build-a-helper path it had before.
static CURRENT_EXE_CARRIES_HOST_BINARIES: AtomicBool = AtomicBool::new(false);

/// Declare whether this process's executable carries the embedded Linux host
/// binaries a builder-VM bootstrap needs. Called once by `mvmctl` at startup.
pub fn declare_current_exe_carries_host_binaries(carries: bool) {
    CURRENT_EXE_CARRIES_HOST_BINARIES.store(carries, Ordering::Relaxed);
}

/// The Cargo features the running `mvmctl` was compiled with, as the root
/// package's build script recorded them. Unset in a binary that declares none.
static CURRENT_EXE_FEATURES: OnceLock<Vec<String>> = OnceLock::new();

/// Declare the Cargo features this `mvmctl` was compiled with, as a
/// comma-separated list of root-package feature names. Called once by `mvmctl`
/// at startup.
///
/// A bootstrap helper this binary has to compile is built with the same set.
/// Built with `embed-host-bins` alone, it dropped every feature that decides how
/// artifacts are acquired — `release-artifact-bootstrap` among them — so a
/// caller that asked to fetch the builder image got a helper that could only
/// build it from source.
pub fn declare_current_exe_features(enabled: &str) {
    let _ = CURRENT_EXE_FEATURES.set(
        enabled
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect(),
    );
}

/// The Cargo feature selection a bootstrap helper is compiled with.
///
/// The helper is this `mvmctl` plus the embedded host binaries, so it mirrors
/// the caller's features — with or without the default set — and adds
/// `embed-host-bins`. A binary that declared nothing gets `embed-host-bins` over
/// the defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperFeatures {
    /// Sorted and deduplicated; always contains `embed-host-bins`.
    features: Vec<String>,
    default_features: bool,
}

impl HelperFeatures {
    const EMBED_HOST_BINS: &'static str = "embed-host-bins";
    const DEFAULT: &'static str = "default";

    fn for_caller(declared: Option<&[String]>) -> Self {
        let Some(declared) = declared else {
            return Self {
                features: vec![Self::EMBED_HOST_BINS.to_owned()],
                default_features: true,
            };
        };
        let mut features: Vec<String> = declared
            .iter()
            .filter(|name| name.as_str() != Self::DEFAULT)
            .cloned()
            .chain(std::iter::once(Self::EMBED_HOST_BINS.to_owned()))
            .collect();
        features.sort();
        features.dedup();
        Self {
            features,
            default_features: declared.iter().any(|name| name == Self::DEFAULT),
        }
    }

    fn cargo_args(&self) -> Vec<String> {
        let selection = ["--features".to_owned(), self.features.join(",")];
        if self.default_features {
            selection.to_vec()
        } else {
            std::iter::once("--no-default-features".to_owned())
                .chain(selection)
                .collect()
        }
    }

    /// The record kept beside a built helper. A later caller whose selection
    /// differs rebuilds the helper rather than reusing one built without its
    /// features.
    fn stamp(&self) -> String {
        self.cargo_args().join(" ")
    }
}

fn current_helper_features() -> HelperFeatures {
    HelperFeatures::for_caller(CURRENT_EXE_FEATURES.get().map(Vec::as_slice))
}

fn helper_features_stamp_path(helper_bin: &Path) -> PathBuf {
    helper_bin.with_extension("features")
}

/// The running executable, when it has declared a host-binary payload and the
/// OS will name it. Both halves must hold: a declared payload we cannot point
/// a `Command` at is no use as a helper.
fn current_exe_as_bootstrap_helper() -> Option<PathBuf> {
    CURRENT_EXE_CARRIES_HOST_BINARIES
        .load(Ordering::Relaxed)
        .then(|| std::env::current_exe().ok())
        .flatten()
}

/// Refresh a cold builder-image cache by running a bootstrap, reporting whether
/// one ran. `Ok(false)` is a decline, not a failure: the caller falls back to
/// its own missing-image error, which says what the cache needs.
pub(crate) fn auto_bootstrap_builder_vm_image(arch_dir: &Path) -> Result<bool, BuilderVmError> {
    auto_bootstrap_builder_vm_image_for(arch_dir, &HostProcess::current())
}

fn auto_bootstrap_builder_vm_image_for(
    arch_dir: &Path,
    host: &HostProcess,
) -> Result<bool, BuilderVmError> {
    if std::env::var_os(BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV).is_some() {
        return Ok(false);
    }

    // This process *is* a bootstrap. Reporting the cold cache is the whole
    // signal; spawning a third one would only lose it.
    if std::env::var_os(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV).is_some() {
        return Ok(false);
    }

    // Refused before the checkout test, so a cold cache reads the same to an
    // embedder whether or not it was built from a source checkout.
    host.refuse_cli_spawn(CliSpawn::BuilderBootstrapHelper)?;

    #[cfg(test)]
    if std::env::var_os(BUILDER_VM_BOOTSTRAP_BIN_ENV).is_none() {
        return Ok(false);
    }

    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(false);
    };

    let bootstrap_bin = resolve_builder_vm_bootstrap_bin_for(&workspace_root, host)?;
    let mut cmd = builder_vm_helper_command(
        host,
        &bootstrap_bin,
        &workspace_root,
        BuilderVmHelperCommand::Bootstrap,
    )?;
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn builder VM bootstrap helper {}: {e}",
            bootstrap_bin.display()
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM bootstrap helper {} exited with {} while refreshing {}",
            bootstrap_bin.display(),
            status.code().unwrap_or(-1),
            arch_dir.display(),
        )));
    }
    Ok(true)
}

pub fn maybe_reexec_builder_vm_bootstrap_helper() -> Result<bool, BuilderVmError> {
    maybe_reexec_builder_vm_helper(BuilderVmHelperCommand::Bootstrap)
}

pub fn maybe_reexec_builder_vm_sdk_sidecar_helper(force: bool) -> Result<bool, BuilderVmError> {
    maybe_reexec_builder_vm_helper(BuilderVmHelperCommand::SdkSidecarBuild { force })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuilderVmHelperCommand {
    Bootstrap,
    SdkSidecarBuild { force: bool },
}

impl BuilderVmHelperCommand {
    fn args(self) -> Vec<&'static str> {
        match self {
            Self::Bootstrap => vec!["__builder-vm-bootstrap"],
            Self::SdkSidecarBuild { force: false } => {
                vec!["build", "sdk-sidecar", "build"]
            }
            Self::SdkSidecarBuild { force: true } => {
                vec!["build", "sdk-sidecar", "build", "--force"]
            }
        }
    }
}

fn maybe_reexec_builder_vm_helper(command: BuilderVmHelperCommand) -> Result<bool, BuilderVmError> {
    maybe_reexec_builder_vm_helper_for(
        command,
        &HostProcess::current(),
        builder_vm_source_checkout_root(),
    )
}

fn maybe_reexec_builder_vm_helper_for(
    command: BuilderVmHelperCommand,
    host: &HostProcess,
    source_checkout_root: Option<PathBuf>,
) -> Result<bool, BuilderVmError> {
    // Refused before the checkout test, for the same reason auto-bootstrap is:
    // a decline would read to an embedder as permission to proceed in-process.
    host.refuse_cli_spawn(CliSpawn::BuilderBootstrapHelper)?;
    let Some(workspace_root) = source_checkout_root else {
        return Ok(false);
    };

    let bootstrap_bin = resolve_builder_vm_bootstrap_bin_for(&workspace_root, host)?;
    if current_exe_matches(&bootstrap_bin) {
        return Ok(false);
    }

    let mut cmd = builder_vm_helper_command(host, &bootstrap_bin, &workspace_root, command)?;
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn embedded builder VM helper {}: {e}",
            bootstrap_bin.display()
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "embedded builder VM helper {} exited with {}",
            bootstrap_bin.display(),
            status.code().unwrap_or(-1),
        )));
    }
    Ok(true)
}

/// The command that runs the `mvmctl` at `helper` for `command` from
/// `workspace_root`, refused for a library embedder.
///
/// The resolver has refused an embedder already; refusing here as well keeps
/// the one place a helper `Command` is built from depending on every caller
/// having gone through it.
fn builder_vm_helper_command(
    host: &HostProcess,
    helper: &Path,
    workspace_root: &Path,
    command: BuilderVmHelperCommand,
) -> Result<Command, BuilderVmError> {
    host.refuse_cli_spawn(CliSpawn::BuilderBootstrapHelper)?;
    let mut cmd = Command::new(helper);
    cmd.current_dir(workspace_root).args(command.args());
    if command == BuilderVmHelperCommand::Bootstrap {
        // Marks the child as a bootstrap so it never spawns one of its own.
        cmd.env(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");
    }
    Ok(cmd)
}

fn current_exe_matches(path: &Path) -> bool {
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let current = current_exe.canonicalize().unwrap_or(current_exe);
    let expected = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    current == expected
}

#[cfg(test)]
pub(crate) fn resolve_builder_vm_bootstrap_bin(
    workspace_root: &Path,
) -> Result<PathBuf, BuilderVmError> {
    resolve_builder_vm_bootstrap_bin_for(workspace_root, &HostProcess::current())
}

/// Resolve the bootstrap helper on behalf of `host`.
///
/// Every rung yields an `mvmctl` — a named one, the current executable, a
/// cached build, or a fresh `cargo build --bin mvmctl` — so a library embedder
/// is refused before the first rung, an explicit override included.
fn resolve_builder_vm_bootstrap_bin_for(
    workspace_root: &Path,
    host: &HostProcess,
) -> Result<PathBuf, BuilderVmError> {
    host.refuse_cli_spawn(CliSpawn::BuilderBootstrapHelper)?;
    if let Some(path) = std::env::var_os(BUILDER_VM_BOOTSTRAP_BIN_ENV).map(PathBuf::from) {
        if path.is_file() {
            return Ok(path);
        }
        return Err(BuilderVmError::ExtractionFailed(format!(
            "{} points at {} which is not a file",
            BUILDER_VM_BOOTSTRAP_BIN_ENV,
            path.display(),
        )));
    }

    if let Some(current_exe) = current_exe_as_bootstrap_helper() {
        return Ok(current_exe);
    }

    let helper_target_dir = builder_vm_bootstrap_helper_target_dir(workspace_root);
    let helper_bin = helper_target_dir.join("debug").join("mvmctl");
    let features = current_helper_features();
    if helper_bin.is_file()
        && !bootstrap_helper_needs_rebuild(&helper_bin, workspace_root, &features)
    {
        return Ok(helper_bin);
    }
    // The helper is built with `embed-host-bins`, which cross-compiles
    // the host binaries with the pinned zig + musl Rust. Ask for that toolchain
    // before spending minutes on a compile whose build script would only panic
    // about it at the very end.
    if let Err(reason) = embed_toolchain_ready(workspace_root) {
        return Err(BuilderVmError::ExtractionFailed(
            bootstrap_helper_toolchain_refusal(&reason),
        ));
    }
    std::fs::create_dir_all(&helper_target_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "create builder VM bootstrap helper target dir {}: {e}",
            helper_target_dir.display()
        ))
    })?;

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = builder_vm_bootstrap_helper_build_command(
        host,
        &cargo,
        workspace_root,
        &helper_target_dir,
        &features,
    )?;
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn cargo to build mvmctl bootstrap helper: {e}"
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "cargo build --bin mvmctl {} exited with {} while preparing the builder VM \
             bootstrap helper. {}",
            features.stamp(),
            status.code().unwrap_or(-1),
            BOOTSTRAP_HELPER_WAYS_OUT,
        )));
    }

    if helper_bin.is_file() {
        // A missing record costs one rebuild on the next call, never a helper
        // with the wrong features, so failing to write it does not fail a build
        // that succeeded.
        let stamp = helper_features_stamp_path(&helper_bin);
        if let Err(e) = fs::write(&stamp, features.stamp()) {
            tracing::warn!(
                path = %stamp.display(),
                error = %e,
                "could not record the builder VM bootstrap helper's features; it will be rebuilt next time"
            );
        }
        return Ok(helper_bin);
    }

    Err(BuilderVmError::ExtractionFailed(format!(
        "mvmctl bootstrap helper not found after build at {}",
        helper_bin.display()
    )))
}

/// The two supported ways past a helper this host cannot build.
///
/// `just embed` is the better one: it gives *this* binary the payload, after
/// which the helper is not needed at all. The env var is the escape hatch for
/// a helper someone else built.
const BOOTSTRAP_HELPER_WAYS_OUT: &str = "Either run `just embed` so this mvmctl \
     carries the embedded Linux host binaries itself (no helper needed), or set \
     MVM_BUILDER_VM_BOOTSTRAP_BIN to an mvmctl that already carries them.";

/// Whether this host can cross-compile the embedded Linux host binaries.
///
/// Runs the same two resolutions `mvm-cli`'s build script does and nothing
/// else — it compiles no code. Asking first turns "wait five minutes, then read
/// a build-script panic" into an immediate, actionable refusal.
fn embed_toolchain_ready(workspace_root: &Path) -> Result<(), String> {
    use crate::embed_toolchain;

    let pin = embed_toolchain::try_read_pinned_toolchain(workspace_root, std::env::consts::ARCH)?;
    embed_toolchain::resolve_pinned_zig(&pin.zig)?;
    embed_toolchain::try_rustup_cargo_and_rustc(
        embed_toolchain::strip_glibc(&pin.target),
        &pin.rust,
    )?;
    Ok(())
}

fn bootstrap_helper_toolchain_refusal(reason: &str) -> String {
    format!(
        "this mvmctl carries no embedded Linux host binaries, and the pinned \
         cross-compile toolchain needed to build a bootstrap helper that does is \
         unavailable: {reason} Install it with `just toolchain-embed`. {}",
        BOOTSTRAP_HELPER_WAYS_OUT,
    )
}

/// The `cargo build --bin mvmctl` that produces a bootstrap helper, refused for
/// a library embedder.
fn builder_vm_bootstrap_helper_build_command(
    host: &HostProcess,
    cargo: &std::ffi::OsStr,
    workspace_root: &Path,
    helper_target_dir: &Path,
    features: &HelperFeatures,
) -> Result<Command, BuilderVmError> {
    host.refuse_cli_spawn(CliSpawn::BuilderBootstrapHelperBuild)?;
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", helper_target_dir)
        .args(["build", "-q", "--bin", "mvmctl"])
        .args(features.cargo_args());
    Ok(cmd)
}

fn bootstrap_helper_needs_rebuild(
    helper_bin: &Path,
    workspace_root: &Path,
    features: &HelperFeatures,
) -> bool {
    !helper_built_with(helper_bin, features) || helper_sources_are_newer(helper_bin, workspace_root)
}

/// Whether the helper on disk was built with exactly `features`. A helper with
/// no record predates the record, and is rebuilt once.
fn helper_built_with(helper_bin: &Path, features: &HelperFeatures) -> bool {
    fs::read_to_string(helper_features_stamp_path(helper_bin))
        .is_ok_and(|recorded| recorded == features.stamp())
}

fn helper_sources_are_newer(helper_bin: &Path, workspace_root: &Path) -> bool {
    let Ok(helper_metadata) = fs::metadata(helper_bin) else {
        return true;
    };
    let Ok(helper_modified) = helper_metadata.modified() else {
        return true;
    };

    bootstrap_helper_inputs(workspace_root)
        .into_iter()
        .any(|path| {
            newest_path_mtime(&path)
                .map(|mtime| mtime > helper_modified)
                .unwrap_or(true)
        })
}

fn bootstrap_helper_inputs(workspace_root: &Path) -> Vec<PathBuf> {
    [
        workspace_root.join("Cargo.toml"),
        workspace_root.join("Cargo.lock"),
        workspace_root.join("crates/mvm-build/Cargo.toml"),
        workspace_root.join("crates/mvm-cli/Cargo.toml"),
        workspace_root.join("crates/mvm-build/src"),
        workspace_root.join("crates/mvm-cli/src"),
    ]
    .into_iter()
    .collect()
}

fn newest_path_mtime(path: &Path) -> io::Result<std::time::SystemTime> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        return metadata.modified();
    }
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "{} is neither a file nor a directory",
            path.display()
        )));
    }

    let mut newest = None;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child_mtime = newest_path_mtime(&entry.path())?;
        match newest {
            Some(current) if child_mtime <= current => {}
            _ => newest = Some(child_mtime),
        }
    }
    newest.or_else(|| metadata.modified().ok()).ok_or_else(|| {
        io::Error::other(format!(
            "failed to read modified time for {}",
            path.display()
        ))
    })
}

fn builder_vm_bootstrap_helper_target_dir(workspace_root: &Path) -> PathBuf {
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR").filter(|dir| !dir.is_empty()) {
        let target_dir = PathBuf::from(target_dir);
        let base = if target_dir.is_absolute() {
            target_dir
        } else {
            workspace_root.join(target_dir)
        };
        return base.join("mvm-builder-vm-bootstrap");
    }

    workspace_root
        .join("target")
        .join("mvm-builder-vm-bootstrap")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::builder_vm::host_arch_tag;
    use mvm_core::util::test_env::TestEnv;
    use tempfile::TempDir;

    fn set_mtime(path: &Path, when: std::time::SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(when).unwrap();
    }

    /// `TestEnv` serializes env mutation; this serializes everything else these
    /// tests share — the payload declaration static and the on-disk helper.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn builder_vm_bootstrap_helper_target_dir_is_dedicated() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove("CARGO_TARGET_DIR");

        let dir = builder_vm_bootstrap_helper_target_dir(Path::new("/workspace"));
        assert_eq!(
            dir,
            PathBuf::from("/workspace/target/mvm-builder-vm-bootstrap")
        );
    }

    #[test]
    fn builder_vm_bootstrap_helper_target_dir_honors_cargo_target_dir() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set("CARGO_TARGET_DIR", "shared-target");

        let dir = builder_vm_bootstrap_helper_target_dir(Path::new("/workspace"));
        assert_eq!(
            dir,
            PathBuf::from("/workspace/shared-target/mvm-builder-vm-bootstrap")
        );
    }

    /// Restore the process-wide payload declaration on drop.
    ///
    /// It is a static, so a test that leaves it set makes the next test in the
    /// same process resolve *its* executable as a bootstrap helper.
    struct DeclaredPayload(bool);

    impl DeclaredPayload {
        fn set(carries: bool) -> Self {
            let previous = CURRENT_EXE_CARRIES_HOST_BINARIES.load(Ordering::Relaxed);
            declare_current_exe_carries_host_binaries(carries);
            Self(previous)
        }
    }

    impl Drop for DeclaredPayload {
        fn drop(&mut self) {
            declare_current_exe_carries_host_binaries(self.0);
        }
    }

    /// The point of the helper is to obtain a binary carrying the embedded
    /// Linux host binaries. When the running one already carries them, building
    /// a second `mvmctl` reproduces what is already loaded — minutes of
    /// compile, plus a silent dependency on the pinned cross-compile toolchain,
    /// for nothing.
    #[test]
    fn a_declared_payload_makes_this_binary_the_bootstrap_helper() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove(BUILDER_VM_BOOTSTRAP_BIN_ENV);
        let _declared = DeclaredPayload::set(true);

        let workspace_root =
            builder_vm_source_checkout_root().expect("tests run from a source checkout");
        let resolved =
            resolve_builder_vm_bootstrap_bin(&workspace_root).expect("current exe resolves");

        assert_eq!(resolved, std::env::current_exe().unwrap());
        // `maybe_reexec_builder_vm_helper` reads this to decide it is already
        // the helper and bootstraps in-process instead of forking.
        assert!(current_exe_matches(&resolved));
    }

    /// The default has to be the conservative one: a library embedder or a test
    /// binary that never declares anything must not be handed to `Command` as
    /// an `mvmctl`.
    #[test]
    fn an_undeclared_binary_is_not_offered_as_the_helper() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _declared = DeclaredPayload::set(false);

        assert!(current_exe_as_bootstrap_helper().is_none());
    }

    /// The explicit override outranks the running binary: someone who names a
    /// helper is telling us theirs is the one to use.
    #[test]
    fn an_explicit_helper_outranks_a_declared_payload() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        let explicit = scratch.path().join("mvmctl");
        std::fs::write(&explicit, b"helper").unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &explicit);
        let _declared = DeclaredPayload::set(true);

        let workspace_root =
            builder_vm_source_checkout_root().expect("tests run from a source checkout");
        assert_eq!(
            resolve_builder_vm_bootstrap_bin(&workspace_root).unwrap(),
            explicit
        );
    }

    /// Every exit is named, because the one the reader reaches for depends on
    /// what they have: the toolchain, a rebuild of this binary, or someone
    /// else's helper.
    #[test]
    fn the_toolchain_refusal_names_every_way_past_it() {
        let message = bootstrap_helper_toolchain_refusal("zig 0.13.0 was not found.");

        assert!(message.contains("zig 0.13.0 was not found."), "{message}");
        assert!(message.contains("just toolchain-embed"), "{message}");
        assert!(message.contains("just embed"), "{message}");
        assert!(message.contains(BUILDER_VM_BOOTSTRAP_BIN_ENV), "{message}");
    }

    /// A bootstrap child that still finds a cold cache has to report it. The
    /// alternative is a fork bomb: each level spawns another child with nothing
    /// new to try.
    #[test]
    fn a_running_bootstrap_does_not_spawn_another_one() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.isolate_mvm_home(scratch.path());
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, "/nonexistent/mvmctl");
        env.set(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());

        assert!(
            !auto_bootstrap_builder_vm_image(&arch_dir).expect("guard declines, it does not error")
        );
    }

    /// The child has to be *told* it is a bootstrap; the guard above is dead
    /// weight if the spawn site forgets to set the marker.
    #[test]
    fn the_spawned_bootstrap_is_marked_as_one() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.isolate_mvm_home(scratch.path());

        let observed = scratch.path().join("marker");
        let script = scratch.path().join("bootstrap-builder-vm.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s' \"${{{}:-unset}}\" > {}\nexit 1\n",
                BUILDER_VM_BOOTSTRAP_ACTIVE_ENV,
                observed.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &script);

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());
        // The helper exits nonzero on purpose — this test is about what it was
        // handed, not about it succeeding.
        assert!(auto_bootstrap_builder_vm_image(&arch_dir).is_err());
        assert_eq!(std::fs::read_to_string(&observed).unwrap(), "1");
    }

    fn backend_observer_script(scratch: &Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let observed = scratch.join("builder-backend");
        let script = scratch.join("observe-builder-backend.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s' \"${{{}:-unset}}\" > builder-backend\n",
                crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        (script, observed)
    }

    #[test]
    fn bootstrap_helper_does_not_inject_a_backend_when_the_caller_set_none() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove(crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV);
        let scratch = TempDir::new().unwrap();
        let (script, observed) = backend_observer_script(scratch.path());

        let status = builder_vm_helper_command(
            &HostProcess::undeclared(),
            &script,
            scratch.path(),
            BuilderVmHelperCommand::Bootstrap,
        )
        .expect("mvmctl may run its helper")
        .status()
        .expect("run backend observer");

        assert!(status.success());
        assert_eq!(std::fs::read_to_string(observed).unwrap(), "unset");
    }

    #[test]
    fn bootstrap_helper_inherits_an_explicit_backend_unchanged() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(
            crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV,
            "firecracker",
        );
        let scratch = TempDir::new().unwrap();
        let (script, observed) = backend_observer_script(scratch.path());

        let status = builder_vm_helper_command(
            &HostProcess::undeclared(),
            &script,
            scratch.path(),
            BuilderVmHelperCommand::Bootstrap,
        )
        .expect("mvmctl may run its helper")
        .status()
        .expect("run backend observer");

        assert!(status.success());
        assert_eq!(std::fs::read_to_string(observed).unwrap(), "firecracker");
    }

    #[test]
    fn bootstrap_helper_build_command_uses_isolated_target_dir() {
        let cmd = builder_vm_bootstrap_helper_build_command(
            &HostProcess::undeclared(),
            std::ffi::OsStr::new("cargo"),
            Path::new("/workspace"),
            Path::new("/tmp/helper-target"),
            &HelperFeatures::for_caller(None),
        )
        .expect("mvmctl may build its helper");

        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                "build",
                "-q",
                "--bin",
                "mvmctl",
                "--features",
                "embed-host-bins"
            ]
        );

        let envs = cmd
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            envs.get("CARGO_TARGET_DIR"),
            Some(&Some("/tmp/helper-target".to_string()))
        );
    }

    #[test]
    fn builder_vm_helper_commands_are_closed_and_preserve_force() {
        assert_eq!(
            BuilderVmHelperCommand::Bootstrap.args(),
            ["__builder-vm-bootstrap"]
        );
        assert_eq!(
            BuilderVmHelperCommand::SdkSidecarBuild { force: false }.args(),
            ["build", "sdk-sidecar", "build"]
        );
        assert_eq!(
            BuilderVmHelperCommand::SdkSidecarBuild { force: true }.args(),
            ["build", "sdk-sidecar", "build", "--force"]
        );
    }

    #[test]
    fn resolve_builder_vm_bootstrap_bin_prefers_env_override() {
        let dir = TempDir::new().unwrap();
        let helper = dir.path().join("mvmctl-helper");
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(
            BUILDER_VM_BOOTSTRAP_BIN_ENV,
            helper.display().to_string().as_str(),
        );

        let got = resolve_builder_vm_bootstrap_bin(dir.path()).expect("helper path");
        assert_eq!(got, helper);
    }

    #[test]
    fn resolve_builder_vm_bootstrap_bin_rejects_missing_env_override() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing-helper");

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(
            BUILDER_VM_BOOTSTRAP_BIN_ENV,
            missing.display().to_string().as_str(),
        );

        let err =
            resolve_builder_vm_bootstrap_bin(dir.path()).expect_err("missing helper must fail");
        assert!(err.to_string().contains("not a file"), "{err}");
        assert!(
            err.to_string().contains(BUILDER_VM_BOOTSTRAP_BIN_ENV),
            "{err}"
        );
    }

    /// A workspace holding a helper binary and every input its staleness check
    /// reads. Every input is dated `inputs_secs` except `mvm-cli`'s source, which
    /// is dated `cli_src_secs`; the helper is dated `helper_secs`.
    fn workspace_with_helper(
        helper_secs: u64,
        inputs_secs: u64,
        cli_src_secs: u64,
    ) -> (TempDir, PathBuf) {
        let workspace = TempDir::new().expect("workspace");
        let root = workspace.path();
        let at = |secs| std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        let write = |rel: &str, body: &str, secs: u64| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, body).expect("write");
            set_mtime(&path, at(secs));
            path
        };

        write("Cargo.toml", "[workspace]\n", inputs_secs);
        write("Cargo.lock", "# lock\n", inputs_secs);
        write("crates/mvm-build/Cargo.toml", "[package]\n", inputs_secs);
        write("crates/mvm-cli/Cargo.toml", "[package]\n", inputs_secs);
        write(
            "crates/mvm-build/src/lib.rs",
            "pub fn build() {}\n",
            inputs_secs,
        );
        write("crates/mvm-cli/src/main.rs", "fn main() {}\n", cli_src_secs);
        let helper = write(
            "target/mvm-builder-vm-bootstrap/debug/mvmctl",
            "helper",
            helper_secs,
        );
        (workspace, helper)
    }

    fn record_features(helper: &Path, features: &HelperFeatures) {
        std::fs::write(helper_features_stamp_path(helper), features.stamp()).expect("stamp");
    }

    #[test]
    fn bootstrap_helper_needs_rebuild_when_tracked_source_is_newer() {
        let (workspace, helper) = workspace_with_helper(10, 10, 20);
        let features = HelperFeatures::for_caller(None);
        // A matching record, so the only reason left to rebuild is the source.
        record_features(&helper, &features);

        assert!(bootstrap_helper_needs_rebuild(
            &helper,
            workspace.path(),
            &features
        ));
    }

    #[test]
    fn bootstrap_helper_needs_rebuild_skips_fresh_helper() {
        let (workspace, helper) = workspace_with_helper(20, 10, 10);
        let features = HelperFeatures::for_caller(None);
        record_features(&helper, &features);

        assert!(!bootstrap_helper_needs_rebuild(
            &helper,
            workspace.path(),
            &features
        ));
    }

    /// The regression this record exists for. A helper cached by an earlier
    /// build that knew nothing of the caller's features is fresh by every
    /// source date, and reusing it would keep handing a fetch-configured caller
    /// a helper that cannot fetch.
    #[test]
    fn a_fresh_helper_built_with_other_features_is_rebuilt() {
        let (workspace, helper) = workspace_with_helper(20, 10, 10);
        record_features(&helper, &HelperFeatures::for_caller(None));

        let caller = HelperFeatures::for_caller(Some(&[
            "default".to_owned(),
            "release-artifact-bootstrap".to_owned(),
        ]));
        assert!(bootstrap_helper_needs_rebuild(
            &helper,
            workspace.path(),
            &caller
        ));
    }

    #[test]
    fn a_fresh_helper_with_no_feature_record_is_rebuilt() {
        let (workspace, helper) = workspace_with_helper(20, 10, 10);

        assert!(bootstrap_helper_needs_rebuild(
            &helper,
            workspace.path(),
            &HelperFeatures::for_caller(None),
        ));
    }

    fn helper_build_args(features: &HelperFeatures) -> Vec<String> {
        builder_vm_bootstrap_helper_build_command(
            &HostProcess::undeclared(),
            std::ffi::OsStr::new("cargo"),
            Path::new("/workspace"),
            Path::new("/tmp/helper-target"),
            features,
        )
        .expect("mvmctl may build its helper")
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
    }

    fn declared(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// The fetch this caller was configured for must survive into the helper
    /// it builds. Without `release-artifact-bootstrap` the helper cannot
    /// download the builder image and falls through to a Stage 0 build.
    #[test]
    fn the_helper_is_built_with_the_callers_acquisition_features() {
        let caller = declared(&["default", "release-artifact-bootstrap", "user"]);

        assert_eq!(
            helper_build_args(&HelperFeatures::for_caller(Some(&caller))),
            vec![
                "build",
                "-q",
                "--bin",
                "mvmctl",
                "--features",
                "embed-host-bins,release-artifact-bootstrap,user",
            ]
        );
    }

    /// Mirroring means not inventing features either: a caller built without
    /// the default set gets a helper built without it.
    #[test]
    fn a_caller_built_without_default_features_gets_a_helper_without_them() {
        let caller = declared(&["host"]);

        assert_eq!(
            helper_build_args(&HelperFeatures::for_caller(Some(&caller))),
            vec![
                "build",
                "-q",
                "--bin",
                "mvmctl",
                "--no-default-features",
                "--features",
                "embed-host-bins,host",
            ]
        );
    }

    #[test]
    fn a_caller_that_already_embeds_lists_embed_host_bins_once() {
        let caller = declared(&["default", "embed-host-bins", "user"]);

        assert_eq!(
            HelperFeatures::for_caller(Some(&caller)).features,
            declared(&["embed-host-bins", "user"])
        );
    }

    /// The root build script turns Cargo's `CARGO_FEATURE_<NAME>` variables back
    /// into feature names by lowercasing and mapping `_` to `-`. That is exact
    /// only while no root feature name contains `_`, and the helper command
    /// names root features directly, so both have to hold for the mirror to be
    /// a mirror.
    #[test]
    fn root_feature_names_survive_the_build_script_mapping() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("read the root manifest");
        let parsed: toml::Table = text.parse().expect("parse the root manifest");
        let features = parsed
            .get("features")
            .and_then(toml::Value::as_table)
            .expect("the root package declares features");

        for name in features.keys() {
            assert!(
                !name.contains('_'),
                "root feature {name:?} contains '_', which the build script cannot recover \
                 from CARGO_FEATURE_*"
            );
        }
        for needed in [
            HelperFeatures::EMBED_HOST_BINS,
            "release-artifact-bootstrap",
        ] {
            assert!(
                features.contains_key(needed),
                "the helper build names root feature {needed:?}, which the root package must declare"
            );
        }
    }

    fn assert_refused(err: BuilderVmError, expected: CliSpawn) {
        match err {
            BuilderVmError::CliSpawnRefused(refused) => {
                assert_eq!(refused.spawn(), &expected);
                assert!(
                    refused.to_string().contains("mvmctl bootstrap"),
                    "{refused}"
                );
            }
            other => panic!("expected a typed refusal, got {other}"),
        }
    }

    fn embedder() -> HostProcess {
        HostProcess::undeclared().as_library_embedder()
    }

    /// Every rung of the ladder yields an `mvmctl`, the explicitly named one
    /// included, so an embedder is refused before any of them is consulted.
    #[test]
    fn a_library_embedder_resolves_no_bootstrap_helper_even_when_one_is_named() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        let explicit = scratch.path().join("mvmctl");
        std::fs::write(&explicit, b"helper").unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &explicit);
        let _declared = DeclaredPayload::set(true);

        let err = resolve_builder_vm_bootstrap_bin_for(scratch.path(), &embedder())
            .expect_err("an embedder never resolves an mvmctl");

        assert_refused(err, CliSpawn::BuilderBootstrapHelper);
    }

    /// The seam that constructs `cargo build --bin mvmctl` refuses on its own,
    /// so no caller can reach the command by skipping the resolver.
    #[test]
    fn a_library_embedder_constructs_no_helper_build_command() {
        let err = builder_vm_bootstrap_helper_build_command(
            &embedder(),
            std::ffi::OsStr::new("cargo"),
            Path::new("/workspace"),
            Path::new("/tmp/helper-target"),
            &HelperFeatures::for_caller(None),
        )
        .expect_err("an embedder never builds mvmctl");

        assert_refused(err, CliSpawn::BuilderBootstrapHelperBuild);
    }

    /// A cold cache is reported to an embedder as the refusal, never answered
    /// by spawning a helper — here one that would record that it ran.
    #[test]
    fn a_library_embedder_never_auto_bootstraps() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.isolate_mvm_home(scratch.path());
        env.remove(BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV);
        env.remove(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV);
        let ran = scratch.path().join("ran");
        let script = executable_script(
            scratch.path(),
            &format!("#!/bin/sh\ntouch {}\n", ran.display()),
        );
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &script);

        let err = auto_bootstrap_builder_vm_image_for(scratch.path(), &embedder())
            .expect_err("an embedder is refused, not declined");

        assert_refused(err, CliSpawn::BuilderBootstrapHelper);
        assert!(!ran.exists(), "the helper must not have run");
    }

    /// The refusal precedes every quiet decline that follows it — no named
    /// helper, no source checkout — so an embedder learns why a cold cache
    /// cannot be filled rather than getting a bare missing-image error.
    #[test]
    fn a_library_embedder_is_refused_before_auto_bootstrap_can_decline() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.isolate_mvm_home(scratch.path());
        env.remove(BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV);
        env.remove(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV);
        env.remove(BUILDER_VM_BOOTSTRAP_BIN_ENV);

        let err = auto_bootstrap_builder_vm_image_for(scratch.path(), &embedder())
            .expect_err("an embedder is refused, not declined");

        assert_refused(err, CliSpawn::BuilderBootstrapHelper);
    }

    /// With nothing declared the named helper is still the one resolved.
    #[test]
    fn an_undeclared_process_still_resolves_the_named_helper() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        let explicit = scratch.path().join("mvmctl");
        std::fs::write(&explicit, b"helper").unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &explicit);

        assert_eq!(
            resolve_builder_vm_bootstrap_bin_for(scratch.path(), &HostProcess::undeclared())
                .unwrap(),
            explicit
        );
    }

    /// The seam that constructs the `mvmctl` helper command refuses on its own,
    /// for both helper verbs.
    #[test]
    fn a_library_embedder_constructs_no_helper_command() {
        for command in [
            BuilderVmHelperCommand::Bootstrap,
            BuilderVmHelperCommand::SdkSidecarBuild { force: true },
        ] {
            let err = builder_vm_helper_command(
                &embedder(),
                Path::new("/opt/mvmctl"),
                Path::new("/workspace"),
                command,
            )
            .expect_err("an embedder never runs mvmctl");

            assert_refused(err, CliSpawn::BuilderBootstrapHelper);
        }
    }

    /// The re-exec entry points refuse before the source-checkout test, so an
    /// embedder outside a checkout never reads a decline as leave to bootstrap
    /// in-process.
    #[test]
    fn a_library_embedder_outside_a_checkout_is_refused_the_helper_reexec() {
        let err = maybe_reexec_builder_vm_helper_for(
            BuilderVmHelperCommand::SdkSidecarBuild { force: false },
            &embedder(),
            None,
        )
        .expect_err("an embedder is refused, not declined");

        assert_refused(err, CliSpawn::BuilderBootstrapHelper);
    }

    /// Inside a checkout, with a helper named and ready to run, an embedder
    /// still runs nothing.
    #[test]
    fn a_library_embedder_inside_a_checkout_runs_no_reexec_helper() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        let ran = scratch.path().join("ran");
        let script = executable_script(
            scratch.path(),
            &format!("#!/bin/sh\ntouch {}\n", ran.display()),
        );
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &script);

        let err = maybe_reexec_builder_vm_helper_for(
            BuilderVmHelperCommand::SdkSidecarBuild { force: false },
            &embedder(),
            Some(scratch.path().to_path_buf()),
        )
        .expect_err("an embedder is refused, not declined");

        assert_refused(err, CliSpawn::BuilderBootstrapHelper);
        assert!(!ran.exists(), "the helper must not have run");
    }

    #[test]
    fn helper_commands_carry_the_bootstrap_marker_only_for_a_bootstrap() {
        let marker = |command| {
            builder_vm_helper_command(
                &HostProcess::undeclared(),
                Path::new("/opt/mvmctl"),
                Path::new("/workspace"),
                command,
            )
            .expect("mvmctl may run its helper")
            .get_envs()
            .any(|(key, value)| {
                key == BUILDER_VM_BOOTSTRAP_ACTIVE_ENV && value.is_some_and(|v| v == "1")
            })
        };

        assert!(marker(BuilderVmHelperCommand::Bootstrap));
        assert!(!marker(BuilderVmHelperCommand::SdkSidecarBuild {
            force: false
        }));
    }

    fn executable_script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let script = dir.join("helper.sh");
        std::fs::write(&script, body).unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script
    }

    #[test]
    fn current_exe_matches_current_binary() {
        let current = std::env::current_exe().expect("current exe");
        assert!(
            current_exe_matches(&current),
            "current executable should match itself"
        );
    }
}
