//! Acquiring and running the builder-VM bootstrap helper.
//!
//! On a source checkout with a cold `~/.mvm/cache/builder-vm/<arch>/`, the
//! image has to be built before anything can boot it — and building it needs
//! the Linux host binaries. The helper is the `mvmctl` that supplies them: an
//! explicitly named one, else the running executable, which carries them
//! compiled in or produces them from its own checkout. There is no third rung;
//! a process that can do neither says so rather than compiling a second
//! `mvmctl`.
//!
//! None of that applies to a library embedding the runtime. It is not `mvmctl`
//! and must never run one, so once [`declare_library_embedder`] has been called
//! every rung of the ladder refuses with [`BuilderVmError::CliSpawnRefused`]
//! instead.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};

use crate::builder_vm::BuilderVmError;
use crate::builder_vm_image::builder_vm_source_checkout_root;

/// Declare that this process is a library embedding the runtime, not `mvmctl`.
///
/// Set-once and irreversible. Afterwards builder-VM bootstrap, a build of the
/// Linux host binaries, and the builder egress supervisor all refuse rather
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

/// Whether the running executable can supply the Linux host binaries.
///
/// The whole point of the bootstrap helper is to obtain a binary that has
/// them, so when the running one can — compiled in, or built from its checkout
/// — it *is* the helper. This crate sits below the one that owns the payload
/// and cannot see it, so the binary that owns it says so once at startup.
/// Default `false`: an undeclared caller (a test binary, a library embedder)
/// is never handed to `Command` as an `mvmctl`.
static CURRENT_EXE_PROVIDES_HOST_BINARIES: AtomicBool = AtomicBool::new(false);

/// Declare whether this process's executable can supply the Linux host binaries
/// a builder-VM bootstrap needs. Called once by `mvmctl` at startup.
pub fn declare_current_exe_provides_host_binaries(provides: bool) {
    CURRENT_EXE_PROVIDES_HOST_BINARIES.store(provides, Ordering::Relaxed);
}

/// The running executable, when it has declared it can supply the host
/// binaries and the OS will name it. Both halves must hold: a declared payload
/// we cannot point a `Command` at is no use as a helper.
fn current_exe_as_bootstrap_helper() -> Option<PathBuf> {
    CURRENT_EXE_PROVIDES_HOST_BINARIES
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
    let mut cmd = mvm_core::env_hygiene::helper_command(helper);
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
/// Every rung yields an `mvmctl` — a named one or the current executable — so
/// a library embedder is refused before the first rung, an explicit override
/// included.
fn resolve_builder_vm_bootstrap_bin_for(
    _workspace_root: &Path,
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

    current_exe_as_bootstrap_helper()
        .ok_or_else(|| BuilderVmError::ExtractionFailed(no_bootstrap_helper_message()))
}

/// The refusal for a process that neither supplies the host binaries nor was
/// pointed at an `mvmctl` that does.
fn no_bootstrap_helper_message() -> String {
    format!(
        "this process cannot supply the Linux host binaries a builder VM bootstrap \
         needs, and {BUILDER_VM_BOOTSTRAP_BIN_ENV} names no helper that can. Run the \
         command through `mvmctl`, or set {BUILDER_VM_BOOTSTRAP_BIN_ENV} to an `mvmctl` \
         binary."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::builder_vm::host_arch_tag;
    use mvm_core::util::test_env::TestEnv;
    use tempfile::TempDir;

    /// `TestEnv` serializes env mutation; this serializes everything else these
    /// tests share — the payload declaration static.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restore the process-wide payload declaration on drop.
    ///
    /// It is a static, so a test that leaves it set makes the next test in the
    /// same process resolve *its* executable as a bootstrap helper.
    struct DeclaredPayload(bool);

    impl DeclaredPayload {
        fn set(carries: bool) -> Self {
            let previous = CURRENT_EXE_PROVIDES_HOST_BINARIES.load(Ordering::Relaxed);
            declare_current_exe_provides_host_binaries(carries);
            Self(previous)
        }
    }

    impl Drop for DeclaredPayload {
        fn drop(&mut self) {
            declare_current_exe_provides_host_binaries(self.0);
        }
    }

    /// The point of the helper is to obtain a binary that supplies the Linux
    /// host binaries. `mvmctl` always can — compiled in, or from its checkout —
    /// so it is its own helper and no second `mvmctl` is ever compiled.
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

    /// With nothing declared and nothing named there is no helper, and the
    /// refusal says so instead of compiling one.
    #[test]
    fn an_undeclared_process_with_no_named_helper_is_refused() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove(BUILDER_VM_BOOTSTRAP_BIN_ENV);
        let _declared = DeclaredPayload::set(false);

        let err = resolve_builder_vm_bootstrap_bin_for(
            Path::new("/workspace"),
            &HostProcess::undeclared(),
        )
        .expect_err("no helper to resolve");

        let message = err.to_string();
        assert!(message.contains(BUILDER_VM_BOOTSTRAP_BIN_ENV), "{message}");
        assert!(message.contains("cannot supply"), "{message}");
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
