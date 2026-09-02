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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, io};

use crate::builder_vm::BuilderVmError;
use crate::libkrun_builder::builder_vm_source_checkout_root;

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
    if std::env::var_os(BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV).is_some() {
        return Ok(false);
    }

    // This process *is* a bootstrap. Reporting the cold cache is the whole
    // signal; spawning a third one would only lose it.
    if std::env::var_os(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV).is_some() {
        return Ok(false);
    }

    #[cfg(test)]
    if std::env::var_os(BUILDER_VM_BOOTSTRAP_BIN_ENV).is_none() {
        return Ok(false);
    }

    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(false);
    };

    let bootstrap_bin = resolve_builder_vm_bootstrap_bin(&workspace_root)?;
    let mut cmd = Command::new(&bootstrap_bin);
    cmd.current_dir(&workspace_root)
        .arg("__builder-vm-bootstrap")
        .env(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");
    #[cfg(target_os = "linux")]
    if std::env::var_os(crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV).is_none() {
        // Source-checkout auto-bootstrap on Linux should follow the Linux
        // builder path, not the libkrun-default host path. The runtime-overlay
        // source-build flow already uses QEMU shell jobs on Linux; keep Stage 0
        // aligned so a cold builder-image cache does not fall into a libkrun
        // networking prerequisite that the Linux builder path itself does not
        // require.
        cmd.env(
            crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV,
            "qemu",
        );
    }
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
    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(false);
    };

    let bootstrap_bin = resolve_builder_vm_bootstrap_bin(&workspace_root)?;
    if current_exe_matches(&bootstrap_bin) {
        return Ok(false);
    }

    let mut cmd = Command::new(&bootstrap_bin);
    cmd.current_dir(&workspace_root).args(command.args());
    if command == BuilderVmHelperCommand::Bootstrap {
        cmd.env(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");
    }
    #[cfg(target_os = "linux")]
    if std::env::var_os(crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV).is_none() {
        cmd.env(
            crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV,
            "qemu",
        );
    }
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

fn current_exe_matches(path: &Path) -> bool {
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let current = current_exe.canonicalize().unwrap_or(current_exe);
    let expected = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    current == expected
}

pub(crate) fn resolve_builder_vm_bootstrap_bin(
    workspace_root: &Path,
) -> Result<PathBuf, BuilderVmError> {
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
    if helper_bin.is_file() && !bootstrap_helper_needs_rebuild(&helper_bin, workspace_root) {
        return Ok(helper_bin);
    }
    // The helper is built `--features embed-host-bins`, which cross-compiles
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
    let mut cmd =
        builder_vm_bootstrap_helper_build_command(&cargo, workspace_root, &helper_target_dir);
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn cargo to build mvmctl bootstrap helper: {e}"
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "cargo build --bin mvmctl --features embed-host-bins exited with {} while \
             preparing the builder VM bootstrap helper. {}",
            status.code().unwrap_or(-1),
            BOOTSTRAP_HELPER_WAYS_OUT,
        )));
    }

    if helper_bin.is_file() {
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

fn builder_vm_bootstrap_helper_build_command(
    cargo: &std::ffi::OsStr,
    workspace_root: &Path,
    helper_target_dir: &Path,
) -> Command {
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", helper_target_dir)
        .args([
            "build",
            "-q",
            "--bin",
            "mvmctl",
            "--features",
            "embed-host-bins",
        ]);
    cmd
}

fn bootstrap_helper_needs_rebuild(helper_bin: &Path, workspace_root: &Path) -> bool {
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

    #[test]
    fn bootstrap_helper_build_command_uses_isolated_target_dir() {
        let cmd = builder_vm_bootstrap_helper_build_command(
            std::ffi::OsStr::new("cargo"),
            Path::new("/workspace"),
            Path::new("/tmp/helper-target"),
        );

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

    #[test]
    fn bootstrap_helper_needs_rebuild_when_tracked_source_is_newer() {
        let workspace = TempDir::new().unwrap();
        let helper = workspace
            .path()
            .join("target/mvm-builder-vm-bootstrap/debug/mvmctl");
        let helper_parent = helper.parent().expect("helper parent");
        std::fs::create_dir_all(helper_parent).unwrap();
        std::fs::write(&helper, b"helper").unwrap();

        let cargo_toml = workspace.path().join("Cargo.toml");
        std::fs::write(&cargo_toml, "[workspace]\n").unwrap();
        let cargo_lock = workspace.path().join("Cargo.lock");
        std::fs::write(&cargo_lock, "# lock\n").unwrap();
        let build_toml = workspace.path().join("crates/mvm-build/Cargo.toml");
        std::fs::create_dir_all(build_toml.parent().expect("mvm-build manifest parent")).unwrap();
        std::fs::write(&build_toml, "[package]\nname = \"mvm-build\"\n").unwrap();
        let cli_toml = workspace.path().join("crates/mvm-cli/Cargo.toml");
        std::fs::create_dir_all(cli_toml.parent().expect("mvm-cli manifest parent")).unwrap();
        std::fs::write(&cli_toml, "[package]\nname = \"mvm-cli\"\n").unwrap();
        let build_src = workspace.path().join("crates/mvm-build/src/lib.rs");
        std::fs::create_dir_all(build_src.parent().expect("mvm-build src parent")).unwrap();
        std::fs::write(&build_src, "pub fn build() {}\n").unwrap();
        let cli_src = workspace.path().join("crates/mvm-cli/src/main.rs");
        std::fs::create_dir_all(cli_src.parent().expect("mvm-cli src parent")).unwrap();
        std::fs::write(&cli_src, "fn main() {}\n").unwrap();

        let older = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let newer = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(20);
        set_mtime(&helper, older);
        set_mtime(&cargo_toml, older);
        set_mtime(&cargo_lock, older);
        set_mtime(&build_toml, older);
        set_mtime(&cli_toml, older);
        set_mtime(&build_src, older);
        set_mtime(&cli_src, newer);

        assert!(bootstrap_helper_needs_rebuild(&helper, workspace.path()));
    }

    #[test]
    fn bootstrap_helper_needs_rebuild_skips_fresh_helper() {
        let workspace = TempDir::new().unwrap();
        let helper = workspace
            .path()
            .join("target/mvm-builder-vm-bootstrap/debug/mvmctl");
        let helper_parent = helper.parent().expect("helper parent");
        std::fs::create_dir_all(helper_parent).unwrap();
        std::fs::write(&helper, b"helper").unwrap();

        let cargo_toml = workspace.path().join("Cargo.toml");
        std::fs::write(&cargo_toml, "[workspace]\n").unwrap();
        let cargo_lock = workspace.path().join("Cargo.lock");
        std::fs::write(&cargo_lock, "# lock\n").unwrap();
        let build_toml = workspace.path().join("crates/mvm-build/Cargo.toml");
        std::fs::create_dir_all(build_toml.parent().expect("mvm-build manifest parent")).unwrap();
        std::fs::write(&build_toml, "[package]\nname = \"mvm-build\"\n").unwrap();
        let cli_toml = workspace.path().join("crates/mvm-cli/Cargo.toml");
        std::fs::create_dir_all(cli_toml.parent().expect("mvm-cli manifest parent")).unwrap();
        std::fs::write(&cli_toml, "[package]\nname = \"mvm-cli\"\n").unwrap();
        let build_src = workspace.path().join("crates/mvm-build/src/lib.rs");
        std::fs::create_dir_all(build_src.parent().expect("mvm-build src parent")).unwrap();
        std::fs::write(&build_src, "pub fn build() {}\n").unwrap();
        let cli_src = workspace.path().join("crates/mvm-cli/src/main.rs");
        std::fs::create_dir_all(cli_src.parent().expect("mvm-cli src parent")).unwrap();
        std::fs::write(&cli_src, "fn main() {}\n").unwrap();

        let older = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let newer = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(20);
        set_mtime(&cargo_toml, older);
        set_mtime(&cargo_lock, older);
        set_mtime(&build_toml, older);
        set_mtime(&cli_toml, older);
        set_mtime(&build_src, older);
        set_mtime(&cli_src, older);
        set_mtime(&helper, newer);

        assert!(!bootstrap_helper_needs_rebuild(&helper, workspace.path()));
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
