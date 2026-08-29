//! Steps that drive the built `mvmctl` binary as a subprocess and assert on
//! its exit code / stdout. Covers the CLI-surface suite; scenarios that need
//! a running microVM call through `mvm-client` instead as those suites land.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use cucumber::{given, then, when};
use tokio::task::spawn_blocking;
use tokio::time::timeout;

use crate::world::CliWorld;
use mvm_conformance::IsolatedHome;

/// Build an `mvmctl` subprocess with the same binary discovery the rest of
/// the conformance suite uses, plus the target directory on `PATH` so helper
/// binaries built alongside `mvmctl` are visible during live boots.
pub(crate) fn mvmctl_command() -> Command {
    let cargo_path = std::env::var_os("CARGO_BIN_EXE_mvmctl")
        .map(PathBuf::from)
        .or_else(|| {
            let mut dir = std::env::current_exe().ok()?;
            dir.pop();
            if dir.ends_with("deps") {
                dir.pop();
            }
            Some(dir.join("mvmctl"))
        })
        .unwrap_or_else(|| {
            panic!(
                "mvmctl binary path unavailable — run `cargo build --bin mvmctl` before `just bdd`"
            )
        });
    let bin_path = if cargo_path.is_absolute() {
        cargo_path
    } else {
        workspace_root().join(cargo_path)
    };
    let mut cmd = Command::new(&bin_path);
    if let Some(bin_dir) = bin_path.parent() {
        let mut path = bin_dir.as_os_str().to_os_string();
        path.push(":");
        if let Some(existing) = std::env::var_os("PATH") {
            path.push(existing);
        }
        cmd.env("PATH", path);
    }

    cmd
}

/// The repository root, resolved from this crate's manifest directory.
///
/// Steps that reference workspace files (e.g. `examples/exit_code`) run `mvmctl`
/// with this as the working directory so relative flake paths resolve the same
/// way they do from a manual invocation at the project root.
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root must exist")
}

#[when(expr = "I run mvmctl with {string}")]
fn run_mvmctl(world: &mut CliWorld, args: String) {
    let mut cmd = mvmctl_command();
    let output = cmd
        .args(mvm_conformance::doc_examples::tokenize(&args))
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[when(expr = "I run mvmctl with {string} with a {int} second timeout")]
async fn run_mvmctl_with_timeout(world: &mut CliWorld, args: String, seconds: i64) {
    let duration =
        Duration::from_secs(u64::try_from(seconds).expect("timeout must be non-negative"));

    let handle = spawn_blocking(move || {
        mvmctl_command()
            .args(mvm_conformance::doc_examples::tokenize(&args))
            .output()
            .expect("failed to spawn mvmctl")
    });

    let output = timeout(duration, handle)
        .await
        .unwrap_or_else(|_| panic!("mvmctl did not exit within {seconds}s"))
        .expect("spawn_blocking task panicked");
    world.last_run = Some(output);
}

#[when(expr = "I run mvmctl with {string} and an isolated mvm home")]
fn run_mvmctl_isolated_home(world: &mut CliWorld, args: String) {
    // A fresh, empty MVM_HOME makes cache-precondition scenarios hermetic: every
    // cache (workload kernel, OCI, guest runtime) is cold, so the run exercises
    // the missing-prerequisite path without depending on — or mutating — the
    // dev's real `~/.mvm`. The run is synchronous (`output()` blocks to exit)
    // and the fail-fast path spawns no VM, so the temp dir can drop right after.
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let mut cmd = mvmctl_command();
    let output = cmd
        .args(mvm_conformance::doc_examples::tokenize(&args))
        .isolated_home(home.path())
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

/// Run against the home a prior `Given an isolated mvm home` created, so a later
/// assertion about that home's contents inspects the directory the run actually
/// used.
///
/// Distinct from `... and an isolated mvm home`, which makes its own throwaway
/// home and drops it: pairing that step with a filesystem assertion checks an
/// empty directory the command never touched, and passes for the wrong reason.
#[when(expr = "I run mvmctl in the isolated mvm home with {string}")]
fn run_mvmctl_in_isolated_home(world: &mut CliWorld, args: String) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step");
    let mut cmd = mvmctl_command();
    cmd.args(mvm_conformance::doc_examples::tokenize(&args))
        .isolated_home(home.path());
    if world.kernel_reacquisition_must_fail {
        cmd.env("MVM_KERNEL_SOURCE", "download")
            .env("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:9");
    }
    let output = cmd.output().expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[given(expr = "an isolated mvm home")]
fn isolated_mvm_home(world: &mut CliWorld) {
    world.isolated_home = Some(tempfile::tempdir().expect("create isolated MVM_HOME"));
}

#[given(expr = "an isolated mvm home with a cached non-verity workload kernel")]
fn isolated_mvm_home_with_non_verity_kernel(world: &mut CliWorld) {
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let arch = std::env::consts::ARCH;
    let kernel_dir = home
        .path()
        .join("cache")
        .join("builder-vm")
        .join(arch)
        .join("kernels")
        .join("workload");
    std::fs::create_dir_all(&kernel_dir).expect("create fake workload kernel cache dir");
    let kernel = kernel_dir.join("vmlinux");
    std::fs::write(&kernel, b"KALLSYMS-free fake kernel bytes\n")
        .expect("write fake workload kernel");
    mvm_build::kernel_fetch::record_kernel_digest(&kernel)
        .expect("record fake workload kernel digest");
    std::fs::write(
        kernel_dir.join("config"),
        "# CONFIG_BLK_DEV_DM is not set\n# CONFIG_DM_VERITY is not set\n",
    )
    .expect("write fake non-verity kernel config");
    world.isolated_home = Some(home);
    world.kernel_reacquisition_must_fail = true;
}

#[then(expr = "the incompatible workload kernel cache is evicted")]
fn incompatible_workload_kernel_cache_is_evicted(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home must remain available");
    let kernel_dir = home
        .path()
        .join("cache")
        .join("builder-vm")
        .join(std::env::consts::ARCH)
        .join("kernels")
        .join("workload");
    for name in ["vmlinux", "vmlinux.sha256", "config"] {
        assert!(
            !kernel_dir.join(name).exists(),
            "incompatible cache member {name} survived"
        );
    }
}

#[given(expr = "warm residency is enabled")]
fn warm_residency_enabled(world: &mut CliWorld) {
    world.warm_residency = true;
}

#[when(expr = "I run mvmctl in an isolated live home with {string}")]
pub(crate) fn run_mvmctl_isolated_live_home(world: &mut CliWorld, args: String) {
    // Like `run_mvmctl_isolated_home`, but for scenarios that boot a real
    // microVM. The working directory is the workspace root so relative flake
    // paths (e.g. `examples/exit_code`) resolve the same way as a manual run
    // from the repo root, and the target directory is prepended to `PATH` so
    // helper binaries built alongside `mvmctl` are found.
    //
    // The home is the artifact-warm one when `MVM_E2E_HOME` names it. A fresh
    // tempdir per scenario looks like better isolation, but the guest binaries
    // are cached *under the home*, so every such scenario re-cross-compiles
    // them from scratch — minutes each, repeated across the live suite. The
    // warm home is what makes a live run finish in a sane time.
    //
    // A home the scenario declared for itself still wins: `Given an isolated
    // mvm home` exists so a scenario can be hermetic, or can seed a cache and
    // then assert on it, and honouring the warm home over that put `machine
    // create` and `machine start` in two different directories.
    let warm_home = std::env::var_os("MVM_E2E_HOME").map(std::path::PathBuf::from);
    if warm_home.is_none() && world.isolated_home.is_none() {
        world.isolated_home = Some(tempfile::tempdir().expect("create isolated MVM_HOME"));
    }
    let scenario_home = world.isolated_home.as_ref().map(|dir| dir.path());
    let home: std::path::PathBuf =
        mvm_conformance::live_home_precedence(scenario_home, warm_home.as_deref())
            .expect("one of the two is set above")
            .to_path_buf();
    let mut command = mvmctl_command();
    command
        .current_dir(workspace_root())
        .args(mvm_conformance::doc_examples::tokenize(&args))
        .isolated_home(&home);
    if world.warm_residency {
        command.env("MVM_RESIDENCY", "warm");
    }
    let output = command.output().expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

/// Install the operator-supplied `.mvmpkg` into an isolated home and remember
/// the content address it registered under. The `@bundle` capability gate
/// guarantees the fixture exists before this scenario is selected.
#[when(expr = "I install the bundle fixture")]
fn install_bundle_fixture(world: &mut CliWorld) {
    trust_the_fixture_publisher(world);
    let fixture = crate::bundle_fixture_path()
        .expect("`@bundle` scenarios only run when MVM_BDD_BUNDLE names a real file");
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home is set by trust_the_fixture_publisher");
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["bundle", "install"])
        .arg(&fixture)
        .isolated_home(home.path())
        .output()
        .expect("failed to spawn mvmctl");
    // `Installed bundle <sha> (N artifacts, publisher key_id=...)`
    world.bundle_sha = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Installed bundle "))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_string);
    world.last_run = Some(output);
}

#[then(expr = "the install reports a bundle content address")]
fn install_reports_bundle_sha(world: &mut CliWorld) {
    let sha = world
        .bundle_sha
        .as_deref()
        .expect("bundle install printed no content address");
    assert_eq!(sha.len(), 64, "expected a 64-char sha256, got {sha:?}");
    assert!(
        sha.chars().all(|c| c.is_ascii_hexdigit()),
        "content address is not hex: {sha:?}"
    );
}

/// Boot the bundle the previous step installed, by content address. `args` is
/// appended after `machine run --manifest <sha>`.
#[when(expr = "I boot the installed bundle with {string}")]
fn boot_installed_bundle(world: &mut CliWorld, args: String) {
    let sha = world
        .bundle_sha
        .clone()
        .expect("no installed bundle — run the install step first");
    let home = world
        .isolated_home
        .as_ref()
        .expect("install step creates the isolated home");
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["machine", "run", "--manifest", &sha])
        .args(mvm_conformance::doc_examples::tokenize(&args))
        .isolated_home(home.path())
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[then(expr = "the isolated mvm home does not contain directory {string}")]
fn isolated_home_no_dir(world: &mut CliWorld, rel: String) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home must be created before checking it");
    let path = home.path().join(rel.as_str());
    assert!(
        !path.exists(),
        "expected {path:?} to be removed after teardown, but it still exists"
    );
}

#[then(expr = "the isolated mvm home has no transient request state directories")]
fn isolated_home_no_transient_request_dirs(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home must be created before checking it");
    let vms_dir = home.path().join("vms");
    let entries = match std::fs::read_dir(&vms_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("read transient VM state directory {vms_dir:?}: {error}"),
    };

    let request_dirs = entries
        .map(|entry| entry.expect("read transient VM state entry").path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_none_or(|name| !name.starts_with("standby-"))
        })
        .collect::<Vec<_>>();
    assert!(
        request_dirs.is_empty(),
        "generated transient request state directories remain: {request_dirs:?}"
    );
}

#[then(expr = "the command exits with code {int}")]
fn exits_with_code(world: &mut CliWorld, code: i64) {
    let output = world.last_output();
    assert_eq!(
        output.status.code(),
        Some(code as i32),
        "unexpected exit code; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[then(expr = "the help output lists the {string} verb")]
fn help_lists_verb(world: &mut CliWorld, verb: String) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let listed = stdout
        .lines()
        .any(|line| line.trim_start().starts_with(verb.as_str()));
    assert!(
        listed,
        "expected top-level verb {verb:?} in `mvmctl --help` output:\n{stdout}"
    );
}

#[then(expr = "the output contains {string}")]
fn output_contains(world: &mut CliWorld, needle: String) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(needle.as_str()),
        "expected stdout to contain {needle:?}; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The negative of `the output contains`, for asserting a record is gone rather
/// than merely that some other line is present.
#[then(expr = "the output does not contain {string}")]
fn output_does_not_contain(world: &mut CliWorld, needle: String) {
    let output = world
        .last_run
        .as_ref()
        .expect("a prior step must run mvmctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(needle.as_str()),
        "expected stdout not to contain {needle:?}, but it did:\n{stdout}"
    );
}

#[then(expr = "the file {string} exists")]
fn file_exists(world: &mut CliWorld, path: String) {
    let _ = world.last_output();
    assert!(Path::new(&path).exists(), "expected file {path:?} to exist");
}

#[then(expr = "the file {string} contains {string}")]
fn file_contains(world: &mut CliWorld, path: String, needle: String) {
    let _ = world.last_output();
    let contents = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    assert!(
        contents.contains(needle.as_str()),
        "expected {path:?} to contain {needle:?}; contents:\n{contents}"
    );
}

#[then(expr = "the error output contains {string}")]
fn error_output_contains(world: &mut CliWorld, needle: String) {
    let output = world.last_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(needle.as_str()),
        "expected stderr to contain {needle:?}; stderr:\n{stderr}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[then(expr = "the error output does not contain {string}")]
fn error_output_does_not_contain(world: &mut CliWorld, unexpected: String) {
    let output = world.last_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(unexpected.as_str()),
        "expected stderr not to contain {unexpected:?}; stderr:\n{stderr}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[then(expr = "the help output contains {string}")]
fn help_contains(world: &mut CliWorld, expected: String) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&expected),
        "expected help output to contain {expected:?}:\n{stdout}"
    );
}

#[then(expr = "the help output does not contain {string}")]
fn help_does_not_contain(world: &mut CliWorld, unexpected: String) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(&unexpected),
        "expected help output not to contain {unexpected:?}:\n{stdout}"
    );
}

#[then(expr = "the help options fit within {int} columns")]
fn help_options_fit_within(world: &mut CliWorld, width: i64) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let option_lines = stdout
        .lines()
        .skip_while(|line| line.trim() != "Options:")
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();

    assert!(
        !option_lines.is_empty(),
        "help output has no options:\n{stdout}"
    );
    for line in option_lines {
        assert!(
            line.trim_start().starts_with('-'),
            "help option wrapped onto a continuation line:\n{line}\n\n{stdout}"
        );
        assert!(
            i64::try_from(line.chars().count()).expect("line length must fit in i64") <= width,
            "help option exceeds {width} columns:\n{line}\n\n{stdout}"
        );
    }
}

#[then(
    expr = "every mvmctl command and subcommand help item is one line shorter than {int} columns"
)]
fn every_command_help_item_is_one_line_shorter_than(_world: &mut CliWorld, width: i64) {
    let violations = all_command_paths()
        .into_iter()
        .flat_map(|mut path| {
            path.push("--help".to_string());
            help_invocation_violations(&path, width, true)
        })
        .collect::<Vec<_>>();

    assert!(
        violations.is_empty(),
        "CLI help items must each occupy one line shorter than {width} columns:\n{}",
        violations.join("\n")
    );
}

#[then(expr = "every alternative CLI help item is one line shorter than {int} columns")]
fn every_alternative_help_entry_point_fits_within(_world: &mut CliWorld, width: i64) {
    for path in all_command_paths() {
        let mut short_help_args = path.clone();
        short_help_args.push("-h".to_string());
        assert_help_invocation_fits(&short_help_args, width, true);

        let mut help_subcommand_args = vec!["help".to_string()];
        help_subcommand_args.extend(path);
        assert_help_invocation_fits(&help_subcommand_args, width, true);
    }
}

fn all_command_paths() -> Vec<Vec<String>> {
    let command = mvm_cli::commands::cli_command();
    let mut command_paths = vec![Vec::new()];
    collect_command_paths(&command, &[], &mut command_paths);
    command_paths
}

fn assert_help_invocation_fits(args: &[String], width: i64, require_single_line_items: bool) {
    let violations = help_invocation_violations(args, width, require_single_line_items);
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

fn help_invocation_violations(
    args: &[String],
    width: i64,
    require_single_line_items: bool,
) -> Vec<String> {
    let invocation = format!("mvmctl {}", args.join(" "));
    let output = mvmctl_command()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run `{invocation}`: {e}"));
    if !output.status.success() {
        return vec![format!(
            "`{invocation}` failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )];
    }

    let help = String::from_utf8_lossy(&output.stdout);
    if help.trim().is_empty() {
        return vec![format!(
            "`{invocation}` exited successfully without printing help"
        )];
    }

    let mut violations = Vec::new();
    if require_single_line_items {
        collect_wrapped_help_items(&invocation, &help, &mut violations);
    }
    for (line_number, line) in help.lines().enumerate() {
        let line_width = i64::try_from(line.chars().count()).expect("line width fits in i64");
        if line_width >= width {
            violations.push(format!(
                "`{invocation}` line {} is {line_width} columns: {line}",
                line_number + 1
            ));
        }
    }
    violations
}

fn collect_wrapped_help_items(invocation: &str, help: &str, violations: &mut Vec<String>) {
    #[derive(Clone, Copy)]
    enum ItemSection {
        Arguments,
        Commands,
        Options,
    }

    let command_names = all_command_paths()
        .into_iter()
        .filter_map(|path| path.last().cloned())
        .collect::<Vec<_>>();
    let mut section = None;

    for (line_number, line) in help.lines().enumerate() {
        let trimmed = line.trim();
        match trimmed {
            "Arguments:" => {
                section = Some(ItemSection::Arguments);
                continue;
            }
            "Commands:" => {
                section = Some(ItemSection::Commands);
                continue;
            }
            "Options:" => {
                section = Some(ItemSection::Options);
                continue;
            }
            "" => {
                section = None;
                continue;
            }
            _ => {}
        }

        let is_item = match section {
            Some(ItemSection::Arguments) => {
                matches!(trimmed.chars().next(), Some('<' | '['))
            }
            Some(ItemSection::Commands) => trimmed.split_whitespace().next().is_some_and(|word| {
                word == "help" || command_names.iter().any(|name| name == word)
            }),
            Some(ItemSection::Options) => trimmed.starts_with('-'),
            None => true,
        };

        if !is_item {
            violations.push(format!(
                "`{invocation}` help item wraps onto line {}: {line}",
                line_number + 1
            ));
        }
    }
}

pub(crate) fn collect_command_paths(
    command: &clap::Command,
    prefix: &[String],
    command_paths: &mut Vec<Vec<String>>,
) {
    for subcommand in command.get_subcommands() {
        let mut child = prefix.to_vec();
        child.push(subcommand.get_name().to_string());
        command_paths.push(child.clone());
        collect_command_paths(subcommand, &child, command_paths);
    }
}

// --- Template registry steps ---

/// Create a local `file://` registry with a single "demo" template that
/// includes an `app.py` SDK source file.
#[given(expr = "a local template registry with a demo template")]
fn local_template_registry_with_demo(world: &mut CliWorld) {
    let tmp = tempfile::tempdir().expect("create temp registry dir");
    let tpl = tmp.path().join("templates/demo");
    std::fs::create_dir_all(&tpl).expect("create template dir");

    let index = serde_json::json!({
        "schema_version": 1,
        "templates": [{
            "name": "demo",
            "description": "demo remote template",
            "path": "templates/demo",
            "mvm_version": ">=0.1.0"
        }]
    });
    std::fs::write(tmp.path().join("index.json"), index.to_string()).expect("write index.json");

    std::fs::write(
        tpl.join("template.toml"),
        r#"name = "demo"
description = "demo remote template"
default_vcpus = 2
default_memory_mib = 512
tags = ["demo"]
files = ["app.py"]
"#,
    )
    .expect("write template.toml");

    std::fs::write(
        tpl.join("flake.nix"),
        r#"{ pkgs }:
{
  mkGuest = { ... }: {
    entrypoint = "hello";
  };
}
"#,
    )
    .expect("write flake.nix");

    std::fs::write(
        tpl.join("app.py"),
        r#"import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
)
def main() -> str:
    return "hello"
"#,
    )
    .expect("write app.py");

    world.template_registry_dir = Some(tmp);
}

/// Run mvmctl against the local registry created by the `Given` step.
#[when(expr = "I run mvmctl with {string} against the local template registry")]
fn run_mvmctl_against_local_registry(world: &mut CliWorld, args: String) {
    let reg = world
        .template_registry_dir
        .as_ref()
        .expect("local template registry must be created first");
    let registry_url = format!("file://{}", reg.path().display());

    let output = mvmctl_command()
        .args(mvm_conformance::doc_examples::tokenize(&args))
        .env("MVM_TEMPLATE_REGISTRY", registry_url)
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

/// Generate a project into a temp dir and remember the path.
#[when(expr = "I generate a project from template {string}")]
fn generate_project_from_template(world: &mut CliWorld, name: String) {
    let reg = world
        .template_registry_dir
        .as_ref()
        .expect("local template registry must be created first");
    let registry_url = format!("file://{}", reg.path().display());

    let out = tempfile::tempdir().expect("create generated project dir");
    let project_dir = out.path().join(&name);
    world.generated_project_dir = Some(project_dir.clone());
    world.generated_project_dir_tmp = Some(out);

    let home = tempfile::tempdir().expect("create isolated template home");
    let home_path = home.path().to_path_buf();
    world.isolated_home = Some(home);

    let output = mvmctl_command()
        .args([
            "generate",
            "template",
            &name,
            &project_dir.to_string_lossy(),
        ])
        .env("MVM_TEMPLATE_REGISTRY", registry_url)
        .isolated_home(&home_path)
        .env("MVM_SKIP_RECONCILE", "1")
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[then(expr = "the generated project contains file {string}")]
fn generated_project_contains_file(world: &mut CliWorld, file: String) {
    let dir = world
        .generated_project_dir
        .as_ref()
        .expect("a project must be generated first");
    let path = dir.join(&file);
    assert!(
        path.is_file(),
        "expected generated project to contain {file:?} at {path:?}"
    );
}

/// Enrol the fixture's publisher key into the scenario's isolated trust store.
///
/// A bundle installs into a fresh `MVM_HOME`, whose trust store starts empty,
/// and `read_and_verify_bundle` refuses an unknown `key_id` — correctly, that
/// is claim 9. So an install scenario has to establish the trust anchor first,
/// exactly as an operator adopting a publisher does.
fn trust_the_fixture_publisher(world: &mut CliWorld) {
    if world.isolated_home.is_none() {
        world.isolated_home = Some(tempfile::tempdir().expect("create isolated MVM_HOME"));
    }
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home is set above");
    let pubkey = crate::bundle_pubkey_path()
        .expect("`@bundle` scenarios only run when MVM_BDD_BUNDLE_PUBKEY names a real file");
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["trust", "add"])
        .arg(&pubkey)
        .isolated_home(home.path())
        .output()
        .expect("failed to spawn mvmctl trust add");
    assert!(
        output.status.success(),
        "enrolling the fixture publisher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Install the fixture into a home that has *not* enrolled its publisher.
#[when(expr = "I install the bundle fixture without trusting its publisher")]
fn install_bundle_fixture_untrusted(world: &mut CliWorld) {
    let fixture = crate::bundle_fixture_path()
        .expect("`@bundle` scenarios only run when MVM_BDD_BUNDLE names a real file");
    if world.isolated_home.is_none() {
        world.isolated_home = Some(tempfile::tempdir().expect("create isolated MVM_HOME"));
    }
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home is set above");
    world.last_run = Some(
        mvmctl_command()
            .current_dir(workspace_root())
            .args(["bundle", "install"])
            .arg(&fixture)
            .isolated_home(home.path())
            .output()
            .expect("failed to spawn mvmctl"),
    );
}

#[then(expr = "the failure names the untrusted publisher key")]
fn failure_names_untrusted_key(world: &mut CliWorld) {
    let run = world.last_run.as_ref().expect("a command has run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        text.contains("trust store has no entry for key_id"),
        "refusal must say the publisher is untrusted, not fail for some other \
         reason; output was:\n{text}"
    );
}
