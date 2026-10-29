//! Steps that drive the built `mvmctl` binary as a subprocess and assert on
//! its exit code / stdout. Covers the CLI-surface suite; scenarios that need
//! a running microVM call through `mvm-client` instead as those suites land.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
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
    let bin_path = mvmctl_path();
    command_for_binary(&bin_path)
}

pub(crate) fn command_for_binary(bin_path: &Path) -> Command {
    let mut cmd = Command::new(bin_path);
    if let Some(bin_dir) = bin_path.parent() {
        let mut path = bin_dir.as_os_str().to_os_string();
        path.push(":");
        if let Some(existing) = std::env::var_os("PATH") {
            path.push(existing);
        }
        cmd.env("PATH", path);
    }
    // A spawned `mvmctl` that has to cold-build does so without the
    // first-run notice, so scenarios that assert on stderr see the same
    // output whether or not an earlier scenario warmed the cache. Scenarios
    // that want a cold build to fail say so with `MVM_COLD_BUILD=refuse`.
    cmd.env("MVM_COLD_BUILD", "auto");

    cmd
}

/// The `mvmctl` binary the suite drives — one resolution shared by the
/// freshness check and every step, so the binary checked is the binary run.
pub(crate) fn mvmctl_path() -> PathBuf {
    let test_binary = std::env::current_exe().expect("locate the conformance test binary");
    mvm_conformance::resolve_mvmctl_path(
        std::env::var_os("CARGO_BIN_EXE_mvmctl").map(PathBuf::from),
        &test_binary,
        &workspace_root(),
    )
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
    let _reaper = mvm_conformance::vmm_reaper::ReapOnDrop::new(home.path());
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
    if super::live_home::is_prepared_live_home(home.path()) {
        super::live_home::use_seeded_runtime(&mut cmd);
    }
    apply_encrypted_volume_probe_path(world, &mut cmd);
    if world.kernel_reacquisition_must_fail {
        cmd.env("MVM_KERNEL_SOURCE", "download")
            .env("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:9");
    }
    mvm_conformance::vmm_reaper::register_launched_home(home.path());
    let output = cmd.output().expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[given(expr = "an isolated mvm home")]
fn isolated_mvm_home(world: &mut CliWorld) {
    world.isolated_home = Some(tempfile::tempdir().expect("create isolated MVM_HOME"));
}

/// A working directory outside the repository for a command whose documented
/// form takes a relative output path.
///
/// `mvmctl generate template python ./my-python-app` cannot be run from the
/// workspace root — it would scaffold a project into the tree. Assembling the
/// argv in Rust avoids that but hides the invocation from the README
/// structural check, which reads commands out of quoted step text; that is
/// exactly why the documented `generate template` line sat unexecuted behind an
/// exemption. Running it verbatim inside a scratch directory satisfies both.
#[given(expr = "a scratch working directory")]
fn scratch_working_directory(world: &mut CliWorld) {
    world.scratch_dir = Some(tempfile::tempdir().expect("create scratch working directory"));
}

#[when(expr = "I run the conformance runner with {string}")]
fn run_conformance_runner(world: &mut CliWorld, args: String) {
    run_conformance_child(world, &args, None);
}

#[when(expr = "I run the conformance runner with {string} excluding probe {string} by shard")]
fn run_conformance_excluding_probe(world: &mut CliWorld, args: String, probe: String) {
    let feature = include_str!("../../../../features/suites/s0_cli/conformance_selection.feature")
        .lines()
        .find_map(|line| line.strip_prefix("Feature:").map(str::trim))
        .expect("selection fixture feature name");
    let first = mvm_conformance::sharding::ScenarioShard::parse("0/2").expect("first shard");
    let excluding = if first.contains(feature, None, &probe) {
        "1/2"
    } else {
        "0/2"
    };
    run_conformance_child(world, &args, Some(excluding));
}

fn run_conformance_child(world: &mut CliWorld, args: &str, shard: Option<&str>) {
    let home = tempfile::tempdir().expect("isolated child runner home");
    let mut command = Command::new(std::env::current_exe().expect("conformance runner"));
    command
        .args(mvm_conformance::doc_examples::tokenize(args))
        .isolated_home(home.path())
        .env_remove("CUCUMBER_FILTER_TAGS")
        .env_remove("MVM_BDD_ONLY_TAG")
        .env_remove("MVM_BDD_SHARD")
        .env_remove("MVM_BDD_LIVE")
        .env_remove(mvm_build::image_source::MVM_IMAGES_DIR_ENV)
        .env_remove("MVM_BDD_STRICT_SKIPS")
        .env_remove("MVM_BDD_ALLOWED_SKIPS")
        .env_remove("MVM_E2E_FAILURE_MANIFEST")
        .env_remove("MVM_E2E_FAILURE_INITIALIZED")
        .stdin(std::process::Stdio::null());
    if let Some(shard) = shard {
        command.env("MVM_BDD_SHARD", shard);
    }
    let output = command
        .output()
        .expect("run the isolated conformance child");
    world.last_run = Some(output);
}

#[then(expr = "the conformance live opt-in is present")]
fn conformance_live_opt_in_is_present(_world: &mut CliWorld) {
    assert!(
        std::env::var_os("MVM_BDD_LIVE").is_some(),
        "a live-tagged fixture executed without its opt-in"
    );
}

#[given(expr = "a command launch plan in the scratch directory")]
fn command_launch_plan_in_scratch(world: &mut CliWorld) {
    let scratch = world
        .scratch_dir
        .as_ref()
        .expect("scratch working directory");
    let working_dir = scratch.path().join("workdir");
    fs::create_dir(&working_dir).expect("create workload directory");
    let plan = serde_json::json!({
        "artifact_format_version": "1.1",
        "entrypoint": {
            "kind": "command",
            "command": ["/bin/sh", "-c", "printf 'PORT=%s\\nAPP_ONLY=%s\\nENTRY_ONLY=%s\\n' \"$PORT\" \"$APP_ONLY\" \"$ENTRY_ONLY\"; pwd"],
            "working_dir": working_dir,
            "env": {
                "PORT": {"kind": "literal", "value": "8081"},
                "ENTRY_ONLY": {"kind": "literal", "value": "entrypoint"}
            }
        },
        "env": {
            "PORT": {"kind": "literal", "value": "8080"},
            "APP_ONLY": {"kind": "literal", "value": "application"}
        }
    });
    fs::write(
        scratch.path().join("launch.json"),
        serde_json::to_vec(&plan).expect("serialize launch plan"),
    )
    .expect("write command launch plan");
}

/// Execute only the generated wrapper, with controlled inputs and an empty
/// host environment. This witnesses execution direction without booting a VM.
#[when(expr = "I execute the guest wrapper for {string}")]
fn execute_launch_plan_wrapper(world: &mut CliWorld, args: String) {
    use mvm_cli::exec::{ExecRequest, ExecTarget, ImageSource};

    let scratch = world
        .scratch_dir
        .as_ref()
        .expect("scratch working directory");
    let argv =
        std::iter::once("mvmctl".to_string()).chain(mvm_conformance::doc_examples::tokenize(&args));
    let matches = mvm_cli::commands::cli_command()
        .try_get_matches_from(argv)
        .expect("documented launch-plan command parses");
    let run = matches.subcommand_matches("run").expect("run command");
    let manifest = run.get_one::<String>("manifest").expect("explicit image");
    let plan = run.get_one::<String>("launch_plan").expect("launch plan");
    let entrypoint = mvm_cli::exec::load_launch_plan(&scratch.path().join(plan))
        .expect("load the command launch plan");
    let env = run
        .get_many::<String>("env")
        .into_iter()
        .flatten()
        .map(|value| {
            let (key, value) = value.split_once('=').expect("fixture env assignment");
            (key.to_owned(), value.to_owned())
        })
        .collect();
    let request = ExecRequest {
        name: None,
        image: ImageSource::Template(manifest.clone()),
        cpus: 1,
        memory_mib: 256,
        mem_initial_mib: None,
        dir_shares: Vec::new(),
        assets: Vec::new(),
        disk_volumes: Vec::new(),
        env,
        target: ExecTarget::LaunchPlan { entrypoint },
        timeout_secs: None,
        pty: false,
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        warm_pool_size: 0,
        standby_refill: None,
        stdin: Vec::new(),
        healthcheck: None,
        sdk_host_services: Vec::new(),
        declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        hypervisor: None,
        gpu: false,
        gpu_device: None,
    };
    assert!(
        matches!(&request.image, ImageSource::Template(name) if name == "minimal"),
        "the launch plan must not replace the explicitly selected image"
    );
    world.last_run = Some(
        Command::new("/bin/sh")
            .args(["-c", &mvm_cli::exec::build_guest_wrapper(&request)])
            .current_dir(scratch.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("execute the fixture's guest wrapper"),
    );
}

#[then(expr = "the guest wrapper used the launch plan working directory")]
fn guest_wrapper_used_plan_directory(world: &mut CliWorld) {
    let scratch = world
        .scratch_dir
        .as_ref()
        .expect("scratch working directory");
    let directory = fs::canonicalize(scratch.path().join("workdir")).expect("workload directory");
    let output = &world.last_run.as_ref().expect("wrapper output").stdout;
    let stdout = String::from_utf8_lossy(output);
    let actual = stdout
        .lines()
        .last()
        .expect("wrapper printed its directory");
    assert_eq!(
        fs::canonicalize(actual).expect("resolve the printed working directory"),
        directory
    );
}

#[given(expr = "the scratch directory contains ambiguous manifest and flake sources")]
fn scratch_directory_contains_ambiguous_build_sources(world: &mut CliWorld) {
    let scratch = world
        .scratch_dir
        .as_ref()
        .expect("`Given a scratch working directory` must run before this step");
    fs::write(scratch.path().join("mvm.toml"), "schema_version = 1\n")
        .expect("write scratch manifest marker");
    fs::write(scratch.path().join("flake.nix"), "{ outputs = _: {}; }\n")
        .expect("write scratch flake marker");
}

/// Seed the isolated home with the live suite's verified kernel and source-built
/// guest runtime, so a verb that needs the runtime reads it from the home
/// instead of fetching a release asset a development build has no release for.
#[given(expr = "the isolated mvm home is prepared for live launches")]
fn isolated_home_prepared_for_live_launches(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step");
    super::live_home::prepare_live_home(home.path());
}

#[when(expr = "I run mvmctl in the scratch directory with {string}")]
fn run_mvmctl_in_scratch_directory(world: &mut CliWorld, args: String) {
    let scratch = world
        .scratch_dir
        .as_ref()
        .expect("`Given a scratch working directory` must run before this step");
    let home = world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step");
    let argv = mvm_conformance::doc_examples::tokenize(&args);
    let live = super::live_home::is_prepared_live_home(home.path());
    let producer = super::pack_build::fixture::producer_binary(
        &argv,
        live,
        std::env::var_os("MVM_E2E_PRODUCER_MVMCTL"),
    );
    let mut command = match &producer {
        Some(path) => command_for_binary(Path::new(path)),
        None => mvmctl_command(),
    };
    if let Some(path) = &producer
        && let Some(refused) =
            apply_producer_revocations(Path::new(path), scratch.path(), home.path())
    {
        world.last_run = Some(refused);
        return;
    }
    command
        .args(argv)
        .current_dir(scratch.path())
        .isolated_home(home.path());
    if live {
        super::live_home::use_seeded_runtime(&mut command);
    }
    let output = command.output().expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[when(expr = "I trust the isolated home's bundle signer")]
fn trust_isolated_bundle_signer(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step");
    let pubkey = mvm_core::config::mvm_keys_dir_at(home.path()).join("host-signer.pub");
    let output = mvmctl_command()
        .args(["trust", "add"])
        .arg(pubkey)
        .isolated_home(home.path())
        .output()
        .expect("failed to spawn mvmctl trust add");
    world.last_run = Some(output);
}

#[then(expr = "the scratch directory contains file {string}")]
fn scratch_directory_contains_file(world: &mut CliWorld, rel: String) {
    let scratch = world
        .scratch_dir
        .as_ref()
        .expect("`Given a scratch working directory` must run before this step");
    let path = scratch.path().join(&rel);
    assert!(
        path.is_file(),
        "expected {rel} under the scratch directory; it holds {:?}",
        std::fs::read_dir(scratch.path())
            .map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
            .unwrap_or_default()
    );
}

#[given(expr = "an isolated mvm home on encrypted backing storage")]
fn isolated_mvm_home_on_encrypted_backing(world: &mut CliWorld) {
    isolated_mvm_home(world);
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated MVM_HOME was just created");
    world.encrypted_volume_probe_path = Some(install_encrypted_backing_probes(home.path()));
}

#[given(expr = "an isolated mvm home on unencrypted backing storage")]
fn isolated_mvm_home_on_unencrypted_backing(world: &mut CliWorld) {
    isolated_mvm_home(world);
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated MVM_HOME was just created");
    world.encrypted_volume_probe_path = Some(install_backing_probes(
        home.path(),
        &UNENCRYPTED_BACKING_PROBES,
    ));
}

#[when(
    expr = "I run mvmctl in the isolated mvm home with {string} allowing unverified volume storage"
)]
fn run_mvmctl_in_isolated_home_allowing_unverified_storage(world: &mut CliWorld, args: String) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step");
    let mut cmd = mvmctl_command();
    cmd.args(mvm_conformance::doc_examples::tokenize(&args))
        .isolated_home(home.path())
        .env("MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE", "1");
    apply_encrypted_volume_probe_path(world, &mut cmd);
    world.last_run = Some(cmd.output().expect("failed to spawn mvmctl"));
}

#[then("the isolated home audit log records a volume storage override")]
fn isolated_home_audit_log_records_volume_storage_override(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home must exist");
    let log_path = home.path().join("state").join("log").join("audit.jsonl");
    let log = fs::read_to_string(&log_path)
        .unwrap_or_else(|error| panic!("read audit log {}: {error}", log_path.display()));
    assert!(
        log.lines()
            .any(|line| line.contains("\"volume_storage_override\"")),
        "no volume_storage_override entry in {}:\n{log}",
        log_path.display()
    );
}

/// Install deterministic platform probes for a subprocess scenario whose
/// encrypted-backing precondition is part of the declared fixture.
pub(super) fn install_encrypted_backing_probes(home: &Path) -> OsString {
    install_backing_probes(home, &ENCRYPTED_BACKING_PROBES)
}

/// The shapes the shared detector parses: one ext4 mount on a dm-crypt
/// mapping, with its journal inside the filesystem.
const ENCRYPTED_BACKING_PROBES: [(&str, &str); 4] = [
    (
        "findmnt",
        "#!/bin/sh\nprintf '%s\\n' \
             '{\"filesystems\":[{\"source\":\"/dev/mapper/mvm-bdd-crypt\",\"fstype\":\"ext4\"}]}'\n",
    ),
    (
        "tune2fs",
        "#!/bin/sh\nprintf '%s\\n' 'Filesystem features: has_journal extents' \
             'Journal inode: 8'\n",
    ),
    (
        "lsblk",
        "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[{\"type\":\"crypt\"}]}'\n",
    ),
    ("diskutil", "#!/bin/sh\nprintf '%s\\n' 'FileVault: Yes'\n"),
];

/// The same mount on a plain partition, and a macOS volume that is only
/// hardware-encrypted at rest: neither is verified encrypted.
const UNENCRYPTED_BACKING_PROBES: [(&str, &str); 4] = [
    (
        "findmnt",
        "#!/bin/sh\nprintf '%s\\n' \
         '{\"filesystems\":[{\"source\":\"/dev/sda2\",\"fstype\":\"ext4\"}]}'\n",
    ),
    (
        "tune2fs",
        "#!/bin/sh\nprintf '%s\\n' 'Filesystem features: has_journal extents' \
         'Journal inode: 8'\n",
    ),
    (
        "lsblk",
        "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[{\"type\":\"part\"}]}'\n",
    ),
    (
        "diskutil",
        "#!/bin/sh\nprintf '%s\\n' 'FileVault: No (Encrypted at rest)'\n",
    ),
];

fn install_backing_probes(home: &Path, probes: &[(&str, &str)]) -> OsString {
    let probe_bin = home.join("encrypted-backing-probe-bin");
    fs::create_dir_all(&probe_bin)
        .unwrap_or_else(|error| panic!("create encryption probe bin {probe_bin:?}: {error}"));
    for (name, body) in probes {
        let probe = probe_bin.join(name);
        fs::write(&probe, body)
            .unwrap_or_else(|error| panic!("write encryption probe {probe:?}: {error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap_or_else(
                |error| panic!("make encryption probe executable {probe:?}: {error}"),
            );
        }
    }
    let mut command_path = vec![probe_bin];
    if let Some(path) = std::env::var_os("PATH") {
        command_path.extend(std::env::split_paths(&path));
    }
    std::env::join_paths(command_path).expect("join hermetic encryption probe PATH")
}

#[given(expr = "an isolated mvm home with a cached non-verity workload kernel")]
fn isolated_mvm_home_with_non_verity_kernel(world: &mut CliWorld) {
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let arch = std::env::consts::ARCH;
    let kernel_dir =
        mvm_build::kernel_fetch::kernel_cache_dir(&home.path().join("cache"), arch, "workload");
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

#[then(expr = "the incompatible workload kernel cache remains unchanged")]
fn incompatible_workload_kernel_cache_remains_unchanged(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("isolated home must remain available");
    let kernel_dir = mvm_build::kernel_fetch::kernel_cache_dir(
        &home.path().join("cache"),
        std::env::consts::ARCH,
        "workload",
    );
    for name in ["vmlinux", "vmlinux.sha256", "config"] {
        assert!(
            kernel_dir.join(name).exists(),
            "prepared-only launch mutated incompatible cache member {name}"
        );
    }
}

#[given(expr = "warm residency is enabled")]
fn warm_residency_enabled(world: &mut CliWorld) {
    world.warm_residency = true;
}

fn selected_live_home(world: &mut CliWorld) -> PathBuf {
    let warm_home = std::env::var_os("MVM_E2E_HOME").map(PathBuf::from);
    if warm_home.is_none() && world.isolated_home.is_none() {
        world.isolated_home = Some(tempfile::tempdir().expect("create isolated MVM_HOME"));
    }
    let scenario_home = world.isolated_home.as_ref().map(|dir| dir.path());
    mvm_conformance::live_home_precedence(scenario_home, warm_home.as_deref())
        .expect("one of the two is set above")
        .to_path_buf()
}

fn vm_state_dirs(home: &Path) -> std::io::Result<HashSet<PathBuf>> {
    let vms_dir = home.join("vms");
    let entries = match std::fs::read_dir(&vms_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(error) => return Err(error),
    };

    entries
        .map(|entry| entry.map(|entry| entry.path()))
        .filter_map(|entry| match entry {
            Ok(path) if path.is_dir() => Some(Ok(path)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn transient_request_dirs(home: &Path) -> std::io::Result<HashSet<PathBuf>> {
    Ok(vm_state_dirs(home)?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| !name.starts_with("standby-"))
        })
        .collect())
}

#[given(expr = "the live mvm home request state is recorded")]
fn record_live_request_state(world: &mut CliWorld) {
    let home = selected_live_home(world);
    let request_dirs = vm_state_dirs(&home).unwrap_or_else(|error| {
        panic!(
            "read transient VM state under the live home {}: {error}",
            home.display()
        )
    });
    world.last_live_home = Some(home);
    world.live_request_dirs_before = Some(request_dirs);
}

#[when(expr = "I run mvmctl in an isolated live home with {string}")]
pub(crate) fn run_mvmctl_isolated_live_home(world: &mut CliWorld, args: String) {
    run_mvmctl_isolated_live_home_argv(world, mvm_conformance::doc_examples::tokenize(&args));
}

#[when("I run the workload-origin scoped-secret live witness")]
fn run_workload_origin_scoped_secret_live_witness(world: &mut CliWorld) {
    run_mvmctl_isolated_live_home_argv(world, workload_origin_scoped_secret_argv());
}

fn workload_origin_scoped_secret_argv() -> Vec<String> {
    [
        "machine",
        "run",
        "--image",
        "python:3.12",
        "--policy",
        "features/suites/s8_readme_contract/fixtures/tool-workload-origin.toml",
        "--secret",
        "tool-live",
        "--",
        "/bin/sh",
        "-c",
        r#"/usr/local/bin/python3 -c "import urllib.request,sys;r=urllib.request.Request(sys.argv[1],headers=dict(Authorization=sys.argv[2]));print(urllib.request.urlopen(r).status==200)" https://httpbingo.org/bearer "Bearer $TOOL_LIVE""#,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// The live-home run with an already-tokenized argv, so steps that
/// substitute scenario state (e.g. a staging path) into the command line
/// reuse exactly the home/cwd/PATH wiring the plain step uses.
pub(crate) fn run_mvmctl_isolated_live_home_argv(world: &mut CliWorld, argv: Vec<String>) {
    run_live_home(world, argv, Terminal::Inherited);
}

/// The live-home run in a new session, with no controlling terminal: what a CI
/// job, a pipeline or a supervisor gives mvmctl. Anything it would ask on
/// `/dev/tty` has nowhere to ask, so a scenario can assert what it prints
/// instead — on a developer's terminal as well as in CI.
#[when(expr = "I run mvmctl without a controlling terminal in an isolated live home with {string}")]
fn run_mvmctl_isolated_live_home_without_terminal(world: &mut CliWorld, args: String) {
    run_live_home(
        world,
        mvm_conformance::doc_examples::tokenize(&args),
        Terminal::Detached,
    );
}

/// Pull an image into the live home the next launch boots from. A launch only
/// boots an image already prepared in its own home, so a scenario that boots
/// one prepares it first, through the same verb an operator runs.
#[given(expr = "the image {string} is prepared in the live home")]
fn image_prepared_in_live_home(world: &mut CliWorld, image: String) {
    run_live_home(
        world,
        vec!["image".into(), "pull".into(), image.clone()],
        Terminal::Inherited,
    );
    let output = world.last_run.take().expect("image pull ran");
    assert!(
        output.status.success(),
        "prepare {image} in the live home\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Whether a live-home run keeps the controlling terminal of the process
/// running the suite.
enum Terminal {
    Inherited,
    Detached,
}

pub(crate) fn seed_live_guest_runtime(home: &Path) -> mvm_build::guest_runtime::GuestRuntime {
    use mvm_build::guest_runtime::{
        resolve_or_build_source_guest_runtime, seed_source_guest_runtime,
    };
    use std::sync::OnceLock;

    // Seed only build artifacts, never keys or VM state. Scenario-declared
    // isolated homes still win over MVM_E2E_HOME and receive separate extractions.
    static SEED: OnceLock<PathBuf> = OnceLock::new();
    let workspace = workspace_root();
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let seed = SEED.get_or_init(|| {
        let cache = std::env::var_os("MVM_E2E_HOME")
            .map(|home| PathBuf::from(home).join("cache"))
            .unwrap_or_else(|| PathBuf::from(mvm_core::config::mvm_cache_dir()));
        eprintln!(
            "conformance: prewarming source guest runtime in {}",
            cache.display()
        );
        resolve_or_build_source_guest_runtime(&cache, version, arch, &workspace)
            .expect("prewarm the live suite's source guest runtime");
        cache
    });
    seed_source_guest_runtime(&home.join("cache"), seed, version, arch, &workspace)
        .expect("verify and copy the live guest runtime into the scenario home")
        .expect("prewarmed guest runtime must match the current source")
}

/// Apply the published signed image-set revocation list to `home` through the
/// producer binary, which refuses offline admission without one. Returns the
/// refused run when the update fails.
pub(crate) fn apply_producer_revocations(
    binary: &Path,
    dir: &Path,
    home: &Path,
) -> Option<std::process::Output> {
    let revocations = std::env::var_os("MVM_E2E_IMAGE_REVOCATIONS_DIR").expect(
        "MVM_E2E_IMAGE_REVOCATIONS_DIR names the downloaded signed image-set revocation list",
    );
    let output = command_for_binary(binary)
        .current_dir(dir)
        .isolated_home(home)
        .args(super::pack_build::fixture::revocation_update_args(
            Path::new(&revocations),
        ))
        .output()
        .expect("apply the canonical signed image revocation policy for the producer");
    (!output.status.success()).then_some(output)
}

fn run_live_home(world: &mut CliWorld, argv: Vec<String>, terminal: Terminal) {
    // Like `run_mvmctl_isolated_home`, but for scenarios that boot a real
    // microVM. The working directory is the workspace root so relative flake
    // paths (e.g. `examples/exit_code`) resolve the same way as a manual run
    // from the repo root, and the target directory is prepended to `PATH` so
    // helper binaries built alongside `mvmctl` are found.
    //
    // Prewarm source guest binaries once and admit independent verified copies
    // into isolated homes, rather than cross-compiling again for every scenario.
    //
    // A home the scenario declared for itself still wins: `Given an isolated
    // mvm home` exists so a scenario can be hermetic, or can seed a cache and
    // then assert on it, and honouring the warm home over that put `machine
    // create` and `machine start` in two different directories.
    let home = selected_live_home(world);
    super::live_home::prepare_live_home(&home);
    let producer = super::pack_build::fixture::producer_binary(
        &argv,
        true,
        std::env::var_os("MVM_E2E_PRODUCER_MVMCTL"),
    );
    let mut command = match &producer {
        Some(path) => command_for_binary(Path::new(path)),
        None => mvmctl_command(),
    };
    super::live_home::use_seeded_runtime(&mut command);
    if let Some(path) = &producer
        && let Some(refused) = apply_producer_revocations(Path::new(path), &workspace_root(), &home)
    {
        world.last_live_home = Some(home);
        world.last_run = Some(refused);
        return;
    }
    command
        .current_dir(workspace_root())
        .args(&argv)
        .isolated_home(&home);
    if argv.first().is_some_and(|arg| arg == "machine")
        && argv.get(1).is_some_and(|arg| arg == "start")
    {
        command.env("MVM_COLD_BUILD", "refuse");
    }
    apply_encrypted_volume_probe_path(world, &mut command);
    if world.warm_residency {
        command.env("MVM_RESIDENCY", "warm");
    }
    if let Terminal::Detached = terminal {
        use std::os::unix::process::CommandExt;
        // SAFETY: `setsid` is async-signal-safe and touches no state of the
        // parent; it is the only thing run between fork and exec.
        unsafe {
            command.pre_exec(|| nix::unistd::setsid().map(drop).map_err(Into::into));
        }
    }
    mvm_conformance::vmm_reaper::register_launched_home(&home);
    let output = command.output().expect("failed to spawn mvmctl");
    world.last_live_home = Some(home);
    world.last_run = Some(output);
}

/// The cached default development rootfs in the home the last live step used.
fn cached_default_dev_rootfs(world: &CliWorld) -> PathBuf {
    let home = world
        .last_live_home
        .as_deref()
        .expect("a live mvmctl step must run before the cached rootfs is inspected");
    mvm_core::config::default_microvm_cache_dir_at(home)
        .join("dev")
        .join("rootfs.ext4")
}

fn cached_default_dev_rootfs_digest(world: &CliWorld) -> String {
    let rootfs = cached_default_dev_rootfs(world);
    mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap_or_else(|error| {
        panic!(
            "hash the cached default development rootfs {}: {error}",
            rootfs.display()
        )
    })
}

#[then("the cached default development rootfs digest is recorded")]
fn record_cached_default_dev_rootfs_digest(world: &mut CliWorld) {
    world.cached_dev_rootfs_digest = Some(cached_default_dev_rootfs_digest(world));
}

#[then("the cached default development rootfs digest is unchanged")]
fn cached_default_dev_rootfs_digest_is_unchanged(world: &mut CliWorld) {
    let recorded = world
        .cached_dev_rootfs_digest
        .clone()
        .expect("the cached development rootfs digest must be recorded first");
    assert_eq!(
        cached_default_dev_rootfs_digest(world),
        recorded,
        "a transient launch rewrote the cached default development rootfs"
    );
}

/// The digest admission recorded is the digest the image still has, so the
/// signed plan describes the bytes the VMM booted.
#[then("the last admitted plan names the cached default development rootfs digest")]
fn last_admitted_plan_names_the_cached_rootfs_digest(world: &mut CliWorld) {
    let home = world
        .last_live_home
        .clone()
        .expect("a live mvmctl step must run before the audit chain is inspected");
    let chain_path = home.join("audit").join("local.jsonl");
    let chain = fs::read_to_string(&chain_path)
        .unwrap_or_else(|error| panic!("read audit chain {}: {error}", chain_path.display()));
    let admitted = chain
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<mvm_contract::verify::SignedEnvelope>(line).ok())
        .find(|envelope| envelope.entry.event == "plan.admitted")
        .unwrap_or_else(|| panic!("no plan.admitted entry in {}", chain_path.display()));
    assert_eq!(
        admitted.entry.image_sha256,
        cached_default_dev_rootfs_digest(world),
        "the admitted plan records a digest the cached rootfs no longer has"
    );
}

fn apply_encrypted_volume_probe_path(world: &CliWorld, command: &mut Command) {
    if let Some(path) = &world.encrypted_volume_probe_path {
        command.env("PATH", path);
    }
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
    let request_dirs = transient_request_dirs(home.path()).unwrap_or_else(|error| {
        panic!(
            "read transient VM state under isolated home {}: {error}",
            home.path().display()
        )
    });
    assert!(
        request_dirs.is_empty(),
        "generated transient request state directories remain: {request_dirs:?}"
    );
}

/// How long the leak check waits, in total, for a detached standby refill to
/// register the directories it is still populating. Each poll re-reads the
/// pool, so a refill that registers early ends the wait early.
const STANDBY_REFILL_POLL_DELAYS: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(15),
    Duration::from_secs(30),
];

/// An unnamed run leaves a standby behind for the next run, and its refill
/// runs detached: the record under `pool/` can land after `machine run` has
/// returned, and a preloaded child's directory exists before the record names
/// it. So a new directory is a leak only once the refill has had its bounded
/// chance to register it; anything a claimable record does not account for
/// by then fails the step.
#[then(expr = "the live mvm home has no new transient request state directories")]
fn live_home_no_new_transient_request_dirs(world: &mut CliWorld) {
    let home = world
        .last_live_home
        .as_ref()
        .expect("a live command must run before checking its home");
    let before = world
        .live_request_dirs_before
        .as_ref()
        .expect("record the live request state before running the journey");
    let pool = mvm_runtime::standby_pool::SupervisorStandbyPool::at(home.join("pool"));
    let mut last = None;
    for (attempt, delay) in STANDBY_REFILL_POLL_DELAYS.iter().enumerate() {
        let after = vm_state_dirs(home).unwrap_or_else(|error| {
            panic!(
                "read transient VM state under live home {}: {error}",
                home.display()
            )
        });
        let standbys = pool.list().unwrap_or_else(|error| {
            panic!("read the standby pool under {}: {error}", home.display())
        });
        let audit = mvm_conformance::standby_audit::audit_new_state_dirs(
            after.difference(before).cloned(),
            &standbys,
        );
        if audit.is_clean() {
            return;
        }
        last = Some(audit);
        if attempt + 1 < STANDBY_REFILL_POLL_DELAYS.len() {
            std::thread::sleep(*delay);
        }
    }
    let audit = last.expect("at least one poll ran");
    panic!(
        "new transient request state directories remain after the standby refill's grace \
         period: {:?} (registered standbys: {:?}, preloaded children: {:?})",
        audit.unregistered, audit.registered_standbys, audit.preloaded_children
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

/// One stderr line that begins with `prefix` and ends with `suffix`, for a
/// line carrying a value the scenario cannot know in advance, such as a plan id.
#[then(expr = "an error output line starts with {string} and ends with {string}")]
fn error_output_line_starts_and_ends_with(world: &mut CliWorld, prefix: String, suffix: String) {
    let output = world.last_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with(prefix.as_str()) && line.ends_with(suffix.as_str())),
        "expected a stderr line starting {prefix:?} and ending {suffix:?}; stderr:\n{stderr}",
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
            rendered_help_violations(&path, width, true)
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
        assert_rendered_help_fits(&short_help_args, width, true);

        let mut help_subcommand_args = vec!["help".to_string()];
        help_subcommand_args.extend(path);
        assert_rendered_help_fits(&help_subcommand_args, width, true);
    }

    // Rendering is the same code the binary runs, but not the same *process*.
    // One real invocation per entry-point form keeps that last inch honest:
    // if `mvmctl --help` ever stopped reaching the arm this renders, every
    // assertion above would still pass against a binary that printed nothing.
    for probe in [
        vec!["--help".to_string()],
        vec!["-h".to_string()],
        vec!["help".to_string()],
    ] {
        assert_help_invocation_fits(&probe, width, true);
    }
}

fn all_command_paths() -> Vec<Vec<String>> {
    let command = mvm_cli::commands::cli_command();
    let mut command_paths = vec![Vec::new()];
    collect_command_paths(&command, &[], &mut command_paths);
    command_paths
}

/// Extract the last component of each command path (e.g., "machine" from ["machine", "run"]).
/// This list is used to identify command names in help text.
/// Computed once per help check pass to avoid rebuilding the CLI tree hundreds of times.
fn command_names() -> Vec<String> {
    all_command_paths()
        .into_iter()
        .filter_map(|path| path.last().cloned())
        .collect()
}

/// The same assertions as [`assert_help_invocation_fits`], against help text
/// rendered in-process instead of read from a spawned `mvmctl`.
fn assert_rendered_help_fits(args: &[String], width: i64, require_single_line_items: bool) {
    let violations = rendered_help_violations(args, width, require_single_line_items);
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// Width violations in the help text `mvmctl <args>` would print, obtained
/// without spawning it.
///
/// The spawning version below is unchanged and still used, deliberately, for a
/// few probe invocations. What it cost as the *bulk* check was one process per
/// command path — a debug `mvmctl` is over 100 MB, and the CLI has enough paths
/// that this single scenario dominated the suite and read as a freeze.
///
/// `mvm_cli::commands::help_text_for` runs the binary's own help arm: the same
/// clap tree parses the same argv and the same output constraint is applied, so
/// `--help`, `-h` and `help <path>` still dispatch and render as they really
/// do. Nothing here re-implements the formatting it is checking.
fn rendered_help_violations(
    args: &[String],
    width: i64,
    require_single_line_items: bool,
) -> Vec<String> {
    let invocation = format!("mvmctl {}", args.join(" "));
    let Some(help) = mvm_cli::commands::help_text_for(args) else {
        return vec![format!("`{invocation}` did not render help")];
    };
    if help.trim().is_empty() {
        return vec![format!("`{invocation}` rendered empty help")];
    }

    let mut violations = Vec::new();
    if require_single_line_items {
        collect_wrapped_help_items(&invocation, &help, &command_names(), &mut violations);
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
        collect_wrapped_help_items(&invocation, &help, &command_names(), &mut violations);
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

/// Helper to check if help items wrap onto multiple lines.
/// Takes `command_names` as a parameter to avoid rebuilding the CLI tree
/// for each help invocation (hundreds of times).
fn collect_wrapped_help_items(
    invocation: &str,
    help: &str,
    command_names: &[String],
    violations: &mut Vec<String>,
) {
    #[derive(Clone, Copy)]
    enum ItemSection {
        Arguments,
        Commands,
        Options,
    }

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

/// Every command path under `command`, depth first.
pub(crate) fn command_paths(command: &clap::Command) -> Vec<Vec<String>> {
    let mut paths = Vec::new();
    collect_command_paths(command, &[], &mut paths);
    paths
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

/// A remote demo template with an optional `[policy]` table and the files it
/// declares. `None` writes the policy-free template the other scenarios use.
fn write_demo_registry(world: &mut CliWorld, policy: Option<(&str, &[(&str, &str)])>) {
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

    let policy_table = policy.map(|(table, _)| table).unwrap_or("");
    std::fs::write(
        tpl.join("template.toml"),
        format!(
            r#"name = "demo"
description = "demo remote template"
default_vcpus = 2
default_memory_mib = 512
tags = ["demo"]
files = ["app.py"]
{policy_table}"#
        ),
    )
    .expect("write template.toml");

    std::fs::write(
        tpl.join("flake.nix"),
        r#"{ pkgs }:
{
  mkGuest = { ... }: {
    entrypoint = "hello",
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

    if let Some((_, files)) = policy {
        for (rel, content) in files {
            let path = tpl.join(rel);
            std::fs::create_dir_all(path.parent().expect("policy file has a parent"))
                .expect("create policy dir");
            std::fs::write(path, content).expect("write policy file");
        }
    }

    world.template_registry_dir = Some(tmp);
}

/// Create a local `file://` registry with a single "demo" template that
/// includes an `app.py` SDK source file.
#[given(expr = "a local template registry with a demo template")]
fn local_template_registry_with_demo(world: &mut CliWorld) {
    write_demo_registry(world, None);
}

#[given(expr = "a local template registry with a demo template shipping policy")]
fn local_template_registry_with_demo_policy(world: &mut CliWorld) {
    write_demo_registry(
        world,
        Some((
            r#"
[policy]
profile = "policy/base.toml"
include = ["policy/apis.toml"]
"#,
            &[
                (
                    "policy/base.toml",
                    "[overrides.network]\nallow = [\"a.test\"]\n",
                ),
                ("policy/apis.toml", "[network]\nallow = [\"b.test\"]\n"),
            ],
        )),
    );
}

#[given(expr = "a local template registry with a demo template shipping broken policy")]
fn local_template_registry_with_demo_broken_policy(world: &mut CliWorld) {
    write_demo_registry(
        world,
        Some((
            r#"
[policy]
profile = "policy/base.toml"
"#,
            &[("policy/base.toml", "[network]\nallowed = []\n")],
        )),
    );
}

#[given(expr = "a local template registry with a demo template selecting a signed pack group")]
fn local_template_registry_with_demo_pack_group(world: &mut CliWorld) {
    write_demo_registry(
        world,
        Some(("\n[policy]\ninclude = [\"runtime/python@1.0.0\"]\n", &[])),
    );
}

#[given(expr = "an isolated mvm home with an empty pack trust policy")]
fn isolated_home_with_empty_pack_trust(world: &mut CliWorld) {
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let policy = mvm_core::registry_pack::RegistryPackPublisherPolicy::new(Vec::new())
        .expect("empty publisher policy is valid");
    mvm_core::registry_pack_store::save_publisher_policy(
        &home.path().join("registry/publishers.toml"),
        &policy,
    )
    .expect("write empty publisher policy");
    world.isolated_home = Some(home);
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

    if world.isolated_home.is_none() {
        world.isolated_home = Some(tempfile::tempdir().expect("create isolated template home"));
    }
    let home_path = world
        .isolated_home
        .as_ref()
        .expect("template home exists")
        .path()
        .to_path_buf();

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

#[then(expr = "the generated project file {string} contains {string}")]
fn generated_project_file_contains(world: &mut CliWorld, file: String, needle: String) {
    let dir = world
        .generated_project_dir
        .as_ref()
        .expect("a project must be generated first");
    let text = std::fs::read_to_string(dir.join(&file))
        .unwrap_or_else(|e| panic!("reading generated {file:?}: {e}"));
    assert!(
        text.contains(&needle),
        "expected generated {file:?} to contain {needle:?}; got:\n{text}"
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

/// Seal what the last live `machine build` produced into a `.mvmpkg`, on the
/// host that ran the build and under that host's signer. The builder VM that
/// produced the image never held the key; this is the step that uses it.
#[when("I seal the live manifest build into a bundle")]
fn seal_live_build(world: &mut CliWorld) {
    let home = world
        .last_live_home
        .clone()
        .expect("a live build step runs before the seal");
    let build = world
        .last_run
        .as_ref()
        .expect("a build ran before the seal");
    assert!(build.status.success(), "the manifest build must succeed");
    let slot = crate::live_artifacts::built_manifest_slot(&build.stdout)
        .expect("the live manifest build must report its completed slot in JSON");
    let dir = tempfile::tempdir().expect("create the sealed-bundle directory");
    let bundle = dir.path().join("build.mvmpkg");
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["dev", "export-template", &slot, "--out"])
        .arg(&bundle)
        .isolated_home(&home)
        .output()
        .expect("failed to spawn internal template exporter");
    if output.status.success() {
        fs::copy(
            home.join("keys/host-signer.pub"),
            dir.path().join("publisher.pub"),
        )
        .expect("the export signed with the home's host signer, so its public half exists");
    }
    world.sealed_bundle = Some(dir);
    world.last_run = Some(output);
}

/// Verify and install the sealed bundle in a home that shares nothing with the
/// one that built it except trust in its signer's public half. Neither command
/// boots anything.
#[when(expr = "I install the sealed bundle into a fresh home that trusts its builder")]
fn install_sealed_bundle(world: &mut CliWorld) {
    let sealed = world
        .sealed_bundle
        .as_ref()
        .expect("a seal step runs before the install");
    let bundle = sealed.path().join("build.mvmpkg");
    let publisher = sealed.path().join("publisher.pub");
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let run = |args: &[&str], path: &Path| {
        mvmctl_command()
            .current_dir(workspace_root())
            .args(args)
            .arg(path)
            .isolated_home(home.path())
            .output()
            .expect("failed to spawn mvmctl")
    };
    for (args, path) in [
        (&["trust", "add"][..], &publisher),
        (&["bundle", "fetch"][..], &bundle),
    ] {
        let output = run(args, path);
        assert!(
            output.status.success(),
            "`mvmctl {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = run(&["bundle", "install"], &bundle);
    // `Installed bundle <sha> (N artifacts, publisher key_id=...)`
    world.bundle_sha = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Installed bundle "))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_string);
    world.isolated_home = Some(home);
    world.last_run = Some(output);
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
