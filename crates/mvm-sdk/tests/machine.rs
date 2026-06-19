use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mvm_sdk::{Machine, MachineClient, MachineCreate, MachineError, MachineRun};
use tempfile::TempDir;

struct FakeCli {
    _dir: TempDir,
    bin: PathBuf,
    argv_path: PathBuf,
}

impl FakeCli {
    fn success() -> Self {
        Self::new(0)
    }

    fn failing() -> Self {
        Self::new(7)
    }

    fn new(exit_code: i32) -> Self {
        let dir = TempDir::new().expect("create fake cli dir");
        let bin = dir.path().join("mvmctl");
        let argv_path = dir.path().join("argv.txt");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nprintf 'fake stdout\\n'\nprintf 'fake stderr\\n' >&2\nexit {exit_code}\n",
            shell_quote(&argv_path),
        );
        fs::write(&bin, script).expect("write fake mvmctl");
        let mut perms = fs::metadata(&bin)
            .expect("fake mvmctl metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin, perms).expect("chmod fake mvmctl");
        Self {
            _dir: dir,
            bin,
            argv_path,
        }
    }

    fn client(&self) -> MachineClient {
        MachineClient::new(&self.bin)
    }

    fn argv(&self) -> Vec<String> {
        fs::read_to_string(&self.argv_path)
            .expect("read argv")
            .lines()
            .map(str::to_string)
            .collect()
    }
}

#[test]
fn machine_run_builder_emits_machine_cli_argv() {
    let args = MachineRun::builder()
        .image("alpine")
        .net(true)
        .allow_host("registry.npmjs.org")
        .cpus(2)
        .memory("1G")
        .profile("dev")
        .add_dir("/src:/workspace:ro")
        .env("RUST_LOG=info")
        .timeout(30)
        .receipt("/tmp/receipt.json")
        .json(true)
        .dry_run(true)
        .command(["sh", "-c", "echo hi"])
        .machine_args()
        .expect("machine run argv");

    assert_eq!(
        args,
        [
            "run",
            "--image",
            "alpine",
            "--net",
            "--allow-host",
            "registry.npmjs.org",
            "--cpus",
            "2",
            "--memory",
            "1G",
            "--profile",
            "dev",
            "--add-dir",
            "/src:/workspace:ro",
            "--env",
            "RUST_LOG=info",
            "--timeout",
            "30",
            "--receipt",
            "/tmp/receipt.json",
            "--json",
            "--dry-run",
            "--",
            "sh",
            "-c",
            "echo hi",
        ]
    );
}

#[test]
fn machine_create_shells_through_mvmctl_machine() {
    let fake = FakeCli::success();
    let machine = MachineCreate::builder("devbox")
        .manifest("mvm.toml")
        .net(true)
        .allow_host("example.com")
        .memory("2G")
        .mem_initial("512M")
        .profile("dev")
        .force(true)
        .json(true)
        .create_with(&fake.client())
        .expect("create machine");

    assert_eq!(machine.name(), "devbox");
    assert_eq!(
        fake.argv(),
        [
            "machine",
            "create",
            "--name",
            "devbox",
            "--manifest",
            "mvm.toml",
            "--net",
            "--allow-host",
            "example.com",
            "--memory",
            "2G",
            "--mem-initial",
            "512M",
            "--profile",
            "dev",
            "--force",
            "--json",
        ]
    );
}

#[test]
fn persistent_machine_lifecycle_builders_reuse_machine_cli() {
    let fake = FakeCli::success();
    let client = fake.client();
    let machine = Machine::named("devbox").expect("machine handle");

    machine
        .start()
        .receipt("/tmp/start.json")
        .json(true)
        .dry_run(true)
        .run_with(&client)
        .expect("start");
    assert_eq!(
        fake.argv(),
        [
            "machine",
            "start",
            "--name",
            "devbox",
            "--receipt",
            "/tmp/start.json",
            "--json",
            "--dry-run",
        ]
    );

    machine
        .exec(["echo", "hi"])
        .force(true)
        .run_with(&client)
        .expect("exec");
    assert_eq!(
        fake.argv(),
        [
            "machine", "exec", "--name", "devbox", "--force", "--", "echo", "hi",
        ]
    );

    machine
        .shell()
        .force(true)
        .run_with(&client)
        .expect("shell");
    assert_eq!(
        fake.argv(),
        ["machine", "shell", "--name", "devbox", "--force"]
    );

    machine.stop().run_with(&client).expect("stop");
    assert_eq!(fake.argv(), ["machine", "stop", "--name", "devbox"]);
}

#[test]
fn machine_builders_reject_invalid_inputs_before_invoking_cli() {
    let conflict = MachineCreate::builder("devbox")
        .image("alpine")
        .manifest("mvm.toml")
        .machine_args()
        .expect_err("image+manifest rejected");
    assert!(conflict.to_string().contains("image OR manifest"));

    let empty_command = MachineRun::builder()
        .image("alpine")
        .command(Vec::<String>::new())
        .machine_args()
        .expect_err("empty command rejected");
    assert!(
        empty_command
            .to_string()
            .contains("command must be non-empty")
    );

    let empty_name = Machine::named("").expect_err("empty name rejected");
    assert!(empty_name.to_string().contains("name must be non-empty"));
}

#[test]
fn machine_errors_preserve_argv_exit_code_and_stderr() {
    let fake = FakeCli::failing();
    let err = MachineRun::builder()
        .image("alpine")
        .command(["true"])
        .run_with(&fake.client())
        .expect_err("fake cli exits nonzero");

    match err {
        MachineError::Failed {
            argv,
            exit_code,
            stderr,
        } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(argv[0], fake.bin.to_string_lossy());
            assert_eq!(
                &argv[1..],
                ["machine", "run", "--image", "alpine", "--", "true"]
            );
            assert!(stderr.contains("fake stderr"));
        }
        other => panic!("expected MachineError::Failed, got {other:?}"),
    }
}

fn shell_quote(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}
