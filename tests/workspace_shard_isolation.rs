use std::fs;

#[cfg(unix)]
#[test]
fn test_state_isolation_handles_missing_home_and_preserves_toolchain_locations() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    for workflow in [
        ".github/workflows/workspace-shard.yml",
        ".github/workflows/ci-main.yml",
    ] {
        let text = fs::read_to_string(workflow).unwrap();
        let step = text
            .split("      - name: Isolate test state\n")
            .nth(1)
            .unwrap();
        let script = step
            .split("        run: |\n")
            .nth(1)
            .unwrap()
            .lines()
            .take_while(|line| line.is_empty() || line.starts_with("          "))
            .map(|line| line.strip_prefix("          ").unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        for home_state in ["unset", "empty", "present"] {
            let scratch = tempfile::tempdir().unwrap();
            let original_home = scratch.path().join("original home");
            let bin = scratch.path().join("bin");
            fs::create_dir(&original_home).unwrap();
            fs::create_dir(&bin).unwrap();
            for (name, contents) in [
                (
                    "getent",
                    "#!/bin/sh\nprintf 'runner:x:1000:1000:runner:%s:/bin/sh\\n' \"$EXPECTED_HOME\"\n",
                ),
                (
                    "rustup",
                    "#!/bin/sh\n[ \"$1 $2\" = 'show home' ] || exit 2\nprintf '%s\\n' \"$EXPECTED_RUSTUP\"\n",
                ),
            ] {
                let path = bin.join(name);
                fs::write(&path, contents).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let github_env = scratch.path().join("github-env");
            let mut command = Command::new("bash");
            command
                .args(["-c", &script])
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("EXPECTED_HOME", &original_home)
                .env("EXPECTED_RUSTUP", "/installed/rustup")
                .env("CARGO_HOME", "/installed/cargo")
                .env_remove("RUSTUP_HOME")
                .env("RUNNER_TEMP", scratch.path())
                .env("GITHUB_RUN_ID", "123")
                .env("GITHUB_RUN_ATTEMPT", "1")
                .env("SHARD", "1")
                .env("GITHUB_ENV", &github_env);
            match home_state {
                "unset" => {
                    command.env_remove("HOME");
                }
                "empty" => {
                    command.env("HOME", "");
                }
                _ => {
                    command
                        .env("HOME", &original_home)
                        .env("RUSTUP_HOME", "/installed/rustup");
                }
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{workflow}, HOME {home_state}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let exported = fs::read_to_string(github_env).unwrap();
            assert!(exported.contains(&format!(
                "RUNNER_ORIGINAL_HOME={}\n",
                original_home.display()
            )));
            assert!(exported.contains("CARGO_HOME=/installed/cargo\n"));
            assert!(exported.contains("RUSTUP_HOME=/installed/rustup\n"));
            let base = scratch.path().join("mvm-w-123-1-1");
            for (name, variable) in [("home", "HOME"), ("mvm", "MVM_HOME"), ("tmp", "TMPDIR")] {
                let path = base.join(name);
                assert!(exported.contains(&format!("{variable}={}\n", path.display())));
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
    }
}

#[test]
fn dedicated_linux_runners_use_their_cpus_without_changing_shared_host_limits() {
    let cache = fs::read_to_string(".github/actions/rust-cache/action.yml").unwrap();
    let configure = cache
        .find("- name: Configure dedicated Linux build workers")
        .unwrap();
    assert!(cache.find("uses: Swatinem/rust-cache@v2").unwrap() < configure);
    let step = &cache[configure..];
    assert!(step.contains("runner.environment == 'github-hosted'"));
    assert!(step.contains("runner.os == 'Linux'"));
    assert!(step.contains("env.CARGO_BUILD_JOBS == ''"));
    assert!(step.contains("workers=\"$(nproc)\""));
    assert!(step.contains("printf 'CARGO_BUILD_JOBS=%s\\n' \"$workers\" >> \"$GITHUB_ENV\""));
}

#[test]
fn feature_suites_have_two_complete_nonoverlapping_partitions() {
    let ci = fs::read_to_string(".github/workflows/ci-main.yml").unwrap();
    let features = ci
        .split("  lint-features:\n")
        .nth(1)
        .unwrap()
        .split("\n  lint-features-test-support:")
        .next()
        .unwrap();
    assert!(features.contains("suite: [portable, signatures]"));
    assert!(features.contains("max-parallel: 2"));
    assert!(features.contains("fail-fast: false"));
    for (name, suite) in [
        ("Clippy (mvm-client tracing-bridge)", "portable"),
        ("hostd-transport feature tests (mvm-core)", "portable"),
        ("client facade tests (mvm-core)", "portable"),
        ("schema feature tests (mvm-sdk)", "portable"),
        (
            "compiler compatibility and deployment feature tests (mvm-sdk)",
            "portable",
        ),
        ("policy schema drift (mvm-client schema)", "portable"),
        (
            "instruction provenance tests (manifest-verify + schema)",
            "portable",
        ),
        ("addons feature tests (guest egress data path)", "portable"),
        ("release signature tests (manifest-verify)", "signatures"),
        (
            "verifier-absent refusal tests (no manifest-verify)",
            "signatures",
        ),
    ] {
        let header = format!("- name: {name}\n        if: matrix.suite == '{suite}'\n");
        assert!(features.contains(&header), "missing partition for {name}");
    }
    assert_eq!(features.matches("if: matrix.suite ==").count(), 10);
}

#[test]
fn workspace_workers_do_not_recompile_for_queue_owned_extras() {
    let worker = fs::read_to_string(".github/workflows/workspace-shard.yml").unwrap();
    let ci = fs::read_to_string(".github/workflows/ci-main.yml").unwrap();
    let extras = ci
        .split("  test-workspace-extras:\n")
        .nth(1)
        .unwrap()
        .split("\n  test-workspace-aarch64:")
        .next()
        .unwrap();
    for command in [
        "cargo run -p xtask -- check-nextest-groups",
        "cargo nextest run -p xtask --features man",
        "cargo nextest run -p mvm-agentd --features addons",
        "cargo test --workspace --doc",
    ] {
        assert!(!worker.contains(command), "worker duplicates {command}");
        assert!(extras.contains(command), "queue lost {command}");
    }
    assert!(!worker.contains("cargo build --all-targets"));
    assert!(worker.contains("cargo nextest run --workspace --all-targets --partition"));
}

#[test]
fn arm_suite_builds_only_after_its_final_environment_is_set() {
    let ci = fs::read_to_string(".github/workflows/ci-main.yml").unwrap();
    let arm = ci
        .split("  test-workspace-aarch64:\n")
        .nth(1)
        .unwrap()
        .split("\n  test-release-witness:")
        .next()
        .unwrap();
    let selection = "cargo nextest run --workspace --exclude mvm-fs --all-targets";
    assert_eq!(
        arm.matches(selection).count(),
        1,
        "do not prebuild then invalidate the suite"
    );
    assert!(arm.find("name: Isolate test state").unwrap() < arm.find(selection).unwrap());
    assert!(
        arm.find("MVM_GUEST_PRIVILEGED_TESTS=1").unwrap()
            < arm.find("name: Isolate test state").unwrap()
    );
    assert!(arm.contains("--test crng_reseed_helper --no-run --message-format=json"));
}

#[test]
fn workspace_shards_keep_mutable_state_per_worker_run() {
    let worker = fs::read_to_string(".github/workflows/workspace-shard.yml")
        .expect("read workspace shard workflow");

    assert!(
        worker.contains(
            "base=\"${RUNNER_TEMP}/mvm-w-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${SHARD}\""
        ),
        "the persistent runner must not reuse another job's mutable state"
    );
    assert!(worker.contains("mkdir -m 700 -- \"$base\""));
    assert!(worker.contains("mkdir -m 700 -- \"$base/home\" \"$base/mvm\" \"$base/tmp\""));
    assert!(worker.contains("CARGO_HOME=%s\\nRUSTUP_HOME=%s\\n"));
    assert!(worker.contains("\"$base/home\" \"$base/mvm\" \"$base/tmp\""));
    assert!(worker.contains(">> \"$GITHUB_ENV\""));
    assert!(worker.contains("if: always()"));
    assert!(
        worker.contains(
            "bash nix/ops/hetzner/job-cleanup.sh \"${RUNNER_TEMP}/mvm-w-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${SHARD}\""
        ),
        "the always-run last step must hand the same base to the cleanup script"
    );

    let cleanup =
        fs::read_to_string("nix/ops/hetzner/job-cleanup.sh").expect("read job cleanup script");
    assert!(cleanup.contains("^/tmp/mvm-w-[0-9]+-[0-9]+-[1-9]$"));
    assert!(cleanup.contains("[ -L \"$path\" ]"));
    assert!(cleanup.contains("chmod -R u+rwX -- \"$path\""));
    assert!(cleanup.contains("rm -rf --one-file-system -- \"$path\""));
    assert!(cleanup.contains("remove_dir \"$base\""));
}
