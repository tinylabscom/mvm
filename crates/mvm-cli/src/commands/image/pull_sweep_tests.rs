use super::pull_core::acquisition_hooks;

fn sweep_before_builder_vm() {
    (acquisition_hooks().before_materialize)();
}

#[test]
fn the_pre_builder_sweep_runs_the_orphan_reaper() {
    if !crate::test_boot_payload::in_fresh_test_process(
        module_path!(),
        "the_pre_builder_sweep_runs_the_orphan_reaper",
    ) {
        return;
    }
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    assert!(!crate::commands::env::builder_vm::before_spawn_sweep_has_run());
    sweep_before_builder_vm();
    assert!(crate::commands::env::builder_vm::before_spawn_sweep_has_run());
    sweep_before_builder_vm();
    assert!(crate::commands::env::builder_vm::before_spawn_sweep_has_run());
}

#[cfg(unix)]
#[test]
fn the_pre_builder_sweep_kills_a_planted_orphan() {
    if !crate::test_boot_payload::in_fresh_test_process(
        module_path!(),
        "the_pre_builder_sweep_kills_a_planted_orphan",
    ) {
        return;
    }
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let name = "mvm-workload-plantedorphan-5d1e-stopped";
    let vm = mvm_core::config::vms_dir().join(name);
    std::fs::create_dir_all(&vm).expect("mkdir");
    std::fs::write(vm.join("libkrun.pid"), format!("{}\n", i32::MAX)).expect("dead owner");
    let pid_file = home.path().join("orphan.pid");
    let script = format!(
        "(sh -c 'echo $$ > {}; sleep 60; : {name}' >/dev/null 2>&1 &)",
        pid_file.display()
    );
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .status()
        .expect("plant orphan");
    assert!(status.success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
        {
            break pid;
        }
        assert!(std::time::Instant::now() < deadline, "orphan never started");
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let reparented = |pid: i32| {
        let out = std::process::Command::new("ps")
            .args(["-o", "ppid=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout).trim() == "1"
    };
    while !reparented(pid) {
        if std::time::Instant::now() > deadline {
            // SAFETY: pid is the child this test spawned and still owns.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    sweep_before_builder_vm();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let gone = loop {
        let out = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        let stat = String::from_utf8_lossy(&out.stdout);
        if stat.trim().is_empty() || stat.trim().starts_with('Z') {
            break true;
        }
        if std::time::Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    if !gone {
        // SAFETY: pid is the child this test spawned and still owns.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert!(gone, "the planted orphan survived the pre-spawn sweep");
}

#[test]
fn a_prior_parent_sweep_does_not_contaminate_the_cold_sweep_witness() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    sweep_before_builder_vm();
    assert!(crate::commands::env::builder_vm::before_spawn_sweep_has_run());
    drop(env);
    the_pre_builder_sweep_runs_the_orphan_reaper();
    assert!(crate::commands::env::builder_vm::before_spawn_sweep_has_run());
}
