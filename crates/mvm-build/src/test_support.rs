//! Process isolation for tests that require control of descriptor lifetimes.

/// Run the complete lock-lifetime probe in its own single-test process.
pub(crate) fn isolated_lock_probe(probe: impl FnOnce()) {
    let env = mvm_core::util::test_env::TestEnv::new();
    const CHILD_ENV: &str = "MVM_TEST_ISOLATED_PRE_EXEC_LOCK_PROBE";
    let thread = std::thread::current();
    let name = thread.name().expect("libtest names the probe thread");
    let completed = format!("completed isolated pre-exec lock probe: {name}");
    if let Some(child_name) = std::env::var_os(CHILD_ENV) {
        assert_eq!(
            child_name,
            std::ffi::OsStr::new(name),
            "the isolated child must run only its intended test"
        );
        // The single-test child may take its own non-reentrant environment guard.
        drop(env);
        probe();
        eprintln!("{completed}");
        return;
    }

    // Any concurrent fork inherits open descriptions, even CLOEXEC ones.
    // Exec a private test process before opening probe resources so last-close
    // assertions cannot race another libtest thread's fork-before-exec window.
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name)
        .output()
        .expect("run the isolated lock probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stderr.lines().filter(|line| *line == completed).count() == 1,
        "isolated lock probe {name} failed:\n{}\n{}",
        stdout,
        stderr,
    );
}
