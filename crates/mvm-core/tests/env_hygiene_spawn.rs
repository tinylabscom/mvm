//! A helper built with `helper_command` does not inherit a denied variable
//! from the process that starts it.
//!
//! The variables have to be in a real parent's environment for this to test
//! anything, and a test must not mutate its own process environment, so the
//! test re-runs its own binary with the variables set. That child plays the
//! `mvmctl` role: it starts `/usr/bin/env` through `helper_command` and prints
//! what the helper actually received.

use std::process::Command;

const PROBE: &str = "MVM_ENV_HYGIENE_SPAWN_PROBE";
const TEST_NAME: &str = "a_helper_does_not_inherit_denied_variables";

#[test]
fn a_helper_does_not_inherit_denied_variables() {
    if std::env::var_os(PROBE).is_some() {
        let output = mvm_core::env_hygiene::helper_command("/usr/bin/env")
            .output()
            .expect("run /usr/bin/env as the helper");
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test binary path"))
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(PROBE, "1")
        .env("BASH_ENV", "/nonexistent/rc")
        .env("OP_SESSION_probe", "session-value")
        .env("PYTHONPATH", "/probe/lib")
        .env("BASH_FUNC_probe%%", "() { :; }")
        .env("MVM_ENV_HYGIENE_KEPT", "kept")
        .output()
        .expect("re-run the test binary as the parent");
    let helper_env = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{helper_env}");
    assert!(
        helper_env.contains("MVM_ENV_HYGIENE_KEPT=kept"),
        "an ordinary variable is inherited: {helper_env}"
    );
    for denied in [
        "BASH_ENV=",
        "OP_SESSION_probe=",
        "PYTHONPATH=",
        "BASH_FUNC_probe",
    ] {
        assert!(
            !helper_env.lines().any(|line| line.starts_with(denied)),
            "{denied} reached the helper: {helper_env}"
        );
    }
    assert!(
        !helper_env.contains("session-value"),
        "the session token's value reached the helper"
    );
}
