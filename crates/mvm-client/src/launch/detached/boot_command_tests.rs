//! Component coverage of the exact ProcStart constructor used after readiness.

use super::*;
use mvm_core::util::test_env::TestEnv;

fn isolated() -> (TestEnv, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(dir.path());
    (env, dir)
}

fn command(env: BTreeMap<String, String>) -> BootCommand {
    BootCommand {
        argv: vec!["/work/task".into(), "--once".into()],
        env,
        cwd: Some("/work".into()),
    }
}

fn enable_egress(name: &str) {
    let marker = mvm_core::config::vm_vsock_egress_marker_path(name);
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(marker, b"1").unwrap();
}

fn canonical_env(name: &str) -> BTreeMap<String, String> {
    mvm_hostd::workload_env::workload_egress_env(name)
        .into_iter()
        .collect()
}

#[test]
fn boot_command_refuses_invalid_names_before_readiness() {
    let (_env, _dir) = isolated();
    for name in [
        "../vms/alias",
        "/absolute",
        "with/slash",
        "with\nnewline",
        "",
    ] {
        let error = start_boot_command(name, command(BTreeMap::new())).unwrap_err();
        assert!(
            format!("{error:#}").contains("invalid boot-command machine name"),
            "{error:#}"
        );
    }
}

fn enable_substitution(name: &str) {
    enable_egress(name);
    std::fs::write(
        mvm_core::config::vm_substitution_env_path(name),
        br#"[["API_KEY","mvm-secret://opaque-placeholder"]]"#,
    )
    .unwrap();
    std::fs::write(
        mvm_core::config::vm_state_dir(name)
            .join(mvm_vmm::host::network_endpoint_spawn::EGRESS_CA_STATE_FILE),
        b"test certificate presence",
    )
    .unwrap();
}

#[test]
fn boot_command_delivers_canonical_proxy_env_without_changing_argv_or_cwd() {
    let (_env, _dir) = isolated();
    let name = "boot-proxy";
    enable_egress(name);
    let expected = canonical_env(name);
    assert!(expected.contains_key("HTTPS_PROXY"));

    let command = command(BTreeMap::from([("TASK_MODE".into(), "once".into())]));
    let process = boot_command_process(name, command.clone()).unwrap();
    assert_eq!(process.argv, command.argv);
    assert_eq!(process.cwd, command.cwd);
    for (key, value) in expected {
        assert_eq!(process.env.get(&key), Some(&value), "{key}");
    }
    assert_eq!(
        process.env.get("TASK_MODE").map(String::as_str),
        Some("once")
    );
}

#[test]
fn boot_command_delivers_canonical_ca_and_substitution_env() {
    let (_env, _dir) = isolated();
    let name = "boot-substitution";
    enable_substitution(name);
    let expected = canonical_env(name);
    for key in [
        "HTTPS_PROXY",
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "API_KEY",
    ] {
        assert!(expected.contains_key(key), "{key}");
    }

    let process = boot_command_process(name, command(BTreeMap::new())).unwrap();
    assert_eq!(process.env, expected);
}

#[test]
fn boot_command_refuses_caller_replacement_of_each_canonical_variable_without_values() {
    let (_env, _dir) = isolated();
    let name = "boot-proxy-override";
    enable_substitution(name);
    let canonical = canonical_env(name);
    assert!(!canonical.is_empty());
    for key in canonical.keys() {
        let supplied = "caller-value-must-not-appear";
        let error = boot_command_process(
            name,
            command(BTreeMap::from([(key.clone(), supplied.into())])),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(key));
        assert!(!message.contains(supplied));
        for value in canonical.values() {
            assert!(!message.contains(value));
        }
    }
}

#[test]
fn boot_command_accepts_identical_canonical_values() {
    let (_env, _dir) = isolated();
    let name = "boot-proxy-repeat";
    enable_substitution(name);
    let expected = canonical_env(name);
    assert!(!expected.is_empty());
    let process = boot_command_process(name, command(expected.clone())).unwrap();
    assert_eq!(process.env, expected);
}

#[test]
fn boot_command_without_egress_keeps_an_empty_environment_empty() {
    let (_env, _dir) = isolated();
    let name = "boot-no-egress";
    assert!(canonical_env(name).is_empty());
    let process = boot_command_process(name, command(BTreeMap::new())).unwrap();
    assert!(process.env.is_empty());
}

#[test]
fn boot_command_without_provisioned_egress_preserves_caller_configuration() {
    let (_env, _dir) = isolated();
    let name = "boot-caller-env";
    assert!(canonical_env(name).is_empty());
    let expected = BTreeMap::from([
        ("HTTPS_PROXY".into(), "caller-proxy".into()),
        ("SSL_CERT_FILE".into(), "/work/ca.pem".into()),
        ("TASK_MODE".into(), "once".into()),
    ]);
    let process = boot_command_process(name, command(expected.clone())).unwrap();
    assert_eq!(process.env, expected);
}

#[test]
fn boot_command_denied_caller_variables_still_refuse_without_values() {
    let (_env, _dir) = isolated();
    let name = "boot-denied-env";
    enable_egress(name);
    for key in ["LD_PRELOAD", "BASH_ENV", "PYTHONPATH", "OP_SESSION_test"] {
        let supplied = "denied-value-must-not-appear";
        let process = boot_command_process(
            name,
            command(BTreeMap::from([(key.into(), supplied.into())])),
        )
        .unwrap();
        let error = crate::guest::start_process(name, process).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("guest process environment"));
        assert!(message.contains(key));
        assert!(!message.contains(supplied));
    }
}
