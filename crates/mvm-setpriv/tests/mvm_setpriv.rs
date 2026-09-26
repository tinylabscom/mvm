#![cfg(target_os = "linux")]

use std::process::Command;

fn run_helper(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mvm-setpriv"))
        .args(arguments)
        .output()
        .expect("mvm-setpriv test process should start")
}

#[test]
fn drops_identity_groups_capabilities_and_enables_no_new_privs() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping privileged helper test when not running as root");
        return;
    }

    let output = run_helper(&[
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "--no-new-privs",
        "--",
        "/bin/sh",
        "-c",
        "test \"$(id -u)\" = 65534 && test \"$(id -g)\" = 65534 && test \"$(id -G)\" = 65534 && grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status && grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status",
    ]);

    assert!(
        output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn retains_only_net_bind_service_as_an_ambient_capability() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping privileged helper test when not running as root");
        return;
    }

    let output = run_helper(&[
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "--no-new-privs",
        "--inh-caps=+net_bind_service",
        "--ambient-caps=+net_bind_service",
        "--",
        "/bin/sh",
        "-c",
        "grep -Eq '^Cap(Eff|Prm|Inh|Amb):[[:space:]]+0000000000000400$' /proc/self/status",
    ]);

    assert!(
        output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_unsupported_privilege_options() {
    let output = run_helper(&[
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--",
        "/bin/true",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported option"));
}
