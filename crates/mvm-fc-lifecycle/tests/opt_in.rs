use std::process::Command;

#[test]
fn default_and_incomplete_commands_never_serve() {
    for args in [
        vec![],
        vec!["serve"],
        vec!["--experimental"],
        vec!["serve", "--experimental", "--path", "/tmp/x"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mvm-fc-lifecycle"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn explicit_opt_in_is_not_sufficient_on_native_non_linux() {
    let output = Command::new(env!("CARGO_BIN_EXE_mvm-fc-lifecycle"))
        .args(["serve", "--experimental"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}
