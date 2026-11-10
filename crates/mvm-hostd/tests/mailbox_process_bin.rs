//! The `mvm-mailbox` binary refuses a config it does not recognise before it
//! binds or dials anything.

use std::io::Write as _;
use std::process::{Command, Stdio};

fn run_with(stdin: &[u8]) -> std::process::ExitStatus {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mvm-mailbox"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mvm-mailbox");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait().expect("wait")
}

#[test]
fn an_empty_config_and_an_unknown_field_are_refused() {
    assert!(!run_with(b"").success());
    assert!(!run_with(br#"{"seed":"00"}"#).success());
}
