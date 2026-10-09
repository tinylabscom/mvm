//! Opt-in Linux witnesses spanning both exec boundaries without changing the
//! test runner's credentials. Run as root with MVM_GUEST_PRIVILEGED_TESTS=1.

use super::*;
use crate::guest_mount::{TOOL_GID, TOOL_HELPER_IDENTITY, TOOL_UID};
use std::io::Write;

const STAGE: &str = "MVM_TOOL_CAPABILITY_TEST_STAGE";
const PROBE: &str = "tool_helper::capability_tests::exec_capability_probe";
const VERIFIED: &str = "execed tool has no capabilities and cannot regain privilege";

fn field<'a>(status: &'a str, name: &str) -> &'a str {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .expect("status field exists")
        .trim()
}

fn assert_caps(status: &str, mask: &str) {
    for set in ["CapPrm", "CapEff", "CapInh", "CapAmb"] {
        assert_eq!(field(status, set), mask, "{set}:\n{status}");
    }
    assert_eq!(field(status, "NoNewPrivs"), "1");
}

#[test]
fn helper_exec_retains_transition_caps_but_tool_exec_cannot_regain_privilege() {
    if std::env::var("MVM_GUEST_PRIVILEGED_TESTS").as_deref() != Ok("1") {
        return;
    }
    // SAFETY: geteuid has no preconditions and does not change credentials.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged witness needs root"
    );
    let output = crate::guest_bootstrap::guest_helper_command(
        &std::env::current_exe().expect("test executable"),
        TOOL_HELPER_IDENTITY,
    )
    .args(["--exact", PROBE, "--nocapture"])
    .env(STAGE, "helper")
    .output()
    .expect("exec helper identity");
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(VERIFIED),
        "the execed tool probe must actually run, not just match zero tests: {output:?}"
    );
}

#[test]
fn exec_capability_probe() {
    let Ok(stage) = std::env::var(STAGE) else {
        return;
    };
    let status = std::fs::read_to_string("/proc/thread-self/status").expect("status");
    match stage.as_str() {
        "helper" => {
            assert_caps(&status, "00000000000000c0");
            assert_eq!(field(&status, "Uid"), "906\t906\t906\t906");
            assert_eq!(field(&status, "Gid"), "906\t906\t906\t906");
            let entry = ToolEntry {
                tool: "capability-probe".into(),
                executable: "/proc/self/exe".into(),
                aliases: Vec::new(),
                stash: "/proc/self/exe".into(),
                digest: String::new(),
            };
            let run = ApprovedRun {
                entry: &entry,
                argv: vec![
                    "capability-probe".into(),
                    "--exact".into(),
                    PROBE.into(),
                    "--nocapture".into(),
                ],
                cwd: "/".into(),
                env: vec![(STAGE.into(), "tool".into())],
                binding: None,
                helper_minted_binding: false,
            };
            let child = spawn_tool(&run, [-1, 1, 2]).expect("spawn from execed helper");
            // Readiness must certify revocation already, not merely promise
            // that the eventual exec will discard the helper's capabilities.
            let gated = std::fs::read_to_string(format!("/proc/{}/status", child.pid))
                .expect("gated child status");
            assert_caps(&gated, "0000000000000000");
            std::fs::File::from(child.gate)
                .write_all(&[1])
                .expect("release exec gate");
            let mut status = 0;
            // SAFETY: this is our child and status is writable.
            assert_eq!(
                unsafe { libc::waitpid(child.pid, &mut status, 0) },
                child.pid
            );
            assert_eq!(child_code(status), 0, "execed tool probe");
        }
        "tool" => {
            assert_caps(&status, "0000000000000000");
            assert_eq!(field(&status, "Groups"), "");
            assert_eq!(
                field(&status, "Uid"),
                format!("{TOOL_UID}\t{TOOL_UID}\t{TOOL_UID}\t{TOOL_UID}")
            );
            assert_eq!(
                field(&status, "Gid"),
                format!("{TOOL_GID}\t{TOOL_GID}\t{TOOL_GID}\t{TOOL_GID}")
            );
            for uid in [TOOL_HELPER_IDENTITY.uid(), 0] {
                // SAFETY: credential syscall with scalar arguments, isolated
                // in this execed probe; success is a security regression.
                assert_eq!(unsafe { libc::setresuid(uid, uid, uid) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            }
            for gid in [TOOL_HELPER_IDENTITY.gid(), 0] {
                // SAFETY: same isolation as the uid probe above.
                assert_eq!(unsafe { libc::setresgid(gid, gid, gid) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            }
            println!("{VERIFIED}");
        }
        other => panic!("unexpected capability probe stage {other}"),
    }
}
