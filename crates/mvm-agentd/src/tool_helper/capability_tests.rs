//! Opt-in Linux witnesses spanning both exec boundaries without changing the
//! test runner's credentials. Run as root with MVM_GUEST_PRIVILEGED_TESTS=1.

use super::*;
use crate::guest_mount::{TOOL_GID, TOOL_HELPER_IDENTITY, TOOL_UID};
use std::io::Write;

const STAGE: &str = "MVM_TOOL_CAPABILITY_TEST_STAGE";
const STASH: &str = "MVM_TOOL_CAPABILITY_TEST_STASH";
const PROBE: &str = "tool_helper::capability_tests::exec_capability_probe";
const VERIFIED: &str = "execed tool has no capabilities and cannot regain privilege";

fn assert_path_denied(path: &str) {
    assert_eq!(
        std::fs::File::open(path).unwrap_err().raw_os_error(),
        Some(libc::EACCES),
        "original stash pathname must not be readable"
    );
    assert_eq!(
        std::fs::metadata(path).unwrap_err().raw_os_error(),
        Some(libc::EACCES),
        "original stash pathname must not be traversable"
    );
}

#[test]
fn installed_stash_executes_only_through_helper_descriptor() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;

    if std::env::var("MVM_GUEST_PRIVILEGED_TESTS").as_deref() != Ok("1") {
        return;
    }
    // SAFETY: geteuid only reads this process's identity.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged witness needs root"
    );
    let executable = std::env::current_exe().expect("test executable");
    let dir = tempfile::tempdir().expect("private stash directory");
    // Match the installed stash directory without touching the guest's real
    // tool directory. It alone must prevent pathname access, not a 0700 parent.
    std::os::unix::fs::chown(dir.path(), Some(0), Some(TOOL_HELPER_IDENTITY.gid()))
        .expect("stash directory ownership");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750))
        .expect("stash directory mode");
    let stash = dir.path().join("probe");
    let stash = stash.to_str().expect("UTF-8 temporary path");
    crate::tool_install::write_stash(stash, &std::fs::read(&executable).unwrap())
        .expect("install actual executable bytes");
    let metadata = std::fs::metadata(stash).unwrap();
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), TOOL_HELPER_IDENTITY.gid());
    assert_eq!(metadata.mode() & 0o7777, 0o551);

    let mut workload = std::process::Command::new(&executable);
    workload
        .args(["--exact", PROBE, "--nocapture"])
        .env(STAGE, "workload-path")
        .env(STASH, stash);
    // SAFETY: the isolated child only invokes credential syscalls and reads
    // errno, without allocating or taking locks after fork.
    unsafe {
        workload.pre_exec(|| {
            let uid = crate::guest_mount::WORKLOAD_UID;
            let gid = crate::guest_mount::WORKLOAD_GID;
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = workload.output().expect("workload pathname probe");
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("workload pathname denied"));

    for (stage, marker) in [
        ("installed-helper", VERIFIED),
        (
            "nonexecutable-helper",
            "nonexecutable stash rejected with exit 127",
        ),
    ] {
        if stage == "nonexecutable-helper" {
            // Reproduce the old installation mode, not an unrelated bad path.
            std::fs::set_permissions(stash, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let output =
            crate::guest_bootstrap::guest_helper_command(&executable, TOOL_HELPER_IDENTITY)
                .args(["--exact", PROBE, "--nocapture"])
                .env(STAGE, stage)
                .env(STASH, stash)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("exec helper over installed stash");
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(marker),
            "probe must actually execute: {output:?}"
        );
    }
}

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
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
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
        "helper" | "installed-helper" | "nonexecutable-helper" => {
            assert_caps(&status, "00000000000000c0");
            assert_eq!(field(&status, "Uid"), "906\t906\t906\t906");
            assert_eq!(field(&status, "Gid"), "906\t906\t906\t906");
            let stash = std::env::var(STASH).ok();
            let entry = ToolEntry {
                tool: "capability-probe".into(),
                executable: "/proc/self/exe".into(),
                aliases: Vec::new(),
                stash: stash.clone().unwrap_or_else(|| "/proc/self/exe".into()),
                digest: String::new(),
            };
            let mut env = vec![(STAGE.into(), "tool".into())];
            if let Some(stash) = stash {
                env.push((STASH.into(), stash));
            }
            let run = ApprovedRun {
                entry: &entry,
                argv: vec![
                    "capability-probe".into(),
                    "--exact".into(),
                    PROBE.into(),
                    "--nocapture".into(),
                ],
                cwd: "/".into(),
                env,
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
            if stage == "nonexecutable-helper" {
                assert_eq!(child_code(status), 127, "nonexecutable installed stash");
                println!("nonexecutable stash rejected with exit 127");
            } else {
                assert_eq!(child_code(status), 0, "execed tool probe");
            }
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
            if let Ok(stash) = std::env::var(STASH) {
                assert_path_denied(&stash);
                assert_eq!(
                    std::fs::File::open("/proc/self/exe")
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EACCES),
                    "execute-only tool cannot read/copy its executable through procfs"
                );
            }
            println!("{VERIFIED}");
        }
        "workload-path" => {
            assert_path_denied(&std::env::var(STASH).expect("installed stash path"));
            println!("workload pathname denied");
        }
        other => panic!("unexpected capability probe stage {other}"),
    }
}
