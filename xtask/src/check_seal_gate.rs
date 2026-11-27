//! `xtask check-seal-gate`
//!
//! Every post-admission change to a running unit passes one host check,
//! `mvm_hostd::seal_gate::authorize`. This gate keeps it that way by text:
//!
//! - each mutation primitive (the calls that pause, resume, capture, rewrite
//!   an expiry or idle timeout, set a memory target, deliver a volume, drive
//!   sleep or wake, or deliver a grant to a restored guest) may appear in
//!   production code only in the files listed for it;
//! - the files that gate a live mutation must still call the gate;
//! - the files that stop, quarantine or kill a unit must never call it, so a
//!   sealed unit is never harder to stop.
//!
//! A primitive with no gated caller today (balloon, volume delivery, sleep and
//! wake) is allowed only in the files that define or forward it, so the first
//! new caller fails here and is pointed at the gate.
//!
//! Test code is exempt, decided as `check-single-exec-secs-writer` decides it:
//! a path under `tests/`, a `test_support.rs` or `*_tests.rs` file, and
//! everything from a file's first `#[cfg(test)]` onward. Lines defining a
//! function (`fn name(`) and comment text are not calls.

use anyhow::{Result, bail};
use std::path::Path;

/// A mutation primitive and the only production files it may appear in. An
/// entry ending in `/` allows a whole directory.
struct Primitive {
    pattern: &'static str,
    allowed: &'static [&'static str],
}

const AGENTD: &str = "crates/mvm-agentd/";
const LOCAL: &str = "crates/mvm-client/src/local.rs";
const SESSION: &str = "crates/mvm-client/src/entrypoint/session.rs";
const CLI_CHECKPOINT: &str = "crates/mvm-cli/src/commands/vm/checkpoint.rs";
const PROMPT_STEP: &str = "crates/mvm-client/src/checkpoint/prompt_step.rs";
const SNAPSHOT: &str = "crates/mvm-runtime/src/vm/instance_snapshot.rs";
const BALLOON_LOOP: &str = "crates/mvm-hostd/src/supervisor/lifecycle/balloon_runtime.rs";

const PRIMITIVES: &[Primitive] = &[
    // Pause and resume of a machine.
    Primitive {
        pattern: "pause_and_seal(",
        allowed: &[LOCAL, SNAPSHOT],
    },
    Primitive {
        pattern: "set_registry_paused(",
        allowed: &[LOCAL],
    },
    Primitive {
        pattern: "verify_and_resume(",
        allowed: &[LOCAL, SNAPSHOT, "crates/mvm-client/src/local/resume.rs"],
    },
    // Full-VM capture of a running unit. The runtime forwards it, and the
    // standby parent is captured before it has a plan or an identity.
    Primitive {
        pattern: ".vm_full_control(",
        allowed: &[
            CLI_CHECKPOINT,
            PROMPT_STEP,
            "crates/mvm-runtime/src/backend.rs",
            "crates/mvm-runtime/src/workload_runner/runner.rs",
            "crates/mvm-runtime/src/workload_runner/runner/standby.rs",
        ],
    },
    // Expiry: set at launch by a detached run, changed afterwards by set_ttl.
    Primitive {
        pattern: "set_machine_expiry(",
        allowed: &[LOCAL, "crates/mvm-client/src/launch/detached.rs"],
    },
    // Idle timeout.
    Primitive {
        pattern: "GuestRequest::UpdateIdleTimeout",
        allowed: &[SESSION, AGENTD],
    },
    // Memory target: the forwarding dispatch, and the reclaim loop, which
    // gates each target.
    Primitive {
        pattern: ".balloon_set_target(",
        allowed: &["crates/mvm-runtime/src/backend.rs", BALLOON_LOOP],
    },
    // Volume delivery to a running guest: no caller today.
    Primitive {
        pattern: "mount_volume_on(",
        allowed: &[AGENTD],
    },
    Primitive {
        pattern: "GuestRequest::MountVolume",
        allowed: &[AGENTD],
    },
    Primitive {
        pattern: "GuestRequest::UnmountVolume",
        allowed: &[AGENTD],
    },
    // Sleep and wake. The two stop-side filesystem flushes use the sleep
    // request and are not sleeps.
    Primitive {
        pattern: "signal_wake(",
        allowed: &[AGENTD],
    },
    Primitive {
        pattern: "GuestRequest::Wake",
        allowed: &[AGENTD],
    },
    Primitive {
        pattern: "request_sleep_prep",
        allowed: &[AGENTD, "crates/mvm-cli/src/exec/transient.rs"],
    },
    Primitive {
        pattern: "GuestRequest::SleepPrep",
        allowed: &[AGENTD, "crates/mvm-vmm/src/driver/fc/stop.rs"],
    },
    // The one channel that can hand a running guest a new grant: a resume
    // (which carries none), a fork child and a warm claim, each admitted.
    Primitive {
        pattern: "VsockPostRestoreSignal",
        allowed: &[
            LOCAL,
            SNAPSHOT,
            "crates/mvm-vmm/src/post_restore.rs",
            "crates/mvm-vmm/src/fc/snapshot.rs",
            "crates/mvm-cli/src/commands/vm/checkpoint/fork_vm_full.rs",
        ],
    },
];

/// Files that gate a live mutation and must keep calling the gate.
const MUST_GATE: &[&str] = &[LOCAL, SESSION, CLI_CHECKPOINT, PROMPT_STEP, BALLOON_LOOP];

/// Files that stop, quarantine or kill a unit and must never call the gate.
const MUST_NOT_GATE: &[&str] = &[
    "crates/mvm-hostd/src/containment.rs",
    "crates/mvm-client/src/containment.rs",
    "crates/mvm-hostd/src/supervisor/lifecycle/wall_clock.rs",
    "crates/mvm-hostd/src/supervisor/lifecycle/session_expiry.rs",
    "crates/mvm-vmm/src/driver/fc/stop.rs",
];

const GATE_CALL: &str = "seal_gate::authorize";
/// The client's adapters over the gate: `LocalBackend`'s, which maps its
/// error, and the full-VM capture's, which the CLI reaches through the client.
const GATE_ADAPTERS: [&str; 2] = ["authorize_change(", "authorize_capture("];

const ROOTS: [&str; 3] = ["crates", "src", "tests"];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let mut problems = Vec::new();
    for root in ROOTS {
        let dir = workspace.join(root);
        if !dir.is_dir() {
            continue;
        }
        crate::fs_walk::for_each_file(&dir, Some("rs"), &mut |path, body| {
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_path(&rel) {
                return;
            }
            check_file(&rel, body, &mut problems);
        })?;
    }
    for file in MUST_GATE {
        match std::fs::read_to_string(workspace.join(file)) {
            Ok(body) if calls_gate(&body) => {}
            Ok(_) => problems.push(format!("{file}: no longer calls {GATE_CALL}")),
            Err(e) => problems.push(format!("{file}: a gated file is missing: {e}")),
        }
    }
    if !problems.is_empty() {
        bail!(
            "a change to a running unit can bypass the seal gate:\n  {}\n\
             Route the mutation through mvm_hostd::seal_gate::authorize with its \
             Mutation, and keep stop, quarantine and kill paths out of it.",
            problems.join("\n  ")
        );
    }
    Ok(())
}

fn check_file(rel: &str, body: &str, problems: &mut Vec<String>) {
    let lines = production_lines(body);
    for primitive in PRIMITIVES {
        if allows(primitive.allowed, rel) {
            continue;
        }
        for (line_no, line) in &lines {
            if uses(line, primitive.pattern) {
                problems.push(format!(
                    "{rel}:{line_no}: `{}` outside its gated files: {}",
                    primitive.pattern,
                    line.trim()
                ));
            }
        }
    }
    if MUST_NOT_GATE.contains(&rel) && calls_gate(body) {
        problems.push(format!("{rel}: a stop path calls the seal gate"));
    }
}

fn allows(allowed: &[&str], rel: &str) -> bool {
    allowed.iter().any(|entry| {
        if entry.ends_with('/') {
            rel.starts_with(entry)
        } else {
            rel == *entry
        }
    })
}

fn calls_gate(body: &str) -> bool {
    production_lines(body).iter().any(|(_, line)| {
        let code = code_of(line);
        code.contains(GATE_CALL) || GATE_ADAPTERS.iter().any(|a| code.contains(a))
    })
}

/// Whether `line` uses `pattern` in code, not in a comment and not as the
/// function's own definition.
fn uses(line: &str, pattern: &str) -> bool {
    let code = code_of(line);
    let Some(idx) = code.find(pattern) else {
        return false;
    };
    !code[..idx].trim_end().ends_with("fn")
}

fn code_of(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

fn is_test_path(rel: &str) -> bool {
    rel.split('/')
        .any(|seg| seg == "tests" || seg == "benches" || seg == "fuzz")
        || rel.ends_with("/test_support.rs")
        || rel.ends_with("_tests.rs")
        || rel.ends_with("/tests.rs")
        || rel.contains("/test_support/")
}

/// The `(1-indexed line number, line)` pairs before a file's inline test
/// module: a `#[cfg(test)]` attribute followed by `mod … {`. A `#[cfg(test)]`
/// on an import or an out-of-line module declaration does not end the
/// production code.
fn production_lines(body: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = body.lines().collect();
    let end = (0..lines.len())
        .find(|&i| {
            let t = lines[i].trim_start();
            (t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(any(test"))
                && lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty() && !l.starts_with("#["))
                    .is_some_and(|l| l.contains("mod ") && l.ends_with('{'))
        })
        .unwrap_or(lines.len());
    lines[..end]
        .iter()
        .enumerate()
        .map(|(i, line)| (i + 1, *line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("every mutation of a running unit passes the seal gate");
    }

    /// A fake workspace whose gated files all call the gate, plus `extra`
    /// files written verbatim.
    fn fixture(label: &str, extra: &[(&str, &str)]) -> std::path::PathBuf {
        let tmp =
            std::env::temp_dir().join(format!("xtask-seal-gate-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        for file in MUST_GATE {
            write(
                &tmp,
                file,
                "fn f() { mvm_hostd::seal_gate::authorize(n, m)?; }\n",
            );
        }
        for (file, body) in extra {
            write(&tmp, file, body);
        }
        tmp
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn a_bypassing_caller_fails() {
        let tmp = fixture(
            "bypass",
            &[(
                "crates/mvm-cli/src/commands/sneaky.rs",
                "fn sneaky() { pause_and_seal(name, io, key)?; }\n",
            )],
        );
        let err = run(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("crates/mvm-cli/src/commands/sneaky.rs:1"),
            "{err}"
        );
        assert!(err.contains("pause_and_seal("), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_new_caller_of_a_dormant_primitive_fails() {
        let tmp = fixture(
            "dormant",
            &[(
                "crates/mvm-client/src/balloon.rs",
                "fn grow(b: &AnyBackend) { b.balloon_set_target(&id, 64).unwrap(); }\n",
            )],
        );
        let err = run(&tmp).unwrap_err().to_string();
        assert!(err.contains(".balloon_set_target("), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_gated_file_that_drops_the_gate_fails() {
        let tmp = fixture(
            "dropped",
            &[(LOCAL, "fn pause() { pause_and_seal(n, io, k)?; }\n")],
        );
        let err = run(&tmp).unwrap_err().to_string();
        assert!(err.contains(&format!("{LOCAL}: no longer calls")), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_stop_path_that_calls_the_gate_fails() {
        let tmp = fixture(
            "stop",
            &[(
                "crates/mvm-hostd/src/containment.rs",
                "fn q() { crate::seal_gate::authorize(n, m)?; }\n",
            )],
        );
        let err = run(&tmp).unwrap_err().to_string();
        assert!(err.contains("a stop path calls the seal gate"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn definitions_comments_and_tests_are_not_calls() {
        let tmp = fixture(
            "exempt",
            &[
                (
                    "crates/mvm-runtime/src/other.rs",
                    "pub fn mount_volume_on(s: &mut S) {}\n\
                     // calls pause_and_seal( later\n\
                     #[cfg(test)]\nmod tests {\n    fn t() { pause_and_seal(a, b, c); }\n}\n",
                ),
                (
                    "crates/mvm-client/src/x_tests.rs",
                    "fn t() { set_registry_paused(n, true); }\n",
                ),
            ],
        );
        run(&tmp).expect("no production call outside the gated files");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
