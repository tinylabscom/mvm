//! `xtask check-single-exec-secs-writer`
//!
//! A workload's wall-clock bound is declared once, as a grant.
//! `TimeoutSpec::exec_secs` is that grant's projection into the plan's older
//! encoding, and nothing else may write it. A second writer is a second
//! declaration of one decision, and the two can disagree — at which point the
//! bound a workload actually runs under is whichever encoding the code path it
//! took happened to read. Same discipline as
//! `check-single-grants-projection`, applied to the other projection.
//!
//! The rule: outside the one permitted writer, no production source may
//! initialise the field. Test code is exempt because a fixture pinning a bound
//! is asserting on the projection's output, not competing with it — and a gate
//! that fired on fixtures would be turned off rather than obeyed.
//!
//! "Test code" is three things, all decided textually: a file under a `tests/`
//! directory, a file named `test_support.rs`, and everything from a file's
//! first `#[cfg(test)]` / `#[cfg(any(test` attribute onward. The last is a
//! heuristic — it assumes test modules come last, which is the convention this
//! workspace follows everywhere. Its failure mode is a false negative in a file
//! that puts production code after its tests, which is caught in review; the
//! alternative (parsing Rust) buys a gate nobody maintains.
//!
//! Known and accepted limit: a write that reaches the field through a variable
//! (`spec.exec_secs = n`) rather than a struct literal is a different shape.
//! Both are matched, but a write through a `&mut TimeoutSpec` handed to a
//! helper is not detectable by a text gate and has to be caught in review.

use anyhow::{Result, bail};
use std::path::Path;

/// The sole file permitted to write `exec_secs` — it holds the call to
/// `exec_secs_from_grants`, which is the projection.
const WRITER_FILE: &str = "crates/mvm-core/src/plan/synthesis.rs";

/// The projection the writer must call. Named here so the gate fails if the
/// permitted writer stops projecting and starts inventing a value.
const PROJECTION_FN: &str = "exec_secs_from_grants";

/// Roots to scan. Root `src/` is the facade and `tests/` holds workspace-level
/// integration tests; both could host a second writer as easily as `crates/`.
const ROOTS: [&str; 3] = ["crates", "src", "tests"];

pub fn run(workspace: &Path) -> Result<()> {
    let writer = workspace.join(WRITER_FILE);
    let body = std::fs::read_to_string(&writer)
        .map_err(|e| anyhow::anyhow!("the exec_secs writer is missing at {WRITER_FILE}: {e}"))?;
    if !body.contains(PROJECTION_FN) {
        bail!(
            "{WRITER_FILE} writes exec_secs without calling {PROJECTION_FN}; \
             the field must be the grant's projection, not a second declaration"
        );
    }

    let mut offenders = Vec::new();
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
            if rel == WRITER_FILE || is_test_path(&rel) {
                return;
            }
            for (line_no, line) in production_lines(body) {
                if writes_exec_secs(line) {
                    offenders.push(format!("{rel}:{line_no}: {}", line.trim()));
                }
            }
        })?;
    }

    if !offenders.is_empty() {
        bail!(
            "a second writer of TimeoutSpec::exec_secs exists in:\n  {}\n\
             The wall-clock bound is declared as a grant; exec_secs is its \
             projection and only {WRITER_FILE} may write it.",
            offenders.join("\n  ")
        );
    }
    Ok(())
}

/// Whether a path is test-only by location or by name.
fn is_test_path(rel: &str) -> bool {
    rel.split('/').any(|seg| seg == "tests")
        || rel.ends_with("/test_support.rs")
        || rel.ends_with("/fuzz_targets")
}

/// The `(1-indexed line number, line)` pairs that precede a file's first test
/// module. Everything from that attribute onward is test code.
fn production_lines(body: &str) -> Vec<(usize, &str)> {
    body.lines()
        .enumerate()
        .take_while(|(_, line)| {
            let t = line.trim_start();
            !(t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(any(test"))
        })
        .map(|(i, line)| (i + 1, line))
        .collect()
}

/// Whether one line writes the field, as a struct-literal initialiser or as an
/// assignment. Comments are excluded so prose about the field is not a match.
///
/// Three things look similar and only two are writes: `exec_secs: <value>` in a
/// struct literal (a write), `t.exec_secs = <value>` (a write, qualification
/// notwithstanding), and `pub exec_secs: u32` in the struct definition (not a
/// write — the type has to declare the field somewhere).
fn writes_exec_secs(line: &str) -> bool {
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    let Some(idx) = code.find("exec_secs") else {
        return false;
    };
    let before = code[..idx].trim_end();
    let rest = code[idx + "exec_secs".len()..].trim_start();

    if let Some(assigned) = rest.strip_prefix('=') {
        return !assigned.starts_with('=');
    }
    let Some(value) = rest.strip_prefix(':') else {
        // A bare mention: a qualified read, a doc reference, an argument.
        return false;
    };
    !is_field_declaration(before, value.trim_start())
}

/// Whether `exec_secs: …` is the struct's own field declaration rather than a
/// literal initialising it. Either marker is enough on its own: a visibility
/// keyword in front, or an integer type where a value would be.
fn is_field_declaration(before: &str, value: &str) -> bool {
    before.ends_with("pub")
        || (before.ends_with(')') && before.contains("pub("))
        || value.starts_with("u8")
        || value.starts_with("u16")
        || value.starts_with("u32")
        || value.starts_with("u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("the real tree carries exactly one exec_secs writer");
    }

    #[test]
    fn missing_writer_file_fails_closed() {
        let tmp = scratch("missing");
        std::fs::create_dir_all(&tmp).unwrap();
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains(WRITER_FILE));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_writer_that_stopped_projecting_is_caught() {
        // The field must carry the grant's value, not one the writer invented.
        let tmp = fixture("not-projected", "exec_secs: 600,", "");
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains(PROJECTION_FN));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_second_struct_literal_writer_is_caught() {
        let tmp = fixture(
            "second-literal",
            "exec_secs: exec_secs_from_grants(g),",
            "pub fn sneaky() -> TimeoutSpec { TimeoutSpec { boot_secs: 1, exec_secs: 600 } }",
        );
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("crates/mvm-core/src/lib.rs"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_second_assignment_writer_is_caught() {
        let tmp = fixture(
            "second-assign",
            "exec_secs: exec_secs_from_grants(g),",
            "pub fn sneaky(t: &mut TimeoutSpec) { t.exec_secs = 600; }",
        );
        // `t.exec_secs = 600` is a qualified assignment; the gate must still
        // read it as a write, because it is one.
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("sneaky"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_field_declaration_itself_is_not_a_writer() {
        // The type has to declare the field somewhere; that is not a second
        // declaration of the bound.
        let tmp = fixture(
            "field-decl",
            "exec_secs: exec_secs_from_grants(g),",
            "pub struct TimeoutSpec {\n    pub boot_secs: u32,\n    pub exec_secs: u32,\n}\n",
        );
        run(&tmp).expect("a struct field declaration is not a writer");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_read_is_not_a_write() {
        let tmp = fixture(
            "read-only",
            "exec_secs: exec_secs_from_grants(g),",
            "pub fn read(p: &Plan) -> u32 { p.resources.timeouts.exec_secs }",
        );
        run(&tmp).expect("reading the field is not a second declaration");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_test_module_fixture_is_not_a_writer() {
        let tmp = fixture(
            "test-module",
            "exec_secs: exec_secs_from_grants(g),",
            "#[cfg(test)]\nmod tests {\n    fn f() { TimeoutSpec { exec_secs: 600 } }\n}\n",
        );
        run(&tmp).expect("a fixture pinning a bound asserts on the projection");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_comment_about_the_field_is_not_a_writer() {
        let tmp = fixture(
            "comment",
            "exec_secs: exec_secs_from_grants(g),",
            "// sets exec_secs: 600 when the grant says so\npub fn f() {}\n",
        );
        run(&tmp).expect("prose is not a declaration");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(format!(
            "xtask-single-exec-secs-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        tmp
    }

    /// A fake workspace: the permitted writer with `writer_line`, plus one
    /// other production file holding `other`.
    fn fixture(label: &str, writer_line: &str, other: &str) -> std::path::PathBuf {
        let tmp = scratch(label);
        let writer_dir = tmp.join("crates/mvm-core/src/plan");
        std::fs::create_dir_all(&writer_dir).unwrap();
        std::fs::write(
            writer_dir.join("synthesis.rs"),
            format!("fn f() {{ TimeoutSpec {{ boot_secs: 1, {writer_line} }} }}\n"),
        )
        .unwrap();

        let other_dir = tmp.join("crates/mvm-core/src");
        std::fs::create_dir_all(&other_dir).unwrap();
        std::fs::write(other_dir.join("lib.rs"), other).unwrap();
        tmp
    }
}
