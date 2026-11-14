//! `xtask check-no-host-nix`
//!
//! Enforce the load-bearing invariant: **`mvmctl` never shells out to a host
//! `nix` binary.** Every Nix evaluation/build goes through the builder VM —
//! the `ShellEnvironment::shell_exec*` path runs `nix` *inside* the guest, and
//! the resident `mvm-builderd` daemon execs `nix` in-guest too. A host
//! `std::process::Command` for `nix` would make `mvmctl` behave differently on
//! a host that happens to have Nix installed: the same `mvmctl` must produce the
//! same artifacts on every host regardless of what nix it has, which is also why
//! source-checkout builds never depend on the host's nix.
//!
//! Flags any literal `Command::new("nix")` / `Command::new("nix-build")` / … in
//! `crates/*/src/**/*.rs`. The builder-VM daemon's nix execs are dynamic
//! (`Command::new(&argv[0])`, argv built by `nix_build_argv`/`flake_check_argv`)
//! and run in-guest, so they are not literal host `nix` Commands and never
//! match.
//!
//! Opt-out: `// allow(host-nix): <reason>` on the line directly above the call
//! (one per call). Reserved for an explicit debug/legacy probe — never a normal
//! build/run path. Reasons land in the lint output so any bypass stays visible.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// Literal host-nix Command constructors. Dynamic `Command::new(&var)` (the
/// in-guest daemon executor) is intentionally not matched.
const HOST_NIX_NEEDLES: &[&str] = &[
    "Command::new(\"nix\")",
    "Command::new(\"nix-build\")",
    "Command::new(\"nix-store\")",
    "Command::new(\"nix-env\")",
    "Command::new(\"nix-shell\")",
    "Command::new(\"nix-instantiate\")",
    "Command::new(\"nix-channel\")",
];
const ALLOW_MARKER: &str = "// allow(host-nix):";

/// Double-keyed exemptions. A call in one of these files survives only when
/// it also carries the inline [`ALLOW_MARKER`]; the marker without an entry
/// here fails the gate. The list only shrinks: entries are validated every
/// run — a deleted file or a file with no remaining marked call is an error,
/// so an exemption can never outlive the call it excuses.
const EXEMPT: &[(&str, &str)] = &[];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    run_with(workspace, EXEMPT)
}

fn run_with(workspace: &Path, exempt: &[(&str, &str)]) -> Result<()> {
    let crates_dir = workspace.join("crates");
    if !crates_dir.is_dir() {
        bail!("expected workspace crates dir at {}", crates_dir.display());
    }
    let mut findings: Vec<String> = Vec::new();
    // Files that carried at least one marker-annotated call this run; every
    // one of them must be enumerated in `exempt`.
    let mut marked: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    visit_rust_files(&crates_dir, &mut |path: &Path| -> Result<()> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if HOST_NIX_NEEDLES.iter().any(|n| line.contains(n)) {
                let allowed = i > 0 && lines[i - 1].trim_start().starts_with(ALLOW_MARKER);
                if allowed {
                    marked.insert(
                        path.strip_prefix(workspace)
                            .unwrap_or(path)
                            .to_string_lossy()
                            .into_owned(),
                    );
                } else {
                    findings.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
        Ok(())
    })?;

    for key in &marked {
        if !exempt.iter().any(|(p, _)| p == key) {
            findings.push(format!(
                "{key}: marked call without an enumerated EXEMPT entry — the marker alone permits \
                 nothing"
            ));
        }
    }
    for (path, reason) in exempt {
        if reason.trim().is_empty() {
            bail!(
                "check-no-host-nix: EXEMPT entry {path} has no reason — exemptions are \
                   enumerated with one"
            );
        }
        let full = workspace.join(path);
        if !full.is_file() {
            bail!(
                "check-no-host-nix: EXEMPT entry {path} names a deleted file — a relief valve for \
                 a file that is gone permits nothing and hides the list's real size; remove the \
                 entry"
            );
        }
        if !marked.contains(*path) {
            bail!(
                "check-no-host-nix: EXEMPT entry {path} has no marked call left — the list only \
                 shrinks; remove the entry"
            );
        }
    }

    if findings.is_empty() {
        eprintln!(
            "check-no-host-nix: clean (no host-nix Command outside a double-keyed exemption)"
        );
        return Ok(());
    }
    eprintln!(
        "check-no-host-nix: {} host-nix Command call site(s) — mvmctl must never shell out to a \
         host nix binary. Route nix through the builder VM (`ShellEnvironment::shell_exec*`, which \
         runs in-guest) or the resident `mvm-builderd` daemon. An exemption is double-keyed: the \
         `// allow(host-nix): <reason>` marker plus an entry in EXEMPT naming the file and a \
         reason:",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {f}");
    }
    bail!(
        "check-no-host-nix: {} unexempted host-nix invocation(s): {}",
        findings.len(),
        findings.join("; ")
    );
}

fn visit_rust_files(dir: &Path, f: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            visit_rust_files(&path, f)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, name: &str, body: &str) {
        let dir = root.join("crates/x/src");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn unannotated_host_nix_command_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "bad.rs",
            "fn f() { std::process::Command::new(\"nix\").status(); }\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn a_marker_without_an_enumerated_exemption_is_rejected() {
        // Double-key (WS7): the inline marker alone permits nothing — the
        // file must also be enumerated in EXEMPT.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "probe.rs",
            "fn f() {\n    // allow(host-nix): debug-only host probe\n    std::process::Command::new(\"nix\").status();\n}\n",
        );
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(
            err.contains("without an enumerated EXEMPT entry"),
            "got: {err}"
        );
    }

    #[test]
    fn a_marker_plus_an_enumerated_exemption_passes() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "probe.rs",
            "fn f() {\n    // allow(host-nix): debug-only host probe\n    std::process::Command::new(\"nix\").status();\n}\n",
        );
        let exempt = [("crates/x/src/probe.rs", "debug probe, never a build path")];
        assert!(run_with(tmp.path(), &exempt).is_ok());
    }

    #[test]
    fn an_exemption_naming_a_deleted_file_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "ok.rs", "fn f() {}\n");
        let exempt = [("crates/x/src/gone.rs", "call removed with the file")];
        let err = run_with(tmp.path(), &exempt).unwrap_err().to_string();
        assert!(err.contains("names a deleted file"), "got: {err}");
    }

    #[test]
    fn an_exemption_for_a_file_without_a_marked_call_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "ok.rs", "fn f() {}\n");
        let exempt = [("crates/x/src/ok.rs", "nothing marked here anymore")];
        let err = run_with(tmp.path(), &exempt).unwrap_err().to_string();
        assert!(err.contains("no marked call left"), "got: {err}");
    }

    #[test]
    fn in_vm_shell_exec_and_dynamic_argv_do_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        // The normal build path (shell_exec) + the daemon's dynamic exec are
        // not literal host-nix Commands.
        write(
            tmp.path(),
            "ok.rs",
            "fn f() { env.shell_exec(\"nix build .#x\"); let _ = std::process::Command::new(&argv[0]); }\n",
        );
        assert!(run(tmp.path()).is_ok());
    }
}
