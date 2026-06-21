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

pub fn run(workspace: &Path) -> Result<()> {
    let crates_dir = workspace.join("crates");
    if !crates_dir.is_dir() {
        bail!("expected workspace crates dir at {}", crates_dir.display());
    }
    let mut findings: Vec<String> = Vec::new();
    visit_rust_files(&crates_dir, &mut |path| -> Result<()> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if HOST_NIX_NEEDLES.iter().any(|n| line.contains(n)) {
                let allowed = i > 0 && lines[i - 1].trim_start().starts_with(ALLOW_MARKER);
                if !allowed {
                    findings.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
        Ok(())
    })?;

    if findings.is_empty() {
        eprintln!(
            "check-no-host-nix: clean (no host-nix Command outside an explicit allow(host-nix) probe)"
        );
        return Ok(());
    }
    eprintln!(
        "check-no-host-nix: {} host-nix Command call site(s) — mvmctl must never shell out to a \
         host nix binary. Route nix through the builder VM (`ShellEnvironment::shell_exec*`, which \
         runs in-guest) or the resident `mvm-builderd` daemon. If this is a genuine debug/legacy \
         probe, annotate with `// allow(host-nix): <reason>`:",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {f}");
    }
    bail!(
        "check-no-host-nix: {} unannotated host-nix invocation(s)",
        findings.len()
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
    fn allow_marker_on_the_line_above_exempts_it() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "probe.rs",
            "fn f() {\n    // allow(host-nix): debug-only host probe\n    std::process::Command::new(\"nix\").status();\n}\n",
        );
        assert!(run(tmp.path()).is_ok());
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
