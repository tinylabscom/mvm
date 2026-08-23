//! `xtask check-single-workload-env`
//!
//! There is one way into a workload and it resolves its environment once.
//!
//! An OCI image declares its `Env`, `WorkingDir`, and `Entrypoint`/`Cmd` in
//! its config, and image materialization copies that declaration into the
//! rootfs. For a long time exactly one binary read it back — the entrypoint
//! runner — and the interactive console assembled its own environment from
//! the guest agent's process vars instead. The two paths were never reconciled
//! because nothing required them to be, and the result was
//! `machine run --image rust:latest -it` landing in a shell whose `PATH` did
//! not contain the toolchain the image exists to provide. The image was
//! mounted, unpacked, and booted correctly; only its declared environment was
//! quietly dropped on one of the two paths.
//!
//! The rule this pins: the materialized config has exactly one reader, and
//! every way of starting a workload process resolves through it. A second
//! reader is not a bug on its own — it is the shape that lets the two paths
//! drift, which is the actual defect and the one that is invisible until
//! somebody opens a shell and finds a tool missing.
//!
//! Test code is exempt: a fixture naming the file is asserting on the
//! resolver's behaviour, not competing with it, and a gate that fired on
//! fixtures would be switched off rather than obeyed.

use anyhow::{Result, bail};
use std::path::Path;

/// The sole module permitted to name and parse the materialized config.
const RESOLVER: &str = "crates/mvm-agentd/src/workload_env.rs";

/// The materialized config's file name. Naming it outside [`RESOLVER`] means
/// reading it outside the resolver.
const CONFIG_FILE: &str = "image-runtime.json";

/// The constructor every consumer must go through.
const BUILDER: &str = "WorkloadEnvironment::builder()";

/// Every way of starting a workload process. Each must resolve through
/// [`BUILDER`]; a new one added without a resolution is what this catches.
const CONSUMERS: [&str; 2] = [
    "crates/mvm-agentd/src/console.rs",
    "crates/mvm-agentd/src/bin/mvm-oci-entrypoint.rs",
];

/// Roots to scan for a second reader.
const ROOTS: [&str; 3] = ["crates", "src", "tests"];

pub fn run(workspace: &Path) -> Result<()> {
    let resolver = workspace.join(RESOLVER);
    let body = std::fs::read_to_string(&resolver)
        .map_err(|e| anyhow::anyhow!("the workload-env resolver is missing at {RESOLVER}: {e}"))?;
    if !body.contains(CONFIG_FILE) {
        bail!(
            "{RESOLVER} no longer names {CONFIG_FILE}; the resolver must be the \
             thing that reads the materialized config, or this gate is pinning nothing"
        );
    }

    for consumer in CONSUMERS {
        let path = workspace.join(consumer);
        let body = std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!("a declared workload-env consumer is missing at {consumer}: {e}")
        })?;
        if !body.contains(BUILDER) {
            bail!(
                "{consumer} starts a workload without resolving through {BUILDER}. \
                 Every path into a workload resolves the image's declared environment \
                 the same way; the one that did not is why `--image rust:latest -it` \
                 opened a shell with no toolchain on PATH."
            );
        }
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
            if rel == RESOLVER || is_test_path(&rel) {
                return;
            }
            for (line_no, line) in production_lines(body) {
                if names_config_file(line) {
                    offenders.push(format!("{rel}:{line_no}: {}", line.trim()));
                }
            }
        })?;
    }

    if !offenders.is_empty() {
        bail!(
            "a second reader of the materialized image config exists in:\n  {}\n\
             Only {RESOLVER} may name {CONFIG_FILE}. Consume it through \
             {BUILDER} instead — two readers is how the console and the \
             entrypoint runner came to disagree about the image's own PATH.",
            offenders.join("\n  ")
        );
    }
    Ok(())
}

/// Whether a path is test-only by location or by name.
fn is_test_path(rel: &str) -> bool {
    rel.split('/').any(|seg| seg == "tests")
        || rel.ends_with("/test_support.rs")
        || rel.split('/').any(|seg| seg == "fuzz_targets")
}

/// The `(1-indexed line number, line)` pairs preceding a file's first test
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

/// Whether a line names the config file in code rather than in prose. The
/// writer reaches it through the resolver's own `CONFIG_REL_PATH` const, so a
/// legitimate site never spells the name out.
fn names_config_file(line: &str) -> bool {
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    code.contains(CONFIG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prose_about_the_config_is_not_a_second_reader() {
        assert!(!names_config_file(
            "    // reads image-runtime.json at boot"
        ));
        assert!(names_config_file(
            "    let p = \"/etc/mvm/image-runtime.json\";"
        ));
    }

    #[test]
    fn test_paths_are_exempt() {
        assert!(is_test_path("crates/mvm-build/tests/inject.rs"));
        assert!(is_test_path("crates/mvm-agentd/fuzz/fuzz_targets/a.rs"));
        assert!(!is_test_path("crates/mvm-agentd/src/console.rs"));
    }

    #[test]
    fn production_lines_stop_at_the_test_module() {
        let src = "fn a() {}\n#[cfg(test)]\nmod tests { fn b() {} }\n";
        let lines = production_lines(src);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], (1, "fn a() {}"));
    }
}
