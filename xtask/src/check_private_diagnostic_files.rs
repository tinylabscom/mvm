//! `xtask check-private-diagnostic-files`
//!
//! Every file the VMM and supervisor layers write — console logs, VMM and
//! helper stderr, lifecycle breadcrumbs, debug traces, guest RAM images — is a
//! sensitive diagnostic under the diagnostic-data policy
//! (`specs/contracts/diagnostic-data-policy.md`) and must be created owner-only,
//! without writing through a link left at its path. The shared helpers do
//! that: `open_console_capture` / `open_private_truncated` for a file that
//! starts afresh each run, `open_private_append` for one that accumulates, and
//! `agent_debug` for the opt-in trace.
//!
//! A bare `File::create`, or an `OpenOptions` chain that creates without
//! naming a mode, creates at the process umask (typically 0644) and follows a
//! symbolic link. Each of those was found in these modules and replaced; this
//! gate keeps a new one from arriving unnoticed.
//!
//! **Deliberately scoped.** Like `check-private-mvm-dirs`, it watches only the
//! modules that write diagnostics, not the whole tree, where most creation is
//! build scratch or an operator-named output. Lock files carry no payload and
//! are listed below with their reason.
//!
//! Comments and string literals are blanked, and `#[cfg(test)]` items and
//! `*_tests.rs` files are skipped: fixtures create files however they like.

use anyhow::{Result, bail};
use std::path::Path;

/// Modules (directories or single files) that create diagnostic files.
const WATCHED: &[&str] = &[
    "crates/mvm-vmm/src/vmm",
    "crates/mvm-vmm/src/host",
    "crates/mvm-backends/src/driver",
    "crates/mvm-backends/src/fc",
    "crates/mvm-hostd/src/bin",
    "crates/mvm-runtime/src/workload_runner",
    "crates/mvm-runtime/src/backends",
    "crates/mvm-build/src/libkrun_builder.rs",
];

/// Creating opens that carry no diagnostic payload, matched by file and by a
/// needle on the flagged line or the chain that follows it.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs",
        "temp_dir()",
        "the codesign serialization lock: an empty file held for flock",
    ),
    (
        "crates/mvm-vmm/src/host/host_agent_spawn.rs",
        "SPAWN_LOCK",
        "the per-tenant spawn lock: an empty file held for flock",
    ),
    (
        "crates/mvm-backends/src/driver/qemu_process.rs",
        "lock_path",
        "the CID allocation lock: an empty file held for flock",
    ),
    (
        "crates/mvm-backends/src/fc/fork_namespace.rs",
        "parent_path",
        "an empty mount-point placeholder a bind mount covers",
    ),
    (
        "crates/mvm-backends/src/fc/fork_devices.rs",
        "open(recorded)",
        "an empty drive placeholder the retarget replaces before the child runs",
    ),
];

/// How far past `OpenOptions::new()` a chain is read for `.create` and a mode.
const CHAIN_WINDOW: usize = 400;

/// What a scan of one file found.
#[derive(Debug, Default, PartialEq, Eq)]
struct Scan {
    /// `(line, call)` for each unmoded creating open.
    unmoded: Vec<(usize, &'static str)>,
    /// Calls to a private-creation helper.
    private: usize,
}

const PRIVATE_HELPERS: &[&str] = &[
    "open_console_capture(",
    "open_private_truncated(",
    "open_private_append(",
    "agent_debug::",
    ".mode(",
    "open_with_mode(",
];

fn scan(source: &str) -> Scan {
    let blanked = crate::rust_source::blank_comments_and_strings(source);
    let body = crate::rust_source::strip_cfg_test_items(&blanked);
    let mut out = Scan::default();
    for helper in PRIVATE_HELPERS {
        out.private += body.matches(helper).count();
    }
    for (offset, _) in body.match_indices("File::create(") {
        out.unmoded.push((line_of(&body, offset), "File::create"));
    }
    for (offset, _) in body.match_indices("OpenOptions::new()") {
        let chain = chain_after(&body, offset);
        let creates = chain.contains(".create(true)") || chain.contains(".create_new(true)");
        let moded = chain.contains(".mode(") || chain.contains("open_with_mode(");
        if creates && !moded {
            out.unmoded.push((line_of(&body, offset), "OpenOptions"));
        }
    }
    out
}

/// The builder chain starting at `offset`, up to its terminating `.open(` (or
/// through an `open_with_mode(`, which names the mode), bounded so an unterminated chain cannot swallow the
/// rest of the file.
fn chain_after(body: &str, offset: usize) -> &str {
    let window = &body[offset..body.len().min(offset + CHAIN_WINDOW)];
    let end = [(".open(", 0), ("open_with_mode(", "open_with_mode(".len())]
        .iter()
        .filter_map(|(call, keep)| window.find(call).map(|at| at + keep))
        .min()
        .unwrap_or(window.len());
    &window[..end]
}

fn line_of(body: &str, offset: usize) -> usize {
    body[..offset].matches('\n').count() + 1
}

fn allowed(relative: &str, raw: &str, line: usize) -> bool {
    let context: String = raw
        .lines()
        .skip(line - 1)
        .take(6)
        .collect::<Vec<_>>()
        .join("\n");
    ALLOWED
        .iter()
        .any(|(file, needle, _)| relative == *file && context.contains(needle))
}

pub fn run(workspace: &Path) -> Result<()> {
    let mut findings = Vec::new();
    let mut private = 0usize;
    for dir in WATCHED {
        let root = workspace.join(dir);
        let files = if root.is_file() {
            vec![root]
        } else if root.is_dir() {
            crate::check_private_mvm_dirs::rust_files(&root)?
        } else {
            bail!("{dir} does not exist; check-private-diagnostic-files is scanning a stale path");
        };
        for file in files {
            let relative = file
                .strip_prefix(workspace)
                .unwrap_or(&file)
                .display()
                .to_string();
            if relative.ends_with("_tests.rs") || relative.contains("/tests/") {
                continue;
            }
            let raw = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            let found = scan(&raw);
            private += found.private;
            for (line, call) in found.unmoded {
                if !allowed(&relative, &raw, line) {
                    findings.push(format!(
                        "{relative}:{line}: `{call}` creates a file at the process umask and \
                         follows a link at its path. Diagnostics written here are sensitive: use \
                         `open_console_capture` / `mvm_core::util::atomic_io::open_private_truncated` \
                         for a per-run file, `open_private_append` for one that accumulates, or \
                         `mvm_vmm::agent_debug` for the opt-in trace. A lock file with no payload \
                         belongs in ALLOWED with its reason."
                    ));
                }
            }
        }
    }
    if !findings.is_empty() {
        bail!(
            "diagnostic files created without an owner-only mode:\n\n{}\n",
            findings.join("\n\n")
        );
    }
    if private == 0 {
        bail!(
            "expected private-creation helpers across {WATCHED:?}; found none. Private \
             diagnostic creation having vanished entirely is a question, not a pass."
        );
    }
    println!(
        "check-private-diagnostic-files: {private} private creation site(s), no unmoded \
         creation in the diagnostic writers"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        run(&workspace).expect("the diagnostic writers must create private files");
    }

    #[test]
    fn flags_a_bare_create_and_an_unmoded_creating_chain() {
        let found = scan(
            "fn a(p: &Path) { let _ = std::fs::File::create(p); }\n\
             fn b(p: &Path) {\n    let _ = std::fs::OpenOptions::new()\n        .create(true)\n        .append(true)\n        .open(p);\n}\n",
        );
        assert_eq!(found.unmoded, vec![(1, "File::create"), (3, "OpenOptions")]);
    }

    #[test]
    fn a_moded_chain_a_read_only_open_and_helpers_pass() {
        let found = scan(
            "fn a(p: &Path) {\n    let _ = OpenOptions::new().create(true).write(true).mode(0o600).open(p);\n    \
             let _ = OpenOptions::new().read(true).open(p);\n    \
             let _ = open_private_append(p);\n}\n",
        );
        assert!(found.unmoded.is_empty(), "{found:?}");
        assert_eq!(found.private, 2);
    }

    #[test]
    fn prose_strings_and_test_items_do_not_trip_the_gate() {
        let found = scan(
            "// File::create is what this replaced\n\
             const DOC: &str = \"OpenOptions::new().create(true).open(p)\";\n\
             #[cfg(test)]\nmod tests {\n    fn f(p: &Path) { let _ = std::fs::File::create(p); }\n}\n",
        );
        assert!(found.unmoded.is_empty(), "{found:?}");
    }

    #[test]
    fn a_chain_is_judged_by_its_own_open_not_the_next_one() {
        let found = scan(
            "fn a(p: &Path) {\n    let _ = OpenOptions::new().create(true).append(true).open(p);\n    \
             let _ = OpenOptions::new().write(true).mode(0o600).open(p);\n}\n",
        );
        assert_eq!(found.unmoded, vec![(2, "OpenOptions")]);
    }

    #[test]
    fn allowances_match_only_their_own_file_and_needle() {
        let raw =
            "let lock = OpenOptions::new()\n    .create(true)\n    .open(dir.join(SPAWN_LOCK));\n";
        assert!(allowed(
            "crates/mvm-vmm/src/host/host_agent_spawn.rs",
            raw,
            1
        ));
        assert!(!allowed("crates/mvm-vmm/src/host/other.rs", raw, 1));
        assert!(!allowed(
            "crates/mvm-vmm/src/host/host_agent_spawn.rs",
            "let f = File::create(path);\n",
            1
        ));
    }
}
