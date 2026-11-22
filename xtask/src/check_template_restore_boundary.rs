//! Reject raw template snapshot restore assembly outside an approved capability.
//!
//! Template acceleration is cold-only. CLI and client code may classify that
//! source, but may not derive snapshot directories, allocate Firecracker slots,
//! construct raw `FlakeRunConfig` values, or call a runtime template restore
//! entry point. Same-identity vm_full restore and sealed instance resume are
//! separate authenticated sources and remain required seams.

use anyhow::{Context, Result, bail};
use std::path::Path;

use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

const CLIENT_ROOTS: [&str; 2] = ["crates/mvm-cli/src", "crates/mvm-client/src"];
const CRATES_ROOT: &str = "crates";
const SAME_IDENTITY_VM_FULL: &str = "crates/mvm-cli/src/commands/vm/checkpoint.rs";
const SEALED_RESUME: &str = "crates/mvm-runtime/src/vm/instance_snapshot.rs";
const DIRECT_RESTORE: &str = "restore_from_template_snapshot";
const RAW_CLIENT_IDENTIFIERS: [&str; 4] = [
    "FlakeRunConfig",
    "template_snapshot_dir",
    "slot_snapshot_dir",
    "allocate_slot",
];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let mut violations = Vec::new();
    crate::fs_walk::for_each_file(
        &workspace.join(CRATES_ROOT),
        Some("rs"),
        &mut |path, source| {
            let rel = relative(workspace, path);
            let production = production_code(source);
            collect_identifier(&rel, &production, DIRECT_RESTORE, &mut violations);
            if CLIENT_ROOTS.iter().any(|root| rel.starts_with(root)) {
                for identifier in RAW_CLIENT_IDENTIFIERS {
                    collect_identifier(&rel, &production, identifier, &mut violations);
                }
            }
        },
    )?;
    if !violations.is_empty() {
        bail!(
            "raw template snapshot restore assembly is forbidden:\n  {}\n\
             Template acceleration remains cold-only until an authenticated \
             capability owns restore assembly.",
            violations.join("\n  ")
        );
    }

    require_distinct_restore_seams(workspace)?;
    Ok(())
}

fn require_distinct_restore_seams(workspace: &Path) -> Result<()> {
    let vm_full = production_code(&read(workspace, SAME_IDENTITY_VM_FULL)?);
    for identifier in ["restore_checkpoint", "RestoreParams"] {
        if !has_identifier(&vm_full, identifier) {
            bail!("{SAME_IDENTITY_VM_FULL} lost the distinct vm_full restore seam `{identifier}`");
        }
    }
    let sealed = production_code(&read(workspace, SEALED_RESUME)?);
    for identifier in [
        "verify_and_resume",
        "verify_and_resume_from_dir",
        "guarded_load_resume",
    ] {
        if !has_identifier(&sealed, identifier) {
            bail!("{SEALED_RESUME} lost the distinct sealed-resume seam `{identifier}`");
        }
    }
    Ok(())
}

fn read(workspace: &Path, rel: &str) -> Result<String> {
    std::fs::read_to_string(workspace.join(rel)).with_context(|| format!("read {rel}"))
}

fn production_code(source: &str) -> String {
    strip_cfg_test_items(&blank_comments_and_strings(source))
}

fn relative(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn collect_identifier(rel: &str, source: &str, identifier: &str, violations: &mut Vec<String>) {
    for (index, line) in source.lines().enumerate() {
        if line
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .any(|token| token == identifier)
        {
            violations.push(format!("{rel}:{}: `{identifier}`", index + 1));
        }
    }
}

fn has_identifier(source: &str, identifier: &str) -> bool {
    source
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|token| token == identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_tree_has_no_raw_template_restore_caller() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("template acceleration stays behind the cold-only boundary");
    }

    #[test]
    fn cli_raw_config_and_direct_restore_calls_are_rejected() {
        let tree = fixture();
        let cli = tree.join("crates/mvm-cli/src/lib.rs");
        std::fs::create_dir_all(cli.parent().expect("CLI parent")).expect("CLI directory");
        std::fs::write(
            &cli,
            "fn bypass() { let _ = FlakeRunConfig\n { name: String::new() }; \
             let restore = restore_from_template_snapshot /* split */ ; restore(); }\n",
        )
        .expect("raw CLI fixture");

        let error = run(&tree).expect_err("raw template restore assembly must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("FlakeRunConfig"), "{rendered}");
        assert!(
            rendered.contains("restore_from_template_snapshot"),
            "{rendered}"
        );
        std::fs::remove_dir_all(tree).expect("remove fixture");
    }

    #[test]
    fn suffix_identifiers_are_not_raw_restore_bypasses() {
        let tree = fixture();
        let cli = tree.join("crates/mvm-cli/src/lib.rs");
        std::fs::create_dir_all(cli.parent().expect("CLI parent")).expect("CLI directory");
        std::fs::write(
            &cli,
            "fn reallocate_slot() {} fn check_restore_from_template_snapshot() {}\n",
        )
        .expect("suffix fixture");

        run(&tree).expect("identifier suffixes are unrelated APIs");
        std::fs::remove_dir_all(tree).expect("remove fixture");
    }

    #[test]
    fn comments_strings_and_test_only_code_do_not_count() {
        let tree = fixture();
        let cli = tree.join("crates/mvm-cli/src/lib.rs");
        std::fs::create_dir_all(cli.parent().expect("CLI parent")).expect("CLI directory");
        std::fs::write(
            &cli,
            "// restore_from_template_snapshot FlakeRunConfig\n\
             const NOTE: &str = \"allocate_slot template_snapshot_dir\";\n\
             #[cfg(test)] mod tests { fn fixture() { restore_from_template_snapshot(); } }\n",
        )
        .expect("non-production fixture");

        run(&tree).expect("non-production text cannot create a restore bypass");
        std::fs::remove_dir_all(tree).expect("remove fixture");
    }

    #[test]
    fn same_identity_vm_full_and_sealed_resume_are_separately_classified() {
        let tree = fixture();
        run(&tree).expect("authenticated same-identity sources are not template acceleration");
        std::fs::remove_dir_all(tree).expect("remove fixture");
    }

    fn fixture() -> std::path::PathBuf {
        let tree = std::env::temp_dir().join(format!(
            "mvm-template-restore-boundary-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tree);
        let vm_full = tree.join(SAME_IDENTITY_VM_FULL);
        std::fs::create_dir_all(vm_full.parent().expect("vm_full parent"))
            .expect("vm_full directory");
        std::fs::write(
            vm_full,
            "fn restore(params: RestoreParams) { restore_checkpoint(params); }\n",
        )
        .expect("vm_full fixture");
        let sealed = tree.join(SEALED_RESUME);
        std::fs::create_dir_all(sealed.parent().expect("sealed parent")).expect("sealed directory");
        std::fs::write(
            sealed,
            "pub fn verify_and_resume() { verify_and_resume_from_dir(); \
             guarded_load_resume(); }\n",
        )
        .expect("sealed fixture");
        tree
    }
}
