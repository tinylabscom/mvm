//! `xtask check-no-mvmd-dependency`
//!
//! `mvm` is the lower repository: `mvmd` depends on it, never the reverse.
//! A manifest that names an `mvmd-*` package, or Rust source that imports an
//! `mvmd_*` path, would make the dependency circular and tie every mvm build
//! to a repository it must not know about.
//!
//! Manifests: every `Cargo.toml` in the workspace is parsed, and any key under
//! a dependency or patch table (`dependencies`, `dev-dependencies`,
//! `build-dependencies`, `workspace.dependencies`, their `target.*` forms and
//! `[patch.*]`), or any `package = "..."` rename, that names an `mvmd` package
//! fails. Source: first-party Rust under `crates/` is read with comments,
//! literals and `#[cfg(test)]` items blanked, so only a real crate path counts
//! (`mvmd_x::`, `use mvmd_x`, `extern crate mvmd_x`); a module or field that
//! merely contains the name, like `mvm_core::mvmd_iface`, is not a dependency.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::Path;

use crate::fs_walk::for_each_file;
use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

fn is_mvmd_name(name: &str) -> bool {
    name == "mvmd" || name.starts_with("mvmd-") || name.starts_with("mvmd_")
}

fn is_dep_table(key: &str) -> bool {
    key.ends_with("dependencies") || key == "patch"
}

/// Dependency names in `manifest` that point at an `mvmd` package.
fn manifest_findings(manifest: &str) -> Result<Vec<String>> {
    let value: toml::Value = toml::from_str(manifest).context("parsing manifest")?;
    let mut found = Vec::new();
    walk(&value, false, &mut found);
    Ok(found)
}

/// `in_deps` is true once an ancestor key is a dependency or patch table.
fn walk(value: &toml::Value, in_deps: bool, found: &mut Vec<String>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        let renamed = key == "package" && child.as_str().is_some_and(is_mvmd_name);
        if renamed {
            found.extend(child.as_str().map(String::from));
        } else if in_deps && is_mvmd_name(key) {
            found.push(key.clone());
        }
        walk(child, in_deps || is_dep_table(key), found);
    }
}

/// Lines of `source` that name an `mvmd_*` path outside comments, literals
/// and tests.
fn source_findings(source: &str) -> Vec<String> {
    let code = strip_cfg_test_items(&blank_comments_and_strings(source));
    let re =
        Regex::new(r"(?:^|[^:\w])mvmd_\w+\s*::|\b(?:use|crate)\s+mvmd_\w+").expect("valid pattern");
    code.lines()
        .enumerate()
        .filter(|(_, l)| re.is_match(l))
        .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
        .collect()
}

fn rel(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .display()
        .to_string()
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let mut problems = Vec::new();
    let mut manifests = 0;
    for_each_file(workspace, Some("toml"), &mut |path, text| {
        if path.file_name().is_some_and(|n| n == "Cargo.toml") {
            manifests += 1;
            match manifest_findings(text) {
                Ok(found) => problems.extend(
                    found
                        .into_iter()
                        .map(|n| format!("{}: `{n}`", rel(workspace, path))),
                ),
                Err(e) => problems.push(format!("{}: {e:#}", rel(workspace, path))),
            }
        }
    })?;
    if manifests == 0 {
        bail!(
            "check-no-mvmd-dependency: no Cargo.toml found; a gate that scans nothing passes forever"
        );
    }
    for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, text| {
        problems.extend(
            source_findings(text)
                .into_iter()
                .map(|f| format!("{}: {f}", rel(workspace, path))),
        );
    })?;
    if !problems.is_empty() {
        bail!(
            "check-no-mvmd-dependency: mvm must not depend on mvmd:\n  {}",
            problems.join("\n  ")
        );
    }
    println!("check-no-mvmd-dependency: clean ({manifests} manifests, crates/ source)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(body: &str) -> Vec<String> {
        manifest_findings(body).unwrap()
    }

    #[test]
    fn every_dependency_table_kind_is_caught() {
        for table in [
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "workspace.dependencies",
            "target.'cfg(unix)'.dependencies",
            "target.x86_64-unknown-linux-gnu.dev-dependencies",
            "patch.crates-io",
        ] {
            let found = manifest(&format!("[{table}]\nmvmd-types = \"1\"\n"));
            assert_eq!(found, ["mvmd-types"], "table {table}");
        }
    }

    #[test]
    fn a_dotted_table_and_a_rename_are_caught() {
        assert_eq!(
            manifest("[dependencies.mvmd_core]\npath = \"x\"\n"),
            ["mvmd_core"]
        );
        assert_eq!(
            manifest("[dependencies]\nfoo = { package = \"mvmd-types\", version = \"1\" }\n"),
            ["mvmd-types"]
        );
    }

    #[test]
    fn unrelated_manifests_and_prose_pass() {
        let body = "# mvmd-types is theirs\n[dependencies]\nserde = \"1\"\n[package]\nname = \"mvm-core\"\ndescription = \"mvmd-types\"\n";
        assert!(manifest(body).is_empty());
    }

    #[test]
    fn a_source_import_is_caught() {
        assert_eq!(source_findings("use mvmd_types::Foo;\n").len(), 1);
        assert_eq!(source_findings("fn f() { mvmd_types::x(); }\n").len(), 1);
    }

    #[test]
    fn comments_strings_and_tests_do_not_count() {
        let src = "// use mvmd_types::A;\n/* mvmd_x */\nconst S: &str = \"mvmd_types\";\n#[cfg(test)]\nmod t { use mvmd_types::B; }\n";
        assert!(source_findings(src).is_empty());
    }

    #[test]
    fn the_current_tree_is_clean() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        run(workspace).unwrap();
    }
}
