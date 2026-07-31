//! `xtask check-mvm-host-binaries-sync`
//!
//! CI lint — asserts the Rust manifest at
//! `crates/mvm-cli/src/host_binaries/manifest.rs` and the Nix
//! attrset at `nix/lib/mvm-host-binaries.nix` agree on the set of
//! entries and their install paths. Adding or renaming a binary
//! requires updating both files in the same PR.
//!
//! A third mirror is checked here too: the workflow steps that
//! cross-compile these binaries for the builder-VM image. The flake reads
//! every manifest entry out of `$MVM_HOST_BIN_DIR`, so a binary added to
//! the manifest but not to the `cargo zigbuild --bin` list makes the
//! image build fail on a missing path — and that build only runs on tags
//! and the nightly cron, so the gap is invisible on the PR that opens
//! it.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

pub fn run(workspace: &Path) -> Result<()> {
    let rust_entries = parse_rust_manifest(workspace)?;
    let nix_entries = parse_nix_attrset(workspace)?;

    if rust_entries != nix_entries {
        bail!(
            "drift between manifests:\n  Rust: {:#?}\n  Nix:  {:#?}\n\n\
             Fix: ensure crates/mvm-cli/src/host_binaries/manifest.rs and \
             nix/lib/mvm-host-binaries.nix list the same entries with the \
             same install_path.",
            rust_entries,
            nix_entries
        );
    }

    let expected: Vec<&str> = rust_entries.keys().map(String::as_str).collect();
    let mut missing = Vec::new();
    for (file, step_args) in zigbuild_steps(workspace)? {
        for name in &expected {
            if !step_args.contains(&format!("--bin {name}")) {
                missing.push(format!("{file}: cross-compile step omits --bin {name}"));
            }
        }
    }
    if !missing.is_empty() {
        bail!(
            "manifest entries are not cross-compiled by every workflow that builds the builder-VM image:\n  {}\n\n\
             Fix: add the missing `--bin <name>` to the `cargo zigbuild` step. \
             The flake reads each manifest entry from $MVM_HOST_BIN_DIR and \
             fails on a missing path.",
            missing.join("\n  ")
        );
    }

    eprintln!(
        "check-mvm-host-binaries-sync: manifests agree ({} entries), cross-compiled by every builder-VM workflow step",
        rust_entries.len()
    );
    Ok(())
}

/// `(workflow file name, joined step text)` for every `cargo zigbuild`
/// invocation that builds `-p mvm-build` host binaries.
fn zigbuild_steps(root: &Path) -> Result<Vec<(String, String)>> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let src =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for step in split_zigbuild_steps(&src) {
            out.push((name.clone(), step));
        }
    }
    out.sort();
    Ok(out)
}

/// Collapse each `cargo zigbuild ... -p mvm-build ...` invocation — which
/// wraps across backslash-continued lines — into one whitespace-normalized
/// string.
fn split_zigbuild_steps(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in src.lines() {
        let t = line.trim();
        if t.contains("cargo zigbuild") {
            current = Some(String::new());
        }
        if let Some(buf) = current.as_mut() {
            buf.push(' ');
            buf.push_str(t.trim_end_matches('\\').trim());
            if !t.ends_with('\\') {
                let done = buf.split_whitespace().collect::<Vec<_>>().join(" ");
                if done.contains("-p mvm-build") {
                    out.push(done);
                }
                current = None;
            }
        }
    }
    out
}

/// Parse `name:` / `install_path:` field pairs from the Rust struct literal
/// in `crates/mvm-cli/src/host_binaries/manifest.rs`.
fn parse_rust_manifest(root: &Path) -> Result<BTreeMap<String, String>> {
    let path = root.join("crates/mvm-cli/src/host_binaries/manifest.rs");
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;

    let mut out = BTreeMap::new();
    let mut current_name: Option<String> = None;

    for line in src.lines() {
        if let Some(n) = extract_quoted_after(line, "name:") {
            current_name = Some(n);
        }
        if let Some(p) = extract_quoted_after(line, "install_path:")
            && let Some(n) = current_name.take()
        {
            out.insert(n, p);
        }
    }

    Ok(out)
}

/// Parse `<name> = { install_path = "..."; }` attribute blocks from
/// `nix/lib/mvm-host-binaries.nix`.
fn parse_nix_attrset(root: &Path) -> Result<BTreeMap<String, String>> {
    let path = root.join("nix/lib/mvm-host-binaries.nix");
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;

    let mut out = BTreeMap::new();
    let mut current_name: Option<String> = None;

    for line in src.lines() {
        let t = line.trim();
        // Match `  name = {` attribute block openers.
        if let Some(eq) = t.find(" = {") {
            let n = t[..eq].trim().to_string();
            if !n.is_empty() && !n.starts_with('#') && !n.starts_with('{') {
                current_name = Some(n);
            }
        }
        if let Some(p) = extract_quoted_after(line, "install_path =")
            && let Some(n) = current_name.take()
        {
            out.insert(n, p);
        }
    }

    Ok(out)
}

/// Extract the first double-quoted string on `line` that appears after
/// `key`. Returns `None` if either `key` or a following quoted value is
/// absent.
fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)? + key.len();
    let rest = &line[i..];
    let q1 = rest.find('"')? + 1;
    let q2 = rest[q1..].find('"')?;
    Some(rest[q1..q1 + q2].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        // From xtask/ go up one level to the workspace root.
        let manifest = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        manifest
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(manifest)
    }

    #[test]
    fn rust_manifest_parses_all_entries() {
        let root = workspace_root();
        let entries = parse_rust_manifest(&root).expect("parse rust manifest");
        assert_eq!(entries.len(), 3, "expected 3 entries, got {entries:?}");
        assert_eq!(
            entries.get("mvm-host-vm-init").map(String::as_str),
            Some("/sbin/mvm-host-vm-init")
        );
        assert_eq!(
            entries.get("mvm-egress-proxy").map(String::as_str),
            Some("/sbin/mvm-egress-proxy")
        );
        assert_eq!(
            entries.get("mvm-builderd").map(String::as_str),
            Some("/sbin/mvm-builderd")
        );
    }

    #[test]
    fn nix_attrset_parses_all_entries() {
        let root = workspace_root();
        let entries = parse_nix_attrset(&root).expect("parse nix attrset");
        assert_eq!(entries.len(), 3, "expected 3 entries, got {entries:?}");
        assert_eq!(
            entries.get("mvm-host-vm-init").map(String::as_str),
            Some("/sbin/mvm-host-vm-init")
        );
        assert_eq!(
            entries.get("mvm-egress-proxy").map(String::as_str),
            Some("/sbin/mvm-egress-proxy")
        );
        assert_eq!(
            entries.get("mvm-builderd").map(String::as_str),
            Some("/sbin/mvm-builderd")
        );
    }

    #[test]
    fn manifests_agree() {
        let root = workspace_root();
        let rust = parse_rust_manifest(&root).expect("rust");
        let nix = parse_nix_attrset(&root).expect("nix");
        assert_eq!(rust, nix, "manifest drift detected in test");
    }

    #[test]
    fn extract_quoted_after_basic() {
        assert_eq!(
            extract_quoted_after(r#"        name: "mvm-host-vm-init","#, "name:"),
            Some("mvm-host-vm-init".to_string())
        );
        assert_eq!(
            extract_quoted_after(
                r#"    install_path: "/sbin/mvm-host-vm-init","#,
                "install_path:"
            ),
            Some("/sbin/mvm-host-vm-init".to_string())
        );
        assert_eq!(extract_quoted_after("no key here", "name:"), None);
    }

    #[test]
    fn run_passes_on_current_workspace() {
        let root = workspace_root();
        run(&root).expect("manifests should agree");
    }
}
