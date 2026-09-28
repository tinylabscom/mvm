//! `xtask check-mvm-host-binaries-sync`
//!
//! CI lint — asserts the Rust manifest at
//! `crates/mvm-cli/src/host_binaries/manifest.rs` and the Nix
//! attrset at `nix/lib/mvm-host-binaries.nix` agree on the set of
//! entries and their install paths. Adding or renaming a binary
//! requires updating both files in the same PR.
//!
//! A third mirror is `BUILDER_HOST_BINARIES` in
//! `crates/mvm-build/src/image_source/build.rs`: the names a local builder
//! image build copies out of the image checkout's host-binary script. A name
//! left there after it leaves the manifest makes every local image build
//! refuse on a binary nothing builds any more.
//!
//! It also holds `.github/actions/install-zigbuild` to installing the Rust
//! version the workspace metadata pins, the compiler `mvmctl`'s embedded
//! copies are built with. The builder-VM image that installs these binaries
//! is built in mvm-images, which reads the Nix attrset through its `mvm`
//! input, so this repository has no image build step left to keep in step.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

const INSTALL_ACTION: &str = ".github/actions/install-zigbuild/action.yml";
const IMAGE_SOURCE_BUILD: &str = "crates/mvm-build/src/image_source/build.rs";
const BUILDER_HOST_BINARIES_DECL: &str = "pub const BUILDER_HOST_BINARIES";

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

    let image_source_path = workspace.join(IMAGE_SOURCE_BUILD);
    let image_source = std::fs::read_to_string(&image_source_path)
        .with_context(|| format!("read {}", image_source_path.display()))?;
    let builder_list = builder_host_binaries(&image_source)?;
    let manifest_names: Vec<String> = rust_entries.keys().cloned().collect();
    if builder_list != manifest_names {
        bail!(
            "{IMAGE_SOURCE_BUILD}: BUILDER_HOST_BINARIES lists {builder_list:?}, the manifest \
             lists {manifest_names:?}. A local builder image build copies exactly these names \
             out of the image checkout's host-binary build, so the two must name the same set."
        );
    }

    let action_path = workspace.join(INSTALL_ACTION);
    let action = std::fs::read_to_string(&action_path)
        .with_context(|| format!("read {}", action_path.display()))?;
    let violations = toolchain_action_violations(&action);
    if !violations.is_empty() {
        bail!(
            "the zig toolchain action has drifted:\n  {}\n\n\
             Fix: install the Rust version pinned in workspace.metadata.mvm.toolchain and \
             expose it as rust_version, so mvmctl's embedded host binaries are built with \
             the pinned compiler.",
            violations.join("\n  ")
        );
    }

    eprintln!(
        "check-mvm-host-binaries-sync: manifests agree ({} entries); the zig toolchain action installs the pinned Rust",
        rust_entries.len()
    );
    Ok(())
}

fn toolchain_action_violations(source: &str) -> Vec<String> {
    [
        (
            "value: ${{ steps.install_rust.outputs.rust_version }}",
            "does not expose the metadata-derived Rust version as rust_version",
        ),
        (
            "id: install_rust",
            "does not identify the Rust installation step as install_rust",
        ),
        (
            r#"echo "rust_version=${RUST_VERSION}" >> "$GITHUB_OUTPUT""#,
            "does not publish the parsed Rust version through GITHUB_OUTPUT",
        ),
        (
            r#"/^\[workspace\.metadata\.mvm\.toolchain\]/"#,
            "does not read the Rust version from workspace.metadata.mvm.toolchain",
        ),
    ]
    .into_iter()
    .filter(|(required, _)| !source.contains(required))
    .map(|(_, reason)| format!("{INSTALL_ACTION}: {reason}"))
    .collect()
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

/// The names in the `BUILDER_HOST_BINARIES` array literal, sorted.
fn builder_host_binaries(source: &str) -> Result<Vec<String>> {
    let start = source.find(BUILDER_HOST_BINARIES_DECL).with_context(|| {
        format!("{IMAGE_SOURCE_BUILD} no longer declares BUILDER_HOST_BINARIES")
    })?;
    let decl = &source[start..];
    let body = decl
        .find('=')
        .and_then(|eq| decl[eq..].find("];").map(|end| &decl[eq..eq + end]))
        .with_context(|| format!("{IMAGE_SOURCE_BUILD}: BUILDER_HOST_BINARIES is not an array"))?;
    let mut names: Vec<String> = body
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    names.sort();
    Ok(names)
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
        assert_eq!(entries.len(), 2, "expected 2 entries, got {entries:?}");
        assert_eq!(
            entries.get("mvm-host-vm-init").map(String::as_str),
            Some("/sbin/mvm-host-vm-init")
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
        assert_eq!(entries.len(), 2, "expected 2 entries, got {entries:?}");
        assert_eq!(
            entries.get("mvm-host-vm-init").map(String::as_str),
            Some("/sbin/mvm-host-vm-init")
        );
        assert_eq!(
            entries.get("mvm-builderd").map(String::as_str),
            Some("/sbin/mvm-builderd")
        );
    }

    #[test]
    fn builder_host_binaries_reads_the_array_literal() {
        let src = r#"
/// doc
pub const BUILDER_HOST_BINARIES: [&str; 2] = ["mvm-host-vm-init", "mvm-builderd"];
const OTHER: [&str; 1] = ["not-this"];
"#;
        assert_eq!(
            builder_host_binaries(src).unwrap(),
            ["mvm-builderd", "mvm-host-vm-init"]
        );
        let wrapped = "pub const BUILDER_HOST_BINARIES: [&str; 3] =\n    [\"a\", \"b\", \"c\"];";
        assert_eq!(builder_host_binaries(wrapped).unwrap(), ["a", "b", "c"]);
        assert!(builder_host_binaries("const NOTHING: u8 = 0;").is_err());
    }

    #[test]
    fn builder_host_binaries_match_the_manifest() {
        let root = workspace_root();
        let src = std::fs::read_to_string(root.join(IMAGE_SOURCE_BUILD)).unwrap();
        let rust: Vec<String> = parse_rust_manifest(&root)
            .expect("rust")
            .into_keys()
            .collect();
        assert_eq!(builder_host_binaries(&src).unwrap(), rust);
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

    #[test]
    fn installer_must_export_the_metadata_derived_rust_version() {
        let valid = r#"
outputs:
  rust_version:
    value: ${{ steps.install_rust.outputs.rust_version }}
steps:
  - id: install_rust
    run: |
      RUST_VERSION=$(awk '/^\[workspace\.metadata\.mvm\.toolchain\]/ { t = 1; next }' Cargo.toml)
      echo "rust_version=${RUST_VERSION}" >> "$GITHUB_OUTPUT"
"#;
        assert!(toolchain_action_violations(valid).is_empty());

        let violations = toolchain_action_violations("outputs: {}");
        assert_eq!(violations.len(), 4);
        assert!(
            violations
                .iter()
                .all(|violation| violation.starts_with(INSTALL_ACTION))
        );
    }
}
