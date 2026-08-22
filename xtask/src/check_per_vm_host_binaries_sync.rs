//! `xtask check-per-vm-host-binaries-sync`
//!
//! CI lint — asserts the canonical `PER_VM_HOST_BINARIES` registry in
//! `crates/mvm-cli/src/host_binaries/manifest.rs` and the two lists in
//! `.github/workflows/release.yml` (the `cargo build --bin` step and the
//! tarball's `REQUIRED_HOSTBINS`) name the same binaries.
//!
//! Why this needs a gate rather than review: `resolve_subprocess_bin` finds
//! these binaries next to the executable, falling back to `target/{release,
//! debug}` — a path that exists only in a source checkout. So a binary present
//! for every contributor can be absent for every *user*, and the failure
//! surfaces as a spawn error on their machine long after the release is cut.
//! The release workflow runs on tags, so nothing on the PR that opens the gap
//! would otherwise notice.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

pub fn run(workspace: &Path) -> Result<()> {
    let registry = parse_registry(workspace)?;
    if registry.is_empty() {
        bail!(
            "no PER_VM_HOST_BINARIES entries parsed out of \
             crates/mvm-cli/src/host_binaries/manifest.rs — the registry moved \
             or was reshaped, and this gate is now vacuous"
        );
    }

    let release = workspace.join(".github/workflows/release.yml");
    let src =
        std::fs::read_to_string(&release).with_context(|| format!("read {}", release.display()))?;

    let built: BTreeSet<String> = bin_flags(&src);
    let packaged: BTreeSet<String> = required_hostbins(&src);

    let mut problems = Vec::new();

    for (name, _scope) in &registry {
        if !built.contains(name) {
            problems.push(format!(
                "release.yml never builds `{name}` (no `--bin {name}`)"
            ));
        }
        if !packaged.contains(name) {
            problems.push(format!(
                "release.yml never packages `{name}` (absent from REQUIRED_HOSTBINS)"
            ));
        }
    }

    let known: BTreeSet<&str> = registry.iter().map(|(n, _)| n.as_str()).collect();
    for name in &packaged {
        if !known.contains(name.as_str()) {
            problems.push(format!(
                "release.yml packages `{name}`, which is not in PER_VM_HOST_BINARIES"
            ));
        }
    }

    if !problems.is_empty() {
        bail!(
            "per-VM host binary lists have drifted:\n  {}\n\n\
             Fix: PER_VM_HOST_BINARIES in crates/mvm-cli/src/host_binaries/manifest.rs \
             is the source of truth. Update .github/workflows/release.yml's \
             `--bin` list and REQUIRED_HOSTBINS to match it.",
            problems.join("\n  ")
        );
    }

    eprintln!(
        "check-per-vm-host-binaries-sync: {} registry entries built and packaged by release.yml",
        registry.len()
    );
    Ok(())
}

/// `(name, scope)` for every `PER_VM_HOST_BINARIES` entry.
fn parse_registry(root: &Path) -> Result<Vec<(String, String)>> {
    let path = root.join("crates/mvm-cli/src/host_binaries/manifest.rs");
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(parse_registry_str(&src))
}

fn parse_registry_str(src: &str) -> Vec<(String, String)> {
    let Some(i) = src.find("PER_VM_HOST_BINARIES") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in src[i..].lines() {
        if let Some(v) = extract_quoted_after(line, "name:") {
            name = Some(v);
        }
        if let Some(scope) = line.trim().strip_prefix("scope: PerVmScope::")
            && let Some(n) = name.take()
        {
            out.push((n, scope.trim_end_matches(',').trim().to_string()));
        }
        if line.starts_with("];") && !out.is_empty() {
            break;
        }
    }
    out
}

/// Every `--bin <name>` argument anywhere in the workflow.
fn bin_flags(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let mut rest = line;
        while let Some(i) = rest.find("--bin ") {
            rest = &rest[i + "--bin ".len()..];
            let name = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches('\\')
                .trim();
            if name.starts_with("mvm-") {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// Every binary named in a `REQUIRED_HOSTBINS=` assignment (the base list and
/// any target-conditional extension).
fn required_hostbins(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("REQUIRED_HOSTBINS=") else {
            continue;
        };
        for tok in rest.trim_matches('"').split_whitespace() {
            let tok = tok.trim_matches('"');
            if tok.starts_with("mvm-") {
                out.insert(tok.to_string());
            }
        }
    }
    out
}

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
        let manifest = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        manifest
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(manifest)
    }

    #[test]
    fn registry_parses_names_and_scopes() {
        let got = parse_registry_str(
            r#"
pub const PER_VM_HOST_BINARIES: &[PerVmBinary] = &[
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-network-endpoint",
        features: "",
        scope: PerVmScope::Always,
    },
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-hvf-supervisor",
        features: "",
        scope: PerVmScope::MacOsAarch64,
    },
];
"#,
        );
        assert_eq!(
            got,
            vec![
                ("mvm-network-endpoint".to_string(), "Always".to_string()),
                ("mvm-hvf-supervisor".to_string(), "MacOsAarch64".to_string()),
            ]
        );
    }

    #[test]
    fn bin_flags_reads_continued_lines() {
        let got = bin_flags(
            "cargo build -p mvm-hostd \\\n  --bin mvm-broker \\\n  --bin mvm-network-endpoint\n",
        );
        assert!(got.contains("mvm-broker"));
        assert!(got.contains("mvm-network-endpoint"));
    }

    #[test]
    fn required_hostbins_reads_base_and_extension() {
        let got = required_hostbins(
            "          REQUIRED_HOSTBINS=\"mvm-network-endpoint mvm-broker\"\n\
             REQUIRED_HOSTBINS=\"${REQUIRED_HOSTBINS} mvm-hvf-supervisor\"\n",
        );
        assert!(got.contains("mvm-network-endpoint"));
        assert!(got.contains("mvm-broker"));
        assert!(got.contains("mvm-hvf-supervisor"));
        assert!(!got.iter().any(|s| s.contains("REQUIRED")));
    }

    #[test]
    fn run_passes_on_current_workspace() {
        run(&workspace_root()).expect("registry and release.yml should agree");
    }
}
