//! The embedded payload's build plan: which binaries it holds and the
//! `cargo zigbuild` argument vector that compiles one.
//!
//! Pure data and string work — the only read is the payload manifest's text —
//! so every consumer assembles the same plan from the same source. Three
//! consumers include this file: `mvm-cli`'s build script and `mvmctl` (both
//! through `payload_build.rs`, which keeps the compiling half), and `xtask`'s
//! compile-units report, which `#[path]`-includes it directly. `xtask` cannot
//! depend on `mvm-cli`: depending on the crate runs its build script, and that
//! build script is the payload build itself.
//!
//! The target triple each binary is built for is *not* here: it is the pinned
//! toolchain's business (`mvm-build`'s `embed_toolchain`), which every
//! consumer reads the same way.

use std::path::Path;

/// One binary in the payload, as the payload manifest declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmbeddedSourceBinary {
    pub package: String,
    pub name: String,
    pub features: String,
}

/// The payload manifest, relative to the workspace root.
pub(crate) const MANIFEST_PATH: &str = "crates/mvm-builder-guest/src/host_payload_manifest.rs";

/// Every binary in the payload, read from the manifest in `workspace_root`.
pub(crate) fn read_manifest(workspace_root: &Path) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let path = workspace_root.join(MANIFEST_PATH);
    let src =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_embedded_manifest(&src)
}

/// Every binary in the payload, in the order the table lists them.
///
/// Read out of the *text* of `crates/mvm-builder-guest/src/host_payload_manifest.rs`,
/// because a build script cannot depend on the crate it is building. The order
/// is part of the payload's identity — extraction hashes the table in order —
/// so both callers must read the same text the same way.
///
/// `HOST_BINARIES` (the builder boot payload) and the bootstrap support list
/// name each binary's package. `SEED_BINARIES` (host-side only, e.g. the
/// Stage 0 nix-seed's `/init`) are `mvm-builder-guest` `[[bin]]`s and name none.
pub(crate) fn parse_embedded_manifest(src: &str) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let mut manifest = parse_host_binaries(src)?;
    manifest.extend(
        read_quoted_strings_block(src, "SEED_BINARIES")?
            .into_iter()
            .map(|name| EmbeddedSourceBinary {
                package: "mvm-builder-guest".to_string(),
                name,
                features: String::new(),
            }),
    );
    manifest.extend(parse_bootstrap_support_binaries(src)?);
    Ok(manifest)
}

fn parse_host_binaries(src: &str) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let section = "HOST_BINARIES";
    let packages = read_quoted_field_block(src, section, "package:")?;
    let names = read_quoted_field_block(src, section, "name:")?;
    if packages.len() != names.len() {
        return Err(format!(
            "{section} in the payload manifest has {} packages and {} names; \
             every entry needs both",
            packages.len(),
            names.len()
        ));
    }
    Ok(packages
        .into_iter()
        .zip(names)
        .map(|(package, name)| EmbeddedSourceBinary {
            package,
            name,
            features: String::new(),
        })
        .collect())
}

fn parse_bootstrap_support_binaries(src: &str) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let section = "BOOTSTRAP_SUPPORT_BINARIES";
    let packages = read_quoted_field_block(src, section, "package:")?;
    let names = read_quoted_field_block(src, section, "name:")?;
    let features = read_quoted_field_block(src, section, "features:")?;
    if packages.len() != names.len() || packages.len() != features.len() {
        return Err(format!(
            "{section} in the payload manifest has {} packages, {} names and {} feature lists; \
             every entry needs all three",
            packages.len(),
            names.len(),
            features.len()
        ));
    }
    Ok(packages
        .into_iter()
        .zip(names)
        .zip(features)
        .map(|((package, name), features)| EmbeddedSourceBinary {
            package,
            name,
            features,
        })
        .collect())
}

fn read_manifest_section<'a>(src: &'a str, name: &str) -> Result<&'a str, String> {
    let start = src
        .find(name)
        .ok_or_else(|| format!("the payload manifest declares no {name}"))?;
    let rest = &src[start..];
    let end = rest.find("];").map(|i| i + 2).unwrap_or(rest.len());
    Ok(&rest[..end])
}

fn read_quoted_field_block(src: &str, section: &str, field: &str) -> Result<Vec<String>, String> {
    Ok(read_manifest_section(src, section)?
        .lines()
        .filter_map(|line| extract_quoted_after(line, field))
        .collect())
}

fn read_quoted_strings_block(src: &str, section: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut s = read_manifest_section(src, section)?;
    while let Some(q1) = s.find('"') {
        let after = &s[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        out.push(after[..q2].to_string());
        s = &after[q2 + 1..];
    }
    Ok(out)
}

/// Extract the quoted string after `key` on one line, e.g.
/// `name: "mvm-host-vm-init",` + `"name:"` → `Some("mvm-host-vm-init")`.
pub(crate) fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)? + key.len();
    let rest = &line[i..];
    let q1 = rest.find('"')? + 1;
    let q2 = rest[q1..].find('"')?;
    Some(rest[q1..q1 + q2].to_string())
}

/// The `cargo` arguments, after the program name, that cross-compile `binary`
/// for `target` — the whole selection the unit graph of that build depends on.
///
/// `--quiet` only silences progress output; the bytes, and so the graph, do
/// not change with it.
pub(crate) fn zigbuild_args(
    binary: &EmbeddedSourceBinary,
    target: &str,
    quiet: bool,
) -> Vec<String> {
    let mut args = vec!["zigbuild".to_string(), "--release".to_string()];
    if quiet {
        args.push("--quiet".to_string());
    }
    args.extend([
        "--target".to_string(),
        target.to_string(),
        "-p".to_string(),
        binary.package.clone(),
        "--bin".to_string(),
        binary.name.clone(),
    ]);
    if !binary.features.is_empty() {
        args.extend(["--features".to_string(), binary.features.clone()]);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bootstrap_support_binaries_with_their_own_package() {
        let src = r#"
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[
    SourceBuiltBinary {
        package: "mvm-agentd",
        name: "mvm-egress-client",
        features: "addons",
    },
];
"#;
        assert_eq!(
            parse_bootstrap_support_binaries(src).unwrap(),
            vec![EmbeddedSourceBinary {
                package: "mvm-agentd".to_string(),
                name: "mvm-egress-client".to_string(),
                features: "addons".to_string(),
            }]
        );
    }

    #[test]
    fn a_support_entry_missing_a_field_is_refused_rather_than_misaligned() {
        let src = r#"
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[
    SourceBuiltBinary { package: "mvm-agentd", name: "mvm-egress-client" },
];
"#;
        let reason = parse_bootstrap_support_binaries(src).unwrap_err();
        assert!(reason.contains("every entry needs all three"), "{reason}");
    }

    #[test]
    fn host_binary_names_exclude_bootstrap_support_entries() {
        let src = r#"
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary { package: "mvm-builder-guest", name: "mvm-host-vm-init", install_path: Some("/sbin/mvm-host-vm-init"), mode: 0o755 },
    HostBinary { package: "mvm-builder-guest", name: "mvm-builderd", install_path: Some("/sbin/mvm-builderd"), mode: 0o755 },
];
pub const SEED_BINARIES: &[&str] = &["stage0-init"];
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[SourceBuiltBinary {
    package: "mvm-agentd",
    name: "mvm-egress-client",
    features: "addons",
}];
"#;
        assert_eq!(
            read_quoted_field_block(src, "HOST_BINARIES", "name:").unwrap(),
            vec!["mvm-host-vm-init".to_string(), "mvm-builderd".to_string()]
        );
    }

    #[test]
    fn a_host_binary_is_built_from_the_package_it_names() {
        let src = r#"
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary {
        package: "mvm-builder-guest",
        name: "mvm-host-vm-init",
        install_path: Some("/sbin/mvm-host-vm-init"),
        mode: 0o755,
    },
    HostBinary {
        package: "mvm-setpriv",
        name: "mvm-setpriv",
        install_path: None,
        mode: 0o755,
    },
];
"#;
        assert_eq!(
            parse_host_binaries(src).unwrap(),
            vec![
                EmbeddedSourceBinary {
                    package: "mvm-builder-guest".to_string(),
                    name: "mvm-host-vm-init".to_string(),
                    features: String::new(),
                },
                EmbeddedSourceBinary {
                    package: "mvm-setpriv".to_string(),
                    name: "mvm-setpriv".to_string(),
                    features: String::new(),
                },
            ]
        );
    }

    #[test]
    fn a_host_binary_without_a_package_is_refused_rather_than_misaligned() {
        let src = r#"
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary { package: "mvm-builder-guest", name: "mvm-host-vm-init", mode: 0o755 },
    HostBinary { name: "mvm-setpriv", mode: 0o755 },
];
"#;
        let reason = parse_host_binaries(src).unwrap_err();
        assert!(reason.contains("every entry needs both"), "{reason}");
    }

    #[test]
    fn extract_quoted_after_reads_the_quoted_value() {
        assert_eq!(
            extract_quoted_after(r#"        name: "mvm-host-vm-init","#, "name:"),
            Some("mvm-host-vm-init".to_string())
        );
        assert_eq!(extract_quoted_after("no key here", "name:"), None);
    }

    #[test]
    fn the_zigbuild_names_the_package_binary_features_and_target() {
        let binary = EmbeddedSourceBinary {
            package: "mvm-agentd".to_string(),
            name: "mvm-egress-client".to_string(),
            features: "addons".to_string(),
        };
        assert_eq!(
            zigbuild_args(&binary, "aarch64-unknown-linux-musl", false),
            [
                "zigbuild",
                "--release",
                "--target",
                "aarch64-unknown-linux-musl",
                "-p",
                "mvm-agentd",
                "--bin",
                "mvm-egress-client",
                "--features",
                "addons",
            ]
        );
    }

    /// Runtime callers pass `--quiet` unless asked to be verbose; nothing else
    /// about the compile may change with it, or the bytes would.
    #[test]
    fn a_quiet_zigbuild_differs_only_by_quiet() {
        let binary = EmbeddedSourceBinary {
            package: "mvm-builder-guest".to_string(),
            name: "mvm-host-vm-init".to_string(),
            features: String::new(),
        };
        let loud = zigbuild_args(&binary, "aarch64-unknown-linux-musl", false);
        let quiet = zigbuild_args(&binary, "aarch64-unknown-linux-musl", true);
        assert!(!loud.iter().any(|arg| arg == "--quiet"));
        assert_eq!(
            quiet.iter().filter(|arg| *arg != "--quiet").count(),
            loud.len()
        );
        assert!(quiet.iter().any(|arg| arg == "--quiet"));
    }
}
