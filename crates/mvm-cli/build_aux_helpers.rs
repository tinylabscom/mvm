//! Pure selection logic for the native per-VM host helpers that mvm-cli's build
//! script compiles up front. Kept I/O-free so the host-conditional and skip
//! rules are unit-tested without running a real build.

/// A native host helper the build script compiles for this host, so that
/// `cargo run` produces it before `mvmctl` executes (cargo on its own builds
/// only the run target, never sibling `[[bin]]`s in other crates).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuxHelperSpec {
    pub package: &'static str,
    pub bin: &'static str,
    pub features: &'static [&'static str],
}

/// The helpers to build for `(target_os, target_arch)`, given whether libkrun
/// is installed and whether the explicit skip flag is set. Empty when skipping.
/// The libkrun supervisor is included only where libkrun is present because it
/// links `-lkrun`; the HVF supervisor only on macOS/aarch64.
pub(crate) fn aux_helper_specs(
    target_os: &str,
    target_arch: &str,
    libkrun_present: bool,
    skip: bool,
) -> Vec<AuxHelperSpec> {
    if skip {
        return Vec::new();
    }
    let mut specs = vec![
        AuxHelperSpec {
            package: "mvm-hostd",
            bin: "mvm-substitution-endpoint",
            features: &[],
        },
        AuxHelperSpec {
            package: "mvm-hostd",
            bin: "mvm-network-tunnel-worker",
            features: &[],
        },
    ];
    if target_os == "macos" && target_arch == "aarch64" {
        specs.push(AuxHelperSpec {
            package: "mvm-vm-host",
            bin: "mvm-hvf-supervisor",
            features: &[],
        });
    }
    if libkrun_present {
        specs.push(AuxHelperSpec {
            package: "mvm-vm-host",
            bin: "mvm-libkrun-supervisor",
            features: &["libkrun-sys"],
        });
    }
    specs
}

/// Whether to skip the native-helper build. Unlike the embedded musl bins
/// (which stub out in debug by default), the native helpers must build in every
/// profile — the debug `cargo run` loop is the whole point — so only the
/// explicit escape hatch skips them.
pub(crate) fn should_skip_aux_helpers(skip_env: Option<&str>) -> bool {
    matches!(skip_env, Some("1"))
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

/// Names in the `HOST_BINARIES` array of `manifest.rs` only — these are the
/// `-p mvm-build` binaries embedded per-bin. The `SourceBuiltBinary` lists that
/// follow (e.g. `BOOTSTRAP_SUPPORT_BINARIES`) carry their own owning `package`
/// and are cross-compiled by the combined guest invocation, so their names must
/// NOT be swept into the per-bin loop — otherwise the embed build fails with
/// `no bin target named <name> in mvm-build`. Scoped to the `HOST_BINARIES`
/// block for exactly that reason (mirrors the `SEED_BINARIES` scan).
pub(crate) fn parse_host_binary_names(src: &str) -> Vec<String> {
    let start = src
        .find("HOST_BINARIES")
        .expect("HOST_BINARIES array in manifest.rs");
    let rest = &src[start..];
    let end = rest.find("];").map(|i| i + 2).unwrap_or(rest.len());
    rest[..end]
        .lines()
        .filter_map(|line| extract_quoted_after(line, "name:"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_after_reads_the_quoted_value() {
        assert_eq!(
            extract_quoted_after(r#"        name: "mvm-host-vm-init","#, "name:"),
            Some("mvm-host-vm-init".to_string())
        );
        assert_eq!(extract_quoted_after("no key here", "name:"), None);
    }

    #[test]
    fn parse_host_binary_names_excludes_source_built_lists() {
        // HOST_BINARIES are `-p mvm-build` bins; the SourceBuiltBinary lists
        // that follow carry their own `package` and are built separately, so
        // their `name:`s must not be swept into the per-bin loop.
        let src = r#"
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary { name: "mvm-host-vm-init", install_path: "/sbin/mvm-host-vm-init", mode: 0o755 },
    HostBinary { name: "mvm-builderd", install_path: "/sbin/mvm-builderd", mode: 0o755 },
];
pub const SEED_BINARIES: &[&str] = &["stage0-init"];
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[SourceBuiltBinary {
    package: "mvm-guest-helpers",
    name: "mvm-egress-client",
}];
"#;
        assert_eq!(
            parse_host_binary_names(src),
            vec!["mvm-host-vm-init".to_string(), "mvm-builderd".to_string()]
        );
        assert!(!parse_host_binary_names(src).contains(&"mvm-egress-client".to_string()));
    }

    #[test]
    fn hostd_helpers_include_substitution_endpoint_and_tunnel_worker() {
        let specs = aux_helper_specs("macos", "aarch64", false, false);
        assert!(
            specs
                .iter()
                .any(|spec| spec.bin == "mvm-substitution-endpoint")
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.bin == "mvm-network-tunnel-worker")
        );
    }

    #[test]
    fn skip_flag_disables_every_aux_helper() {
        assert!(aux_helper_specs("macos", "aarch64", true, true).is_empty());
        assert!(should_skip_aux_helpers(Some("1")));
        assert!(!should_skip_aux_helpers(None));
    }
}
