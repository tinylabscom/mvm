//! Pure selection logic for the native per-VM host helpers that mvm-cli's build
//! script compiles up front. Kept I/O-free so the host-conditional
//! selection rules are unit-tested without running a real build.

use std::path::{Path, PathBuf};

/// A native host helper the build script compiles for this host, so that
/// `cargo run` produces it before `mvmctl` executes (cargo on its own builds
/// only the run target, never sibling `[[bin]]`s in other crates).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuxHelperSpec {
    pub package: String,
    pub bin: String,
    pub features: Vec<String>,
}

/// One `PER_VM_HOST_BINARIES` entry, parsed out of the manifest source.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PerVmEntry {
    pub package: String,
    pub name: String,
    pub features: String,
    pub scope: String,
}

/// Parse `PER_VM_HOST_BINARIES` out of the text of
/// `crates/mvm-cli/src/host_binaries/manifest.rs`.
///
/// Text-parsed rather than imported because a build script cannot depend on
/// the crate it is building; this mirrors how `build.rs` already reads
/// `HOST_BINARIES` and `SEED_BINARIES` from the same file, and keeps this
/// module I/O-free so the selection rules stay unit-testable.
pub(crate) fn parse_per_vm_binaries(src: &str) -> Vec<PerVmEntry> {
    let Some(i) = src.find("PER_VM_HOST_BINARIES") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let (mut package, mut name, mut features) = (None, None, None);
    for line in src[i..].lines() {
        if let Some(v) = extract_quoted_after(line, "package:") {
            package = Some(v);
        }
        if let Some(v) = extract_quoted_after(line, "name:") {
            name = Some(v);
        }
        if let Some(v) = extract_quoted_after(line, "features:") {
            features = Some(v);
        }
        if let Some(scope) = line.trim().strip_prefix("scope: PerVmScope::") {
            let scope = scope.trim_end_matches(',').trim().to_string();
            if let (Some(package), Some(name), Some(features)) =
                (package.take(), name.take(), features.take())
            {
                out.push(PerVmEntry {
                    package,
                    name,
                    features,
                    scope,
                });
            }
        }
        // The const ends at the closing `];` in column 0.
        if line.starts_with("];") && !out.is_empty() {
            break;
        }
    }
    out
}

/// Whether a registry entry applies to this host, given its scope.
pub(crate) fn scope_applies(
    scope: &str,
    target_os: &str,
    target_arch: &str,
    libkrun_present: bool,
) -> bool {
    match scope {
        "Always" => true,
        "MacOsAarch64" => target_os == "macos" && target_arch == "aarch64",
        "RequiresLibkrun" => libkrun_present,
        _ => false,
    }
}

/// The helpers to build for `(target_os, target_arch)`, selected from the
/// canonical `PER_VM_HOST_BINARIES` registry. `manifest_src` is the text of
/// `crates/mvm-cli/src/host_binaries/manifest.rs`.
pub(crate) fn aux_helper_specs_from(
    manifest_src: &str,
    target_os: &str,
    target_arch: &str,
    libkrun_present: bool,
) -> Vec<AuxHelperSpec> {
    parse_per_vm_binaries(manifest_src)
        .into_iter()
        .filter(|e| scope_applies(&e.scope, target_os, target_arch, libkrun_present))
        .map(|e| AuxHelperSpec {
            package: e.package,
            bin: e.name,
            features: if e.features.is_empty() {
                Vec::new()
            } else {
                e.features.split(',').map(str::to_string).collect()
            },
        })
        .collect()
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

/// Return a nested Cargo target shared by every feature fingerprint of the
/// same outer profile. Cargo gives each build-script fingerprint a different
/// `OUT_DIR`; placing nested builds directly below it makes identical embedded
/// binaries rebuild for clippy, feature tests, and examples. Their common
/// `target/<profile>/build` parent is still isolated from the outer Cargo lock
/// while allowing the nested Cargo invocation to reuse its own fingerprints.
pub(crate) fn shared_nested_target_dir(out_dir: &Path) -> PathBuf {
    let build_dir = out_dir
        .parent()
        .and_then(Path::parent)
        .expect("Cargo OUT_DIR must end in build/<package-fingerprint>/out");
    build_dir.join("mvm-cli-nested-target")
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
    fn parser_reads_package_name_features_and_scope() {
        let src = r#"
pub const PER_VM_HOST_BINARIES: &[PerVmBinary] = &[
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-network-endpoint",
        features: "",
        scope: PerVmScope::Always,
    },
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-libkrun-supervisor",
        features: "libkrun-sys",
        scope: PerVmScope::RequiresLibkrun,
    },
];
"#;
        let got = parse_per_vm_binaries(src);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "mvm-network-endpoint");
        assert_eq!(got[0].scope, "Always");
        assert_eq!(got[1].features, "libkrun-sys");
        assert_eq!(got[1].scope, "RequiresLibkrun");
    }

    #[test]
    fn parser_yields_nothing_when_the_const_is_absent() {
        assert!(parse_per_vm_binaries("fn main() {}").is_empty());
    }

    #[test]
    fn an_unknown_scope_selects_nothing() {
        assert!(!scope_applies("SomethingNew", "linux", "x86_64", true));
    }

    #[test]
    fn nested_target_is_shared_across_package_fingerprints() {
        let first = Path::new("/target/debug/build/mvm-cli-first/out");
        let second = Path::new("/target/debug/build/mvm-cli-second/out");
        assert_eq!(
            shared_nested_target_dir(first),
            shared_nested_target_dir(second)
        );
    }
}
