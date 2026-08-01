//! Pure selection logic for the native per-VM host helpers that mvm-cli's build
//! script compiles up front. Kept I/O-free so the host-conditional
//! selection rules are unit-tested without running a real build.

use std::path::{Path, PathBuf};

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
/// is installed. The libkrun supervisor is included only where libkrun is
/// present because it links `-lkrun`; the HVF supervisor only on macOS/aarch64.
pub(crate) fn aux_helper_specs(
    target_os: &str,
    target_arch: &str,
    libkrun_present: bool,
) -> Vec<AuxHelperSpec> {
    let mut specs = vec![AuxHelperSpec {
        package: "mvm-hostd",
        bin: "mvm-substitution-endpoint",
        features: &[],
    }];
    if target_os == "macos" && target_arch == "aarch64" {
        specs.push(AuxHelperSpec {
            package: "mvm-hostd",
            bin: "mvm-hvf-supervisor",
            features: &[],
        });
    }
    if libkrun_present {
        specs.push(AuxHelperSpec {
            package: "mvm-hostd",
            bin: "mvm-libkrun-supervisor",
            features: &["libkrun-sys"],
        });
    }
    specs
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
    fn hostd_helpers_include_substitution_endpoint() {
        let specs = aux_helper_specs("macos", "aarch64", false);
        assert!(
            specs
                .iter()
                .any(|spec| spec.bin == "mvm-substitution-endpoint")
        );
    }

    #[test]
    fn helper_specs_are_never_globally_skipped() {
        assert!(!aux_helper_specs("linux", "x86_64", false).is_empty());
        assert!(!aux_helper_specs("macos", "aarch64", true).is_empty());
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
