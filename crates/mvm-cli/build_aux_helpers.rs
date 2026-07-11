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

#[cfg(test)]
mod tests {
    use super::*;

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
