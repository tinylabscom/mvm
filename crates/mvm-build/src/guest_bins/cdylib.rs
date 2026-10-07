//! The guest shared objects this workspace builds, and the names a guest
//! loader finds them by.
//!
//! This table is the one place the mapping lives. The guest-bins build reads it
//! to know what to compile and how to install each object, and the GPU
//! end-to-end witness reads it to stage the shims it boots with.

/// One `cdylib` a guest loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestCdylib {
    /// The Cargo package that builds it.
    pub package: &'static str,
    /// The package's `[lib] name`, which decides cargo's output file name.
    pub lib_name: &'static str,
    /// The name the object is installed under — the soname a workload links
    /// against, or the file name an SDK `dlopen`s.
    pub soname: &'static str,
}

impl GuestCdylib {
    /// The file cargo writes into `target/<triple>/release/`.
    pub fn cargo_output_file(&self) -> String {
        format!("lib{}.so", self.lib_name)
    }
}

/// The in-guest host-services C ABI every language SDK loads.
pub const HOST_SERVICES_CDYLIB: GuestCdylib = GuestCdylib {
    package: "mvm-host-services",
    lib_name: "mvm_host_services",
    soname: "libmvm_host_services.so",
};

/// The drop-in CUDA driver, CUDA runtime and NVML replacements that forward
/// to the per-VM host GPU endpoint.
pub const GPU_SHIM_CDYLIBS: [GuestCdylib; 3] = [
    GuestCdylib {
        package: "mvm-gpu-cuda-shim",
        lib_name: "cuda",
        soname: "libcuda.so.1",
    },
    GuestCdylib {
        package: "mvm-gpu-cudart-shim",
        lib_name: "cudart",
        soname: "libcudart.so",
    },
    GuestCdylib {
        package: "mvm-gpu-nvml-shim",
        lib_name: "nvidia_ml",
        soname: "libnvidia-ml.so.1",
    },
];

/// Every guest shared object, host services first.
pub fn guest_cdylibs() -> [GuestCdylib; 4] {
    let [cuda, cudart, nvml] = GPU_SHIM_CDYLIBS;
    [HOST_SERVICES_CDYLIB, cuda, cudart, nvml]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn workspace_root() -> std::path::PathBuf {
        crate::guest_agent_build::source_workspace_from(std::path::Path::new(env!(
            "CARGO_MANIFEST_DIR"
        )))
        .expect("the test runs inside the mvm workspace")
    }

    /// `crate => (lib_name, soname)` from the Nix recipe's `shims` attrset.
    fn nix_shims(recipe: &str) -> BTreeMap<String, (String, String)> {
        let start = recipe
            .find("shims = {")
            .expect("mvm-gpu-shims.nix declares a `shims` attrset");
        let body = &recipe[start..];
        let body = &body[..body.find("\n  };").expect("the attrset closes")];
        let quoted = |line: &str| line.split('"').nth(1).map(str::to_string);
        let mut shims = BTreeMap::new();
        let mut current: Option<(String, Option<String>)> = None;
        for line in body.lines().map(str::trim) {
            if line.starts_with("\"mvm-gpu-") {
                current = quoted(line).map(|package| (package, None));
            } else if line.starts_with("libName") {
                if let Some((_, lib_name)) = current.as_mut() {
                    *lib_name = quoted(line);
                }
            } else if line.starts_with("soname")
                && let Some((package, Some(lib_name))) = current.take()
            {
                let soname = quoted(line).expect("a quoted soname");
                shims.insert(package, (lib_name, soname));
            }
        }
        shims
    }

    /// While the Nix recipe still builds the shims for the image flakes, the
    /// two must install the same objects under the same names. The recipe is
    /// read unconditionally: when it is deleted, this test goes with it rather
    /// than passing with nothing to compare.
    #[test]
    fn the_gpu_shim_table_agrees_with_the_nix_recipe() {
        let recipe_path = workspace_root().join("nix/packages/mvm-gpu-shims.nix");
        let recipe = std::fs::read_to_string(&recipe_path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}; if the recipe is gone, delete this test with it",
                recipe_path.display()
            )
        });
        let from_nix = nix_shims(&recipe);
        let from_table: BTreeMap<String, (String, String)> = GPU_SHIM_CDYLIBS
            .iter()
            .map(|c| {
                (
                    c.package.to_string(),
                    (c.lib_name.to_string(), c.soname.to_string()),
                )
            })
            .collect();
        assert_eq!(from_nix.len(), 3, "parsed {from_nix:?} from the recipe");
        assert_eq!(from_table, from_nix);
    }

    #[test]
    fn each_package_declares_the_lib_name_the_table_names() {
        for cdylib in guest_cdylibs() {
            let manifest = workspace_root()
                .join("crates")
                .join(cdylib.package)
                .join("Cargo.toml");
            let manifest: toml::Value = std::fs::read_to_string(&manifest)
                .expect("read the package manifest")
                .parse()
                .expect("parse the package manifest");
            let lib_name = manifest
                .get("lib")
                .and_then(|lib| lib.get("name"))
                .and_then(toml::Value::as_str)
                .unwrap_or(cdylib.package)
                .replace('-', "_");
            assert_eq!(lib_name, cdylib.lib_name, "{}", cdylib.package);
        }
    }

    #[test]
    fn cargo_names_the_output_after_the_lib_name() {
        assert_eq!(
            HOST_SERVICES_CDYLIB.cargo_output_file(),
            "libmvm_host_services.so"
        );
        assert_eq!(GPU_SHIM_CDYLIBS[2].cargo_output_file(), "libnvidia_ml.so");
    }
}
