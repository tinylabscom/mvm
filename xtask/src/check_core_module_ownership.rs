//! Keep single-consumer code with its owner and retired `mvm-core` modules gone.

use anyhow::{Result, bail};
use std::path::Path;

const RETIRED_MODULES: &[&str] = &[
    "action_state",
    "at_rest",
    "conformance_badge",
    "egress_handler",
    "ingress_redaction",
    "init_supervisor",
    "launch_metadata",
    "memory_budget",
    "metering",
];

const OWNED_MODULES: &[(&str, &str)] = &[
    ("egress_broker", "crates/mvm-hostd/src/egress_broker.rs"),
    (
        "extension_admission",
        "crates/mvm-hostd/src/extension_admission.rs",
    ),
    ("grants_resolve", "crates/mvm-client/src/grants_resolve.rs"),
    ("kernel_artifact", "crates/mvm-build/src/kernel_artifact.rs"),
    ("page_merge", "crates/mvm-conformance/src/page_merge.rs"),
    ("rate_limit", "crates/mvm-hostd/src/rate_limit.rs"),
    ("run_sidecars", "crates/mvm-backends/src/run_sidecars.rs"),
    ("socks5_udp", "crates/mvm-agentd/src/socks5_udp.rs"),
];

pub fn run(workspace: &Path) -> Result<()> {
    let core_src = workspace.join("crates/mvm-core/src");
    let core_lib = std::fs::read_to_string(core_src.join("lib.rs"))?;

    for module in RETIRED_MODULES {
        reject_core_module(&core_src, &core_lib, module, "retired")?;
    }

    for (module, owner_path) in OWNED_MODULES {
        reject_core_module(&core_src, &core_lib, module, "single-consumer")?;
        if !workspace.join(owner_path).is_file() {
            bail!(
                "single-consumer module `{module}` must live at {owner_path}; keep it with its consuming crate"
            );
        }
    }

    eprintln!(
        "check-core-module-ownership: {} retired modules absent; {} single-consumer modules owned by their consumers",
        RETIRED_MODULES.len(),
        OWNED_MODULES.len(),
    );
    Ok(())
}

fn reject_core_module(core_src: &Path, core_lib: &str, module: &str, reason: &str) -> Result<()> {
    let file = core_src.join(format!("{module}.rs"));
    let directory = core_src.join(module).join("mod.rs");
    let export = format!("pub mod {module};");
    if file.exists() || directory.exists() || core_lib.lines().any(|line| line.trim() == export) {
        bail!(
            "{reason} module `{module}` must not live in mvm-core; remove it or place it with its sole consuming crate"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("test path has a parent"))
            .expect("create test directory");
        std::fs::write(path, contents).expect("write test fixture");
    }

    fn compliant_workspace() -> tempfile::TempDir {
        let workspace = tempfile::tempdir().expect("tempdir");
        write(&workspace.path().join("crates/mvm-core/src/lib.rs"), "");
        for (_, owner_path) in OWNED_MODULES {
            write(&workspace.path().join(owner_path), "");
        }
        workspace
    }

    #[test]
    fn accepts_retired_absence_and_consumer_ownership() {
        let workspace = compliant_workspace();
        run(workspace.path()).expect("compliant ownership should pass");
    }

    #[test]
    fn rejects_a_retired_module_file() {
        let workspace = compliant_workspace();
        write(
            &workspace.path().join("crates/mvm-core/src/metering.rs"),
            "",
        );
        let error = run(workspace.path()).expect_err("retired module must fail");
        assert!(error.to_string().contains("retired module `metering`"));
    }

    #[test]
    fn rejects_a_legacy_core_export() {
        let workspace = compliant_workspace();
        write(
            &workspace.path().join("crates/mvm-core/src/lib.rs"),
            "pub mod rate_limit;\n",
        );
        let error = run(workspace.path()).expect_err("legacy export must fail");
        assert!(
            error
                .to_string()
                .contains("single-consumer module `rate_limit`")
        );
    }

    #[test]
    fn rejects_a_missing_owner_module() {
        let workspace = compliant_workspace();
        std::fs::remove_file(workspace.path().join("crates/mvm-agentd/src/socks5_udp.rs"))
            .expect("remove owner fixture");
        let error = run(workspace.path()).expect_err("missing owner must fail");
        assert!(
            error
                .to_string()
                .contains("crates/mvm-agentd/src/socks5_udp.rs")
        );
    }
}
