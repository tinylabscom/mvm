//! Legacy name-keyed template CRUD: create/load/list/delete a
//! `~/.mvm/templates/<name>/template.json` record.

use anyhow::{Context, Result};
use mvm_core::naming::validate_template_name;
use mvm_core::template::{TemplateSpec, template_dir, template_spec_path};
use tracing::instrument;

fn validate_legacy_template_name(id: &str) -> Result<()> {
    validate_template_name(id).with_context(|| format!("Invalid template name: {id:?}"))
}

#[instrument(skip_all, fields(template_id = %spec.template_id))]
pub fn template_create(spec: &TemplateSpec) -> Result<()> {
    validate_legacy_template_name(&spec.template_id)?;
    let dir = template_dir(&spec.template_id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create template directory {}", dir))?;
    let path = template_spec_path(&spec.template_id);
    let json = serde_json::to_string_pretty(spec)?;
    std::fs::write(&path, json)
        .with_context(|| format!("Failed to write template spec {}", path))?;
    Ok(())
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_load(id: &str) -> Result<TemplateSpec> {
    validate_legacy_template_name(id)?;
    let path = template_spec_path(id);
    // Read directly from host filesystem — ~/.mvm/ resolves to $HOME/.mvm
    // on the host (no VM-nesting layer to route through).
    let data = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to load template {} (does it exist? try `mvm template list`)",
            id
        )
    })?;
    let spec: TemplateSpec =
        serde_json::from_str(&data).with_context(|| format!("Corrupt template {}", id))?;
    Ok(spec)
}

#[instrument(skip_all)]
pub fn template_list() -> Result<Vec<String>> {
    let base = mvm_core::template::templates_base_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to list templates dir {}", base));
        }
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    Ok(names)
}

#[instrument(skip_all, fields(template_id = id, force))]
pub fn template_delete(id: &str, force: bool) -> Result<()> {
    let dir = template_dir(id);
    let path = std::path::Path::new(&dir);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && force => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to delete template {}", id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn test_template_spec(template_id: &str) -> TemplateSpec {
        TemplateSpec {
            schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
            template_id: template_id.to_string(),
            flake_ref: ".".to_string(),
            profile: "default".to_string(),
            role: "test".to_string(),
            vcpus: 1,
            mem_mib: 256,
            mem_initial_mib: None,
            data_disk_mib: 0,
            created_at: "2026-06-16T00:00:00Z".to_string(),
            updated_at: "2026-06-16T00:00:00Z".to_string(),
            default_network_policy: None,
        }
    }

    #[test]
    fn template_load_rejects_traversal_identifier() {
        let err = template_load("../../etc/x").expect_err("traversal id must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("template name"),
            "expected template-name validation error, got: {msg}"
        );
    }

    #[test]
    fn template_create_rejects_traversal_identifier_before_writing() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let err = template_create(&test_template_spec("../../etc/x"))
            .expect_err("traversal template id must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("template name"),
            "expected template-name validation error, got: {msg}"
        );
        assert!(
            !tmp.path().join("templates").exists(),
            "invalid template id must not create template directories"
        );
    }

    #[test]
    fn template_create_then_load_accepts_valid_template_name() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let spec = test_template_spec("valid-template");
        template_create(&spec).expect("create valid template");
        let loaded = template_load("valid-template").expect("load valid template");
        assert_eq!(loaded.template_id, "valid-template");
    }
}
