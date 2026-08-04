//! Persistent-machine secret references.
//!
//! A persistent machine that consumes a secret records a *reference* — the
//! secret's scope + name plus placeholder/usage metadata — in a sidecar next
//! to its `machine.json`. The sidecar carries no secret bytes, ever: the
//! value stays in the encrypted store and only the host-side substitution
//! path resolves it at egress. The reference record is what lets the service
//! (a) refuse deleting a secret a machine still depends on, and (b) validate
//! every reference at admission time before the machine boots.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::atomic_io::atomic_write;
use mvm_core::crypto::keystore::validate_shell_id;
use serde::{Deserialize, Serialize};

/// Sidecar filename inside a machine's state dir, next to `machine.json`.
pub const MACHINE_SECRET_REFS_FILENAME: &str = "secret-refs.json";

/// Schema version stamped into every sidecar.
pub const MACHINE_SECRET_REFS_SCHEMA_VERSION: u32 = 1;

/// One machine → secret reference: scope + name plus non-secret usage
/// metadata (the guest-facing placeholder variable and the destinations the
/// workload intends to reach). Never carries a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSecretRef {
    /// Scope (tenant namespace) the secret lives in.
    pub tenant: String,
    /// Secret name inside that scope.
    pub name: String,
    /// Guest-facing env var that receives the opaque placeholder at boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder_var: Option<String>,
    /// Destinations the workload intends to reach with the substituted
    /// credential. Validated against the binding allow-list at admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<String>,
}

/// The persisted sidecar: every secret reference one machine declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSecretRefSet {
    pub schema_version: u32,
    /// Machine name the record belongs to (mirrors the directory name).
    pub machine: String,
    /// RFC 3339 timestamp of the last write.
    pub recorded_at: String,
    #[serde(default)]
    pub references: Vec<MachineSecretRef>,
}

fn sidecar_path(machines_root: &Path, machine: &str) -> Result<PathBuf> {
    mvm_core::naming::validate_id(machine, "machine name")?;
    Ok(machines_root
        .join(machine)
        .join(MACHINE_SECRET_REFS_FILENAME))
}

fn machine_spec_exists(machines_root: &Path, machine: &str) -> bool {
    machines_root.join(machine).join("machine.json").exists()
}

/// Persist the full reference set for `machine`, replacing any previous
/// record. Each reference's scope and name are validated up front so a
/// malformed record never lands on disk.
pub fn record_refs(machines_root: &Path, machine: &str, refs: &[MachineSecretRef]) -> Result<()> {
    for r in refs {
        validate_shell_id(&r.tenant)
            .with_context(|| format!("invalid secret scope in reference: {:?}", r.tenant))?;
        validate_shell_id(&r.name)
            .with_context(|| format!("invalid secret name in reference: {:?}", r.name))?;
    }
    let path = sidecar_path(machines_root, machine)?;
    let record = MachineSecretRefSet {
        schema_version: MACHINE_SECRET_REFS_SCHEMA_VERSION,
        machine: machine.to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        references: refs.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&record).context("serializing secret references")?;
    atomic_write(&path, &bytes)
        .with_context(|| format!("writing secret references {}", path.display()))
}

/// Remove `machine`'s reference record. Idempotent — an absent sidecar is
/// not an error.
pub fn clear_refs(machines_root: &Path, machine: &str) -> Result<()> {
    let path = sidecar_path(machines_root, machine)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("removing {}", path.display()))),
    }
}

/// Load `machine`'s reference record, if one exists.
pub fn load_refs(machines_root: &Path, machine: &str) -> Result<Option<MachineSecretRefSet>> {
    let path = sidecar_path(machines_root, machine)?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            let record = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing secret references {}", path.display()))?;
            Ok(Some(record))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    }
}

/// Every existing persistent machine (one with a `machine.json`) whose
/// reference record names `(tenant, name)`. A malformed sidecar propagates
/// as an error — deletion decisions must fail closed on records we cannot
/// read, never silently skip them.
pub fn machines_referencing(machines_root: &Path, tenant: &str, name: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(machines_root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => {
            return Err(anyhow::Error::from(e)
                .context(format!("reading machines root {}", machines_root.display())));
        }
    };
    for entry in entries {
        let entry = entry.context("reading machines root entry")?;
        if !entry.path().is_dir() {
            continue;
        }
        let Some(machine) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        // Only machines that still exist can reference a secret; a leftover
        // sidecar without a spec belongs to a removed machine.
        if !machine_spec_exists(machines_root, &machine) {
            continue;
        }
        let Some(record) = load_refs(machines_root, &machine)? else {
            continue;
        };
        if record
            .references
            .iter()
            .any(|r| r.tenant == tenant && r.name == name)
        {
            out.push(machine);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn oref(tenant: &str, name: &str) -> MachineSecretRef {
        MachineSecretRef {
            tenant: tenant.into(),
            name: name.into(),
            placeholder_var: Some("OPENAI_API_KEY".into()),
            destinations: vec!["api.openai.com".into()],
        }
    }

    fn create_machine(root: &Path, machine: &str) {
        let dir = root.join(machine);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("machine.json"), b"{}").unwrap();
    }

    #[test]
    fn record_then_load_roundtrips_metadata() {
        let tmp = tempdir().unwrap();
        create_machine(tmp.path(), "web");
        record_refs(tmp.path(), "web", &[oref("local", "openai")]).unwrap();
        let record = load_refs(tmp.path(), "web").unwrap().unwrap();
        assert_eq!(record.machine, "web");
        assert_eq!(record.schema_version, MACHINE_SECRET_REFS_SCHEMA_VERSION);
        assert_eq!(record.references, vec![oref("local", "openai")]);
        assert!(!record.recorded_at.is_empty());
    }

    #[test]
    fn sidecar_carries_reference_metadata_never_values() {
        let tmp = tempdir().unwrap();
        create_machine(tmp.path(), "web");
        record_refs(tmp.path(), "web", &[oref("local", "openai")]).unwrap();
        let raw =
            std::fs::read_to_string(tmp.path().join("web").join(MACHINE_SECRET_REFS_FILENAME))
                .unwrap();
        // Names + usage metadata only; the record shape has no value slot.
        assert!(raw.contains("\"openai\""));
        assert!(raw.contains("\"placeholder_var\""));
        assert!(
            !raw.contains("\"value\""),
            "sidecar must not carry a value field: {raw}"
        );
    }

    #[test]
    fn machines_referencing_finds_only_matching_machines() {
        let tmp = tempdir().unwrap();
        create_machine(tmp.path(), "web");
        create_machine(tmp.path(), "worker");
        record_refs(tmp.path(), "web", &[oref("local", "openai")]).unwrap();
        record_refs(tmp.path(), "worker", &[oref("local", "aws")]).unwrap();

        let hits = machines_referencing(tmp.path(), "local", "openai").unwrap();
        assert_eq!(hits, vec!["web"]);
        assert!(
            machines_referencing(tmp.path(), "local", "absent")
                .unwrap()
                .is_empty()
        );
        // Same name in a different scope is a different secret.
        assert!(
            machines_referencing(tmp.path(), "acme", "openai")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sidecar_without_machine_spec_does_not_count() {
        let tmp = tempdir().unwrap();
        // Sidecar present but the machine.json is gone: the machine no
        // longer exists, so its stale record must not pin the secret.
        std::fs::create_dir_all(tmp.path().join("gone")).unwrap();
        let record = MachineSecretRefSet {
            schema_version: MACHINE_SECRET_REFS_SCHEMA_VERSION,
            machine: "gone".into(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
            references: vec![oref("local", "openai")],
        };
        std::fs::write(
            tmp.path().join("gone").join(MACHINE_SECRET_REFS_FILENAME),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert!(
            machines_referencing(tmp.path(), "local", "openai")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_sidecar_fails_closed() {
        let tmp = tempdir().unwrap();
        create_machine(tmp.path(), "web");
        std::fs::write(
            tmp.path().join("web").join(MACHINE_SECRET_REFS_FILENAME),
            b"not-json",
        )
        .unwrap();
        assert!(machines_referencing(tmp.path(), "local", "openai").is_err());
    }

    #[test]
    fn clear_refs_is_idempotent() {
        let tmp = tempdir().unwrap();
        create_machine(tmp.path(), "web");
        record_refs(tmp.path(), "web", &[oref("local", "openai")]).unwrap();
        clear_refs(tmp.path(), "web").unwrap();
        assert!(load_refs(tmp.path(), "web").unwrap().is_none());
        clear_refs(tmp.path(), "web").unwrap(); // second clear: no error
    }

    #[test]
    fn record_refs_rejects_unsafe_scope_or_name() {
        let tmp = tempdir().unwrap();
        create_machine(tmp.path(), "web");
        assert!(record_refs(tmp.path(), "web", &[oref("../etc", "k")]).is_err());
        assert!(record_refs(tmp.path(), "web", &[oref("local", "../escape")]).is_err());
        assert!(record_refs(tmp.path(), "../web", &[oref("local", "k")]).is_err());
    }

    #[test]
    fn empty_root_yields_no_references() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert!(
            machines_referencing(&missing, "local", "openai")
                .unwrap()
                .is_empty()
        );
    }
}
