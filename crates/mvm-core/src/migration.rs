use anyhow::{Result, bail};

/// A versioned migration function: takes a raw JSON value at schema version N
/// and returns a transformed value at schema version N+1.
pub type MigrateFn = fn(serde_json::Value) -> Result<serde_json::Value>;

/// Apply a chain of migrations to a raw JSON value.
///
/// Migrations are indexed by the version they *produce*: `migrations[0]`
/// upgrades version 0 → 1, `migrations[1]` upgrades version 1 → 2, etc.
///
/// - If `from == to`, the value is returned unchanged.
/// - If `from > to`, an error is returned (downgrade not supported).
/// - If the required migration functions are not all present, an error is returned.
pub fn migrate(
    mut value: serde_json::Value,
    from: u32,
    to: u32,
    migrations: &[MigrateFn],
) -> Result<serde_json::Value> {
    if from > to {
        bail!(
            "cannot downgrade schema from version {} to {} (downgrade not supported)",
            from,
            to
        );
    }
    for version in from..to {
        let idx = version as usize;
        if idx >= migrations.len() {
            bail!(
                "no migration available from version {} to {} (only {} migration(s) defined)",
                version,
                version + 1,
                migrations.len()
            );
        }
        value = migrations[idx](value)?;
    }
    Ok(value)
}

/// Read the `schema_version` field from a raw JSON object value.
/// Returns 0 if the field is absent (pre-versioned files).
pub fn schema_version_of(value: &serde_json::Value) -> u32 {
    value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bump_version(mut v: serde_json::Value) -> Result<serde_json::Value> {
        v["schema_version"] = json!(
            v.get("schema_version")
                .and_then(|s| s.as_u64())
                .unwrap_or(0)
                + 1
        );
        Ok(v)
    }

    fn add_field(mut v: serde_json::Value) -> Result<serde_json::Value> {
        v["new_field"] = json!("added");
        Ok(v)
    }

    #[test]
    fn migrate_noop() {
        let value = json!({"schema_version": 1, "mode": "dev"});
        let result = migrate(value.clone(), 1, 1, &[]).unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn migrate_one_step() {
        let value = json!({"schema_version": 0, "mode": "dev"});
        let result = migrate(value, 0, 1, &[bump_version as MigrateFn]).unwrap();
        assert_eq!(result["schema_version"], 1);
        assert_eq!(result["mode"], "dev");
    }

    #[test]
    fn migrate_chain() {
        let value = json!({"schema_version": 0, "mode": "flake"});
        let result = migrate(
            value,
            0,
            2,
            &[bump_version as MigrateFn, add_field as MigrateFn],
        )
        .unwrap();
        assert_eq!(result["schema_version"], 1); // bump_version sets it to 1
        assert_eq!(result["new_field"], "added");
        assert_eq!(result["mode"], "flake");
    }

    #[test]
    fn migrate_downgrade_err() {
        let value = json!({"schema_version": 2});
        let err = migrate(value, 2, 1, &[]).unwrap_err();
        assert!(err.to_string().contains("downgrade not supported"));
    }

    #[test]
    fn migrate_missing_migration_err() {
        let value = json!({"schema_version": 0});
        // Asked to go 0 → 2 but only one migration provided
        let err = migrate(value, 0, 2, &[bump_version as MigrateFn]).unwrap_err();
        assert!(err.to_string().contains("no migration available"));
    }

    #[test]
    fn schema_version_of_present() {
        let v = json!({"schema_version": 3, "mode": "dev"});
        assert_eq!(schema_version_of(&v), 3);
    }

    #[test]
    fn schema_version_of_missing() {
        let v = json!({"mode": "dev"});
        assert_eq!(schema_version_of(&v), 0);
    }

    #[test]
    fn migrate_run_info_from_unversioned() {
        // A JSON blob without schema_version (old file format) should be
        // treated as version 0. With an empty migrations list (0 → 0 is a
        // noop), it deserialises cleanly.
        let old_json = json!({"mode": "dev", "guest_user": "ubuntu"});
        let from = schema_version_of(&old_json); // 0
        let result = migrate(old_json.clone(), from, 0, &[]).unwrap();
        // No migrations needed — value is unchanged
        assert_eq!(result["mode"], "dev");
        assert_eq!(result["guest_user"], "ubuntu");
    }
}
