use anyhow::{Context, Result, bail};
use mvm_core::domain::instance::InstanceReadiness;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Persistent registry mapping VM names to their runtime directories.
///
/// Stored as `{mvm_share_dir}/vm-names.json`. Enables reliable name-based
/// lookups for `mvmctl logs`, `mvmctl forward`, `mvmctl down`, etc.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmNameRegistry {
    /// Map from VM name to registration info.
    pub vms: HashMap<String, VmRegistration>,
}

/// Registration info for a running or recently-running VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRegistration {
    /// Absolute path to the VM's runtime directory.
    pub vm_dir: String,
    /// Network name the VM is attached to.
    pub network: String,
    /// Guest IP address.
    pub guest_ip: Option<String>,
    /// VM slot index.
    pub slot_index: u8,
    /// RFC 3339 timestamp of registration.
    pub registered_at: String,
    /// Caller-supplied metadata (validated via
    /// `mvm_core::crypto::policy::InputValidator::validate_tag_map`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    /// RFC 3339 wall-clock time at which the supervisor reaper should
    /// tear this VM down. `None` = no TTL.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// When `true`, connecting to a sleeping VM auto-resumes it.
    #[serde(default = "default_auto_resume")]
    pub auto_resume: bool,
    /// `true` while the VM has a sealed instance snapshot at
    /// `~/.mvm/instances/<name>/snapshot/` and is not currently
    /// running. Set by `mvmctl pause`, cleared by `mvmctl resume`
    /// or `mvmctl snapshot rm`. Distinct from the backends' own
    /// "running"/"stopped" reports — those describe the live VM,
    /// while `paused` describes the sealed-snapshot lifecycle.
    /// W1 / A4.
    #[serde(default)]
    pub paused: bool,
    /// Finer-grained host-observed readiness (ADR-053 §3 / plan 74
    /// W2). Updated by `mvmctl up` as each launch milestone is
    /// reached (`LaunchAccepted` → `AgentConnecting` → `AgentReady`,
    /// with the rest of the taxonomy wiring in subsequent PRs).
    /// `None` on legacy records and on VMs that haven't yet been
    /// touched by a readiness-aware launch path.
    #[serde(default)]
    pub readiness: Option<InstanceReadiness>,
    /// RFC 3339 timestamp of the last `readiness` change. Paired
    /// with `readiness` — both are `Some` or both are `None`.
    #[serde(default)]
    pub last_readiness_change_at: Option<String>,
}

fn default_auto_resume() -> bool {
    true
}

impl VmNameRegistry {
    /// Load the registry from disk. Returns an empty registry if the file
    /// doesn't exist yet.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read VM name registry: {}", path.display()))?;
        let registry: Self = serde_json::from_str(&text)
            .with_context(|| format!("Failed to parse VM name registry: {}", path.display()))?;
        Ok(registry)
    }

    /// Save the registry to disk, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text =
            serde_json::to_string_pretty(self).context("Failed to serialize VM name registry")?;
        mvm_core::atomic_io::atomic_write(path, text.as_bytes())
            .with_context(|| format!("Failed to write VM name registry: {}", path.display()))
    }

    /// Register a VM name. Returns an error if the name is already taken.
    pub fn register(
        &mut self,
        name: &str,
        vm_dir: &str,
        network: &str,
        guest_ip: Option<&str>,
        slot_index: u8,
    ) -> Result<()> {
        self.register_with_metadata(RegisterParams {
            name,
            vm_dir,
            network,
            guest_ip,
            slot_index,
            tags: BTreeMap::new(),
            expires_at: None,
            auto_resume: true,
        })
    }

    /// Register a VM with the full set of sandbox metadata fields.
    pub fn register_with_metadata(&mut self, params: RegisterParams<'_>) -> Result<()> {
        if self.vms.contains_key(params.name) {
            bail!("VM name {:?} is already registered", params.name);
        }
        let timestamp = mvm_core::time::utc_now();
        self.vms.insert(
            params.name.to_string(),
            VmRegistration {
                vm_dir: params.vm_dir.to_string(),
                network: params.network.to_string(),
                guest_ip: params.guest_ip.map(str::to_owned),
                slot_index: params.slot_index,
                registered_at: timestamp,
                tags: params.tags,
                expires_at: params.expires_at,
                auto_resume: params.auto_resume,
                paused: false,
                readiness: None,
                last_readiness_change_at: None,
            },
        );
        Ok(())
    }

    /// Mutate an existing registration's TTL. Returns Ok(true) if updated,
    /// Ok(false) if the name is unknown.
    pub fn set_expires_at(&mut self, name: &str, expires_at: Option<String>) -> Result<bool> {
        match self.vms.get_mut(name) {
            Some(reg) => {
                reg.expires_at = expires_at;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Flip the `paused` flag on an existing registration. Returns
    /// `Ok(true)` if updated, `Ok(false)` if the name is unknown.
    /// Used by `mvmctl pause` / `mvmctl resume` to track the
    /// sealed-snapshot lifecycle alongside backends' own
    /// running/stopped state.
    pub fn set_paused(&mut self, name: &str, paused: bool) -> Result<bool> {
        match self.vms.get_mut(name) {
            Some(reg) => {
                reg.paused = paused;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Record a host-observed readiness milestone (ADR-053 §3 /
    /// plan 74 W2). Returns `Ok(true)` if updated, `Ok(false)` if
    /// the name is unknown. Updates both `readiness` and
    /// `last_readiness_change_at` atomically; callers pass the
    /// timestamp explicitly so test fixtures stay deterministic.
    pub fn set_readiness(
        &mut self,
        name: &str,
        readiness: InstanceReadiness,
        now_rfc3339: impl Into<String>,
    ) -> Result<bool> {
        match self.vms.get_mut(name) {
            Some(reg) => {
                reg.readiness = Some(readiness);
                reg.last_readiness_change_at = Some(now_rfc3339.into());
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Clear the readiness signal (record teardown / `mvmctl down`).
    /// Returns `Ok(true)` if updated, `Ok(false)` if the name is
    /// unknown. Both `readiness` and `last_readiness_change_at` reset
    /// to `None` so a torn-down record never carries a stale
    /// "ServicesReady" ghost.
    pub fn clear_readiness(&mut self, name: &str) -> Result<bool> {
        match self.vms.get_mut(name) {
            Some(reg) => {
                reg.readiness = None;
                reg.last_readiness_change_at = None;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Iterate registrations whose tag map contains every entry in `filter`.
    /// An empty filter matches every registration.
    pub fn filter_by_tags<'a>(
        &'a self,
        filter: &'a BTreeMap<String, String>,
    ) -> impl Iterator<Item = (&'a str, &'a VmRegistration)> + 'a {
        self.vms
            .iter()
            .filter(move |(_, reg)| {
                filter
                    .iter()
                    .all(|(k, v)| reg.tags.get(k).map(String::as_str) == Some(v.as_str()))
            })
            .map(|(name, reg)| (name.as_str(), reg))
    }

    /// Deregister a VM by name. Returns the registration if it existed.
    pub fn deregister(&mut self, name: &str) -> Option<VmRegistration> {
        self.vms.remove(name)
    }

    /// Look up a VM by name.
    pub fn lookup(&self, name: &str) -> Option<&VmRegistration> {
        self.vms.get(name)
    }

    /// List all registered VM names.
    pub fn names(&self) -> Vec<&str> {
        self.vms.keys().map(String::as_str).collect()
    }

    /// Number of registered VMs.
    pub fn len(&self) -> usize {
        self.vms.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.vms.is_empty()
    }
}

/// Builder-style params for `register_with_metadata`.
pub struct RegisterParams<'a> {
    pub name: &'a str,
    pub vm_dir: &'a str,
    pub network: &'a str,
    pub guest_ip: Option<&'a str>,
    pub slot_index: u8,
    pub tags: BTreeMap<String, String>,
    pub expires_at: Option<String>,
    pub auto_resume: bool,
}

impl<'a> RegisterParams<'a> {
    /// Convenience: a `RegisterParams` with no tags, no TTL, and
    /// `auto_resume = true` — the shape used by every callsite
    /// before A5 lands. Lets new callers focus only on the fields
    /// they actually want to change.
    pub fn minimal(name: &'a str, vm_dir: &'a str, network: &'a str) -> Self {
        Self {
            name,
            vm_dir,
            network,
            guest_ip: None,
            slot_index: 0,
            tags: BTreeMap::new(),
            expires_at: None,
            auto_resume: true,
        }
    }
}

/// Default registry file path.
pub fn registry_path() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_share_dir()).join("vm-names.json")
}

/// Generate a unique VM name with a random suffix.
pub fn generate_vm_name() -> String {
    let id = mvm_core::naming::generate_instance_id();
    // Use the hex suffix from instance ID generation
    let suffix = &id[2..]; // strip "i-" prefix
    format!("vm-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let reg = VmNameRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.names().is_empty());
    }

    #[test]
    fn test_register_and_lookup() {
        let mut reg = VmNameRegistry::default();
        reg.register("myvm", "/tmp/vms/myvm", "default", Some("172.16.0.2"), 0)
            .unwrap();

        assert_eq!(reg.len(), 1);
        let info = reg.lookup("myvm").unwrap();
        assert_eq!(info.vm_dir, "/tmp/vms/myvm");
        assert_eq!(info.network, "default");
        assert_eq!(info.guest_ip.as_deref(), Some("172.16.0.2"));
    }

    #[test]
    fn test_register_duplicate_fails() {
        let mut reg = VmNameRegistry::default();
        reg.register("myvm", "/tmp/vms/myvm", "default", None, 0)
            .unwrap();
        assert!(
            reg.register("myvm", "/tmp/vms/myvm2", "default", None, 1)
                .is_err()
        );
    }

    #[test]
    fn test_deregister() {
        let mut reg = VmNameRegistry::default();
        reg.register("myvm", "/tmp/vms/myvm", "default", None, 0)
            .unwrap();
        let removed = reg.deregister("myvm");
        assert!(removed.is_some());
        assert!(reg.is_empty());
        assert!(reg.lookup("myvm").is_none());
    }

    #[test]
    fn test_deregister_nonexistent() {
        let mut reg = VmNameRegistry::default();
        assert!(reg.deregister("nonexistent").is_none());
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut reg = VmNameRegistry::default();
        reg.register("vm1", "/tmp/vms/vm1", "default", Some("172.16.0.2"), 0)
            .unwrap();
        reg.register("vm2", "/tmp/vms/vm2", "isolated", None, 1)
            .unwrap();

        let json = serde_json::to_string(&reg).unwrap();
        let parsed: VmNameRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.lookup("vm1").is_some());
        assert!(parsed.lookup("vm2").is_some());
    }

    #[test]
    fn test_load_save_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vm-names.json");

        let mut reg = VmNameRegistry::default();
        reg.register("myvm", "/tmp/vms/myvm", "default", Some("172.16.0.2"), 0)
            .unwrap();
        reg.save(&path).unwrap();

        let loaded = VmNameRegistry::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.lookup("myvm").unwrap().guest_ip.as_deref(),
            Some("172.16.0.2")
        );
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let path = PathBuf::from("/nonexistent/vm-names.json");
        let reg = VmNameRegistry::load(&path).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn test_generate_vm_name_format() {
        let name = generate_vm_name();
        assert!(name.starts_with("vm-"));
        assert!(name.len() > 3);
    }

    #[test]
    fn test_generate_vm_name_unique() {
        let name1 = generate_vm_name();
        let name2 = generate_vm_name();
        assert_ne!(name1, name2);
    }

    #[test]
    fn test_names_list() {
        let mut reg = VmNameRegistry::default();
        reg.register("alpha", "/tmp/alpha", "default", None, 0)
            .unwrap();
        reg.register("beta", "/tmp/beta", "default", None, 1)
            .unwrap();
        let mut names = reg.names();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn legacy_registration_defaults_new_fields() {
        let mut reg = VmNameRegistry::default();
        reg.register("legacy", "/tmp/legacy", "default", None, 0)
            .unwrap();
        let r = reg.lookup("legacy").unwrap();
        assert!(r.tags.is_empty());
        assert!(r.expires_at.is_none());
        assert!(r.auto_resume);
    }

    #[test]
    fn register_with_metadata_persists_fields() {
        let mut reg = VmNameRegistry::default();
        let mut tags = BTreeMap::new();
        tags.insert("job".to_string(), "etl".to_string());
        reg.register_with_metadata(RegisterParams {
            name: "fancy",
            vm_dir: "/tmp/fancy",
            network: "default",
            guest_ip: None,
            slot_index: 2,
            tags,
            expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            auto_resume: false,
        })
        .unwrap();
        let r = reg.lookup("fancy").unwrap();
        assert_eq!(r.tags.get("job").map(String::as_str), Some("etl"));
        assert_eq!(r.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert!(!r.auto_resume);
    }

    #[test]
    fn set_expires_at_returns_false_for_unknown_vm() {
        let mut reg = VmNameRegistry::default();
        assert!(!reg.set_expires_at("ghost", Some("x".to_string())).unwrap());
    }

    #[test]
    fn set_expires_at_updates_existing() {
        let mut reg = VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        assert!(
            reg.set_expires_at("vm1", Some("2099-01-01T00:00:00Z".to_string()))
                .unwrap()
        );
        assert_eq!(
            reg.lookup("vm1").unwrap().expires_at.as_deref(),
            Some("2099-01-01T00:00:00Z")
        );
        // Clearing back to None works too.
        assert!(reg.set_expires_at("vm1", None).unwrap());
        assert!(reg.lookup("vm1").unwrap().expires_at.is_none());
    }

    #[test]
    fn filter_by_tags_matches_subset() {
        let mut reg = VmNameRegistry::default();
        let mut a_tags = BTreeMap::new();
        a_tags.insert("job".to_string(), "etl".to_string());
        a_tags.insert("env".to_string(), "prod".to_string());
        reg.register_with_metadata(RegisterParams {
            name: "a",
            vm_dir: "/tmp/a",
            network: "default",
            guest_ip: None,
            slot_index: 0,
            tags: a_tags,
            expires_at: None,
            auto_resume: true,
        })
        .unwrap();
        let mut b_tags = BTreeMap::new();
        b_tags.insert("job".to_string(), "etl".to_string());
        b_tags.insert("env".to_string(), "dev".to_string());
        reg.register_with_metadata(RegisterParams {
            name: "b",
            vm_dir: "/tmp/b",
            network: "default",
            guest_ip: None,
            slot_index: 1,
            tags: b_tags,
            expires_at: None,
            auto_resume: true,
        })
        .unwrap();

        // Filter on both keys: only `a` matches.
        let mut want = BTreeMap::new();
        want.insert("job".to_string(), "etl".to_string());
        want.insert("env".to_string(), "prod".to_string());
        let names: Vec<_> = reg.filter_by_tags(&want).map(|(n, _)| n).collect();
        assert_eq!(names, vec!["a"]);

        // Filter on shared key only: both match.
        let mut want = BTreeMap::new();
        want.insert("job".to_string(), "etl".to_string());
        let mut names: Vec<_> = reg.filter_by_tags(&want).map(|(n, _)| n).collect();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);

        // Empty filter matches all.
        let want = BTreeMap::new();
        assert_eq!(reg.filter_by_tags(&want).count(), 2);
    }

    #[test]
    fn set_paused_returns_false_for_unknown_vm() {
        let mut reg = VmNameRegistry::default();
        assert!(!reg.set_paused("ghost", true).unwrap());
    }

    #[test]
    fn set_paused_flips_flag() {
        let mut reg = VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        assert!(!reg.lookup("vm1").unwrap().paused);
        assert!(reg.set_paused("vm1", true).unwrap());
        assert!(reg.lookup("vm1").unwrap().paused);
        assert!(reg.set_paused("vm1", false).unwrap());
        assert!(!reg.lookup("vm1").unwrap().paused);
    }

    #[test]
    fn register_params_minimal_default_shape() {
        let p = RegisterParams::minimal("v", "/tmp/v", "default");
        assert_eq!(p.guest_ip, None);
        assert_eq!(p.slot_index, 0);
        assert!(p.tags.is_empty());
        assert!(p.expires_at.is_none());
        assert!(p.auto_resume);
    }

    #[test]
    fn legacy_json_deserializes_with_default_fields() {
        // Pre-sandbox-SDK records persisted on disk should still load.
        let json = r#"{
            "vms": {
                "old": {
                    "vm_dir": "/tmp/old",
                    "network": "default",
                    "guest_ip": null,
                    "slot_index": 0,
                    "registered_at": "2024-01-01T00:00:00Z"
                }
            }
        }"#;
        let parsed: VmNameRegistry = serde_json::from_str(json).unwrap();
        let r = parsed.lookup("old").unwrap();
        assert!(r.tags.is_empty());
        assert!(r.expires_at.is_none());
        assert!(r.auto_resume);
        // ADR-053 / plan 74 W2 readiness fields default cleanly on
        // legacy records that pre-date the field. mvm-cli `ls --json`
        // emits them as `null` on legacy rows.
        assert_eq!(r.readiness, None);
        assert_eq!(r.last_readiness_change_at, None);
    }

    // -------- Readiness milestones (ADR-053 §3 / plan 74 W2) --------

    #[test]
    fn set_readiness_returns_false_for_unknown_vm() {
        let mut reg = VmNameRegistry::default();
        assert!(
            !reg.set_readiness(
                "ghost",
                InstanceReadiness::AgentReady,
                "2025-01-01T00:00:00Z"
            )
            .unwrap()
        );
    }

    #[test]
    fn set_readiness_updates_both_fields_atomically() {
        let mut reg = VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        assert_eq!(reg.lookup("vm1").unwrap().readiness, None);

        assert!(
            reg.set_readiness(
                "vm1",
                InstanceReadiness::LaunchAccepted,
                "2025-01-01T00:00:00Z"
            )
            .unwrap()
        );
        let r = reg.lookup("vm1").unwrap();
        assert_eq!(r.readiness, Some(InstanceReadiness::LaunchAccepted));
        assert_eq!(
            r.last_readiness_change_at.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );

        // Successive transitions overwrite both fields together.
        assert!(
            reg.set_readiness("vm1", InstanceReadiness::AgentReady, "2025-01-01T00:00:05Z")
                .unwrap()
        );
        let r = reg.lookup("vm1").unwrap();
        assert_eq!(r.readiness, Some(InstanceReadiness::AgentReady));
        assert_eq!(
            r.last_readiness_change_at.as_deref(),
            Some("2025-01-01T00:00:05Z")
        );
    }

    #[test]
    fn clear_readiness_resets_both_fields() {
        let mut reg = VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        reg.set_readiness("vm1", InstanceReadiness::AgentReady, "2025-01-01T00:00:00Z")
            .unwrap();

        assert!(reg.clear_readiness("vm1").unwrap());
        let r = reg.lookup("vm1").unwrap();
        assert_eq!(r.readiness, None);
        assert_eq!(r.last_readiness_change_at, None);

        // Clearing an unknown VM returns Ok(false), no error.
        assert!(!reg.clear_readiness("ghost").unwrap());
    }

    #[test]
    fn readiness_roundtrip_through_registry_save_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vm-names.json");

        let mut reg = VmNameRegistry::default();
        reg.register("vm1", "/tmp/vm1", "default", None, 0).unwrap();
        reg.set_readiness(
            "vm1",
            InstanceReadiness::ServicesStarting {
                pending: vec!["postgres".to_string()],
            },
            "2025-01-01T00:00:00Z",
        )
        .unwrap();
        reg.save(&path).unwrap();

        let loaded = VmNameRegistry::load(&path).unwrap();
        let r = loaded.lookup("vm1").unwrap();
        assert_eq!(
            r.readiness,
            Some(InstanceReadiness::ServicesStarting {
                pending: vec!["postgres".to_string()]
            })
        );
        assert_eq!(
            r.last_readiness_change_at.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
    }
}
